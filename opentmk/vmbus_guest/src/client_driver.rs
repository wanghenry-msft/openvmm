// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synchronous runtime adapter for [`vmbus_client_core::ClientCore`].

use crate::Result;
use crate::deadline::Clock;
use crate::deadline::Deadline;
use crate::hvsock::dispatch_connect_result;
use crate::hypercalls::post_message;
use crate::hypercalls::post_message_until;
use crate::hypercalls::signal_event;
use crate::message::parse;
use crate::protocol::VMBUS_CONNECTION_ID_LEGACY;
use crate::protocol::VMBUS_CONNECTION_ID_MODERN;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use opentmk_core::context::HypercallPlatformTrait;
use opentmk_core::platform::hyperv::ctx::HyperVHypercallConfig;
use spin::Mutex;
use spin::MutexGuard;
use spin::Once;
use vmbus_client_core::Action;
use vmbus_client_core::ActionSink;
use vmbus_client_core::ClientCore;
use vmbus_client_core::ClientPhase;
use vmbus_client_core::CompletionResult;
use vmbus_client_core::Config;
use vmbus_client_core::Event;
use vmbus_client_core::RequestId;
use vmbus_core::VersionInfo;
use vmbus_core::protocol::ChannelId;
use vmbus_core::protocol::MessageType;
use vmbus_core::protocol::OfferChannel;
use vmbus_core::protocol::TlConnectResult;
use vmbus_core::protocol::Version;
use vmbus_core::protocol::VersionResponse;
use vmbus_core::protocol::VersionResponse3;
use vmbus_core::protocol::VmbusMessage;

/// Versions understood by the guest, ordered oldest to newest as required by
/// [`ClientCore`].
pub const SUPPORTED_VERSIONS: &[Version] = &[
    Version::Win8,
    Version::Win8_1,
    Version::Win10,
    Version::Win10Rs3_1,
    Version::Win10Rs4,
    Version::Win10Rs5,
    Version::Iron,
    Version::Copper,
];

/// A source of raw channel-manager messages.
pub trait MessagePump {
    /// Poll until one message is available.
    fn poll_message<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
        &mut self,
        ctx: &mut C,
    ) -> Result<Vec<u8>>;

    /// Poll until one message is available or `deadline` passes, in which
    /// case [`Error::DeadlineExceeded`](crate::Error::DeadlineExceeded)
    /// is returned.
    ///
    /// The default checks the deadline once and then defers to
    /// [`Self::poll_message`], so it is only bounded if that is. Pumps
    /// that block should override it to re-check the deadline while
    /// waiting.
    fn poll_message_until<C, K>(&mut self, ctx: &mut C, deadline: &Deadline<K>) -> Result<Vec<u8>>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        deadline.check()?;
        self.poll_message(ctx)
    }
}

#[derive(Default)]
struct ActionBuffer {
    actions: Vec<Action>,
}

impl ActionSink for ActionBuffer {
    fn emit(&mut self, action: Action) {
        self.actions.push(action);
    }
}

/// Synchronous owner of the shared VMBus protocol state.
pub struct ClientDriver {
    core: ClientCore,
    supported_versions: &'static [Version],
    next_request_id: u64,
    completions: BTreeMap<RequestId, CompletionResult>,
    detached_requests: BTreeSet<RequestId>,
    offers: Vec<OfferChannel>,
    rescinded: BTreeSet<ChannelId>,
    post_message_connection_id: u32,
    parent_to_child_monitor_page_gpa: u64,
    child_to_parent_monitor_page_gpa: u64,
}

impl Default for ClientDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientDriver {
    /// Construct a running driver with the guest's supported version set.
    pub fn new() -> Self {
        Self::with_versions(SUPPORTED_VERSIONS)
    }

    /// Construct a driver with an explicit version set.
    pub fn with_versions(supported_versions: &'static [Version]) -> Self {
        let mut core = ClientCore::new(Config {
            sint: crate::synic::VMBUS_SINT,
            vtl: 0,
            supported_versions,
            supported_feature_flags: crate::protocol::supported_feature_flags(),
        });
        core.step(Event::Start, &mut ActionBuffer::default());
        Self {
            core,
            supported_versions,
            next_request_id: 1,
            completions: BTreeMap::new(),
            detached_requests: BTreeSet::new(),
            offers: Vec::new(),
            rescinded: BTreeSet::new(),
            post_message_connection_id: VMBUS_CONNECTION_ID_MODERN,
            parent_to_child_monitor_page_gpa: 0,
            child_to_parent_monitor_page_gpa: 0,
        }
    }

    /// Return the protocol core.
    pub fn core(&self) -> &ClientCore {
        &self.core
    }

    /// Return the currently negotiated version.
    pub fn version(&self) -> Option<VersionInfo> {
        self.core.phase().version()
    }

    /// Return the connection ID used for channel-manager messages.
    pub fn post_message_connection_id(&self) -> u32 {
        self.post_message_connection_id
    }

    /// Return the monitor pages supplied by the server.
    pub fn monitor_pages(&self) -> (u64, u64) {
        (
            self.parent_to_child_monitor_page_gpa,
            self.child_to_parent_monitor_page_gpa,
        )
    }

    /// Return whether the host has rescinded a channel.
    pub fn is_rescinded(&self, channel_id: ChannelId) -> bool {
        self.rescinded.contains(&channel_id)
    }

    /// Allocate a request identifier.
    pub fn request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_request_id);
        self.next_request_id = self.next_request_id.wrapping_add(1);
        assert_ne!(self.next_request_id, 0, "vmbus request id exhausted");
        id
    }

    /// Mark a fire-and-forget request so its eventual completion is discarded.
    pub fn detach_request(&mut self, request_id: RequestId) {
        self.detached_requests.insert(request_id);
    }

    /// Drive one event and execute every emitted runtime action synchronously.
    pub fn step<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
        &mut self,
        ctx: &mut C,
        event: Event<'_>,
    ) -> Result<()> {
        self.step_opt(ctx, event, None::<&Deadline>)
    }

    /// Deadline-aware [`Self::step`]: every `PostMessage` action uses
    /// [`post_message_until`].
    ///
    /// As with [`Self::step`], a failed post (including
    /// [`Error::DeadlineExceeded`](crate::Error::DeadlineExceeded))
    /// resets the protocol core, so the connection must be
    /// re-established afterwards.
    pub fn step_until<C, K>(
        &mut self,
        ctx: &mut C,
        event: Event<'_>,
        deadline: &Deadline<K>,
    ) -> Result<()>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        self.step_opt(ctx, event, Some(deadline))
    }

    /// [`Self::step`] or [`Self::step_until`] depending on `deadline`.
    pub(crate) fn step_opt<C, K>(
        &mut self,
        ctx: &mut C,
        event: Event<'_>,
        deadline: Option<&Deadline<K>>,
    ) -> Result<()>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        if let Event::HostMessage(bytes) = event {
            self.observe_host_message(bytes);
        }

        let mut sink = ActionBuffer::default();
        self.core.step(event, &mut sink);
        for action in sink.actions {
            match action {
                Action::PostMessage(bytes) => {
                    let connection_id = match self.core.phase() {
                        ClientPhase::Connecting { version, .. } => {
                            crate::connection::initial_connection_id(*version)
                        }
                        _ => self.post_message_connection_id,
                    };
                    let posted = match deadline {
                        Some(deadline) => post_message_until(ctx, connection_id, &bytes, deadline),
                        None => post_message(ctx, connection_id, &bytes),
                    };
                    if let Err(error) = posted {
                        // The core has already advanced to a pending state. A
                        // failed post cannot produce its completion, so reset
                        // rather than leaving the synchronous API wedged.
                        self.reset_protocol();
                        return Err(error);
                    }
                }
                Action::SignalEvent {
                    connection_id,
                    event_flag,
                } => signal_event(ctx, connection_id, event_flag)?,
                Action::Complete { request_id, result } => {
                    if self.detached_requests.remove(&request_id) {
                        continue;
                    }
                    if matches!(&result, CompletionResult::Unload) {
                        self.clear_runtime_state();
                    }
                    self.completions.insert(request_id, result);
                }
                Action::OfferReceived(offer) => {
                    self.rescinded.remove(&offer.offer.channel_id);
                    self.offers.push(offer.offer);
                }
                Action::OfferRescinded { channel_id } => {
                    self.rescinded.insert(channel_id);
                    self.offers.retain(|offer| offer.channel_id != channel_id);
                }
                Action::ChannelObservable { .. }
                | Action::ChannelRemoved { .. }
                | Action::FreeEventFlag(_)
                | Action::PauseComplete => {}
            }
        }
        Ok(())
    }

    /// Wait until a request completes while feeding host messages into the core.
    pub fn wait_for<C, P>(
        &mut self,
        ctx: &mut C,
        pump: &mut P,
        request_id: RequestId,
    ) -> Result<CompletionResult>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
    {
        loop {
            if let Some(result) = self.completions.remove(&request_id) {
                return Ok(result);
            }
            let message = pump.poll_message(ctx)?;
            self.step(ctx, Event::HostMessage(&message))?;
        }
    }

    /// Deadline-aware [`Self::wait_for`].
    ///
    /// Unrelated host messages are still fed into the core (offers,
    /// rescinds, other completions), but the wait returns
    /// [`Error::DeadlineExceeded`](crate::Error::DeadlineExceeded) once
    /// `deadline` passes, however many messages keep arriving. On any
    /// error the request is detached, so a late completion is discarded
    /// instead of accumulating. The host-side outcome of the request is
    /// then unknown.
    pub fn wait_for_until<C, P, K>(
        &mut self,
        ctx: &mut C,
        pump: &mut P,
        request_id: RequestId,
        deadline: &Deadline<K>,
    ) -> Result<CompletionResult>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
        K: Clock,
    {
        let result = self.wait_for_until_inner(ctx, pump, request_id, deadline);
        if result.is_err() {
            self.detach_request(request_id);
        }
        result
    }

    /// [`Self::wait_for`] or [`Self::wait_for_until`] depending on
    /// `deadline`.
    pub(crate) fn wait_opt<C, P, K>(
        &mut self,
        ctx: &mut C,
        pump: &mut P,
        request_id: RequestId,
        deadline: Option<&Deadline<K>>,
    ) -> Result<CompletionResult>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
        K: Clock,
    {
        match deadline {
            Some(deadline) => self.wait_for_until(ctx, pump, request_id, deadline),
            None => self.wait_for(ctx, pump, request_id),
        }
    }

    fn wait_for_until_inner<C, P, K>(
        &mut self,
        ctx: &mut C,
        pump: &mut P,
        request_id: RequestId,
        deadline: &Deadline<K>,
    ) -> Result<CompletionResult>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
        K: Clock,
    {
        loop {
            if let Some(result) = self.completions.remove(&request_id) {
                return Ok(result);
            }
            deadline.check()?;
            let message = pump.poll_message_until(ctx, deadline)?;
            self.step_until(ctx, Event::HostMessage(&message), deadline)?;
        }
    }

    /// Drain offers accumulated during `RequestOffers`.
    pub fn take_offers(&mut self) -> Vec<OfferChannel> {
        core::mem::take(&mut self.offers)
    }

    fn observe_host_message(&mut self, bytes: &[u8]) {
        let Ok(message_type) = crate::message::peek_header(bytes) else {
            return;
        };
        if message_type == MessageType::TL_CONNECT_REQUEST_RESULT {
            if let Ok(result) = parse::<TlConnectResult>(bytes) {
                dispatch_connect_result(&result);
            }
            return;
        }
        if message_type != MessageType::VERSION_RESPONSE {
            return;
        }
        let ClientPhase::Connecting { version, .. } = self.core.phase() else {
            return;
        };
        let Ok(response) = parse::<VersionResponse>(bytes) else {
            return;
        };
        if response.version_supported == 0
            || response.connection_state != vmbus_core::protocol::ConnectionState::SUCCESSFUL
        {
            return;
        }
        self.post_message_connection_id = if *version < Version::Win10Rs3_1 {
            VMBUS_CONNECTION_ID_LEGACY
        } else {
            response.selected_version_or_connection_id
        };
        self.parent_to_child_monitor_page_gpa = 0;
        self.child_to_parent_monitor_page_gpa = 0;
        if bytes.len() >= VersionResponse3::MESSAGE_SIZE {
            if let Ok(response) = parse::<VersionResponse3>(bytes) {
                self.parent_to_child_monitor_page_gpa = response.parent_to_child_monitor_page_gpa;
                self.child_to_parent_monitor_page_gpa = response.child_to_parent_monitor_page_gpa;
            }
        }
    }

    fn clear_runtime_state(&mut self) {
        self.offers.clear();
        self.rescinded.clear();
        self.detached_requests.clear();
        self.post_message_connection_id = VMBUS_CONNECTION_ID_MODERN;
        self.parent_to_child_monitor_page_gpa = 0;
        self.child_to_parent_monitor_page_gpa = 0;
    }

    fn reset_protocol(&mut self) {
        self.core = ClientCore::new(Config {
            sint: crate::synic::VMBUS_SINT,
            vtl: 0,
            supported_versions: self.supported_versions,
            supported_feature_flags: crate::protocol::supported_feature_flags(),
        });
        self.core.step(Event::Start, &mut ActionBuffer::default());
        self.completions.clear();
        self.clear_runtime_state();
    }
}

static DRIVER: Once<Mutex<ClientDriver>> = Once::new();

/// Lock the process-wide guest driver.
pub fn driver() -> MutexGuard<'static, ClientDriver> {
    DRIVER.call_once(|| Mutex::new(ClientDriver::new())).lock()
}
