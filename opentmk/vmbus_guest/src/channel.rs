// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VMBus channel lifecycle operations.

use crate::Error;
use crate::Result;
use crate::client_driver::ClientDriver;
use crate::client_driver::MessagePump;
use crate::client_driver::driver;
use crate::deadline::Clock;
use crate::deadline::Deadline;
use crate::gpadl::GpadlHandle;
use crate::hypercalls::signal_event;
use crate::interrupt::SimpPump;
pub use crate::ring::PacketFlags;
pub use crate::ring::RecvPacket;
use crate::synic::synic_pages;
use opentmk_core::context::HypercallPlatformTrait;
use opentmk_core::platform::hyperv::ctx::HyperVHypercallConfig;
use vmbus_client_core::CompletionResult;
use vmbus_client_core::Event;
use vmbus_client_core::OpenChannelParams;
use vmbus_core::protocol::ChannelId;
use vmbus_core::protocol::OfferChannel;

/// Whether the channel is usable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// The channel is open.
    Open,
    /// The host rescinded the channel.
    Rescinded,
    /// The channel was closed.
    Closed,
}

/// A guest-side handle to an open VMBus channel.
#[derive(Debug)]
pub struct Channel {
    pub(crate) channel_id: ChannelId,
    pub(crate) open_id: u32,
    pub(crate) ring_gpadl: GpadlHandle,
    pub(crate) connection_id: u32,
    pub(crate) event_flag: u16,
    pub(crate) state: ChannelState,
}

impl Channel {
    /// The host-assigned channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    /// The open ID. `ClientCore` uses zero, as allowed by the protocol.
    pub fn open_id(&self) -> u32 {
        self.open_id
    }

    /// The GPADL backing the ring.
    pub fn ring_gpadl(&self) -> GpadlHandle {
        self.ring_gpadl
    }

    /// Connection ID used to signal the host.
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// Host-to-guest event flag.
    pub fn event_flag(&self) -> u16 {
        self.event_flag
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ChannelState {
        if driver().is_rescinded(self.channel_id) {
            ChannelState::Rescinded
        } else {
            self.state
        }
    }

    /// Signal the host after publishing ring data.
    pub fn signal<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
        &self,
        ctx: &mut C,
    ) -> Result<()> {
        if self.state() != ChannelState::Open {
            return Err(Error::Rescinded);
        }
        signal_event(ctx, self.connection_id, 0)
    }
}

/// Open a channel using an explicit driver and message pump.
pub fn open_channel_with<C, P>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    pump: &mut P,
    offer: &OfferChannel,
    ring_gpadl: GpadlHandle,
    send_data_pages: u32,
    connection_id: u32,
    event_flag: u16,
) -> Result<Channel>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    P: MessagePump,
{
    open_channel_inner(
        ctx,
        driver,
        pump,
        offer,
        ring_gpadl,
        send_data_pages,
        connection_id,
        event_flag,
        None::<&Deadline>,
    )
}

/// Deadline-aware [`open_channel_with`].
///
/// On [`Error::DeadlineExceeded`] the host may or may not have opened
/// the channel; the ring GPADL must not be reused.
pub fn open_channel_with_until<C, P, K>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    pump: &mut P,
    offer: &OfferChannel,
    ring_gpadl: GpadlHandle,
    send_data_pages: u32,
    connection_id: u32,
    event_flag: u16,
    deadline: &Deadline<K>,
) -> Result<Channel>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    P: MessagePump,
    K: Clock,
{
    open_channel_inner(
        ctx,
        driver,
        pump,
        offer,
        ring_gpadl,
        send_data_pages,
        connection_id,
        event_flag,
        Some(deadline),
    )
}

fn open_channel_inner<C, P, K>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    pump: &mut P,
    offer: &OfferChannel,
    ring_gpadl: GpadlHandle,
    send_data_pages: u32,
    connection_id: u32,
    event_flag: u16,
    deadline: Option<&Deadline<K>>,
) -> Result<Channel>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    P: MessagePump,
    K: Clock,
{
    let request_id = driver.request_id();
    driver.step_opt(
        ctx,
        Event::OpenChannel {
            request_id,
            channel_id: offer.channel_id,
            open: OpenChannelParams {
                target_vp: None,
                ring_offset: 1 + send_data_pages,
                ring_gpadl_id: ring_gpadl.gpadl_id,
                event_flag,
                connection_id,
                redirected_event_flag: None,
                user_data: Default::default(),
            },
        },
        deadline,
    )?;
    match driver.wait_opt(ctx, pump, request_id, deadline)? {
        CompletionResult::OpenChannel(Ok(_)) => Ok(Channel {
            channel_id: offer.channel_id,
            open_id: 0,
            ring_gpadl,
            connection_id,
            event_flag,
            state: ChannelState::Open,
        }),
        CompletionResult::OpenChannel(Err(_)) => Err(Error::OpenFailed),
        _ => Err(Error::UnexpectedCompletion),
    }
}

fn close_channel_inner<C, K>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    channel: Channel,
    release: bool,
    deadline: Option<&Deadline<K>>,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    driver.step_opt(
        ctx,
        Event::CloseChannel {
            channel_id: channel.channel_id,
        },
        deadline,
    )?;
    if release {
        driver.step_opt(
            ctx,
            Event::ReleaseChannel {
                channel_id: channel.channel_id,
            },
            deadline,
        )?;
    }
    Ok(())
}

/// Close a channel and release caller ownership.
pub fn close_channel_with<C>(ctx: &mut C, driver: &mut ClientDriver, channel: Channel) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
{
    close_channel_inner(ctx, driver, channel, true, None::<&Deadline>)
}

/// Close a channel while retaining its relid for GPADL teardown/reopen.
pub fn close_channel_keep_relid_with<C>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    channel: Channel,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
{
    close_channel_inner(ctx, driver, channel, false, None::<&Deadline>)
}

/// Deadline-aware [`close_channel_with`]. Close is fire-and-forget, so
/// the deadline bounds only the `CloseChannel`/`RelIdReleased` posts.
pub fn close_channel_with_until<C, K>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    channel: Channel,
    deadline: &Deadline<K>,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    close_channel_inner(ctx, driver, channel, true, Some(deadline))
}

/// Deadline-aware [`close_channel_keep_relid_with`].
pub fn close_channel_keep_relid_with_until<C, K>(
    ctx: &mut C,
    driver: &mut ClientDriver,
    channel: Channel,
    deadline: &Deadline<K>,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    close_channel_inner(ctx, driver, channel, false, Some(deadline))
}

/// Open using the process-wide driver and SIMP pump.
pub fn open_channel<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
    ctx: &mut C,
    offer: &OfferChannel,
    ring_gpadl: GpadlHandle,
    send_data_pages: u32,
    connection_id: u32,
    event_flag: u16,
) -> Result<Channel> {
    let pages = synic_pages().ok_or(Error::VersionMismatch)?;
    open_channel_with(
        ctx,
        &mut driver(),
        &mut SimpPump::new(pages.simp_gpa),
        offer,
        ring_gpadl,
        send_data_pages,
        connection_id,
        event_flag,
    )
}

/// Close using the process-wide driver.
pub fn close_channel<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
    ctx: &mut C,
    channel: Channel,
) -> Result<()> {
    close_channel_with(ctx, &mut driver(), channel)
}

/// Close without releasing the relid using the process-wide driver.
pub fn close_channel_keep_relid<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
    ctx: &mut C,
    channel: Channel,
) -> Result<()> {
    close_channel_keep_relid_with(ctx, &mut driver(), channel)
}

/// [`open_channel_with_until`] using the process-wide driver and SIMP
/// pump.
pub fn open_channel_until<C, K>(
    ctx: &mut C,
    offer: &OfferChannel,
    ring_gpadl: GpadlHandle,
    send_data_pages: u32,
    connection_id: u32,
    event_flag: u16,
    deadline: &Deadline<K>,
) -> Result<Channel>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    let pages = synic_pages().ok_or(Error::VersionMismatch)?;
    open_channel_with_until(
        ctx,
        &mut driver(),
        &mut SimpPump::new(pages.simp_gpa),
        offer,
        ring_gpadl,
        send_data_pages,
        connection_id,
        event_flag,
        deadline,
    )
}

/// [`close_channel_with_until`] using the process-wide driver.
pub fn close_channel_until<C, K>(
    ctx: &mut C,
    channel: Channel,
    deadline: &Deadline<K>,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    close_channel_with_until(ctx, &mut driver(), channel, deadline)
}

/// [`close_channel_keep_relid_with_until`] using the process-wide driver.
pub fn close_channel_keep_relid_until<C, K>(
    ctx: &mut C,
    channel: Channel,
    deadline: &Deadline<K>,
) -> Result<()>
where
    C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    K: Clock,
{
    close_channel_keep_relid_with_until(ctx, &mut driver(), channel, deadline)
}
