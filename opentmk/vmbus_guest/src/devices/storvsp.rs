// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Polling guest client for the synthetic SCSI controller (StorVSP).
//!
//! The session lifecycle is [`StorSession::open_until`] (GPADL + channel
//! open, no protocol traffic) → optional [`StorSession::negotiate_until`]
//! (Begin → QueryVersion ladder → QueryProperties → End) → any mix of
//! [`StorSession::send_request`], [`StorSession::request_until`],
//! [`StorSession::send_raw`] and [`StorSession::poll`] →
//! [`StorSession::close_until`].
//!
//! Only the negotiation order and completion matching of
//! `storvsc_driver` are mirrored; none of its async runtime is used.
//!
//! # Restart-required semantics
//!
//! A VMBus control operation whose host-side outcome is unknown (a
//! GPADL create/teardown or `OpenResult` that never arrives, a failed
//! post that reset the driver's protocol state, ...) is reported as
//! [`StorvspError::RestartRequired`]. In that case the ring/GPADL pages
//! are deliberately leaked — the host may still map them — and the
//! caller must stop issuing StorVSP work and restart the VM. The global
//! entry points additionally latch the reason (see [`restart_reason`])
//! and refuse further opens. Ring-level failures (request timeouts,
//! error statuses, malformed or corrupt inbound data) are *not*
//! restart-worthy: the channel can still be closed cleanly.

use crate::Error;
use crate::channel::Channel;
use crate::channel::close_channel_keep_relid_with_until;
use crate::channel::open_channel_with_until;
use crate::client_driver::ClientDriver;
use crate::client_driver::MessagePump;
use crate::client_driver::driver;
use crate::deadline::Clock;
use crate::deadline::Deadline;
use crate::gpadl::allocate_gpadl_id;
use crate::gpadl::establish_gpadl_with_until;
use crate::gpadl::teardown_gpadl_with_until;
use crate::hypercalls::signal_event;
use crate::interrupt::SimpPump;
use crate::ring::OutgoingRingExt;
use crate::ring::PacketFlags;
use crate::ring::RawRingMem;
use crate::ring::RecvRing;
use crate::ring::RingMem;
use crate::ring::SendRing;
use crate::synic::synic_pages;
use crate::virt_to_phys;
use alloc::alloc::alloc_zeroed;
use alloc::alloc::dealloc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::hint::spin_loop;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use guestmem_core::MemoryRead;
use guid::Guid;
use opentmk_core::context::HypercallPlatformTrait;
use opentmk_core::platform::hyperv::ctx::HyperVHypercallConfig;
use storvsp_protocol::ChannelProperties;
use storvsp_protocol::NtStatus;
use storvsp_protocol::Operation;
use storvsp_protocol::ProtocolVersion;
use thiserror::Error;
use vmbus_client_core::Event;
use vmbus_core::protocol::ChannelId;
use vmbus_core::protocol::GpadlId;
use vmbus_core::protocol::OfferChannel;
use vmbus_ring::IncomingPacketType;
use vmbus_ring::ReadError;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

const PAGE_SIZE: usize = 4096;

/// Data pages per ring direction (power of two, as `vmbus_ring` requires).
pub const RING_DATA_PAGES: usize = 16;
const RING_DATA_BYTES: usize = RING_DATA_PAGES * PAGE_SIZE;
/// Send control + data, then recv control + data.
const REGION_PAGES: usize = 2 * (1 + RING_DATA_PAGES);
const REGION_BYTES: usize = REGION_PAGES * PAGE_SIZE;

/// Maximum outstanding requests awaiting a completion.
pub const PENDING_CAPACITY: usize = 64;

/// Size of the VSTOR [`storvsp_protocol::Packet`] header.
pub const HEADER_LEN: usize = size_of::<storvsp_protocol::Packet>();
/// Frame size for protocol versions below WIN8 (header + V1 SRB).
pub const FRAME_LEN_V1: usize = HEADER_LEN + storvsp_protocol::SCSI_REQUEST_LEN_V1;
/// Frame size for WIN8 and later (header + V2 SRB). Also used for every
/// initialization packet, like `storvsc_driver`, because the host caps
/// a completion at the size of its request.
pub const FRAME_LEN_V2: usize = HEADER_LEN + storvsp_protocol::SCSI_REQUEST_LEN_MAX;

/// Version ladder, newest first.
pub const VERSION_LADDER: [u16; 6] = [
    storvsp_protocol::VERSION_IRON,
    storvsp_protocol::VERSION_THRESHOLD,
    storvsp_protocol::VERSION_BLUE,
    storvsp_protocol::VERSION_WIN8,
    storvsp_protocol::VERSION_WIN7,
    storvsp_protocol::VERSION_WIN6,
];

const DESCRIPTOR_LEN: usize = 16;
const FOOTER_LEN: usize = 8;
/// Ring reads attempted between deadline checks while awaiting a completion.
const WAIT_CHUNK: usize = 256;
/// Packets drained per ring read while awaiting a completion.
const WAIT_DRAIN_BUDGET: usize = 16;

/// Errors returned by the StorVSP client.
#[derive(Debug, Error)]
pub enum StorvspError {
    /// No subchannel-0 offer with the SCSI interface GUID.
    #[error("no StorVSP controller offer found")]
    NoController,
    /// More than one subchannel-0 SCSI offer; selection would be a guess.
    #[error("more than one StorVSP controller offer found")]
    AmbiguousController,
    /// The pending-completion table is full.
    #[error("pending completion table full ({PENDING_CAPACITY} entries)")]
    Backpressure,
    /// A payload does not fit the frame or ring.
    #[error("payload of {len} bytes exceeds the maximum of {max}")]
    PayloadTooLarge {
        /// Requested length in bytes.
        len: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },
    /// Guest-side ring allocation or setup failed.
    #[error("ring setup failed: {0}")]
    RingSetup(&'static str),
    /// The host left a ring's indices or contents in an inconsistent
    /// state (out-of-range or misaligned indices, unparsable packets).
    #[error("ring corrupt")]
    RingCorrupt,
    /// A typed request completed with a non-success status.
    #[error("operation {op:#x} completed with status {status:#x}")]
    Status {
        /// The VSTOR operation that was requested.
        op: u32,
        /// The host's completion status.
        status: u32,
    },
    /// The host rejected every version on the ladder.
    #[error("host rejected every offered protocol version")]
    NoVersion,
    /// An awaited completion could not be parsed.
    #[error("malformed completion: {0}")]
    Malformed(&'static str),
    /// A VMBus control operation has an unknown outcome; its pages were
    /// leaked and the VM must be restarted before more StorVSP work.
    #[error("restart required: {0}")]
    RestartRequired(&'static str),
    /// A lower-level VMBus error (including deadline expiry).
    #[error(transparent)]
    Vmbus(#[from] Error),
}

impl StorvspError {
    /// The restart reason, if this error requires a VM restart.
    pub fn restart_reason(&self) -> Option<&'static str> {
        match self {
            Self::RestartRequired(reason) => Some(reason),
            _ => None,
        }
    }

    /// Whether the error is a timeout or deadline expiry.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Vmbus(e) if e.is_timeout())
    }
}

/// Result alias for this module.
pub type Result<T> = core::result::Result<T, StorvspError>;

/// Outcome of a successful send.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SendOutcome {
    /// Transaction ID placed in the VMBus descriptor.
    pub tid: u64,
    /// Whether the host was signalled (for this packet or to retry an
    /// earlier failed signal).
    pub signalled: bool,
}

/// Counters from one [`StorSession::poll`] call.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PollReport {
    /// Packets consumed from the ring.
    pub packets: u32,
    /// Completions matched to a pending transaction ID.
    pub completions: u32,
    /// Unsolicited ENUMERATE_BUS / EVENT_NOTIFICATION / REMOVE_DEVICE.
    pub unsolicited: u32,
    /// Completions whose transaction ID was not pending.
    pub unknown_tid: u32,
    /// Packets that were short, of unexpected type, or unknown operation.
    pub malformed: u32,
}

/// Result of a successful negotiation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedInfo {
    /// Accepted protocol version (`major << 8 | minor`).
    pub version: u16,
    /// `ChannelProperties::maximum_sub_channel_count`.
    pub max_sub_channel_count: u16,
    /// `ChannelProperties::max_transfer_bytes`.
    pub max_transfer_bytes: u32,
    /// `STORAGE_CHANNEL_SUPPORTS_MULTI_CHANNEL` in `ChannelProperties::flags`.
    pub multi_channel: bool,
}

/// A completion for a request issued with [`StorSession::request_until`].
#[derive(Copy, Clone, Debug)]
pub struct Completion {
    /// Transaction ID of the completed request.
    pub tid: u64,
    /// `Packet::status`.
    pub status: NtStatus,
    /// `Packet::flags`.
    pub flags: u32,
    body: [u8; storvsp_protocol::SCSI_REQUEST_LEN_MAX],
    body_len: usize,
}

impl Completion {
    /// Bytes after the 12-byte header, truncated to the V2 SRB size.
    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
    }
}

/// Decision taken on a QUERY_PROTOCOL_VERSION completion status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LadderStep {
    /// The version was accepted.
    Accept,
    /// The version was rejected; try the next one.
    Advance,
    /// Any other status aborts negotiation.
    Abort,
}

/// Classify a QUERY_PROTOCOL_VERSION completion status.
pub fn ladder_decision(status: NtStatus) -> LadderStep {
    match status {
        NtStatus::SUCCESS => LadderStep::Accept,
        NtStatus::INVALID_DEVICE_STATE | NtStatus::REVISION_MISMATCH => LadderStep::Advance,
        _ => LadderStep::Abort,
    }
}

/// Versions on [`VERSION_LADDER`] at or below `cap`, newest first.
pub fn ladder_from(cap: u16) -> impl Iterator<Item = u16> {
    VERSION_LADDER.into_iter().filter(move |&v| v <= cap)
}

/// Frame size for SRB traffic at `version`.
pub fn frame_len_for(version: u16) -> usize {
    if version >= storvsp_protocol::VERSION_WIN8 {
        FRAME_LEN_V2
    } else {
        FRAME_LEN_V1
    }
}

/// Build a VSTOR frame: header (`flags` = 0, `status` = 0) then `body`,
/// zero-padded to `frame_len`.
pub fn build_frame(operation: Operation, body: &[u8], frame_len: usize) -> Result<Vec<u8>> {
    let len = HEADER_LEN + body.len();
    if len > frame_len {
        return Err(StorvspError::PayloadTooLarge {
            len,
            max: frame_len,
        });
    }
    let header = storvsp_protocol::Packet {
        operation,
        flags: 0,
        status: NtStatus::SUCCESS,
    };
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(body);
    frame.resize(frame_len, 0);
    Ok(frame)
}

/// Pick the single subchannel-0 SCSI controller offer.
pub fn select_offer(offers: &[OfferChannel]) -> Result<&OfferChannel> {
    let mut matching = offers.iter().filter(|o| {
        o.interface_id == storvsp_protocol::SCSI_INTERFACE_ID && o.subchannel_index == 0
    });
    let offer = matching.next().ok_or(StorvspError::NoController)?;
    if matching.next().is_some() {
        return Err(StorvspError::AmbiguousController);
    }
    Ok(offer)
}

/// In-band data descriptor with `flags` passed through verbatim.
fn raw_descriptor(payload_len: usize, flags: u16, tid: u64) -> [u8; DESCRIPTOR_LEN] {
    let len8 = u16::try_from((DESCRIPTOR_LEN + payload_len).div_ceil(8)).unwrap_or(u16::MAX);
    let mut d = [0u8; DESCRIPTOR_LEN];
    d[0..2].copy_from_slice(&6u16.to_le_bytes()); // VM_PKT_DATA_INBAND
    d[2..4].copy_from_slice(&((DESCRIPTOR_LEN / 8) as u16).to_le_bytes());
    d[4..6].copy_from_slice(&len8.to_le_bytes());
    d[6..8].copy_from_slice(&flags.to_le_bytes());
    d[8..16].copy_from_slice(&tid.to_le_bytes());
    d
}

/// Guest memory backing a session's rings.
///
/// Abstracted so host tests can substitute in-memory rings. Dropping a
/// backing without calling [`free`](Self::free) must leak it. Both
/// `rings` and `free` are `unsafe` because the rings alias the backing
/// without a borrow; [`StorSession`] upholds the contract internally.
pub trait RingBacking {
    /// Ring memory type.
    type Mem: RingMem + Sync;
    /// Page frame numbers covering the whole region, in GPADL order.
    fn pfns(&self) -> &[u64];
    /// Region size in bytes.
    fn total_bytes(&self) -> u32;
    /// Pages occupied by the send ring (control + data) minus one, i.e.
    /// the `send_data_pages` argument to channel open.
    fn send_data_pages(&self) -> u32;
    /// Ring data bytes per direction.
    fn ring_data_bytes(&self) -> usize;
    /// Construct the guest send and receive rings.
    ///
    /// # Safety
    ///
    /// The rings refer to the backing's memory without borrowing it: the
    /// caller must drop them before calling [`Self::free`].
    #[expect(unsafe_code, reason = "rings alias the backing without a borrow")]
    unsafe fn rings(&self) -> Result<(SendRing<Self::Mem>, RecvRing<Self::Mem>)>;
    /// Release the memory.
    ///
    /// # Safety
    ///
    /// Every ring returned by [`Self::rings`] must already be dropped,
    /// and the host must no longer be able to access the memory (the
    /// GPADL covering it was never created or is confirmed torn down).
    #[expect(unsafe_code, reason = "freeing memory the host or rings may use")]
    unsafe fn free(self);
}

/// Page-aligned heap region for the real rings. Has no `Drop`: it is
/// leaked unless [`RingBacking::free`] is called.
pub struct PageBacking {
    base: *mut u8,
    layout: Layout,
    pfns: Vec<u64>,
}

#[expect(
    unsafe_code,
    reason = "single-threaded UEFI runtime; identity-mapped allocations"
)]
// SAFETY: the guest runtime is single-threaded and the region is only
// touched through the owning session, mirroring `NetvspBacking`.
unsafe impl Send for PageBacking {}

impl PageBacking {
    /// Allocate a zeroed region for two rings of [`RING_DATA_PAGES`].
    pub fn alloc() -> Result<Self> {
        let layout = Layout::from_size_align(REGION_BYTES, PAGE_SIZE)
            .map_err(|_| StorvspError::RingSetup("invalid ring layout"))?;
        // SAFETY: the layout has non-zero size; the region is freed only
        // via `RingBacking::free`.
        #[expect(unsafe_code, reason = "raw page-aligned allocation for GPADL")]
        let base = unsafe { alloc_zeroed(layout) };
        if base.is_null() {
            return Err(StorvspError::RingSetup("ring allocation failed"));
        }
        let base_gpa = virt_to_phys(base);
        let pfns = (0..REGION_PAGES)
            .map(|i| (base_gpa + (i * PAGE_SIZE) as u64) >> 12)
            .collect();
        Ok(Self { base, layout, pfns })
    }
}

impl RingBacking for PageBacking {
    type Mem = RawRingMem;

    fn pfns(&self) -> &[u64] {
        &self.pfns
    }

    fn total_bytes(&self) -> u32 {
        REGION_BYTES as u32
    }

    fn send_data_pages(&self) -> u32 {
        RING_DATA_PAGES as u32
    }

    fn ring_data_bytes(&self) -> usize {
        RING_DATA_BYTES
    }

    #[expect(unsafe_code, reason = "rings alias the backing without a borrow")]
    unsafe fn rings(&self) -> Result<(SendRing<RawRingMem>, RecvRing<RawRingMem>)> {
        let recv_ctrl = PAGE_SIZE + RING_DATA_BYTES;
        // SAFETY: all offsets lie within the `REGION_BYTES` allocation,
        // which `free`'s contract keeps alive until the rings are dropped.
        #[expect(unsafe_code, reason = "raw ring memory over identity-mapped region")]
        let (send_mem, recv_mem) = unsafe {
            (
                RawRingMem::new(
                    self.base as *const AtomicU32,
                    self.base.add(PAGE_SIZE) as *const AtomicU8,
                    RING_DATA_BYTES,
                ),
                RawRingMem::new(
                    self.base.add(recv_ctrl) as *const AtomicU32,
                    self.base.add(recv_ctrl + PAGE_SIZE) as *const AtomicU8,
                    RING_DATA_BYTES,
                ),
            )
        };
        let send =
            SendRing::new(send_mem).map_err(|_| StorvspError::RingSetup("send ring rejected"))?;
        let recv =
            RecvRing::new(recv_mem).map_err(|_| StorvspError::RingSetup("recv ring rejected"))?;
        Ok((send, recv))
    }

    #[expect(unsafe_code, reason = "freeing memory the host or rings may use")]
    unsafe fn free(self) {
        // SAFETY: `base`/`layout` are exactly what `alloc` allocated;
        // `self` is consumed so this happens once, and the caller
        // guarantees no ring or host mapping still refers to it.
        #[expect(unsafe_code, reason = "free ring region from PageBacking::alloc")]
        unsafe {
            dealloc(self.base, self.layout)
        };
    }
}

/// Drop a backing's rings, then free it.
///
/// # Safety
///
/// `rings` must be the only rings created from `backing`, and the host
/// must no longer be able to access its memory.
#[expect(unsafe_code, reason = "forwards RingBacking::free's contract")]
unsafe fn release<B: RingBacking>(rings: (SendRing<B::Mem>, RecvRing<B::Mem>), backing: B) {
    drop(rings);
    // SAFETY: the rings are dropped; host access is excluded by the caller.
    #[expect(unsafe_code, reason = "free ring backing")]
    unsafe {
        backing.free()
    };
}

/// Outcome for the transaction a caller is waiting on.
type Awaited = core::result::Result<Completion, &'static str>;

/// An open StorVSP channel.
pub struct StorSession<B: RingBacking = PageBacking> {
    channel: Channel,
    instance_id: Guid,
    send: SendRing<B::Mem>,
    recv: RecvRing<B::Mem>,
    backing: B,
    next_tid: u64,
    pending: [Option<u64>; PENDING_CAPACITY],
    negotiated: Option<NegotiatedInfo>,
    /// A needed host signal failed to post and must be retried; see
    /// [`StorSession::signal_owed`].
    signal_owed: bool,
}

impl<B: RingBacking> core::fmt::Debug for StorSession<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StorSession")
            .field("channel_id", &self.channel.channel_id())
            .field("instance_id", &self.instance_id)
            .field("next_tid", &self.next_tid)
            .field("pending", &self.pending_count())
            .field("negotiated", &self.negotiated)
            .finish_non_exhaustive()
    }
}

static RESTART_LATCH: spin::Mutex<Option<&'static str>> = spin::Mutex::new(None);

/// Reason recorded when a global-driver open/close required a restart.
/// Once set, [`StorSession::open_until`] refuses to run.
pub fn restart_reason() -> Option<&'static str> {
    *RESTART_LATCH.lock()
}

fn latch<T>(result: Result<T>) -> Result<T> {
    if let Err(StorvspError::RestartRequired(reason)) = &result {
        RESTART_LATCH.lock().get_or_insert(reason);
    }
    result
}

fn restart(reason: &'static str, error: &Error) -> StorvspError {
    log::warn!("storvsp: {reason} ({error}); leaking ring pages, restart required");
    StorvspError::RestartRequired(reason)
}

impl StorSession<PageBacking> {
    /// Open the single StorVSP controller among `offers` using the
    /// global driver and SIMP pump. Does not negotiate.
    pub fn open_until<C, K>(
        ctx: &mut C,
        offers: &[OfferChannel],
        deadline: &Deadline<K>,
    ) -> Result<Self>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        if let Some(reason) = restart_reason() {
            return Err(StorvspError::RestartRequired(reason));
        }
        let offer = select_offer(offers)?;
        let pages = synic_pages().ok_or(Error::VersionMismatch)?;
        let mut pump = SimpPump::new(pages.simp_gpa);
        let backing = PageBacking::alloc()?;
        latch(Self::open_with_until(
            ctx,
            &mut driver(),
            &mut pump,
            offer,
            allocate_gpadl_id(),
            backing,
            deadline,
        ))
    }

    /// [`Self::close_with_until`] using the global driver and SIMP pump.
    pub fn close_until<C, K>(self, ctx: &mut C, deadline: &Deadline<K>) -> Result<()>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        let Some(pages) = synic_pages() else {
            core::mem::forget(self);
            return latch(Err(StorvspError::RestartRequired("SynIC not initialized")));
        };
        let mut pump = SimpPump::new(pages.simp_gpa);
        latch(self.close_with_until(ctx, &mut driver(), &mut pump, deadline))
    }
}

impl<B: RingBacking> StorSession<B> {
    /// Establish the ring GPADL over `backing` and open `offer`'s channel.
    ///
    /// A definite host rejection unwinds (GPADL teardown, free) and
    /// returns the VMBus error. Any uncertain outcome leaks `backing`
    /// and returns [`StorvspError::RestartRequired`].
    pub fn open_with_until<C, P, K>(
        ctx: &mut C,
        driver: &mut ClientDriver,
        pump: &mut P,
        offer: &OfferChannel,
        gpadl_id: GpadlId,
        backing: B,
        deadline: &Deadline<K>,
    ) -> Result<Self>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
        K: Clock,
    {
        // SAFETY: the rings are owned by this function until they are
        // stored in the session, and are dropped before `free` on every
        // path that frees the backing.
        #[expect(unsafe_code, reason = "ring construction over owned backing")]
        let rings = match unsafe { backing.rings() } {
            Ok(rings) => rings,
            Err(e) => {
                // SAFETY: no rings exist and no GPADL was created.
                #[expect(unsafe_code, reason = "free unshared ring backing")]
                unsafe {
                    backing.free()
                };
                return Err(e);
            }
        };
        let gpadl = match establish_gpadl_with_until(
            ctx,
            driver,
            pump,
            offer.channel_id,
            gpadl_id,
            backing.total_bytes(),
            backing.pfns(),
            deadline,
        ) {
            Ok(gpadl) => gpadl,
            Err(Error::GpadlFailed) => {
                // SAFETY: the host rejected the GPADL, so it cannot map it.
                #[expect(unsafe_code, reason = "free unshared ring backing")]
                unsafe {
                    release(rings, backing)
                };
                return Err(Error::GpadlFailed.into());
            }
            Err(e) => {
                core::mem::forget(backing);
                return Err(restart("GPADL create outcome unknown", &e));
            }
        };
        let channel = match open_channel_with_until(
            ctx,
            driver,
            pump,
            offer,
            gpadl,
            backing.send_data_pages(),
            offer.connection_id,
            offer.channel_id.0 as u16,
            deadline,
        ) {
            Ok(channel) => channel,
            Err(Error::OpenFailed) => {
                return match teardown_gpadl_with_until(ctx, driver, pump, gpadl, deadline) {
                    Ok(()) => {
                        // SAFETY: the GPADL is confirmed torn down.
                        #[expect(unsafe_code, reason = "free unshared ring backing")]
                        unsafe {
                            release(rings, backing)
                        };
                        Err(Error::OpenFailed.into())
                    }
                    Err(e) => {
                        core::mem::forget(backing);
                        Err(restart("GPADL teardown after rejected open failed", &e))
                    }
                };
            }
            Err(e) => {
                core::mem::forget(backing);
                return Err(restart("OpenResult missing or unexpected", &e));
            }
        };
        log::debug!(
            "storvsp: opened channel {:?} instance {}",
            offer.channel_id,
            offer.instance_id
        );
        let (send, recv) = rings;
        Ok(Self {
            channel,
            instance_id: offer.instance_id,
            send,
            recv,
            backing,
            next_tid: 1,
            pending: [None; PENDING_CAPACITY],
            negotiated: None,
            signal_owed: false,
        })
    }

    /// Close the channel, tear down the ring GPADL, release the relid and
    /// free the rings.
    ///
    /// Any failure before the GPADL is confirmed torn down leaks the
    /// rings and returns [`StorvspError::RestartRequired`]. A failed relid
    /// release still frees the (now unmapped) rings but also requires a
    /// restart, since the driver's protocol state was reset.
    pub fn close_with_until<C, P, K>(
        self,
        ctx: &mut C,
        driver: &mut ClientDriver,
        pump: &mut P,
        deadline: &Deadline<K>,
    ) -> Result<()>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        P: MessagePump,
        K: Clock,
    {
        let Self {
            channel,
            send,
            recv,
            backing,
            ..
        } = self;
        let channel_id = channel.channel_id();
        let gpadl = channel.ring_gpadl();
        if let Err(e) = close_channel_keep_relid_with_until(ctx, driver, channel, deadline) {
            core::mem::forget(backing);
            return Err(restart("CloseChannel post failed", &e));
        }
        if let Err(e) = teardown_gpadl_with_until(ctx, driver, pump, gpadl, deadline) {
            core::mem::forget(backing);
            return Err(restart("ring GPADL teardown did not complete", &e));
        }
        let released = driver.step_until(ctx, Event::ReleaseChannel { channel_id }, deadline);
        // SAFETY: the GPADL is confirmed torn down.
        #[expect(unsafe_code, reason = "free ring backing after GPADL teardown")]
        unsafe {
            release((send, recv), backing)
        };
        released.map_err(|e| restart("relid release failed", &e))
    }

    /// Host-assigned channel ID (relid).
    pub fn channel_id(&self) -> ChannelId {
        self.channel.channel_id()
    }

    /// Controller instance GUID from the offer.
    pub fn instance_id(&self) -> Guid {
        self.instance_id
    }

    /// Result of the last successful [`Self::negotiate_until`].
    pub fn negotiated(&self) -> Option<NegotiatedInfo> {
        self.negotiated
    }

    /// Number of transaction IDs awaiting a completion.
    pub fn pending_count(&self) -> usize {
        self.pending.iter().flatten().count()
    }

    /// Whether a host signal failed and is still owed.
    ///
    /// A failed `signal_event` makes the triggering send or poll return
    /// the VMBus error (a send's packet is nevertheless published and
    /// its tid forgotten). Because the ring would never request that
    /// wakeup again, every later send and poll retries it before any
    /// other work; if that retry fails too, the operation returns the
    /// VMBus error without touching the rings. While
    /// this stays `true` the host may be idle; the caller decides
    /// whether to keep retrying or close the session.
    pub fn signal_owed(&self) -> bool {
        self.signal_owed
    }

    /// Largest payload [`Self::send_raw`] accepts.
    pub fn max_raw_payload(&self) -> usize {
        self.backing
            .ring_data_bytes()
            .saturating_sub(DESCRIPTOR_LEN + 2 * FOOTER_LEN)
    }

    /// Run the full initialization sequence, trying versions from
    /// `version_cap` down the ladder.
    pub fn negotiate_until<C, K>(
        &mut self,
        ctx: &mut C,
        version_cap: u16,
        deadline: &Deadline<K>,
    ) -> Result<NegotiatedInfo>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        self.request_ok(ctx, Operation::BEGIN_INITIALIZATION, &[], deadline)?;
        let mut accepted = None;
        for version in ladder_from(version_cap) {
            let body = ProtocolVersion {
                major_minor: version,
                reserved: 0,
            };
            let c = self.request_until(
                ctx,
                Operation::QUERY_PROTOCOL_VERSION,
                body.as_bytes(),
                deadline,
            )?;
            match ladder_decision(c.status) {
                LadderStep::Accept => {
                    accepted = Some(version);
                    break;
                }
                LadderStep::Advance => {}
                LadderStep::Abort => {
                    return Err(StorvspError::Status {
                        op: Operation::QUERY_PROTOCOL_VERSION.0,
                        status: c.status.0,
                    });
                }
            }
        }
        let version = accepted.ok_or(StorvspError::NoVersion)?;
        let c = self.request_ok(ctx, Operation::QUERY_PROPERTIES, &[], deadline)?;
        let (props, _) = ChannelProperties::read_from_prefix(c.body())
            .map_err(|_| StorvspError::Malformed("short QUERY_PROPERTIES completion"))?;
        self.request_ok(ctx, Operation::END_INITIALIZATION, &[], deadline)?;
        let info = NegotiatedInfo {
            version,
            max_sub_channel_count: props.maximum_sub_channel_count,
            max_transfer_bytes: props.max_transfer_bytes,
            multi_channel: props.flags & storvsp_protocol::STORAGE_CHANNEL_SUPPORTS_MULTI_CHANNEL
                != 0,
        };
        self.negotiated = Some(info);
        Ok(info)
    }

    /// Send a typed request without waiting.
    ///
    /// Initialization operations use [`FRAME_LEN_V2`]; others use the
    /// negotiated version's frame size (V2 before negotiation).
    /// `want_completion` sets the VMBus completion-request flag and
    /// records the tid in the pending table.
    pub fn send_request<C>(
        &mut self,
        ctx: &mut C,
        operation: Operation,
        body: &[u8],
        want_completion: bool,
    ) -> Result<SendOutcome>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        let retried = self.retry_owed_signal(ctx)?;
        let frame_len = match operation {
            Operation::BEGIN_INITIALIZATION
            | Operation::END_INITIALIZATION
            | Operation::QUERY_PROTOCOL_VERSION
            | Operation::QUERY_PROPERTIES => FRAME_LEN_V2,
            _ => self
                .negotiated
                .map_or(FRAME_LEN_V2, |n| frame_len_for(n.version)),
        };
        let frame = build_frame(operation, body, frame_len)?;
        let flags = PacketFlags::new().with_request_completion(want_completion);
        self.post(ctx, want_completion, retried, |send, tid| {
            send.write_inband(&frame, flags, tid)
        })
    }

    /// Send a typed request and wait for its completion, whatever its
    /// status. On error (including deadline expiry) the tid is dropped
    /// from the pending table, so a late completion counts as unknown.
    pub fn request_until<C, K>(
        &mut self,
        ctx: &mut C,
        operation: Operation,
        body: &[u8],
        deadline: &Deadline<K>,
    ) -> Result<Completion>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        let tid = self.send_request(ctx, operation, body, true)?.tid;
        let result = self.wait_until(ctx, tid, deadline);
        if result.is_err() {
            self.take_pending(tid);
        }
        result
    }

    /// Send `bytes` verbatim as one in-band packet whose descriptor
    /// `flags` are `vmbus_flags` unmodified. `want_completion` only
    /// controls whether the tid enters the pending table.
    pub fn send_raw<C>(
        &mut self,
        ctx: &mut C,
        bytes: &[u8],
        vmbus_flags: u16,
        want_completion: bool,
    ) -> Result<SendOutcome>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        let retried = self.retry_owed_signal(ctx)?;
        let max = self.max_raw_payload();
        if bytes.len() > max {
            return Err(StorvspError::PayloadTooLarge {
                len: bytes.len(),
                max,
            });
        }
        self.post(ctx, want_completion, retried, |send, tid| {
            send.write_raw_packet(&raw_descriptor(bytes.len(), vmbus_flags, tid), bytes)
        })
    }

    /// Consume up to `budget` inbound packets, matching completions
    /// against the pending table. Never blocks.
    pub fn poll<C>(&mut self, ctx: &mut C, budget: usize) -> Result<PollReport>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        let mut report = PollReport::default();
        self.drain(ctx, budget, None, &mut report)?;
        Ok(report)
    }

    fn request_ok<C, K>(
        &mut self,
        ctx: &mut C,
        operation: Operation,
        body: &[u8],
        deadline: &Deadline<K>,
    ) -> Result<Completion>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        let c = self.request_until(ctx, operation, body, deadline)?;
        if c.status != NtStatus::SUCCESS {
            return Err(StorvspError::Status {
                op: operation.0,
                status: c.status.0,
            });
        }
        Ok(c)
    }

    fn post<C>(
        &mut self,
        ctx: &mut C,
        want_completion: bool,
        retried: bool,
        write: impl FnOnce(&SendRing<B::Mem>, u64) -> crate::Result<bool>,
    ) -> Result<SendOutcome>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        let slot = if want_completion {
            Some(
                self.pending
                    .iter()
                    .position(Option::is_none)
                    .ok_or(StorvspError::Backpressure)?,
            )
        } else {
            None
        };
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);
        // Every write-side failure means the host-owned indices or ring
        // contents are inconsistent, except a full ring.
        let needs_signal = write(&self.send, tid).map_err(|e| match e {
            Error::RingFull => StorvspError::Vmbus(Error::RingFull),
            _ => StorvspError::RingCorrupt,
        })?;
        if let Some(slot) = slot {
            self.pending[slot] = Some(tid);
        }
        match self.signal_host(ctx, needs_signal) {
            Ok(signalled) => Ok(SendOutcome {
                tid,
                signalled: signalled || retried,
            }),
            Err(e) => {
                // The caller never learns the tid; don't let it occupy a slot.
                self.take_pending(tid);
                Err(e)
            }
        }
    }

    /// Signal the host if `needed` or a previous signal was lost.
    ///
    /// A lost empty→non-empty (or space-available) signal is never
    /// re-triggered by the ring itself, so a failure is remembered and
    /// retried at the start of every later send and poll (before any
    /// fallible ring work, so a full ring cannot starve the retry).
    fn signal_host<C>(&mut self, ctx: &mut C, needed: bool) -> Result<bool>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        if !needed && !self.signal_owed {
            return Ok(false);
        }
        match signal_event(ctx, self.channel.connection_id(), 0) {
            Ok(()) => {
                self.signal_owed = false;
                Ok(true)
            }
            Err(e) => {
                self.signal_owed = true;
                Err(e.into())
            }
        }
    }

    /// Retry a previously failed signal, if any. Returns whether the host
    /// was signalled.
    fn retry_owed_signal<C>(&mut self, ctx: &mut C) -> Result<bool>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        self.signal_host(ctx, false)
    }

    fn take_pending(&mut self, tid: u64) -> bool {
        match self.pending.iter_mut().find(|slot| **slot == Some(tid)) {
            Some(slot) => {
                *slot = None;
                true
            }
            None => false,
        }
    }

    fn wait_until<C, K>(
        &mut self,
        ctx: &mut C,
        tid: u64,
        deadline: &Deadline<K>,
    ) -> Result<Completion>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
        K: Clock,
    {
        let mut report = PollReport::default();
        loop {
            deadline.check()?;
            for _ in 0..WAIT_CHUNK {
                if let Some(awaited) = self.drain(ctx, WAIT_DRAIN_BUDGET, Some(tid), &mut report)? {
                    return awaited.map_err(StorvspError::Malformed);
                }
                spin_loop();
            }
        }
    }

    /// Consume up to `budget` packets, committing and signalling the host
    /// if the read freed space it is waiting for. Stops early once
    /// `awaited`'s completion is found.
    fn drain<C>(
        &mut self,
        ctx: &mut C,
        budget: usize,
        awaited: Option<u64>,
        report: &mut PollReport,
    ) -> Result<Option<Awaited>>
    where
        C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
    {
        self.retry_owed_signal(ctx)?;
        let mut off = self
            .recv
            .incoming()
            .map_err(|_| StorvspError::RingCorrupt)?;
        let mut found = None;
        let mut corrupt = false;
        for _ in 0..budget {
            let packet = match self.recv.read(&mut off) {
                Ok(packet) => packet,
                Err(ReadError::Empty) => break,
                Err(ReadError::Corrupt(_)) => {
                    corrupt = true;
                    break;
                }
            };
            report.packets += 1;
            // Only the header and an SRB-sized body are ever inspected;
            // the rest of a long packet is skipped by the commit.
            let mut buf = [0u8; FRAME_LEN_V2];
            let n = packet.payload.len().min(buf.len());
            let data = match packet.payload.reader(&self.recv).read(&mut buf[..n]) {
                Ok(_) => &buf[..n],
                Err(_) => &buf[..0],
            };
            let outcome = self.classify(packet.typ, packet.transaction_id, data, report);
            if let Some((tid, outcome)) = outcome {
                if Some(tid) == awaited {
                    found = Some(outcome);
                    break;
                }
            }
        }
        let needs_signal = self.recv.commit_read(&mut off);
        self.signal_host(ctx, needs_signal)?;
        if corrupt {
            return Err(StorvspError::RingCorrupt);
        }
        Ok(found)
    }

    /// Account for one packet. Returns the outcome for a matched completion.
    fn classify(
        &mut self,
        typ: IncomingPacketType,
        tid: Option<u64>,
        data: &[u8],
        report: &mut PollReport,
    ) -> Option<(u64, Awaited)> {
        let header = storvsp_protocol::Packet::read_from_prefix(data)
            .ok()
            .map(|(h, _)| h);
        match typ {
            IncomingPacketType::Completion => {
                let tid = tid?;
                if !self.take_pending(tid) {
                    report.unknown_tid += 1;
                    return None;
                }
                report.completions += 1;
                let outcome = match header {
                    None => Err("completion shorter than header"),
                    Some(h) if h.operation != Operation::COMPLETE_IO => {
                        Err("completion is not COMPLETE_IO")
                    }
                    Some(h) => {
                        let body_data = &data[HEADER_LEN..];
                        let mut body = [0; storvsp_protocol::SCSI_REQUEST_LEN_MAX];
                        body[..body_data.len()].copy_from_slice(body_data);
                        Ok(Completion {
                            tid,
                            status: h.status,
                            flags: h.flags,
                            body,
                            body_len: body_data.len(),
                        })
                    }
                };
                if outcome.is_err() {
                    report.malformed += 1;
                }
                Some((tid, outcome))
            }
            IncomingPacketType::InBand
                if header.is_some_and(|h| {
                    matches!(
                        h.operation,
                        Operation::ENUMERATE_BUS
                            | Operation::EVENT_NOTIFICATION
                            | Operation::REMOVE_DEVICE
                    )
                }) =>
            {
                report.unsolicited += 1;
                None
            }
            _ => {
                report.malformed += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::CLIENT_ID;
    use crate::connection::initiate_with;
    use crate::connection::request_offers_with;
    use crate::message::encode;
    use crate::protocol::supported_feature_flags;
    use crate::ring::FlatRingMem;
    use crate::ring::IncomingRingExt;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use core::cell::Cell;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::Ordering;
    use opentmk_core::tmkdefs::TmkResult;
    use storvsp_protocol::VERSION_BLUE;
    use storvsp_protocol::VERSION_IRON;
    use storvsp_protocol::VERSION_THRESHOLD;
    use storvsp_protocol::VERSION_WIN6;
    use storvsp_protocol::VERSION_WIN7;
    use storvsp_protocol::VERSION_WIN8;
    use vmbus_core::protocol::AllOffersDelivered;
    use vmbus_core::protocol::GpadlCreated;
    use vmbus_core::protocol::GpadlTorndown;
    use vmbus_core::protocol::MAX_MESSAGE_SIZE;
    use vmbus_core::protocol::OpenResult;
    use vmbus_core::protocol::VersionResponse;
    use vmbus_core::protocol::VersionResponse2;
    use vmbus_ring::Ring;
    use zerocopy::FromZeros;
    use zerocopy::Immutable;

    const TEST_RING: usize = 4096;
    const BUDGET: u64 = 1_000_000;

    #[derive(Default)]
    struct Ctx {
        hypercalls: usize,
        /// Number of upcoming hypercalls to fail.
        fail_next: usize,
    }

    impl HypercallPlatformTrait for Ctx {
        type Config = HyperVHypercallConfig;

        fn hypercall(
            &mut self,
            _code: u64,
            _input: &[u8],
            _output: &mut [u8],
            _cfg: HyperVHypercallConfig,
        ) -> TmkResult<()> {
            if self.fail_next > 0 {
                self.fail_next -= 1;
                return Err(opentmk_core::tmkdefs::TmkError::InvalidParameter);
            }
            self.hypercalls += 1;
            Ok(())
        }
    }

    /// Advances one tick per read.
    struct FakeClock(Cell<u64>);

    impl Clock for FakeClock {
        fn now(&self) -> u64 {
            let t = self.0.get();
            self.0.set(t + 1);
            t
        }
    }

    /// Delivers queued messages, then never answers again.
    #[derive(Default)]
    struct Pump(VecDeque<Vec<u8>>);

    impl MessagePump for Pump {
        fn poll_message<C: HypercallPlatformTrait<Config = HyperVHypercallConfig>>(
            &mut self,
            _ctx: &mut C,
        ) -> crate::Result<Vec<u8>> {
            self.0.pop_front().ok_or(Error::Timeout)
        }

        fn poll_message_until<C, K>(
            &mut self,
            _ctx: &mut C,
            deadline: &Deadline<K>,
        ) -> crate::Result<Vec<u8>>
        where
            C: HypercallPlatformTrait<Config = HyperVHypercallConfig>,
            K: Clock,
        {
            deadline.poll(1, || Ok(self.0.pop_front()))
        }
    }

    fn msg<M: vmbus_core::protocol::VmbusMessage + IntoBytes + Immutable>(m: &M) -> Vec<u8> {
        let mut bytes = [0; MAX_MESSAGE_SIZE];
        let used = encode(m, &mut bytes);
        bytes[..used].to_vec()
    }

    struct FakeBacking {
        out: FlatRingMem,
        inn: FlatRingMem,
        pfns: Vec<u64>,
        freed: Arc<AtomicBool>,
    }

    impl RingBacking for FakeBacking {
        type Mem = FlatRingMem;

        fn pfns(&self) -> &[u64] {
            &self.pfns
        }

        fn total_bytes(&self) -> u32 {
            (self.pfns.len() * PAGE_SIZE) as u32
        }

        fn send_data_pages(&self) -> u32 {
            1
        }

        fn ring_data_bytes(&self) -> usize {
            TEST_RING
        }

        #[expect(unsafe_code, reason = "RingBacking contract")]
        unsafe fn rings(&self) -> Result<(SendRing<FlatRingMem>, RecvRing<FlatRingMem>)> {
            Ok((
                SendRing::new(self.out.clone()).unwrap(),
                RecvRing::new(self.inn.clone()).unwrap(),
            ))
        }

        #[expect(unsafe_code, reason = "RingBacking contract")]
        unsafe fn free(self) {
            self.freed.store(true, Ordering::SeqCst);
        }
    }

    /// Host ends of the rings.
    struct Host {
        to_guest: SendRing<FlatRingMem>,
        from_guest: RecvRing<FlatRingMem>,
        out: FlatRingMem,
        freed: Arc<AtomicBool>,
    }

    impl Host {
        fn complete(&self, tid: u64, status: NtStatus, body: &[u8]) {
            let header = storvsp_protocol::Packet {
                operation: Operation::COMPLETE_IO,
                flags: 0,
                status,
            };
            let mut payload = header.as_bytes().to_vec();
            payload.extend_from_slice(body);
            self.to_guest.write_completion(&payload, tid).unwrap();
        }

        fn inband(&self, payload: &[u8]) {
            self.to_guest
                .write_inband(payload, PacketFlags::new(), 0)
                .unwrap();
        }

        fn sent(&self) -> Vec<(u64, Vec<u8>)> {
            let mut out = Vec::new();
            let mut buf = [0u8; TEST_RING];
            while let Ok(p) = self.from_guest.read_packet(&mut buf) {
                out.push((p.descriptor.transaction_id, p.payload.to_vec()));
            }
            out
        }

        fn freed(&self) -> bool {
            self.freed.load(Ordering::SeqCst)
        }
    }

    fn backing() -> (FakeBacking, Host) {
        let out = FlatRingMem::new(TEST_RING);
        let inn = FlatRingMem::new(TEST_RING);
        let freed = Arc::new(AtomicBool::new(false));
        let host = Host {
            to_guest: SendRing::new(inn.clone()).unwrap(),
            from_guest: RecvRing::new(out.clone()).unwrap(),
            out: out.clone(),
            freed: freed.clone(),
        };
        let backing = FakeBacking {
            out,
            inn,
            pfns: alloc::vec![1, 2, 3, 4],
            freed,
        };
        (backing, host)
    }

    fn scsi_offer(channel: u32, subchannel_index: u16) -> OfferChannel {
        let mut offer = OfferChannel::new_zeroed();
        offer.interface_id = storvsp_protocol::SCSI_INTERFACE_ID;
        offer.subchannel_index = subchannel_index;
        offer.channel_id = ChannelId(channel);
        offer.connection_id = 0x40;
        offer
    }

    fn connected(offer: OfferChannel) -> ClientDriver {
        let mut driver = ClientDriver::new();
        let mut ctx = Ctx::default();
        let mut pump = Pump(
            [msg(&VersionResponse2 {
                version_response: VersionResponse {
                    version_supported: 1,
                    connection_state: vmbus_core::protocol::ConnectionState::SUCCESSFUL,
                    padding: 0,
                    selected_version_or_connection_id: 4,
                },
                supported_features: supported_feature_flags().into_bits(),
            })]
            .into(),
        );
        initiate_with(&mut ctx, &mut driver, &mut pump, CLIENT_ID).unwrap();
        pump.0 = [msg(&offer), msg(&AllOffersDelivered {})].into();
        assert_eq!(
            request_offers_with(&mut ctx, &mut driver, &mut pump)
                .unwrap()
                .len(),
            1
        );
        driver
    }

    const GPADL: GpadlId = GpadlId(77);

    fn gpadl_created(status: i32) -> Vec<u8> {
        msg(&GpadlCreated {
            channel_id: ChannelId(5),
            gpadl_id: GPADL,
            status,
        })
    }

    fn open_result(status: u32) -> Vec<u8> {
        msg(&OpenResult {
            channel_id: ChannelId(5),
            open_id: 0,
            status,
        })
    }

    fn open(
        script: &[Vec<u8>],
        budget: u64,
    ) -> (ClientDriver, Result<StorSession<FakeBacking>>, Host) {
        let offer = scsi_offer(5, 0);
        let mut driver = connected(offer);
        let (backing, host) = backing();
        let clock = FakeClock(Cell::new(0));
        let deadline = Deadline::after(&clock, budget);
        let mut pump = Pump(script.iter().cloned().collect());
        let result = StorSession::open_with_until(
            &mut Ctx::default(),
            &mut driver,
            &mut pump,
            &offer,
            GPADL,
            backing,
            &deadline,
        );
        (driver, result, host)
    }

    fn session() -> (StorSession<FakeBacking>, Host) {
        let (_, session, host) = open(&[gpadl_created(0), open_result(0)], BUDGET);
        (session.unwrap(), host)
    }

    fn deadline(clock: &FakeClock) -> Deadline<&FakeClock> {
        Deadline::after(clock, BUDGET)
    }

    #[test]
    fn frames_have_version_sizes_and_layout() {
        assert_eq!(HEADER_LEN, 12);
        assert_eq!(size_of::<storvsp_protocol::ScsiRequest>(), 0x34);
        assert_eq!(frame_len_for(VERSION_WIN6), 48);
        assert_eq!(frame_len_for(VERSION_WIN7), 48);
        assert_eq!(frame_len_for(VERSION_WIN8), 64);
        assert_eq!(frame_len_for(VERSION_IRON), 64);

        let body: Vec<u8> = (1..=storvsp_protocol::SCSI_REQUEST_LEN_V1 as u8).collect();
        for frame_len in [FRAME_LEN_V1, FRAME_LEN_V2] {
            let frame = build_frame(Operation::EXECUTE_SRB, &body, frame_len).unwrap();
            assert_eq!(frame.len(), frame_len);
            assert_eq!(frame[0..4], 3u32.to_le_bytes());
            assert_eq!(frame[4..12], [0; 8], "flags and status are zero");
            assert_eq!(frame[12..48], body[..]);
            assert!(frame[48..].iter().all(|&b| b == 0));
        }
        let v2 = [0xaa; storvsp_protocol::SCSI_REQUEST_LEN_V2];
        assert!(matches!(
            build_frame(Operation::EXECUTE_SRB, &v2, FRAME_LEN_V1),
            Err(StorvspError::PayloadTooLarge { len: 64, max: 48 })
        ));
    }

    #[test]
    fn version_ladder_decisions() {
        assert_eq!(ladder_decision(NtStatus::SUCCESS), LadderStep::Accept);
        assert_eq!(
            ladder_decision(NtStatus::INVALID_DEVICE_STATE),
            LadderStep::Advance
        );
        assert_eq!(
            ladder_decision(NtStatus::REVISION_MISMATCH),
            LadderStep::Advance
        );
        assert_eq!(ladder_decision(NtStatus(0xc000_0001)), LadderStep::Abort);
        assert_eq!(
            ladder_from(u16::MAX).collect::<Vec<_>>(),
            [
                VERSION_IRON,
                VERSION_THRESHOLD,
                VERSION_BLUE,
                VERSION_WIN8,
                VERSION_WIN7,
                VERSION_WIN6
            ]
        );
        assert_eq!(
            ladder_from(VERSION_WIN8).collect::<Vec<_>>(),
            [VERSION_WIN8, VERSION_WIN7, VERSION_WIN6]
        );
        assert_eq!(ladder_from(0x100).count(), 0);
    }

    #[test]
    fn offer_selection() {
        let other = OfferChannel::new_zeroed();
        assert!(matches!(
            select_offer(&[other, scsi_offer(2, 1)]),
            Err(StorvspError::NoController)
        ));
        let offers = [other, scsi_offer(2, 1), scsi_offer(3, 0)];
        assert_eq!(select_offer(&offers).unwrap().channel_id, ChannelId(3));
        assert!(matches!(
            select_offer(&[scsi_offer(3, 0), scsi_offer(4, 0)]),
            Err(StorvspError::AmbiguousController)
        ));
    }

    #[test]
    fn negotiation_walks_ladder_and_reads_properties() {
        let (mut s, host) = session();
        let mut props = ChannelProperties::new_zeroed();
        props.maximum_sub_channel_count = 3;
        props.max_transfer_bytes = 0x10_0000;
        props.flags = storvsp_protocol::STORAGE_CHANNEL_SUPPORTS_MULTI_CHANNEL;
        host.complete(1, NtStatus::SUCCESS, &[]);
        host.complete(2, NtStatus::REVISION_MISMATCH, &[0; 4]);
        host.complete(3, NtStatus::INVALID_DEVICE_STATE, &[0; 4]);
        host.complete(4, NtStatus::SUCCESS, &[0; 4]);
        host.complete(5, NtStatus::SUCCESS, props.as_bytes());
        host.complete(6, NtStatus::SUCCESS, &[]);
        let clock = FakeClock(Cell::new(0));
        let info = s
            .negotiate_until(&mut Ctx::default(), u16::MAX, &deadline(&clock))
            .unwrap();
        assert_eq!(
            info,
            NegotiatedInfo {
                version: VERSION_BLUE,
                max_sub_channel_count: 3,
                max_transfer_bytes: 0x10_0000,
                multi_channel: true,
            }
        );
        let sent = host.sent();
        let ops: Vec<u32> = sent
            .iter()
            .map(|(_, p)| u32::from_le_bytes(p[0..4].try_into().unwrap()))
            .collect();
        assert_eq!(ops, [7, 9, 9, 9, 10, 8]);
        let versions: Vec<u16> = sent[1..4]
            .iter()
            .map(|(_, p)| u16::from_le_bytes([p[12], p[13]]))
            .collect();
        assert_eq!(versions, [VERSION_IRON, VERSION_THRESHOLD, VERSION_BLUE]);
        for (i, (tid, payload)) in sent.iter().enumerate() {
            assert_eq!(*tid, i as u64 + 1);
            assert_eq!(payload.len(), FRAME_LEN_V2);
            assert_eq!(payload[4..8], [0; 4], "VSTOR flags are zero");
        }
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn negotiation_aborts_on_other_status() {
        let (mut s, host) = session();
        host.complete(1, NtStatus::SUCCESS, &[]);
        host.complete(2, NtStatus(0xc000_0001), &[]);
        let clock = FakeClock(Cell::new(0));
        let err = s
            .negotiate_until(&mut Ctx::default(), u16::MAX, &deadline(&clock))
            .unwrap_err();
        assert!(matches!(
            err,
            StorvspError::Status {
                op: 9,
                status: 0xc000_0001
            }
        ));
        assert!(s.negotiated().is_none());
    }

    #[test]
    fn completions_match_by_tid() {
        let (mut s, host) = session();
        let ctx = &mut Ctx::default();
        let a = s.send_raw(ctx, &[1], 0, true).unwrap().tid;
        let b = s.send_raw(ctx, &[2], 0, true).unwrap().tid;
        let c = s.send_raw(ctx, &[3], 0, false).unwrap().tid;
        assert_eq!((a, b, c), (1, 2, 3));
        host.complete(b, NtStatus::SUCCESS, &[]);
        host.complete(c, NtStatus::SUCCESS, &[]);
        host.complete(a, NtStatus::SUCCESS, &[]);
        host.complete(a, NtStatus::SUCCESS, &[]);
        let report = s.poll(ctx, 2).unwrap();
        assert_eq!((report.packets, report.completions), (2, 1));
        let report = s.poll(ctx, 100).unwrap();
        assert_eq!(
            report,
            PollReport {
                packets: 2,
                completions: 1,
                unknown_tid: 1,
                ..Default::default()
            }
        );
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn unsolicited_short_and_oversized_packets_are_consumed() {
        let (mut s, host) = session();
        let ctx = &mut Ctx::default();
        let tid = s.send_raw(ctx, &[], 0, true).unwrap().tid;
        let enumerate = storvsp_protocol::Packet {
            operation: Operation::ENUMERATE_BUS,
            flags: 0,
            status: NtStatus::SUCCESS,
        };
        host.inband(enumerate.as_bytes());
        host.inband(&[1, 2, 3]);
        host.complete(tid, NtStatus::SUCCESS, &[0xee; 3000]);
        host.to_guest.write_completion(&[0; 4], 99).unwrap();
        let report = s.poll(ctx, 100).unwrap();
        assert_eq!(
            report,
            PollReport {
                packets: 4,
                completions: 1,
                unsolicited: 1,
                unknown_tid: 1,
                malformed: 1,
            }
        );
        assert_eq!(s.recv.available(), 0);
    }

    #[test]
    fn pending_overflow_is_backpressure() {
        let (mut s, host) = session();
        let ctx = &mut Ctx::default();
        for _ in 0..PENDING_CAPACITY {
            s.send_raw(ctx, &[], 0, true).unwrap();
        }
        assert!(matches!(
            s.send_raw(ctx, &[], 0, true),
            Err(StorvspError::Backpressure)
        ));
        assert_eq!(host.sent().len(), PENDING_CAPACITY);
        s.send_raw(ctx, &[], 0, false).unwrap();
    }

    #[test]
    fn send_raw_descriptor_is_verbatim() {
        let (mut s, host) = session();
        let ctx = &mut Ctx::default();
        let out = s.send_raw(ctx, &[9; 3], 0xfffe, false).unwrap();
        assert_eq!(out.tid, 1);
        let mut desc = [0u8; 16];
        host.out.read_at(0, &mut desc);
        assert_eq!(desc[0..2], 6u16.to_le_bytes());
        assert_eq!(desc[2..4], 2u16.to_le_bytes());
        assert_eq!(desc[4..6], 3u16.to_le_bytes(), "ceil(19 / 8)");
        assert_eq!(desc[6..8], 0xfffeu16.to_le_bytes());
        assert_eq!(desc[8..16], 1u64.to_le_bytes());
        assert_eq!(raw_descriptor(8, 0, 0)[4..6], 3u16.to_le_bytes());
        assert_eq!(raw_descriptor(9, 0, 0)[4..6], 4u16.to_le_bytes());

        let max = s.max_raw_payload();
        assert_eq!(max, TEST_RING - 32);
        let err = s.send_raw(ctx, &alloc::vec![0; max + 1], 0, false);
        assert!(matches!(err, Err(StorvspError::PayloadTooLarge { .. })));
    }

    #[test]
    fn max_raw_payload_fits_empty_ring() {
        let (mut s, _host) = session();
        let max = s.max_raw_payload();
        s.send_raw(&mut Ctx::default(), &alloc::vec![0; max], 1, false)
            .unwrap();
    }

    /// Control words 0 and 1 are the ring's write and read indices.
    #[test]
    fn hostile_ring_indices_are_corrupt_not_panics() {
        let cases = [
            (0, 1),
            (0, 4),
            (12, 0),
            (TEST_RING as u32, 0),
            (0, u32::MAX),
        ];
        for (write, read) in cases {
            let (mut s, host) = session();
            let ctrl = host.out.control();
            ctrl[0].store(write, Ordering::SeqCst);
            ctrl[1].store(read, Ordering::SeqCst);
            let ctx = &mut Ctx::default();
            let max = s.max_raw_payload();
            for len in [0, 1, max] {
                let err = s.send_raw(ctx, &alloc::vec![0; len], 0, true);
                assert!(matches!(err, Err(StorvspError::RingCorrupt)), "{err:?}");
            }
            let err = s.send_request(ctx, Operation::QUERY_PROPERTIES, &[], true);
            assert!(matches!(err, Err(StorvspError::RingCorrupt)), "{err:?}");
            assert_eq!(s.pending_count(), 0);

            let ctrl = host.to_guest.mem().control();
            ctrl[0].store(write, Ordering::SeqCst);
            ctrl[1].store(read, Ordering::SeqCst);
            let err = s.poll(ctx, 4);
            assert!(matches!(err, Err(StorvspError::RingCorrupt)), "{err:?}");
        }
    }

    #[test]
    fn failed_send_signal_is_retried_by_next_send() {
        let (mut s, host) = session();
        host.from_guest.set_interrupt_mask(false);
        let ctx = &mut Ctx {
            fail_next: 1,
            ..Default::default()
        };
        let err = s.send_raw(ctx, &[1; 8], 0, true).unwrap_err();
        assert!(matches!(err, StorvspError::Vmbus(_)), "{err:?}");
        assert!(s.signal_owed());
        assert_eq!(s.pending_count(), 0);

        // The ring is no longer empty, so only the owed flag signals.
        let sent = s.send_raw(ctx, &[2; 8], 0, false).unwrap();
        assert!(sent.signalled);
        assert!(!s.signal_owed());
        assert_eq!(ctx.hypercalls, 1);
        let sent = s.send_raw(ctx, &[3; 8], 0, false).unwrap();
        assert!(!sent.signalled);
        assert_eq!(host.sent().len(), 3, "the first packet was still published");
    }

    #[test]
    fn owed_signal_is_retried_before_ring_full() {
        let (mut s, host) = session();
        host.from_guest.set_interrupt_mask(false);
        let ctx = &mut Ctx {
            fail_next: 1,
            ..Default::default()
        };
        let max = s.max_raw_payload();
        let err = s.send_raw(ctx, &alloc::vec![0; max], 0, false).unwrap_err();
        assert!(matches!(err, StorvspError::Vmbus(_)), "{err:?}");
        assert!(s.signal_owed());

        let err = s.send_raw(ctx, &[1; 8], 0, true).unwrap_err();
        assert!(
            matches!(err, StorvspError::Vmbus(Error::RingFull)),
            "{err:?}"
        );
        assert!(!s.signal_owed(), "the retry precedes the full-ring write");
        assert_eq!(ctx.hypercalls, 1);
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn owed_signal_is_retried_before_corrupt_poll() {
        let (mut s, host) = session();
        host.from_guest.set_interrupt_mask(false);
        let ctx = &mut Ctx {
            fail_next: 1,
            ..Default::default()
        };
        assert!(s.send_raw(ctx, &[1; 8], 0, false).is_err());
        host.to_guest.mem().control()[1].store(4, Ordering::SeqCst);
        let err = s.poll(ctx, 4);
        assert!(matches!(err, Err(StorvspError::RingCorrupt)), "{err:?}");
        assert!(!s.signal_owed());
        assert_eq!(ctx.hypercalls, 1);
    }

    #[test]
    fn failed_space_signal_is_retried_by_next_poll() {
        let (mut s, host) = session();
        host.inband(&[0; 16]);
        host.to_guest.mem().control()[3].store((TEST_RING - 8) as u32, Ordering::SeqCst);
        let ctx = &mut Ctx {
            fail_next: 1,
            ..Default::default()
        };
        assert!(s.poll(ctx, 4).is_err());
        assert!(s.signal_owed());
        assert_eq!(s.poll(ctx, 4).unwrap().packets, 0);
        assert!(!s.signal_owed());
        assert_eq!(ctx.hypercalls, 1);
        s.poll(ctx, 4).unwrap();
        assert_eq!(ctx.hypercalls, 1, "no further signals once delivered");
    }

    #[test]
    fn request_times_out_and_forgets_tid() {
        let (mut s, host) = session();
        let clock = FakeClock(Cell::new(0));
        let deadline = Deadline::after(&clock, 3);
        let err = s
            .request_until(
                &mut Ctx::default(),
                Operation::QUERY_PROPERTIES,
                &[],
                &deadline,
            )
            .unwrap_err();
        assert!(err.is_timeout(), "{err:?}");
        assert!(err.restart_reason().is_none());
        assert_eq!(s.pending_count(), 0);
        host.complete(1, NtStatus::SUCCESS, &[]);
        assert_eq!(s.poll(&mut Ctx::default(), 10).unwrap().unknown_tid, 1);
    }

    #[test]
    fn open_and_close_free_backing() {
        let (mut driver, s, host) = open(&[gpadl_created(0), open_result(0)], BUDGET);
        let clock = FakeClock(Cell::new(0));
        let mut pump = Pump([msg(&GpadlTorndown { gpadl_id: GPADL })].into());
        s.unwrap()
            .close_with_until(
                &mut Ctx::default(),
                &mut driver,
                &mut pump,
                &deadline(&clock),
            )
            .unwrap();
        assert!(host.freed());
    }

    #[test]
    fn rejected_gpadl_or_open_unwinds() {
        let (_, result, host) = open(&[gpadl_created(1)], BUDGET);
        assert!(matches!(
            result,
            Err(StorvspError::Vmbus(Error::GpadlFailed))
        ));
        assert!(host.freed());

        let (_, result, host) = open(
            &[
                gpadl_created(0),
                open_result(1),
                msg(&GpadlTorndown { gpadl_id: GPADL }),
            ],
            BUDGET,
        );
        assert!(matches!(
            result,
            Err(StorvspError::Vmbus(Error::OpenFailed))
        ));
        assert!(host.freed());
    }

    #[test]
    fn missing_gpadl_or_open_result_requires_restart() {
        let (_, result, host) = open(&[], 50);
        assert!(result.unwrap_err().restart_reason().is_some());
        assert!(!host.freed());

        let (mut driver, result, host) = open(&[gpadl_created(0)], 50);
        assert_eq!(
            result.unwrap_err().restart_reason(),
            Some("OpenResult missing or unexpected")
        );
        assert!(!host.freed());
        // A late OpenResult is absorbed without resurrecting the session.
        driver
            .step(&mut Ctx::default(), Event::HostMessage(&open_result(0)))
            .unwrap();
        assert!(!host.freed());

        // A rejected open whose GPADL teardown never completes also leaks.
        let (_, result, host) = open(&[gpadl_created(0), open_result(1)], 200);
        assert!(result.unwrap_err().restart_reason().is_some());
        assert!(!host.freed());
    }

    #[test]
    fn gpadl_teardown_timeout_on_close_requires_restart() {
        let offer = scsi_offer(5, 0);
        let mut driver = connected(offer);
        let (backing, host) = backing();
        let clock = FakeClock(Cell::new(0));
        let mut pump = Pump([gpadl_created(0), open_result(0)].into());
        let s = StorSession::open_with_until(
            &mut Ctx::default(),
            &mut driver,
            &mut pump,
            &offer,
            GPADL,
            backing,
            &deadline(&clock),
        )
        .unwrap();
        let short = Deadline::after(&clock, 50);
        let err = s
            .close_with_until(
                &mut Ctx::default(),
                &mut driver,
                &mut Pump::default(),
                &short,
            )
            .unwrap_err();
        assert_eq!(
            err.restart_reason(),
            Some("ring GPADL teardown did not complete")
        );
        assert!(!host.freed());
    }
}
