// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest-side fuzz handlers for the synthetic SCSI controller (StorVSP).
//!
//! These handlers back the host `storvsp_fuzzer` grammar on top of the
//! polling client in [`vmbus_guest::devices::storvsp`]. The VMBus
//! connection (SynIC + `InitiateContact` + offers) is brought up on first
//! use and kept for the guest's lifetime; the StorVSP channel itself is
//! per-testcase: [`reset_session`] closes it at every testcase boundary.
//!
//! # Handlers
//!
//! All arguments are syzlang integers. Pointer arguments are guest
//! addresses resolved through the testcase's [`SafeMemoryMap`].
//!
//! | name | args | returns |
//! |---|---|---|
//! | `storvsp_open` | — | `Void`; opens the channel without negotiating |
//! | `storvsp_close` | — | `Void`; closes the channel |
//! | `storvsp_init` | `version_cap: u16` | `Int(version)`; opens if needed, then negotiates from `version_cap` down |
//! | `storvsp_send_raw` | `ptr, len, vmbus_flags: u16, want_completion: u8` | `Void`; bytes sent verbatim |
//! | `storvsp_begin_init` | — | `Int(status)` of BEGIN_INITIALIZATION |
//! | `storvsp_query_version` | `version: u16` | `Int(status)` of QUERY_PROTOCOL_VERSION |
//! | `storvsp_query_properties` | — | `Int(status)` of QUERY_PROPERTIES |
//! | `storvsp_end_init` | — | `Int(status)` of END_INITIALIZATION |
//! | `storvsp_execute_srb` | `ptr, len` | `Int(status)` of EXECUTE_SRB wrapping the bytes |
//! | `storvsp_poll` | — | `Int(completions)` matched by a bounded drain |
//!
//! `want_completion` is a boolean (non-zero = true). Integer arguments
//! outside their declared width are rejected as grammar bugs.
//!
//! # Implicit opens
//!
//! `storvsp_open` and `storvsp_init` always (re)open when no channel is
//! open. Other handlers open implicitly only if no channel has been
//! opened yet in the current testcase, so a grammar that closes the
//! channel is never silently reopened: later calls log `NotOpen`.
//! `storvsp_send_raw` and `storvsp_execute_srb` open *and* negotiate
//! (from the newest version); the single-stage handlers only open, so
//! the grammar controls the initialization order. `storvsp_poll` never
//! opens.
//!
//! # Error policy
//!
//! - Device-side failures (error statuses, timeouts, corrupt rings, full
//!   rings, backpressure, oversized or unreadable inputs, a closed
//!   channel) are logged; the handler returns normally.
//! - Argument count/type/range mismatches and a missing or ambiguous
//!   controller are configuration bugs and return `Err`.
//! - [`StorvspError::RestartRequired`] (or the client's global restart
//!   latch) requests a VM restart via [`restart::request_restart`]; the
//!   rest of the testcase is skipped.
//! - A VMBus connect or offer enumeration that times out, or that leaves
//!   the shared client driver mid-transition, also requests a restart:
//!   the late reply could only be consumed by a pump nobody runs, and the
//!   driver rejects every retry until then. Definite bring-up failures
//!   (driver back in a settled phase) are logged and retried by the next
//!   open.
//!
//! Each testcase gets a [`DEFAULT_TESTCASE_CEILING`] budget, and each
//! call at most [`DEFAULT_CALL_BUDGET`] of it.
//!
//! # Limitations
//!
//! Mixing these handlers with the netvsp ones in one campaign is
//! unsupported: both drive the single process-wide VMBus client driver
//! and keep independent connection state.

// UNSAFETY: the session lives in a `static` behind a mutex, which requires
// an `unsafe impl Send` for the state type.
#![expect(unsafe_code)]

use crate::functions::FuzzFunctionVariable;
use crate::functions::VerifyFuzzVariables;
use crate::prelude::*;
use crate::restart;
use hvdef::Vtl;
use opentmk_core::platform::hyperv::ctx::HvTestCtx;
use opentmk_decoder::SafeMemoryMap;
use spin::Mutex;
use storvsp_protocol::Operation;
use storvsp_protocol::ProtocolVersion;
use vmbus_client_core::ClientPhase;
use vmbus_core::protocol::OfferChannel;
use vmbus_guest::deadline::DEFAULT_CALL_BUDGET;
use vmbus_guest::deadline::DEFAULT_TESTCASE_CEILING;
use vmbus_guest::deadline::Deadline;
use vmbus_guest::devices::storvsp;
use vmbus_guest::devices::storvsp::StorSession;
use vmbus_guest::devices::storvsp::StorvspError;
use zerocopy::IntoBytes;

/// Packets consumed by one `storvsp_poll`.
const POLL_BUDGET: usize = storvsp::PENDING_CAPACITY;
/// Largest `storvsp_execute_srb` body (V2 frame minus the VSTOR header).
const MAX_SRB_BODY: usize = storvsp::FRAME_LEN_V2 - storvsp::HEADER_LEN;
/// Version cap used by implicit negotiation.
const LAZY_VERSION_CAP: u16 = storvsp::VERSION_LADDER[0];
const NOT_OPEN: &str = "NotOpen: StorVSP channel was closed in this testcase";

/// The persistent VMBus connection.
struct Conn {
    // Boxed: `HvTestCtx` embeds two 4 KiB hypercall pages, too large for
    // the UEFI stack.
    ctx: Box<HvTestCtx>,
    offers: Vec<OfferChannel>,
}

struct State {
    conn: Option<Conn>,
    session: Option<StorSession>,
    /// A channel was opened in the current testcase.
    opened_this_testcase: bool,
    /// Per-testcase ceiling, started by the testcase's first call.
    ceiling: Option<Deadline>,
}

// SAFETY: the guest executor is single-threaded; the raw pointers inside
// `StorSession`/`HvTestCtx` are only touched while holding `STORVSP`.
unsafe impl Send for State {}

static STORVSP: Mutex<State> = Mutex::new(State {
    conn: None,
    session: None,
    opened_this_testcase: false,
    ceiling: None,
});

/// A handler failure, before the error policy is applied.
#[derive(Debug)]
enum Failure {
    /// Logged; the campaign continues.
    Soft(String),
    /// Classified by [`classify`].
    Device(&'static str, StorvspError),
}

fn dev(what: &'static str) -> impl FnOnce(StorvspError) -> Failure {
    move |e| Failure::Device(what, e)
}

fn vmbus(what: &'static str) -> impl FnOnce(vmbus_guest::Error) -> Failure {
    move |e| Failure::Device(what, StorvspError::Vmbus(e))
}

/// What the error policy does with a [`StorvspError`].
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Log,
    Fatal,
    Restart(&'static str),
}

fn classify(e: &StorvspError) -> Action {
    match e {
        StorvspError::NoController | StorvspError::AmbiguousController => Action::Fatal,
        _ => e.restart_reason().map_or(Action::Log, Action::Restart),
    }
}

/// Apply the error policy to a handler result.
fn finish(
    name: &str,
    result: Result<FuzzFunctionVariable, Failure>,
) -> Result<FuzzFunctionVariable, String> {
    match result {
        Ok(v) => Ok(v),
        Err(Failure::Soft(msg)) => {
            log::error!("{name}: {msg}");
            Ok(FuzzFunctionVariable::Void)
        }
        Err(Failure::Device(what, e)) => match classify(&e) {
            Action::Fatal => Err(format!("{name}: {what}: {e}")),
            Action::Restart(reason) => {
                restart::request_restart(format!("storvsp: {reason}"));
                Ok(FuzzFunctionVariable::Void)
            }
            Action::Log => {
                log::error!("{name}: {what}: {e}");
                Ok(FuzzFunctionVariable::Void)
            }
        },
    }
}

/// Whether a handler may open the channel implicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lazy {
    Open,
    OpenAndInit,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Ready,
    Open { negotiate: bool },
    NotOpen,
}

fn plan(has_session: bool, opened_this_testcase: bool, lazy: Lazy) -> Plan {
    if has_session {
        Plan::Ready
    } else if opened_this_testcase {
        Plan::NotOpen
    } else {
        Plan::Open {
            negotiate: lazy == Lazy::OpenAndInit,
        }
    }
}

/// Whether the shared client driver is between top-level transitions.
///
/// A connect or offer enumeration that is still pending can only be
/// finished by pumping its reply, and every new connect/enumeration is
/// rejected with `InvalidState` until then.
fn phase_settled(phase: &ClientPhase) -> bool {
    matches!(
        phase,
        ClientPhase::Disconnected | ClientPhase::Connected { .. }
    )
}

/// Map a failed connect/offer enumeration on the shared driver.
///
/// The failure is definite (logged, retried by the next open) only if it
/// did not time out and left the driver settled. Otherwise the reply may
/// still arrive (or the driver is already wedged mid-transition), so no
/// later bring-up can succeed without a restart.
fn bring_up_failure(
    what: &'static str,
    reason: &'static str,
    e: vmbus_guest::Error,
    settled: bool,
) -> Failure {
    if e.is_timeout() || !settled {
        log::warn!("storvsp: {what}: {e}; driver settled: {settled}");
        Failure::Device(what, StorvspError::RestartRequired(reason))
    } else {
        Failure::Device(what, StorvspError::Vmbus(e))
    }
}

fn driver_settled() -> bool {
    phase_settled(vmbus_guest::client_driver::driver().core().phase())
}

fn bring_up_vmbus(deadline: &Deadline) -> Result<Conn, Failure> {
    let mut ctx = Box::new(HvTestCtx::new());
    ctx.init(Vtl::Vtl0)
        .map_err(|e| Failure::Soft(format!("HvTestCtx init failed: {e}")))?;
    if vmbus_guest::synic::synic_pages().is_none() {
        vmbus_guest::synic::init_synic(&mut *ctx).map_err(vmbus("init_synic"))?;
    }
    if vmbus_guest::connection::connection().is_none() {
        vmbus_guest::connection::initiate_until(&mut *ctx, deadline).map_err(|e| {
            bring_up_failure(
                "vmbus initiate",
                "VMBus connect outcome unknown",
                e,
                driver_settled(),
            )
        })?;
    }
    let offers =
        vmbus_guest::connection::request_offers_until(&mut *ctx, deadline).map_err(|e| {
            bring_up_failure(
                "request_offers",
                "VMBus offer enumeration outcome unknown",
                e,
                driver_settled(),
            )
        })?;
    Ok(Conn { ctx, offers })
}

impl State {
    fn call_deadline(&mut self) -> Deadline {
        self.ceiling
            .get_or_insert_with(|| Deadline::from_now(DEFAULT_TESTCASE_CEILING))
            .sub_budget(DEFAULT_CALL_BUDGET)
    }

    fn open(&mut self, deadline: &Deadline) -> Result<(), Failure> {
        // Avoid VMBus bring-up when the client already refuses to open.
        if let Some(reason) = storvsp::restart_reason() {
            return Err(Failure::Device(
                "open",
                StorvspError::RestartRequired(reason),
            ));
        }
        let conn = match self.conn.take() {
            Some(conn) => conn,
            None => bring_up_vmbus(deadline)?,
        };
        let conn = self.conn.insert(conn);
        // Another user of the shared driver may have left it mid-connect
        // or mid-enumeration; nothing short of a restart recovers that.
        if !driver_settled() {
            return Err(Failure::Device(
                "open",
                StorvspError::RestartRequired("VMBus driver left mid-transition"),
            ));
        }
        let session =
            StorSession::open_until(&mut *conn.ctx, &conn.offers, deadline).map_err(dev("open"))?;
        self.session = Some(session);
        self.opened_this_testcase = true;
        Ok(())
    }

    fn parts(&mut self) -> Result<(&mut HvTestCtx, &mut StorSession), Failure> {
        match (self.conn.as_mut(), self.session.as_mut()) {
            (Some(conn), Some(session)) => Ok((&mut *conn.ctx, session)),
            _ => Err(Failure::Soft(String::from(NOT_OPEN))),
        }
    }

    fn negotiate(&mut self, cap: u16, deadline: &Deadline) -> Result<u16, Failure> {
        let (ctx, session) = self.parts()?;
        let info = session
            .negotiate_until(ctx, cap, deadline)
            .map_err(dev("negotiate"))?;
        log::info!("storvsp: negotiated {info:?}");
        Ok(info.version)
    }

    /// The open session, opening it first if `lazy` allows.
    fn active(
        &mut self,
        lazy: Lazy,
        deadline: &Deadline,
    ) -> Result<(&mut HvTestCtx, &mut StorSession), Failure> {
        match plan(self.session.is_some(), self.opened_this_testcase, lazy) {
            Plan::Ready => {}
            Plan::NotOpen => return Err(Failure::Soft(String::from(NOT_OPEN))),
            Plan::Open { negotiate } => {
                self.open(deadline)?;
                if negotiate {
                    self.negotiate(LAZY_VERSION_CAP, deadline)?;
                }
            }
        }
        self.parts()
    }

    /// Send a typed request and wait for its completion.
    fn request(
        &mut self,
        lazy: Lazy,
        op: Operation,
        body: &[u8],
    ) -> Result<FuzzFunctionVariable, Failure> {
        let deadline = self.call_deadline();
        let (ctx, session) = self.active(lazy, &deadline)?;
        let c = session
            .request_until(ctx, op, body, &deadline)
            .map_err(dev("request"))?;
        log::debug!("storvsp: op {:#x} completed with {:#x}", op.0, c.status.0);
        Ok(FuzzFunctionVariable::Int(c.status.0.into()))
    }
}

fn with_state<R>(f: impl FnOnce(&mut State) -> Result<R, Failure>) -> Result<R, Failure> {
    f(&mut STORVSP.lock())
}

/// Close the testcase's channel and reset per-testcase state.
///
/// Called from the executor before every testcase. A close whose outcome
/// is unknown requests a VM restart for the upcoming testcase.
pub fn reset_session() {
    let mut state = STORVSP.lock();
    state.opened_this_testcase = false;
    state.ceiling = None;
    let Some(session) = state.session.take() else {
        return;
    };
    let Some(conn) = state.conn.as_mut() else {
        // Unreachable by construction; leak rather than free pages the
        // host may still map.
        core::mem::forget(session);
        restart::request_restart("storvsp: session without VMBus connection");
        return;
    };
    let deadline = Deadline::from_now(DEFAULT_CALL_BUDGET);
    if let Err(e) = session.close_until(&mut *conn.ctx, &deadline) {
        match e.restart_reason() {
            Some(reason) => restart::request_restart(format!("storvsp: {reason}")),
            None => log::warn!("storvsp: reset close failed: {e}"),
        }
    }
}

fn int_arg<T: TryFrom<u64>>(var: &FuzzFunctionVariable, name: &str) -> Result<T, String> {
    let v = var.expect_int(name)?;
    T::try_from(v).map_err(|_| {
        format!(
            "{name} = {v:#x} does not fit {}",
            core::any::type_name::<T>()
        )
    })
}

/// Read `len` bytes at `ptr`, refusing lengths above `max` before
/// allocating.
fn read_input(
    mem: &mut dyn SafeMemoryMap,
    ptr: usize,
    len: usize,
    max: usize,
) -> Result<Vec<u8>, Failure> {
    if len > max {
        return Err(Failure::Device(
            "input",
            StorvspError::PayloadTooLarge { len, max },
        ));
    }
    if ptr.checked_add(len).is_none() {
        return Err(Failure::Soft(format!(
            "input range {ptr:#x}+{len:#x} overflows"
        )));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        mem.try_read_mem(ptr, &mut buf)
            .map_err(|e| Failure::Soft(format!("failed to read input at {ptr:#x}: {e}")))?;
    }
    Ok(buf)
}

/// `storvsp_open()`
pub fn storvsp_open(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_open",
        with_state(|s| {
            if s.session.is_none() {
                let deadline = s.call_deadline();
                s.open(&deadline)?;
            }
            Ok(FuzzFunctionVariable::Void)
        }),
    )
}

/// `storvsp_close()`
pub fn storvsp_close(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_close",
        with_state(|s| {
            let deadline = s.call_deadline();
            let (Some(session), Some(conn)) = (s.session.take(), s.conn.as_mut()) else {
                return Err(Failure::Soft(String::from("no open channel")));
            };
            session
                .close_until(&mut *conn.ctx, &deadline)
                .map_err(dev("close"))?;
            Ok(FuzzFunctionVariable::Void)
        }),
    )
}

/// `storvsp_init(version_cap: u16)`
pub fn storvsp_init(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [cap] = vars.verify_num_params()?;
    let cap: u16 = int_arg(cap, "version_cap")?;
    finish(
        "storvsp_init",
        with_state(|s| {
            let deadline = s.call_deadline();
            if s.session.is_none() {
                s.open(&deadline)?;
            }
            let version = s.negotiate(cap, &deadline)?;
            Ok(FuzzFunctionVariable::Int(version.into()))
        }),
    )
}

/// `storvsp_send_raw(ptr, len, vmbus_flags: u16, want_completion: u8)`
pub fn storvsp_send_raw(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [ptr, len, flags, want] = vars.verify_num_params()?;
    let ptr: usize = int_arg(ptr, "ptr")?;
    let len: usize = int_arg(len, "len")?;
    let flags: u16 = int_arg(flags, "vmbus_flags")?;
    let want: u8 = int_arg(want, "want_completion")?;
    finish(
        "storvsp_send_raw",
        with_state(|s| {
            let deadline = s.call_deadline();
            let (ctx, session) = s.active(Lazy::OpenAndInit, &deadline)?;
            let bytes = read_input(mem, ptr, len, session.max_raw_payload())?;
            session
                .send_raw(ctx, &bytes, flags, want != 0)
                .map_err(dev("send_raw"))?;
            Ok(FuzzFunctionVariable::Void)
        }),
    )
}

/// `storvsp_begin_init()`
pub fn storvsp_begin_init(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_begin_init",
        with_state(|s| s.request(Lazy::Open, Operation::BEGIN_INITIALIZATION, &[])),
    )
}

/// `storvsp_query_version(version: u16)`
pub fn storvsp_query_version(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [version] = vars.verify_num_params()?;
    let body = ProtocolVersion {
        major_minor: int_arg(version, "version")?,
        reserved: 0,
    };
    finish(
        "storvsp_query_version",
        with_state(|s| {
            s.request(
                Lazy::Open,
                Operation::QUERY_PROTOCOL_VERSION,
                body.as_bytes(),
            )
        }),
    )
}

/// `storvsp_query_properties()`
pub fn storvsp_query_properties(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_query_properties",
        with_state(|s| s.request(Lazy::Open, Operation::QUERY_PROPERTIES, &[])),
    )
}

/// `storvsp_end_init()`
pub fn storvsp_end_init(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_end_init",
        with_state(|s| s.request(Lazy::Open, Operation::END_INITIALIZATION, &[])),
    )
}

/// `storvsp_execute_srb(ptr, len)`
///
/// The body is sent unmodified after an EXECUTE_SRB header and padded to
/// the negotiated frame size; a body longer than that frame is logged as
/// too large.
pub fn storvsp_execute_srb(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [ptr, len] = vars.verify_num_params()?;
    let ptr: usize = int_arg(ptr, "ptr")?;
    let len: usize = int_arg(len, "len")?;
    finish(
        "storvsp_execute_srb",
        with_state(|s| {
            let body = read_input(mem, ptr, len, MAX_SRB_BODY)?;
            s.request(Lazy::OpenAndInit, Operation::EXECUTE_SRB, &body)
        }),
    )
}

/// `storvsp_poll()`
pub fn storvsp_poll(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [] = vars.verify_num_params()?;
    finish(
        "storvsp_poll",
        with_state(|s| {
            if s.session.is_none() {
                return Ok(FuzzFunctionVariable::Int(0));
            }
            let (ctx, session) = s.parts()?;
            let report = session.poll(ctx, POLL_BUDGET).map_err(dev("poll"))?;
            log::debug!("storvsp: poll {report:?}");
            Ok(FuzzFunctionVariable::Int(report.completions.into()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::FuzzFunction;
    use FuzzFunctionVariable::Int;

    struct NoMem;

    impl SafeMemoryMap for NoMem {
        fn partial_write_mem(&mut self, _: usize, _: &[u8]) -> usize {
            panic!("unexpected write")
        }

        fn partial_read_mem(&mut self, _: usize, _: &mut [u8]) -> usize {
            panic!("unexpected read")
        }
    }

    #[test]
    fn bad_args_are_errors() {
        let cases: &[(FuzzFunction, Vec<FuzzFunctionVariable>)] = &[
            (storvsp_open, vec![Int(0)]),
            (storvsp_poll, vec![Int(0)]),
            (storvsp_init, vec![]),
            (storvsp_init, vec![Int(0x1_0000)]),
            (storvsp_init, vec![FuzzFunctionVariable::Void]),
            (storvsp_query_version, vec![Int(0x1_0000)]),
            (storvsp_send_raw, vec![Int(0), Int(0), Int(0)]),
            (
                storvsp_send_raw,
                vec![Int(0), Int(0), Int(0x1_0000), Int(0)],
            ),
            (storvsp_send_raw, vec![Int(0), Int(0), Int(0), Int(0x100)]),
            (storvsp_execute_srb, vec![Int(0)]),
        ];
        for (f, args) in cases {
            assert!(f(&mut NoMem, args.clone()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn oversized_input_is_rejected_before_reading() {
        let r = read_input(&mut NoMem, 0, MAX_SRB_BODY + 1, MAX_SRB_BODY);
        assert!(matches!(
            r,
            Err(Failure::Device("input", StorvspError::PayloadTooLarge { len, max }))
                if len == MAX_SRB_BODY + 1 && max == MAX_SRB_BODY
        ));
        // Logged, not fatal; and the handler never reads guest memory.
        let r = storvsp_execute_srb(&mut NoMem, vec![Int(0), Int(u64::MAX)]);
        assert!(matches!(r, Ok(FuzzFunctionVariable::Void)));
    }

    #[test]
    fn read_input_bounds() {
        let mut mem = vec![1u8, 2, 3, 4];
        let base = mem.as_ptr() as usize;
        assert_eq!(read_input(&mut mem, base + 1, 2, 4).unwrap(), [2, 3]);
        assert!(matches!(
            read_input(&mut mem, base, 5, 8),
            Err(Failure::Soft(_))
        ));
        assert!(matches!(
            read_input(&mut mem, usize::MAX, 2, 8),
            Err(Failure::Soft(_))
        ));
        assert!(read_input(&mut NoMem, 0, 0, 8).unwrap().is_empty());
    }

    #[test]
    fn classify_errors() {
        use StorvspError as E;
        assert_eq!(classify(&E::NoController), Action::Fatal);
        assert_eq!(classify(&E::AmbiguousController), Action::Fatal);
        assert_eq!(classify(&E::RestartRequired("x")), Action::Restart("x"));
        for e in [
            E::Backpressure,
            E::PayloadTooLarge { len: 2, max: 1 },
            E::RingSetup("x"),
            E::RingCorrupt,
            E::Status { op: 1, status: 2 },
            E::NoVersion,
            E::Malformed("x"),
            E::Vmbus(vmbus_guest::Error::DeadlineExceeded),
        ] {
            assert_eq!(classify(&e), Action::Log, "{e:?}");
        }
    }

    #[test]
    fn finish_applies_policy() {
        assert!(finish("t", Err(Failure::Device("d", StorvspError::NoController))).is_err());
        assert!(matches!(
            finish("t", Err(Failure::Device("d", StorvspError::RingCorrupt))),
            Ok(FuzzFunctionVariable::Void)
        ));
        assert!(!restart::restart_requested());
        assert!(matches!(
            finish(
                "t",
                Err(Failure::Device("d", StorvspError::RestartRequired("gone")))
            ),
            Ok(FuzzFunctionVariable::Void)
        ));
        assert_eq!(
            restart::take_restart_request().as_deref(),
            Some("storvsp: gone")
        );
    }

    #[test]
    fn uncertain_bring_up_requests_restart() {
        use vmbus_guest::Error as E;
        let cases = [
            // A late VersionResponse/AllOffersDelivered may still arrive.
            (E::DeadlineExceeded, true, true),
            (E::DeadlineExceeded, false, true),
            // Rejected because the driver is stuck mid-transition.
            (E::VersionMismatch, false, true),
            // Definite failure; the driver is ready for a retry.
            (E::VersionMismatch, true, false),
        ];
        for (e, settled, restarts) in cases {
            let label = format!("{e:?} settled={settled}");
            let result = finish("t", Err(bring_up_failure("w", "unknown", e, settled)));
            assert!(matches!(result, Ok(FuzzFunctionVariable::Void)), "{label}");
            let expected = restarts.then_some("storvsp: unknown");
            assert_eq!(
                restart::take_restart_request().as_deref(),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn transitional_driver_phases_are_unsettled() {
        use vmbus_core::VersionInfo;
        use vmbus_core::protocol::FeatureFlags;
        use vmbus_core::protocol::Version;
        let version = VersionInfo {
            version: Version::Copper,
            feature_flags: FeatureFlags::new(),
        };
        let request_id = vmbus_client_core::RequestId(1);
        assert!(phase_settled(&ClientPhase::Disconnected));
        assert!(phase_settled(&ClientPhase::Connected { version }));
        assert!(!phase_settled(&ClientPhase::RequestingOffers {
            version,
            request_id,
            offer_count: 0,
        }));
        assert!(!phase_settled(&ClientPhase::Disconnecting {
            version,
            request_id,
        }));
    }

    #[test]
    fn implicit_open_plan() {
        assert_eq!(plan(true, true, Lazy::Open), Plan::Ready);
        assert_eq!(
            plan(false, false, Lazy::Open),
            Plan::Open { negotiate: false }
        );
        assert_eq!(
            plan(false, false, Lazy::OpenAndInit),
            Plan::Open { negotiate: true }
        );
        // After an explicit close in this testcase: no silent reopen.
        assert_eq!(plan(false, true, Lazy::OpenAndInit), Plan::NotOpen);
    }

    #[test]
    fn idle_handlers_touch_no_hardware() {
        reset_session();
        assert!(matches!(storvsp_poll(&mut NoMem, vec![]), Ok(Int(0))));
        assert!(matches!(
            storvsp_close(&mut NoMem, vec![]),
            Ok(FuzzFunctionVariable::Void)
        ));
    }
}
