// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-testcase "VM restart required" signal.
//!
//! Handlers and per-testcase reset hooks call [`request_restart`] when the
//! guest session is poisoned (e.g. a device channel could not be torn down)
//! and no later testcase can run reliably in this VM. Once requested:
//!
//! - every remaining call in the current testcase is skipped (see
//!   [`FunctionRegistry::exec`](crate::functions::FunctionRegistry::exec));
//! - the executor replies with
//!   [`OpenTMKPacket::RestartRequired`](opentmk_exec_packet::OpenTMKPacket::RestartRequired)
//!   instead of `Ack`, so the host keeps the testcase's coverage and reboots
//!   the VM before the next testcase.
//!
//! The request is consumed when the testcase response is built, so a request
//! made by a reset hook before the testcase is deserialized applies to that
//! testcase. Handlers should still return normally (e.g. `Ok(Void)`) after
//! requesting a restart; returning `Err` instead reports a fatal error, which
//! takes precedence and stops the campaign.

use crate::prelude::*;

// The executor is single threaded in the guest; tests run on many threads, so
// keep the flag per thread there to isolate concurrently running tests.
#[cfg(not(test))]
static RESTART_REASON: spin::Mutex<Option<String>> = spin::Mutex::new(None);

#[cfg(test)]
std::thread_local! {
    static RESTART_REASON: core::cell::RefCell<Option<String>> =
        const { core::cell::RefCell::new(None) };
}

fn with_reason<R>(f: impl FnOnce(&mut Option<String>) -> R) -> R {
    #[cfg(not(test))]
    return f(&mut RESTART_REASON.lock());
    #[cfg(test)]
    return RESTART_REASON.with(|r| f(&mut r.borrow_mut()));
}

/// Requests a VM restart after the current testcase. The first reason
/// recorded for a testcase is kept; later requests are only logged.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "API for device handlers; remove once a handler calls it"
    )
)]
pub fn request_restart(reason: impl Into<String>) {
    let reason = reason.into();
    with_reason(|r| match r {
        Some(first) => log::warn!("restart already requested ({first}); also: {reason}"),
        None => {
            log::warn!("VM restart requested: {reason}");
            *r = Some(reason);
        }
    });
}

/// Returns `true` if a restart has been requested for the current testcase.
pub fn restart_requested() -> bool {
    with_reason(|r| r.is_some())
}

/// Clears and returns the pending restart request, if any.
pub(crate) fn take_restart_request() -> Option<String> {
    with_reason(Option::take)
}
