// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wall-clock deadlines for bounded VMBus waits.
//!
//! The legacy waits in this crate are bounded by spin counts, whose
//! wall-clock duration depends on the CPU and host load. The `_until`
//! entry points instead take a [`Deadline`] measured against a
//! [`Clock`] — on the guest, the Hyper-V partition reference counter
//! ([`RefCounterClock`], 100 ns units). Every blocking loop that honours
//! a deadline spins in bounded chunks and re-reads the clock between
//! chunks, so it returns [`Error::DeadlineExceeded`] at most one chunk
//! after the deadline passes.

use crate::Error;
use crate::Result;
use core::cell::Cell;
use core::hint::spin_loop;

/// Clock ticks per second (the reference counter runs at 10 MHz).
pub const TICKS_PER_SECOND: u64 = 10_000_000;

/// Clock ticks per millisecond.
pub const TICKS_PER_MILLI: u64 = TICKS_PER_SECOND / 1000;

/// Default budget for a single control operation (5 s).
pub const DEFAULT_CALL_BUDGET: u64 = 5 * TICKS_PER_SECOND;

/// Default ceiling for all VMBus work in one testcase (20 s). Kept
/// below the host-side 30 s testcase timeout so the guest can report a
/// timeout instead of being killed.
pub const DEFAULT_TESTCASE_CEILING: u64 = 20 * TICKS_PER_SECOND;

/// Spin iterations between clock reads in deadline-aware loops.
pub const DEADLINE_CHUNK_SPINS: usize = 65_536;

/// A monotonic time source in 100 ns ticks.
pub trait Clock {
    /// Return the current time in 100 ns ticks, or [`CLOCK_FAILED`] if
    /// the clock could not be read.
    fn now(&self) -> u64;
}

/// Sentinel returned by [`Clock::now`] when the clock cannot be read.
/// A [`Deadline`] that observes it is permanently expired.
pub const CLOCK_FAILED: u64 = u64::MAX;

impl<T: Clock + ?Sized> Clock for &T {
    fn now(&self) -> u64 {
        (**self).now()
    }
}

#[cfg(all(
    target_os = "uefi",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("RefCounterClock supports only x86_64 and aarch64 UEFI guests");

/// The Hyper-V partition reference counter, in 100 ns units.
///
/// On x86_64 UEFI guests this reads `HV_X64_MSR_TIME_REF_COUNT` (MSR
/// `0x40000020`); on aarch64 UEFI guests it reads
/// `HvArm64RegisterTimeRefCount` via a fast `HvCallGetVpRegisters`.
///
/// On non-UEFI targets (host unit tests) [`Clock::now`] returns
/// [`CLOCK_FAILED`], so every deadline built from this clock is already
/// expired: deadline-aware waits fail fast rather than hang. Host tests
/// should supply their own [`Clock`].
#[derive(Copy, Clone, Debug, Default)]
pub struct RefCounterClock;

impl Clock for RefCounterClock {
    #[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
    fn now(&self) -> u64 {
        // SAFETY: the partition reference counter MSR is architecturally
        // defined for Hyper-V guests and reading it has no side effects.
        #[expect(unsafe_code, reason = "rdmsr of the reference counter")]
        unsafe {
            minimal_rt::arch::msr::read_msr(hvdef::HV_X64_MSR_TIME_REF_COUNT)
        }
    }

    #[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
    fn now(&self) -> u64 {
        // A failed read reports "expired" so waits fail fast instead of
        // hanging on a clock that never advances.
        minimal_rt::arch::hypercall::get_register_fast(
            hvdef::HvArm64RegisterName::TimeRefCount.into(),
        )
        .map_or(CLOCK_FAILED, |value| value.as_u64())
    }

    #[cfg(not(target_os = "uefi"))]
    fn now(&self) -> u64 {
        CLOCK_FAILED
    }
}

/// A time budget measured on a [`Clock`] from the moment it was created.
///
/// Elapsed time is `now.wrapping_sub(start)`, so a counter that wraps
/// between reads is handled correctly, while a counter that runs
/// backwards appears to have advanced by almost 2^64 ticks and expires
/// the deadline (fail closed).
///
/// Expiry is sticky: once any read observes the deadline as expired —
/// including a read returning [`CLOCK_FAILED`], at construction or later
/// — every subsequent query reports it expired, even if the clock
/// recovers. Deadlines derived with [`Self::sub_budget`] from an expired
/// parent are expired too.
#[derive(Clone, Debug)]
pub struct Deadline<K: Clock = RefCounterClock> {
    clock: K,
    start: u64,
    budget: u64,
    expired: Cell<bool>,
}

impl Deadline<RefCounterClock> {
    /// A deadline `budget` ticks from now on the reference counter.
    pub fn from_now(budget: u64) -> Self {
        Self::after(RefCounterClock, budget)
    }
}

impl<K: Clock> Deadline<K> {
    fn anchored(clock: K, start: u64, budget: u64, expired: bool) -> Self {
        Self {
            clock,
            start,
            budget,
            expired: Cell::new(expired || start == CLOCK_FAILED),
        }
    }

    /// A deadline `budget` ticks after the current time of `clock`.
    pub fn after(clock: K, budget: u64) -> Self {
        let start = clock.now();
        Self::anchored(clock, start, budget, false)
    }

    /// A deadline at the absolute tick `expires_at` on `clock`.
    ///
    /// Reads the clock once and converts `expires_at` into a budget from
    /// that read; a tick at or before the current time yields a deadline
    /// that expires on the next read.
    pub fn at(clock: K, expires_at: u64) -> Self {
        let start = clock.now();
        Self::anchored(clock, start, expires_at.saturating_sub(start), false)
    }

    /// The nominal expiry tick (`start + budget`, wrapping with the
    /// counter). Diagnostic only: use [`Self::is_expired`] or
    /// [`Self::remaining`] for decisions, since a deadline may also be
    /// expired by clock failure or regression.
    pub fn expires_at(&self) -> u64 {
        self.start.wrapping_add(self.budget)
    }

    /// The clock this deadline is measured against.
    pub fn clock(&self) -> &K {
        &self.clock
    }

    /// Ticks remaining as of a clock read of `now`, latching expiry.
    fn remaining_at(&self, now: u64) -> u64 {
        if self.expired.get() {
            return 0;
        }
        let remaining = if now == CLOCK_FAILED {
            0
        } else {
            self.budget.saturating_sub(now.wrapping_sub(self.start))
        };
        if remaining == 0 {
            self.expired.set(true);
        }
        remaining
    }

    /// Ticks remaining, or zero once expired.
    pub fn remaining(&self) -> u64 {
        if self.expired.get() {
            return 0;
        }
        self.remaining_at(self.clock.now())
    }

    /// Whether the deadline has passed (or the clock failed).
    pub fn is_expired(&self) -> bool {
        self.remaining() == 0
    }

    /// Return [`Error::DeadlineExceeded`] if the deadline has passed.
    pub fn check(&self) -> Result<()> {
        if self.is_expired() {
            Err(Error::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    /// A deadline `budget` ticks from now, but no later than `self`.
    ///
    /// Use this to derive a per-call deadline from a per-testcase
    /// ceiling. If `self` is already expired (or the clock fails) the
    /// result is expired.
    pub fn sub_budget(&self, budget: u64) -> Self
    where
        K: Clone,
    {
        let now = self.clock.now();
        let parent_remaining = self.remaining_at(now);
        Self::anchored(
            self.clock.clone(),
            now,
            budget.min(parent_remaining),
            parent_remaining == 0,
        )
    }

    /// Spin `iters` times, reading the clock every
    /// [`DEADLINE_CHUNK_SPINS`] iterations. Returns
    /// [`Error::DeadlineExceeded`] if the deadline passes first.
    pub fn spin(&self, iters: usize) -> Result<()> {
        let mut left = iters;
        while left > 0 {
            self.check()?;
            let chunk = left.min(DEADLINE_CHUNK_SPINS);
            for _ in 0..chunk {
                spin_loop();
            }
            left -= chunk;
        }
        Ok(())
    }

    /// Repeatedly call `attempt` until it yields a value, reading the
    /// clock every `chunk` attempts. Returns
    /// [`Error::DeadlineExceeded`] once the deadline passes; errors from
    /// `attempt` are returned immediately.
    pub fn poll<T>(
        &self,
        chunk: usize,
        mut attempt: impl FnMut() -> Result<Option<T>>,
    ) -> Result<T> {
        assert!(chunk > 0, "deadline poll chunk must be non-zero");
        loop {
            self.check()?;
            for _ in 0..chunk {
                if let Some(value) = attempt()? {
                    return Ok(value);
                }
                spin_loop();
            }
        }
    }
}
