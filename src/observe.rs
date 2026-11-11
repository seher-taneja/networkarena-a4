//! The observation layer of a world with an `[observe]` section.
//!
//! A real switch hands its CPU a few thousand events a second, not every
//! packet, and a controller's reports share the links with customer
//! traffic. A world that turns this layer on gives every switch two
//! budgets:
//!
//! - **events to the controller:** punts and samples are served one
//!   at a time at `punt_events_per_s`, with room for `punt_backlog` to
//!   wait. One more is lost, and the log says so.
//! - **bytes from the controller:** injected packets draw on a token
//!   bucket of `export_burst_bytes` that refills at `export_bytes_per_s`.
//!   A packet the bucket cannot cover is not sent, and the log says so.
//!
//! Worlds without the section never reach this module, so their runs are
//! unchanged.

use std::collections::VecDeque;
use std::time::Duration;

use switch_program_types::ObserveLimitsW;

use crate::types::SimTime;

/// The lowest size an injected packet is charged and sent at, before its
/// payload: an IPv4 header plus a transport header, as a real report would
/// carry.
pub const REPORT_HEADER_BYTES: u64 = 40;

/// Ids of controller-created packets have this bit set, so a log reader can
/// tell them from customer traffic. Below it: the switch id, then a count.
pub const REPORT_ID_BIT: u64 = 1 << 63;

/// Punts and samples, served first come first served.
#[derive(Debug, Clone)]
pub struct EventLimiter {
    interval: Duration,
    backlog: usize,
    /// Delivery times of admitted events not yet delivered, oldest first.
    pending: VecDeque<SimTime>,
    next_free: SimTime,
}

impl EventLimiter {
    pub fn new(events_per_s: u32, backlog: u32) -> Self {
        Self {
            interval: Duration::from_nanos(1_000_000_000 / events_per_s.max(1) as u64),
            backlog: backlog.max(1) as usize,
            pending: VecDeque::new(),
            next_free: SimTime::ZERO,
        }
    }

    /// Admit an event raised at `now` that takes `latency` to reach the
    /// controller. Returns when it is delivered, or `None` when the backlog
    /// is full and the event is lost.
    pub fn admit(&mut self, now: SimTime, latency: Duration) -> Option<SimTime> {
        while self.pending.front().is_some_and(|t| *t <= now) {
            self.pending.pop_front();
        }
        if self.pending.len() >= self.backlog {
            return None;
        }
        let at = (now + latency).max(self.next_free);
        self.next_free = at + self.interval;
        self.pending.push_back(at);
        Some(at)
    }
}

/// Bytes a controller may inject: a token bucket, full at the start.
#[derive(Debug, Clone)]
pub struct ExportBucket {
    bytes_per_s: u64,
    /// Capacity and fill in byte-nanoseconds, so refills are exact.
    cap: u128,
    tokens: u128,
    last: SimTime,
}

impl ExportBucket {
    pub fn new(bytes_per_s: u64, burst_bytes: u64) -> Self {
        let cap = burst_bytes as u128 * 1_000_000_000;
        Self { bytes_per_s, cap, tokens: cap, last: SimTime::ZERO }
    }

    /// Take `bytes` at `now` if the bucket holds them.
    pub fn take(&mut self, now: SimTime, bytes: u64) -> bool {
        let dt = now.saturating_sub(self.last).as_nanos();
        self.last = self.last.max(now);
        self.tokens = (self.tokens + dt * self.bytes_per_s as u128).min(self.cap);
        let need = bytes as u128 * 1_000_000_000;
        if need > self.tokens {
            return false;
        }
        self.tokens -= need;
        true
    }
}

/// One switch's budgets and counters.
#[derive(Debug, Clone)]
pub struct SwitchObserve {
    pub events: EventLimiter,
    pub export: ExportBucket,
    /// Controller-created packets so far, for their ids.
    pub reports: u64,
}

impl SwitchObserve {
    pub fn new(limits: &ObserveLimitsW) -> Self {
        Self {
            events: EventLimiter::new(limits.punt_events_per_s, limits.punt_backlog),
            export: ExportBucket::new(limits.export_bytes_per_s, limits.export_burst_bytes),
            reports: 0,
        }
    }

    /// The id for this switch's next controller-created packet.
    pub fn next_report_id(&mut self, switch: u32) -> u64 {
        self.reports += 1;
        REPORT_ID_BIT | ((switch as u64) << 32) | (self.reports & 0xFFFF_FFFF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> SimTime {
        Duration::from_millis(n)
    }

    #[test]
    fn events_are_served_at_the_rate_and_the_backlog_overflows() {
        // 1000 events/s: one per millisecond; three may wait.
        let mut l = EventLimiter::new(1000, 3);
        let lat = Duration::from_micros(10);
        assert_eq!(l.admit(ms(0), lat), Some(ms(0) + lat));
        assert_eq!(l.admit(ms(0), lat), Some(ms(1) + lat));
        assert_eq!(l.admit(ms(0), lat), Some(ms(2) + lat));
        assert_eq!(l.admit(ms(0), lat), None, "fourth waiting event is lost");
        // Once the first is delivered there is room again, behind the rest.
        assert_eq!(l.admit(ms(1), lat), Some(ms(3) + lat));
        // After a quiet spell, delivery is immediate again.
        assert_eq!(l.admit(ms(100), lat), Some(ms(100) + lat));
    }

    #[test]
    fn the_bucket_allows_a_burst_then_the_rate() {
        // 1000 B/s, 300 B burst.
        let mut b = ExportBucket::new(1000, 300);
        assert!(b.take(ms(0), 200));
        assert!(b.take(ms(0), 100));
        assert!(!b.take(ms(0), 1), "burst spent");
        assert!(!b.take(ms(49), 50), "49 ms refills 49 bytes");
        assert!(b.take(ms(50), 50));
        // A long silence refills only up to the burst.
        assert!(!b.take(ms(10_000), 301));
        assert!(b.take(ms(10_000), 300));
    }

    #[test]
    fn report_ids_are_unique_and_marked() {
        let limits = ObserveLimitsW {
            punt_events_per_s: 1,
            punt_backlog: 1,
            export_bytes_per_s: 1,
            export_burst_bytes: 1,
        };
        let mut a = SwitchObserve::new(&limits);
        let mut b = SwitchObserve::new(&limits);
        let (a1, a2, b1) = (a.next_report_id(3), a.next_report_id(3), b.next_report_id(4));
        assert!(a1 != a2 && a1 != b1);
        assert!([a1, a2, b1].iter().all(|id| id & REPORT_ID_BIT != 0));
    }
}
