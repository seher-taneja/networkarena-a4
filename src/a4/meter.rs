//! Border meters (A4): what crossed from one AS to another, per epoch and
//! class, and how it ended. Settlement programs read these after a round.
//!
//! A packet is counted when it ends, delivered or dropped, from its hidden
//! trail: every pair of consecutive switches owned by different ASes is one
//! crossing, filed under the epoch in which it reached the far side. A
//! crossing from x to y is also *returned* when the packet then came
//! straight back from y into x: x's own traffic, carried by y between two
//! parts of x (what a backup agreement sells). A packet counts as returned
//! once per pair, however often it bounced between them.
//!
//! Only customer traffic is metered: a packet a switch program injected
//! (a hello, a probe) carries no sending app, so it uses capacity but never
//! shows on a meter or a bill.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::packet::Packet;
use crate::types::SimTime;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reading {
    pub bytes: u64,
    pub on_time: u64,
    pub late: u64,
    pub lost: u64,
    pub returned: u64,
    pub returned_on_time: u64,
}

#[derive(Debug, Clone)]
pub struct Meter {
    epoch: Duration,
    owner: BTreeMap<u32, u32>,
    target: BTreeMap<u8, Duration>,
    /// (from AS, to AS, epoch, class) -> what crossed, in simulated bytes.
    pub readings: BTreeMap<(u32, u32, u32, u8), Reading>,
}

impl Meter {
    /// `owner` maps switch to AS; `target` maps class to its latency target.
    pub fn new(epoch: Duration, owner: BTreeMap<u32, u32>, target: BTreeMap<u8, Duration>) -> Self {
        Self { epoch, owner, target, readings: BTreeMap::new() }
    }

    /// A packet ended at `now`: delivered, or dropped.
    pub fn record(&mut self, p: &Packet, now: SimTime, delivered: bool) {
        if p.app_id.raw() == 0 {
            return;
        }
        let class = p.ip_dscp;
        let on_time = self.target.get(&class).is_none_or(|t| now.saturating_sub(p.created_at) <= *t);
        let owners: Vec<Option<u32>> = p.trail.hops.iter().map(|h| self.owner.get(&h.switch.raw()).copied()).collect();
        let mut counted: Vec<(u32, u32)> = Vec::new();
        for i in 1..owners.len() {
            let (Some(x), Some(y)) = (owners[i - 1], owners[i]) else { continue };
            if x == y {
                continue;
            }
            let returned = owners[i..].iter().find(|o| **o != Some(y)) == Some(&Some(x)) && !counted.contains(&(x, y));
            if returned {
                counted.push((x, y));
            }
            let epoch = (p.trail.hops[i].arrived_at.as_nanos() / self.epoch.as_nanos()) as u32;
            let r = self.readings.entry((x, y, epoch, class)).or_default();
            let n = p.size_bytes;
            r.bytes += n;
            match (delivered, on_time) {
                (false, _) => r.lost += n,
                (true, true) => r.on_time += n,
                (true, false) => r.late += n,
            }
            if returned {
                r.returned += n;
                if delivered && on_time {
                    r.returned_on_time += n;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, TrailHop};
    use crate::types::{AppId, PacketId, SwitchId};

    fn packet(path: &[(u32, u64)], class: u8) -> Packet {
        let mut p = Packet::new(PacketId::new(1), Duration::ZERO, 1000);
        p.ip_dscp = class;
        p.app_id = AppId::new(1);
        for &(s, ms) in path {
            p.trail.hops.push(TrailHop { switch: SwitchId::new(s), as_id: None, link_in: None, arrived_at: Duration::from_millis(ms) });
        }
        p
    }

    #[test]
    fn every_border_a_packet_crossed_gets_its_bytes_and_how_it_ended() {
        // Switches 11, 12 are AS 1; 21 is AS 2; 31 is AS 3. Class 1 has a 50 ms target.
        let owner = BTreeMap::from([(11, 1), (12, 1), (21, 2), (31, 3)]);
        let mut m = Meter::new(Duration::from_millis(100), owner, BTreeMap::from([(1, Duration::from_millis(50))]));
        // 11 -> 12 -> 21 (at 30 ms) -> 31 (at 120 ms), delivered at 130 ms: late.
        m.record(&packet(&[(11, 0), (12, 10), (21, 30), (31, 120)], 1), Duration::from_millis(130), true);
        // 11 -> 21 at 20 ms, delivered at 40 ms: on time.
        m.record(&packet(&[(11, 0), (21, 20)], 1), Duration::from_millis(40), true);
        // 21 -> 11 at 20 ms, then dropped: lost.
        m.record(&packet(&[(21, 0), (11, 20)], 1), Duration::from_millis(25), false);
        let r = |x, y, e| m.readings.get(&(x, y, e, 1)).copied().unwrap_or_default();
        let read = |bytes, on_time, late, lost| Reading { bytes, on_time, late, lost, ..Default::default() };
        assert_eq!(r(1, 2, 0), read(2000, 1000, 1000, 0));
        assert_eq!(r(2, 3, 1), read(1000, 0, 1000, 0), "filed by when it reached AS 3");
        assert_eq!(r(2, 1, 0), read(1000, 0, 0, 1000));
        assert_eq!(m.readings.len(), 3, "no reading inside an AS");
    }

    #[test]
    fn a_crossing_is_returned_when_the_packet_comes_straight_back() {
        let owner = BTreeMap::from([(11, 1), (12, 1), (21, 2), (22, 2), (31, 3)]);
        let mut m = Meter::new(Duration::from_millis(100), owner, BTreeMap::from([(1, Duration::from_millis(50))]));
        // AS 1's west hub -> AS 2 (two switches) -> AS 1's east hub: AS 2 carried
        // AS 1's own traffic. Delivered on time.
        m.record(&packet(&[(11, 0), (21, 5), (22, 10), (12, 15)], 1), Duration::from_millis(20), true);
        // Out through AS 2 and on to AS 3: not returned.
        m.record(&packet(&[(11, 0), (21, 5), (31, 10)], 1), Duration::from_millis(20), true);
        // Back to AS 1, but by way of AS 3: not straight back.
        m.record(&packet(&[(11, 0), (21, 5), (31, 10), (12, 15)], 1), Duration::from_millis(20), true);
        // Straight back, then dropped.
        m.record(&packet(&[(11, 0), (21, 5), (12, 15)], 1), Duration::from_millis(20), false);
        // Bounced between AS 1 and AS 2 three times, then dropped: returned once.
        m.record(&packet(&[(11, 0), (21, 5), (12, 10), (21, 15), (11, 20), (21, 25), (12, 30)], 1), Duration::from_millis(30), false);
        let r = m.readings[&(1, 2, 0, 1)];
        assert_eq!((r.bytes, r.returned, r.returned_on_time), (7000, 3000, 1000));
        // The straight-back packets count on the way out only; the bouncing
        // one also came straight back to AS 2 through AS 1.
        assert_eq!(m.readings[&(2, 1, 0, 1)].returned, 1000);
    }

    #[test]
    fn a_packet_a_program_injected_is_never_metered() {
        let owner = BTreeMap::from([(11, 1), (21, 2)]);
        let mut m = Meter::new(Duration::from_millis(100), owner, BTreeMap::from([(1, Duration::from_millis(50))]));
        let mut junk = packet(&[(11, 0), (21, 5)], 1);
        junk.app_id = AppId::default();
        m.record(&junk, Duration::from_millis(10), true);
        assert!(m.readings.is_empty(), "no sending app: not customer traffic");
    }
}
