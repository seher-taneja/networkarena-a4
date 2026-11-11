//! A run where the harness forwards.
//!
//! A world with a `[harness]` section stages a run for A3. The harness, not
//! the switch program, decides where every customer packet goes and how
//! each queue is shaped, so no program can steer around the planted fault
//! or hide it. The program still runs on every switch, as an observer: its
//! pipeline sees each packet (on a copy), its counters and registers keep
//! what it wrote, its punts reach the controller as samples through
//! the observation budget, and its controllers send reports. Packets a controller creates are forwarded by the program's
//! own tables, as in any other run.
//!
//! The harness also sends a small keepalive out of every switch-to-switch
//! port, so "this link went quiet" has an answer that does not depend on
//! what the program sends. An incident may silence one direction's
//! keepalives for a while; data keeps flowing.

use std::collections::HashMap;
use std::time::Duration;

use crate::packet::{IpAddr, Packet, PacketKind};
use crate::types::{PacketId, PortId, SimTime, SwitchId};

/// Ids of harness keepalives have this bit set (and not bit 63, which marks
/// packets a controller created).
pub const KEEPALIVE_ID_BIT: u64 = 1 << 62;

/// The size of a keepalive on the wire, in bytes.
pub const KEEPALIVE_BYTES: u64 = 64;

/// Where the harness sends packets for one destination from one switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub primary: PortId,
    /// Taken at once while the primary's link is down.
    pub backup: Option<PortId>,
    /// When set, every other packet leaves here instead of `primary`.
    pub split: Option<PortId>,
}

/// One direction whose keepalives the harness holds back for a while.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub switch: SwitchId,
    pub port: PortId,
    pub start: SimTime,
    pub end: SimTime,
}

#[derive(Debug, Clone, Default)]
pub struct Harness {
    pub keepalive_period: Duration,
    /// Destination prefixes `(addr, len)`, indexed like `routes`' second key.
    dests: Vec<(u32, u8)>,
    routes: HashMap<(SwitchId, usize), Route>,
    /// Split routes whose next packet takes the `split` port.
    turns: HashMap<(SwitchId, usize), bool>,
    gaps: Vec<Gap>,
    keepalive_seq: HashMap<(SwitchId, PortId), u64>,
    keepalives: u64,
    /// What the program wrote down. See `crate::team_log`.
    pub team_log: crate::team_log::TeamLog,
    /// Rule 9: how deep each port's report queue is, in packets.
    pub report_queue_packets: u32,
    /// Rule 9: the largest report a switch may send, in bytes.
    pub report_max_bytes: u64,
}

impl Harness {
    pub fn new(keepalive_period: Duration) -> Self {
        Self { keepalive_period, report_queue_packets: 4, report_max_bytes: u64::MAX, ..Default::default() }
    }

    /// Add a destination prefix; returns its index for `set_route`.
    pub fn add_dest(&mut self, addr: u32, len: u8) -> usize {
        self.dests.push((crate::world::mask(addr, len), len));
        self.dests.len() - 1
    }

    pub fn set_route(&mut self, switch: SwitchId, dest: usize, route: Route) {
        self.routes.insert((switch, dest), route);
    }

    pub fn add_gap(&mut self, gap: Gap) {
        self.gaps.push(gap);
    }

    /// What a program is told at `init`.
    pub fn info(&self) -> switch_program_types::HarnessInfoW {
        switch_program_types::HarnessInfoW {
            keepalive_period_ns: self.keepalive_period.as_nanos() as u64,
        }
    }

    /// The route at `switch` toward `ip`, by longest prefix. A split
    /// route comes back with its two ports swapped every other call.
    pub fn route(&mut self, switch: SwitchId, ip: IpAddr) -> Option<Route> {
        let dest = self
            .dests
            .iter()
            .enumerate()
            .filter(|(_, (addr, len))| crate::world::mask(ip.0, *len) == *addr)
            .max_by_key(|(_, (_, len))| *len)
            .map(|(i, _)| i)?;
        let mut r = *self.routes.get(&(switch, dest))?;
        if let Some(other) = r.split {
            let turn = self.turns.entry((switch, dest)).or_default();
            *turn = !*turn;
            if *turn {
                r = Route { primary: other, backup: Some(r.primary), split: r.split };
            } else {
                r.backup = Some(other);
            }
        }
        Some(r)
    }

    /// Whether keepalives out of `switch:port` are held back at `now`.
    pub fn silenced(&self, switch: SwitchId, port: PortId, now: SimTime) -> bool {
        self.gaps
            .iter()
            .any(|g| g.switch == switch && g.port == port && g.start <= now && now < g.end)
    }

    /// The next keepalive out of `switch:port`.
    pub fn keepalive(&mut self, switch: SwitchId, port: PortId, now: SimTime) -> Packet {
        self.keepalives += 1;
        let seq = self.keepalive_seq.entry((switch, port)).or_insert(0);
        *seq += 1;
        let mut p = Packet::new(PacketId::new(KEEPALIVE_ID_BIT | self.keepalives), now, KEEPALIVE_BYTES);
        p.kind = PacketKind::Keepalive;
        p.seq = Some(*seq);
        p.payload = postcard::to_allocvec(&switch_program_types::KeepaliveW {
            switch: switch.raw(),
            port: port.raw(),
            seq: *seq,
            sent_ns: now.as_nanos() as u64,
        })
        .expect("postcard encode");
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_go_by_the_longest_prefix() {
        let mut h = Harness::new(Duration::from_millis(100));
        let wide = h.add_dest(0x0a00_0000, 8);
        let narrow = h.add_dest(0x0a00_0200, 24);
        let s = SwitchId::new(1);
        h.set_route(s, wide, Route { primary: PortId::new(0), backup: None, split: None });
        h.set_route(s, narrow, Route { primary: PortId::new(1), backup: Some(PortId::new(2)), split: None });
        assert_eq!(h.route(s, IpAddr(0x0a00_0201)).unwrap().primary, PortId::new(1));
        assert_eq!(h.route(s, IpAddr(0x0a00_0301)).unwrap().primary, PortId::new(0));
        assert!(h.route(s, IpAddr(0x0b00_0001)).is_none());
    }

    #[test]
    fn a_split_route_alternates_and_each_port_backs_the_other() {
        let mut h = Harness::new(Duration::from_millis(100));
        let d = h.add_dest(0x0a00_0200, 24);
        let s = SwitchId::new(1);
        h.set_route(s, d, Route { primary: PortId::new(1), backup: None, split: Some(PortId::new(2)) });
        let ports: Vec<(u16, u16)> = (0..4)
            .map(|_| h.route(s, IpAddr(0x0a00_0201)).unwrap())
            .map(|r| (r.primary.raw(), r.backup.unwrap().raw()))
            .collect();
        assert_eq!(ports, [(2, 1), (1, 2), (2, 1), (1, 2)]);
    }

    #[test]
    fn keepalives_count_per_port_and_gaps_are_half_open() {
        let mut h = Harness::new(Duration::from_millis(100));
        let (s, p, q) = (SwitchId::new(2), PortId::new(0), PortId::new(1));
        h.add_gap(Gap { switch: s, port: p, start: Duration::from_secs(1), end: Duration::from_secs(2) });
        assert!(!h.silenced(s, p, Duration::from_millis(999)));
        assert!(h.silenced(s, p, Duration::from_secs(1)));
        assert!(!h.silenced(s, p, Duration::from_secs(2)));
        assert!(!h.silenced(s, q, Duration::from_millis(1500)));
        let a = h.keepalive(s, p, SimTime::ZERO);
        let b = h.keepalive(s, p, SimTime::ZERO);
        let c = h.keepalive(s, q, SimTime::ZERO);
        assert_eq!((a.seq, b.seq, c.seq), (Some(1), Some(2), Some(1)));
        assert!(a.id != b.id && a.id.raw() & KEEPALIVE_ID_BIT != 0 && a.id.raw() >> 63 == 0);
        let k: switch_program_types::KeepaliveW = postcard::from_bytes(&c.payload).unwrap();
        assert_eq!((k.switch, k.port, k.seq), (2, 1, 1));
    }
}
