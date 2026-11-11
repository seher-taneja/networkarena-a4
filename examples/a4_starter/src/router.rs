//! Helpers for an A4 switch program: turn the A4 init information into a
//! forwarding table for one switch, given how to rank offered routes.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use switch_program_sdk::wire::{A4InfoW, A4RouteW};
use switch_program_sdk::*;

pub const T_ROUTE: u32 = 1;
pub const T_CLASS: u32 = 2;
pub const T_PROTO: u32 = 3;
pub const PROTO_HELLO: u8 = 89;
pub const CTRL_IP: u32 = 0xe000_0005;

/// The port at `me` toward `to` inside the AS, avoiding `down` links
/// (given as (switch, port) at either end).
pub fn next_hop(info: &A4InfoW, me: u32, to: u32, down: &BTreeSet<(u32, u16)>) -> Option<u16> {
    if me == to {
        return None;
    }
    // BFS from `to` back to `me`; the first hop is the neighbour of `me`
    // that is one step closer.
    let mut dist: BTreeMap<u32, u32> = BTreeMap::from([(to, 0)]);
    let mut q = VecDeque::from([to]);
    while let Some(s) = q.pop_front() {
        for l in &info.internal {
            if down.contains(&(l.a, l.a_port)) || down.contains(&(l.b, l.b_port)) {
                continue;
            }
            let n = if l.a == s { l.b } else if l.b == s { l.a } else { continue };
            if !dist.contains_key(&n) {
                dist.insert(n, dist[&s] + 1);
                q.push_back(n);
            }
        }
    }
    let mine = *dist.get(&me)?;
    info.internal
        .iter()
        .filter(|l| !down.contains(&(l.a, l.a_port)) && !down.contains(&(l.b, l.b_port)))
        .filter_map(|l| {
            if l.a == me { Some((l.b, l.a_port)) } else if l.b == me { Some((l.a, l.b_port)) } else { None }
        })
        .filter(|(n, _)| dist.get(n).is_some_and(|d| *d + 1 == mine))
        .map(|(_, p)| p)
        .min()
}

/// Hop distance inside the AS from `me` to `to`, or None.
pub fn inside(info: &A4InfoW, me: u32, to: u32, down: &BTreeSet<(u32, u16)>) -> Option<u32> {
    let mut cur = me;
    let mut n = 0;
    while cur != to {
        let p = next_hop(info, cur, to, down)?;
        let l = info.internal.iter().find(|l| (l.a == cur && l.a_port == p) || (l.b == cur && l.b_port == p))?;
        cur = if l.a == cur { l.b } else { l.a };
        n += 1;
        if n > 64 {
            return None;
        }
    }
    Some(n)
}

/// The forwarding table at `me`: (addr, len, port) for every own prefix
/// and every prefix some route offers. `rank` orders a prefix's offered
/// routes (lower first) and may refuse one with None; the first that can
/// be reached inside the AS wins.
pub fn table(
    info: &A4InfoW,
    me: u32,
    down: &BTreeSet<(u32, u16)>,
    rank: impl Fn(&A4RouteW, u32) -> Option<u64>,
) -> Vec<(u32, u8, u16)> {
    let mut out = Vec::new();
    for p in &info.own {
        if p.switch == me {
            out.push((p.addr, p.len, p.port));
        } else if let Some(port) = next_hop(info, me, p.switch, down) {
            out.push((p.addr, p.len, port));
        }
    }
    let mut by_prefix: BTreeMap<(u32, u8), Vec<&A4RouteW>> = BTreeMap::new();
    for r in &info.routes {
        if down.contains(&(r.switch, r.port)) {
            continue;
        }
        by_prefix.entry((r.addr, r.len)).or_default().push(r);
    }
    for ((addr, len), rs) in by_prefix {
        if out.iter().any(|&(a, l, _)| a == addr && l == len) {
            continue;
        }
        let mut ranked: Vec<(u64, u32, u16, &A4RouteW)> = rs
            .into_iter()
            .filter_map(|r| {
                let d = inside(info, me, r.switch, down)?;
                Some((rank(r, d)?, r.switch, r.port, r))
            })
            .collect();
        ranked.sort_by_key(|(k, s, p, _)| (*k, *s, *p));
        if let Some(&(_, s, p, _)) = ranked.first() {
            let port = if s == me { p } else { next_hop(info, me, s, down).unwrap() };
            out.push((addr, len, port));
        }
    }
    out
}

/// The usual pipeline: control packets punted by protocol, then a route by
/// destination, then a queue by class.
pub fn setup(routes: &[(u32, u8, u16)], prio: bool) -> ProgramSetup {
    let mut setup = ProgramSetup::new();
    setup.declare_table(T_PROTO, MatchKind::Exact, 8);
    setup.declare_table(T_ROUTE, MatchKind::Lpm, 4096);
    setup.declare_table(T_CLASS, MatchKind::Exact, 8);
    setup.set_program(
        text::parse_tiny_program(
            "
            stage alu=4 mem=1
                load    r0, ip_proto
                table   t3, r0 -> m0
            stage alu=4 mem=1
                load    r1, ip_dst
                table   t1, r1 -> m1
            stage alu=4 mem=1
                load    r2, ip_dscp
                table   t2, r2 -> m2
            ",
        )
        .unwrap(),
    );
    setup.add_entry(
        T_PROTO,
        TableEntry {
            id: wire::EntryIdW(1),
            key: PROTO_HELLO as u64,
            prefix_len: 8,
            priority: 0,
            action: TableAction::Punt { reason: PuntReason::Custom(PROTO_HELLO as u32) },
        },
    );
    for (i, &(addr, len, port)) in routes.iter().enumerate() {
        setup.add_entry(T_ROUTE, route_entry(1000 + i as u64, addr, len, port));
    }
    if prio {
        // Calls (3) and Trading (4) go first.
        for (i, class) in [3u64, 4].iter().enumerate() {
            setup.add_entry(
                T_CLASS,
                TableEntry {
                    id: wire::EntryIdW(10 + i as u64),
                    key: *class,
                    prefix_len: 8,
                    priority: 0,
                    action: TableAction::SetQueue { queue: wire::QueueIdW(0) },
                },
            );
        }
        for (i, class) in [0u64, 1, 2].iter().enumerate() {
            setup.add_entry(
                T_CLASS,
                TableEntry {
                    id: wire::EntryIdW(20 + i as u64),
                    key: *class,
                    prefix_len: 8,
                    priority: 0,
                    action: TableAction::SetQueue { queue: wire::QueueIdW(1) },
                },
            );
        }
    }
    setup
}

pub fn route_entry(id: u64, addr: u32, len: u8, port: u16) -> TableEntry {
    TableEntry {
        id: wire::EntryIdW(id),
        key: addr as u64,
        prefix_len: len,
        priority: 0,
        action: TableAction::SetEgress { port: wire::PortIdW(port) },
    }
}

/// Replace the installed table `old` (with entry ids) by `new`.
pub fn reinstall(old: &mut Vec<(u64, u32, u8, u16)>, new: &[(u32, u8, u16)], next_id: &mut u64) -> Vec<Action> {
    let mut out = Vec::new();
    let want: BTreeMap<(u32, u8), u16> = new.iter().map(|&(a, l, p)| ((a, l), p)).collect();
    let mut keep = Vec::new();
    for &(id, a, l, p) in old.iter() {
        if want.get(&(a, l)) == Some(&p) {
            keep.push((id, a, l, p));
        } else {
            out.push(actions::delete_entry(T_ROUTE, id));
        }
    }
    for (&(a, l), &p) in &want {
        if !keep.iter().any(|&(_, ka, kl, _)| ka == a && kl == l) {
            *next_id += 1;
            out.push(actions::install_entry(T_ROUTE, route_entry(*next_id, a, l, p)));
            keep.push((*next_id, a, l, p));
        }
    }
    *old = keep;
    out
}

/// This switch's internal ports: the ones whose link stays inside the AS.
pub fn internal_ports(info: &A4InfoW, me: u32) -> Vec<u16> {
    let mut v: Vec<u16> = info
        .internal
        .iter()
        .filter_map(|l| if l.a == me { Some(l.a_port) } else if l.b == me { Some(l.b_port) } else { None })
        .collect();
    v.sort_unstable();
    v
}

/// Ports that leave the AS or reach an app: every port that is not internal.
pub fn edge_ports(info: &A4InfoW, me: u32) -> Vec<u16> {
    let mut v: Vec<u16> = info.borders.iter().filter(|b| b.switch == me).map(|b| b.port).collect();
    v.extend(info.own.iter().filter(|p| p.switch == me).map(|p| p.port));
    v.sort_unstable();
    v.dedup();
    v
}
