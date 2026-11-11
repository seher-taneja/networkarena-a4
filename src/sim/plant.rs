//! Plants: what a run is made to do so that an egg is true in it, or so
//! that it is a near miss. A world lists them as `[[plant]]` rows, each
//! with a `kind`. The harness plays them; nothing a program does starts or
//! stops one. The practice runs carry theirs in the open; a graded run's
//! are the secret.
//!
//! Kinds:
//!
//! - `side_flow`: a customer also sends a steady stream of its own, beside
//!   its main traffic: `rate_pps` packets a second of `size_bytes` (scaled
//!   by the run's load), from `start_ms` to `stop_ms` (the end of the run
//!   if absent), to the app `to` (the customer's peer if absent). The
//!   packets leave by the customer's own port, carry its addresses in
//!   turn (its `hosts`) and no sequence number, and are not acknowledged.
//!   `proto` ("tcp" or "udp") is their protocol; absent, the customer's.
//! - `link_delay`: the link between switches `a` and `b` takes `a_to_b_us`
//!   one way and `b_to_a_us` the other, all run, in place of the world's
//!   link latency. Nothing is lost and the link stays up.
//! - `wire_loss`: the link between switches `a` and `b` loses `loss_pct`
//!   percent of what crosses it, either way, on the wire, from `start_ms`
//!   to `stop_ms` (the end of the run if absent). Which packets is
//!   decided by a hash of the packet, the link and the world's seed. The
//!   link stays up and its queues are untouched.
//! - `link_capacity`: the link between switches `a` and `b` changes
//!   capacity on a schedule: `steps = [[at_ms, mbps], ...]`, each taking
//!   effect for the packets that start onto the wire from then on, both
//!   ways.
//! - `fail`: the link between switches `a` and `b` goes down at `at_ms`
//!   and comes back `for_ms` later, or never if `for_ms` is absent. The
//!   harness stops its keepalives on it and routes around it where it has
//!   a backup (egg 21).
//! - `pause`: the customer `app` sends nothing from `at_ms` for `for_ms`,
//!   then carries on (egg 22).
//! - `scan`: one host of the customer `app` sends `each` small packets of
//!   `size_bytes` to each of the first `addresses` addresses of the app
//!   `to`'s range, from its own address up (its peer's range if `to` is
//!   absent), address by address, spread
//!   evenly from `start_ms` over `for_ms`. Unnumbered, unacknowledged,
//!   not scaled by the load (egg 23).

use std::time::Duration;

use serde::Deserialize;

use super::Simulator;
use crate::event::EventKind;
use crate::network::Node;
use crate::packet::{IpAddr, Packet};
use crate::types::{AppId, FlowId, PacketId, PortId, SimTime, SwitchId};
use crate::world::{World, WorldError};

/// Planted packets' ids, and their flows', have this bit set.
pub(super) const PLANT_BIT: u64 = 1 << 61;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Plant {
    SideFlow {
        app: u32,
        #[serde(default)]
        to: Option<u32>,
        rate_pps: f64,
        size_bytes: u64,
        #[serde(default)]
        start_ms: u64,
        #[serde(default)]
        stop_ms: Option<u64>,
        #[serde(default)]
        proto: Option<crate::world::Proto>,
    },
    LinkDelay {
        a: u32,
        b: u32,
        a_to_b_us: u64,
        b_to_a_us: u64,
    },
    WireLoss {
        a: u32,
        b: u32,
        loss_pct: f64,
        #[serde(default)]
        start_ms: u64,
        #[serde(default)]
        stop_ms: Option<u64>,
    },
    LinkCapacity {
        a: u32,
        b: u32,
        /// `[at_ms, mbps]` pairs, in time order.
        steps: Vec<[u64; 2]>,
    },
    Fail {
        a: u32,
        b: u32,
        at_ms: u64,
        #[serde(default)]
        for_ms: Option<u64>,
    },
    Pause {
        app: u32,
        at_ms: u64,
        for_ms: u64,
    },
    Scan {
        app: u32,
        #[serde(default)]
        to: Option<u32>,
        start_ms: u64,
        for_ms: u64,
        addresses: u32,
        #[serde(default = "one")]
        each: u64,
        size_bytes: u64,
    },
}

fn one() -> u64 {
    1
}

/// The capacity steps a `link_capacity` plant gives the link `a`-`b`, as
/// `(at, mbps)`, in time order; empty if none does.
pub fn capacity_steps(world: &World, a: u32, b: u32) -> Result<Vec<(Duration, u64)>, WorldError> {
    Ok(plants(world)?
        .iter()
        .find_map(|p| match p {
            Plant::LinkCapacity { steps, .. } if same_link(p, a, b) => {
                Some(steps.iter().map(|s| (Duration::from_millis(s[0]), s[1])).collect())
            }
            _ => None,
        })
        .unwrap_or_default())
}

/// Plants with the same `kind` on the link `a`-`b`, either way round.
fn same_link(p: &Plant, a: u32, b: u32) -> bool {
    match p {
        Plant::LinkDelay { a: pa, b: pb, .. } | Plant::WireLoss { a: pa, b: pb, .. } | Plant::LinkCapacity { a: pa, b: pb, .. } => {
            (*pa, *pb) == (a, b) || (*pa, *pb) == (b, a)
        }
        _ => false,
    }
}

/// The one-way delays a `link_delay` plant gives the link `a`-`b`, as
/// `(a_to_b, b_to_a)`, or the world's link latency both ways if none
/// does. The order of `a` and `b` does not matter.
pub fn link_delays(world: &World, a: u32, b: u32) -> Result<(Duration, Duration), WorldError> {
    let base = Duration::from_micros(world.params.link_latency_us);
    for p in plants(world)? {
        if let Plant::LinkDelay { a: pa, b: pb, a_to_b_us, b_to_a_us } = p {
            if (pa, pb) == (a, b) {
                return Ok((Duration::from_micros(a_to_b_us), Duration::from_micros(b_to_a_us)));
            }
            if (pa, pb) == (b, a) {
                return Ok((Duration::from_micros(b_to_a_us), Duration::from_micros(a_to_b_us)));
            }
        }
    }
    Ok((base, base))
}

/// The world's `[[plant]]` rows.
pub fn plants(world: &World) -> Result<Vec<Plant>, WorldError> {
    world
        .plants
        .iter()
        .enumerate()
        .map(|(i, row)| {
            Plant::deserialize(toml::Value::Table(row.clone()))
                .map_err(|e| WorldError::Invalid(format!("plant {}: {e}", i + 1)))
        })
        .collect()
}

pub fn validate(world: &World) -> Result<(), WorldError> {
    let bad = |m: String| Err(WorldError::Invalid(m));
    let app = |id: u32| world.apps.iter().find(|a| a.id == id);
    for (i, p) in plants(world)?.iter().enumerate() {
        let n = i + 1;
        match p {
            Plant::SideFlow { app: a, to, rate_pps, size_bytes, start_ms, stop_ms, .. } => {
                let Some(spec) = app(*a) else { return bad(format!("plant {n}: no app {a}")) };
                match to.or(spec.peer) {
                    Some(t) if app(t).is_some() && t != *a => {}
                    _ => return bad(format!("plant {n}: app {a} needs a `to` that is another app")),
                }
                if !(*rate_pps > 0.0 && rate_pps.is_finite()) {
                    return bad(format!("plant {n}: rate_pps must be positive"));
                }
                let unit = world.params.packet_size_bytes.unwrap_or_else(|| world.workload.packet_size_bytes());
                if *size_bytes == 0 || *size_bytes > unit {
                    return bad(format!("plant {n}: size_bytes must be 1 to {unit}"));
                }
                if stop_ms.is_some_and(|s| s <= *start_ms) {
                    return bad(format!("plant {n}: stop_ms must be after start_ms"));
                }
            }
            Plant::LinkDelay { a, b, a_to_b_us, b_to_a_us } => {
                if world.port_toward(*a, *b).is_none() {
                    return bad(format!("plant {n}: no link between switches {a} and {b}"));
                }
                if *a_to_b_us == 0 || *b_to_a_us == 0 {
                    return bad(format!("plant {n}: both delays must be above 0"));
                }
                let twice = plants(world)?
                    .iter()
                    .filter(|q| matches!(q, Plant::LinkDelay { .. }) && same_link(q, *a, *b))
                    .count();
                if twice > 1 {
                    return bad(format!("plant {n}: the link {a}-{b} has more than one delay"));
                }
            }
            Plant::WireLoss { a, b, loss_pct, start_ms, stop_ms } => {
                if world.port_toward(*a, *b).is_none() {
                    return bad(format!("plant {n}: no link between switches {a} and {b}"));
                }
                if !(*loss_pct > 0.0 && *loss_pct <= 100.0) {
                    return bad(format!("plant {n}: loss_pct must be above 0 and at most 100"));
                }
                if stop_ms.is_some_and(|s| s <= *start_ms) {
                    return bad(format!("plant {n}: stop_ms must be after start_ms"));
                }
                let twice = plants(world)?
                    .iter()
                    .filter(|q| matches!(q, Plant::WireLoss { .. }) && same_link(q, *a, *b))
                    .count();
                if twice > 1 {
                    return bad(format!("plant {n}: the link {a}-{b} has more than one leak"));
                }
            }
            Plant::LinkCapacity { a, b, steps } => {
                if world.port_toward(*a, *b).is_none() {
                    return bad(format!("plant {n}: no link between switches {a} and {b}"));
                }
                if steps.is_empty() || steps.iter().any(|s| s[1] == 0) {
                    return bad(format!("plant {n}: steps need at least one [at_ms, mbps] with mbps above 0"));
                }
                if steps.windows(2).any(|w| w[1][0] <= w[0][0]) {
                    return bad(format!("plant {n}: steps must be in time order"));
                }
                let twice = plants(world)?
                    .iter()
                    .filter(|q| matches!(q, Plant::LinkCapacity { .. }) && same_link(q, *a, *b))
                    .count();
                if twice > 1 {
                    return bad(format!("plant {n}: the link {a}-{b} has more than one capacity schedule"));
                }
            }
            Plant::Fail { a, b, for_ms, .. } => {
                if world.port_toward(*a, *b).is_none() {
                    return bad(format!("plant {n}: no link between switches {a} and {b}"));
                }
                if *for_ms == Some(0) {
                    return bad(format!("plant {n}: for_ms must be above 0"));
                }
            }
            Plant::Pause { app: a, for_ms, .. } => {
                if !app(*a).is_some_and(|s| s.preset.is_some()) {
                    return bad(format!("plant {n}: app {a} is not a customer that sends"));
                }
                if *for_ms == 0 {
                    return bad(format!("plant {n}: for_ms must be above 0"));
                }
            }
            Plant::Scan { app: a, to, for_ms, addresses, each, size_bytes, .. } => {
                let Some(spec) = app(*a) else { return bad(format!("plant {n}: no app {a}")) };
                let target = match to.or(spec.peer) {
                    Some(t) if t != *a => app(t),
                    _ => None,
                };
                let Some(target) = target else {
                    return bad(format!("plant {n}: app {a} needs a `to` that is another app"));
                };
                let room = crate::world::Prefix::parse(&target.prefix)?.room();
                if *addresses == 0 || *addresses > room {
                    return bad(format!("plant {n}: addresses must be 1 to {room}, the size of app {}'s range", target.id));
                }
                if *for_ms == 0 || *each == 0 {
                    return bad(format!("plant {n}: for_ms and each must be above 0"));
                }
                let unit = world.params.packet_size_bytes.unwrap_or_else(|| world.workload.packet_size_bytes());
                if *size_bytes == 0 || *size_bytes > unit {
                    return bad(format!("plant {n}: size_bytes must be 1 to {unit}"));
                }
            }
        }
    }
    Ok(())
}

/// Schedule every plant of `world` in `sim`, after the world is built.
pub fn install(world: &World, sim: &mut Simulator, load_scale: f64) -> Result<(), WorldError> {
    let built = |sim: &Simulator, id: u32| sim.apps.contains_key(&AppId::new(id));
    for (i, p) in plants(world)?.into_iter().enumerate() {
        match p {
            Plant::SideFlow { app, to, rate_pps, size_bytes, start_ms, stop_ms, proto } => {
                let peer = world.apps.iter().find(|a| a.id == app).and_then(|a| a.peer);
                let to = to.or(peer).expect("validated");
                if !(built(sim, app) && built(sim, to)) {
                    return Err(WorldError::Invalid(format!("plant {}: app {app} or {to} was not built", i + 1)));
                }
                let sender = &sim.apps[&AppId::new(app)];
                let tick = Tick {
                    app: AppId::new(app),
                    src: sender.base(),
                    hosts: sender.hosts.clone(),
                    proto: proto.map_or(sender.proto, crate::world::Proto::number),
                    dest: addresses_of(&sim.apps[&AppId::new(to)]),
                    interval: Duration::from_secs_f64(1.0 / (rate_pps * load_scale)),
                    size_bytes,
                    stop: stop_ms.map(Duration::from_millis),
                    flow: FlowId::new(PLANT_BIT | i as u64),
                    sent: 0,
                    limit: None,
                    addresses: 1,
                    each: 1,
                };
                sim.queue.schedule(Duration::from_millis(start_ms), EventKind::PlantTick { tick });
            }
            Plant::Scan { app, to, start_ms, for_ms, addresses, each, size_bytes } => {
                let peer = world.apps.iter().find(|a| a.id == app).and_then(|a| a.peer);
                let to = to.or(peer).expect("validated");
                if !(built(sim, app) && built(sim, to)) {
                    return Err(WorldError::Invalid(format!("plant {}: app {app} or {to} was not built", i + 1)));
                }
                let sender = &sim.apps[&AppId::new(app)];
                let start = Duration::from_millis(start_ms);
                let tick = Tick {
                    app: AppId::new(app),
                    src: sender.base(),
                    hosts: vec![sender.hosts[0]],
                    proto: sender.proto,
                    dest: addresses_of(&sim.apps[&AppId::new(to)]),
                    interval: Duration::from_millis(for_ms) / (addresses * each as u32),
                    size_bytes,
                    stop: None,
                    flow: FlowId::new(PLANT_BIT | i as u64),
                    sent: 0,
                    limit: Some(addresses as u64 * each),
                    addresses,
                    each,
                };
                sim.queue.schedule(start, EventKind::PlantTick { tick });
            }
            Plant::Fail { a, b, at_ms, for_ms } => {
                let node = Node::Switch(SwitchId::new(a));
                let link = world
                    .port_toward(a, b)
                    .and_then(|port| sim.network.link_at(node, PortId::new(port)))
                    .ok_or_else(|| WorldError::Invalid(format!("plant {}: the link {a}-{b} was not built", i + 1)))?;
                let down = Duration::from_millis(at_ms);
                sim.queue.schedule(down, EventKind::PlantLink { link, up: false });
                if let Some(f) = for_ms {
                    sim.queue.schedule(down + Duration::from_millis(f), EventKind::PlantLink { link, up: true });
                }
            }
            Plant::Pause { app, at_ms, for_ms } => {
                let at = Duration::from_millis(at_ms);
                let until = at + Duration::from_millis(for_ms);
                sim.queue.schedule(at, EventKind::PlantPause { app: AppId::new(app), until });
            }
            Plant::LinkDelay { a, b, a_to_b_us, b_to_a_us } => {
                let node = Node::Switch(SwitchId::new(a));
                let link = world
                    .port_toward(a, b)
                    .and_then(|port| sim.network.link_at(node, PortId::new(port)))
                    .and_then(|id| sim.links.get_mut(&id))
                    .ok_or_else(|| WorldError::Invalid(format!("plant {}: the link {a}-{b} was not built", i + 1)))?;
                let a_is_src = link.is_src(node.as_node_id());
                link.set_latency(a_is_src, Duration::from_micros(a_to_b_us));
                link.set_latency(!a_is_src, Duration::from_micros(b_to_a_us));
            }
            Plant::WireLoss { a, b, loss_pct, start_ms, stop_ms } => {
                let node = Node::Switch(SwitchId::new(a));
                let link = world
                    .port_toward(a, b)
                    .and_then(|port| sim.network.link_at(node, PortId::new(port)))
                    .and_then(|id| sim.links.get_mut(&id))
                    .ok_or_else(|| WorldError::Invalid(format!("plant {}: the link {a}-{b} was not built", i + 1)))?;
                link.leak = Some(crate::link::WireLeak {
                    ppm: (loss_pct * 10_000.0).round() as u32,
                    start: Duration::from_millis(start_ms),
                    stop: stop_ms.map(Duration::from_millis),
                    seed: world.world.seed,
                });
            }
            Plant::LinkCapacity { a, b, steps } => {
                let node = Node::Switch(SwitchId::new(a));
                let link = world
                    .port_toward(a, b)
                    .and_then(|port| sim.network.link_at(node, PortId::new(port)))
                    .ok_or_else(|| WorldError::Invalid(format!("plant {}: the link {a}-{b} was not built", i + 1)))?;
                for s in steps {
                    sim.queue.schedule(Duration::from_millis(s[0]), EventKind::PlantCapacity { link, bps: s[1] * 1_000_000 });
                }
            }
        }
    }
    Ok(())
}

/// A planted source's next send. It carries its own state, so the
/// simulator keeps none.
#[derive(Debug, Clone)]
pub struct Tick {
    app: AppId,
    /// The sender's network address, and the hosts it sends from in turn.
    src: u32,
    hosts: Vec<u32>,
    proto: u8,
    /// The receiver's network address, its first host, and how many hosts
    /// its range has room for: a scan walks on from the first and wraps.
    dest: (u32, u32, u32),
    interval: Duration,
    size_bytes: u64,
    stop: Option<SimTime>,
    flow: FlowId,
    sent: u64,
    /// How many to send in all, if not open-ended.
    limit: Option<u64>,
    /// Destination addresses from `dest` on, each used `each` times in
    /// a row before the next; 1 and 1 for a stream to one address.
    addresses: u32,
    each: u64,
}

/// An app's range as a `Tick` destination.
fn addresses_of(app: &crate::app::App) -> (u32, u32, u32) {
    let room = (1u64 << (32 - app.prefix_len.min(32))).saturating_sub(2).min(u32::MAX as u64) as u32;
    (app.base(), app.hosts[0], room.max(1))
}

impl Simulator {
    pub(super) fn plant_tick(&mut self, mut tick: Tick) {
        if tick.stop.is_some_and(|s| self.now >= s) || tick.limit.is_some_and(|n| tick.sent >= n) {
            return;
        }
        let id = PLANT_BIT | (tick.flow.raw() & 0xff) << 40 | tick.sent;
        let mut p = Packet::new(PacketId::new(id), self.now, tick.size_bytes);
        p.app_id = tick.app;
        p.flow_id = tick.flow;
        p.ip_src = IpAddr(tick.src | tick.hosts[tick.sent as usize % tick.hosts.len()]);
        p.ip_proto = tick.proto;
        let (base, first, room) = tick.dest;
        p.ip_dst = IpAddr(base | ((first - 1 + (tick.sent / tick.each) as u32 % tick.addresses) % room + 1));
        tick.sent += 1;
        let app = tick.app;
        let next = self.now + tick.interval;
        self.queue.schedule(next, EventKind::PlantTick { tick });
        self.send_from_app(app, p);
    }
}
