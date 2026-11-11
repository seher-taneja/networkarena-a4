//! World files: a network as data, not code.
//!
//! A *world* is one TOML file holding everything needed to instantiate a
//! run: the topology, where customer apps sit and what prefixes they own,
//! the workload, and the run parameters. Everything downstream reads this
//! format — the world generator writes it, the simulator builds from it,
//! and the scorer reads it back to know what "correct" meant.
//!
//! The format is meant to grow. A2 adds workload variants and per-link
//! capacity, A3 adds telemetry, A4 adds AS membership and policy. Fields
//! are optional with defaults wherever possible so old worlds keep
//! parsing.
//!
//! Design decisions, fixed:
//! - **Explicit IDs.** Switches and apps carry the integer that appears in
//!   report cards, log excerpts, and quiz exhibits. Deleting a switch from
//!   a world never renumbers the others.
//! - **IPs belong to apps.** Switches have IDs and ports, no addresses.
//! - **Hierarchical prefixes.** Apps take sub-prefixes inside a per-AS
//!   block, so route aggregation is possible later.
//! - **Failures live elsewhere.** One world can host many failure
//!   schedules.

use crate::flow::FlowEngine;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::app::{App, TrafficPattern};
use crate::link::LinkConfig;
use crate::network::Node;
use crate::packet::IpAddr;
use crate::sim::Simulator;
use crate::types::{AppId, LinkId, PortId, SwitchId};

/// Port number apps attach on. Kept high and out of the way of the
/// inter-switch ports, which are numbered from 0.
pub const APP_PORT: u16 = 100;

// ---------------------------------------------------------------------------
// The format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct World {
    pub world: WorldMeta,
    #[serde(default)]
    pub params: Params,
    #[serde(rename = "switch", default)]
    pub switches: Vec<SwitchSpec>,
    #[serde(rename = "link", default)]
    pub links: Vec<LinkSpec>,
    #[serde(rename = "app", default)]
    pub apps: Vec<AppSpec>,
    pub workload: Workload,
    /// The A2 grading floors. Absent means the A1 criteria apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floors: Option<Floors>,
    /// The A3 observation layer: what a switch can tell its controller
    /// and what a controller may send. Absent means neither is limited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe: Option<Observe>,
    /// An A3 run where the harness forwards and shapes the queues, and the
    /// program only observes. See `crate::harness`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessSpec>,
    /// What the run is made to do, row by row; read by the full build
    /// only, and empty in every world a student is given.
    #[serde(rename = "plant", default, skip_serializing_if = "Vec::is_empty")]
    pub plants: Vec<toml::Table>,
    /// Which eggs the run is meant to have, row by row; read by the full
    /// build only, and empty in every world a student is given.
    #[serde(rename = "egg", default, skip_serializing_if = "Vec::is_empty")]
    pub eggs: Vec<toml::Table>,
    /// An A4 world: its ASes, agreements and traffic. See `crate::a4`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a4: Option<crate::a4::A4Spec>,
}

/// The `[harness]` section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// How often a keepalive leaves every switch-to-switch port.
    #[serde(default = "default_keepalive_ms")]
    pub keepalive_ms: u64,
    /// The team's log holds at most this many bytes. See `crate::team_log`.
    #[serde(default = "default_log_cap_bytes")]
    pub log_cap_bytes: u64,
    /// Routes that differ from the shortest path, or that name a backup.
    #[serde(rename = "route", default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<HarnessRoute>,
    #[serde(rename = "queue", default, skip_serializing_if = "Vec::is_empty")]
    pub queues: Vec<HarnessQueue>,
    #[serde(rename = "keepalive_gap", default, skip_serializing_if = "Vec::is_empty")]
    pub keepalive_gaps: Vec<KeepaliveGap>,
    /// Reports ride behind customers: every switch port has a second,
    /// lower-priority queue for them, this many packets deep. It never
    /// delays or drops a customer packet.
    #[serde(default = "default_report_queue_packets")]
    pub report_queue_packets: u32,
    /// A report larger than this is refused where it is made, so a
    /// customer packet waits at most this long behind one. Absent means
    /// the world's packet size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_max_bytes: Option<u64>,
}

fn default_report_queue_packets() -> u32 {
    4
}

fn default_keepalive_ms() -> u64 {
    100
}
fn default_log_cap_bytes() -> u64 {
    4096
}
/// At `switch`, packets for `prefix` leave toward the neighbour `via`, or
/// toward `backup` while that link is down; with `split`, every other
/// packet leaves toward that neighbour instead. Every other route is the
/// shortest path (lowest neighbour id on a tie), with a backup that is the
/// shortest path around the down link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessRoute {
    pub switch: u32,
    pub prefix: String,
    pub via: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<u32>,
}

/// The output queue at `switch` toward `toward` holds `packets` packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessQueue {
    pub switch: u32,
    pub toward: u32,
    pub packets: u32,
}

/// No keepalives leave `switch` toward `toward` in `[start_ms, end_ms)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepaliveGap {
    pub switch: u32,
    pub toward: u32,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// The `[observe]` section. Every switch gets the same budgets; see
/// `crate::observe` for how they are enforced. Turning the section on also
/// turns off the in-band trace, clears custom words and labels on packets
/// that cross a switch-to-switch link, hands each timer a copy of the
/// program's counters, and leaves every customer's rate ask out of the
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observe {
    /// Punts and samples delivered to a controller per second.
    pub punt_events_per_s: u32,
    /// Events that may wait for delivery.
    pub punt_backlog: u32,
    /// Bytes per second a controller may inject, sustained.
    pub export_bytes_per_s: u64,
    /// Bytes a controller may inject at once after a quiet spell.
    pub export_burst_bytes: u64,
}

impl Observe {
    pub fn limits(&self) -> switch_program_types::ObserveLimitsW {
        switch_program_types::ObserveLimitsW {
            punt_events_per_s: self.punt_events_per_s,
            punt_backlog: self.punt_backlog,
            export_bytes_per_s: self.export_bytes_per_s,
            export_burst_bytes: self.export_burst_bytes,
        }
    }
}

/// The three floors of the A2 handout, with the numbers a world publishes
/// for them. Every value is one of the handout's bracketed constants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Floors {
    /// The collapse note: when first-time data across a bottleneck falls
    /// under this percentage of its capacity in an overloaded window, the
    /// card says so. Measured, never graded; the fairness floor is what
    /// grades the harm.
    #[serde(default = "default_goodput_pct")]
    pub goodput_pct: f64,
    /// [U]: in every window the network delivers at least this percentage
    /// of what the max-min fair allocation would deliver.
    #[serde(default = "default_utilization_pct")]
    pub utilization_pct: f64,
    /// [X]: every customer gets at least this percentage of its max-min
    /// fair share, in every window.
    #[serde(default = "default_share_pct")]
    pub share_pct: f64,
    /// [W]: the window the floors are checked over, in milliseconds.
    #[serde(default = "default_window_ms")]
    pub window_ms: u64,
    /// The fairness check skips windows that begin within this long of a
    /// burst starting: steady state is graded, not the moment of impact.
    #[serde(default = "default_settling_ms")]
    pub settling_ms: u64,
    /// The links the collapse floor watches, as `[a, b]` switch pairs.
    /// Each direction is judged on its own.
    #[serde(default)]
    pub bottlenecks: Vec<[u32; 2]>,
    /// How the fairness floor computes a customer's share. Absent: over
    /// the path its packets took, so only the queues along that path are
    /// on trial (Part 1). Present: over every route from its switch to
    /// its peer's no longer than the shortest plus this many hops, so a
    /// program that leaves a detour empty is judged against the detour
    /// (Part 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour_hops: Option<u32>,
}

// The calibrated defaults: see scripts/calibrate-a2.sh. Set so the A2
// reference clears every floor with margin on the calibration set and the
// A1 reference fails at least one floor on every world in it.
fn default_goodput_pct() -> f64 {
    50.0
}
fn default_utilization_pct() -> f64 {
    55.0
}
fn default_share_pct() -> f64 {
    40.0
}
fn default_window_ms() -> u64 {
    1_000
}
fn default_settling_ms() -> u64 {
    // Two windows: one for an AIMD customer to recover from the moment a
    // burst hits a busy link, one for a program to move customers.
    2_000
}

impl Default for Floors {
    fn default() -> Self {
        Self {
            goodput_pct: default_goodput_pct(),
            utilization_pct: default_utilization_pct(),
            share_pct: default_share_pct(),
            window_ms: default_window_ms(),
            settling_ms: default_settling_ms(),
            bottlenecks: Vec::new(),
            detour_hops: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldMeta {
    pub name: String,
    /// Seed the generator used. Published for practice worlds, withheld
    /// for grading worlds.
    #[serde(default)]
    pub seed: u64,
    /// Format version. Bump only on a breaking change.
    #[serde(default = "one")]
    pub version: u32,
    /// Topology family this world came from, e.g. `ring_chords`. Empty for
    /// hand-written worlds.
    #[serde(default)]
    pub family: String,
    /// Longest shortest-path in hops. Convergence time scales with this,
    /// so the scorer uses it when it sets the warmup window.
    #[serde(default)]
    pub diameter: u32,
    /// Version of the generator that wrote this file. Bumped whenever the
    /// generator's output changes for a fixed seed.
    #[serde(default)]
    pub generator: u32,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    /// Capacity of every link, unless a link overrides it.
    #[serde(default = "default_capacity")]
    pub link_capacity_mbps: u64,
    #[serde(default = "default_latency")]
    pub link_latency_us: u64,
    #[serde(default = "default_queue")]
    pub queue_capacity_bytes: u64,
    /// Grace period before scoring starts. Packets sent during warmup do
    /// not count for or against delivery.
    #[serde(default = "default_warmup")]
    pub warmup_ms: u64,
    /// Total simulated run length, warmup included.
    #[serde(default = "default_duration")]
    pub duration_ms: u64,
    /// Fraction of scored packets that must arrive, as a percentage. The
    /// world owns this because it is a property of the world: a run with
    /// failures loses packets that were already on the cable when it died,
    /// and no program can prevent that.
    #[serde(default = "default_delivery_floor")]
    pub delivery_floor_pct: f64,
    /// Shared buffer per switch, in packets of `packet_size_bytes`. This
    /// is the handout's [B]. Absent means the pool does not bind and only
    /// `queue_capacity_bytes` limits each port (A1 behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_budget_packets: Option<u64>,
    /// What one "packet" means when programs size queues and the buffer
    /// is set in packets. Absent means the workload's data packet size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_size_bytes: Option<u64>,
    /// The handout's [Δ]: how long a controller action (route install,
    /// queue config, declaration) takes to reach the data plane, as the
    /// config pipe's latency. Absent means the switch default (10 µs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_delay_us: Option<u64>,
    /// A rate-matching customer measures its delivered rate over at least
    /// this many of its own packets (see `FlowEngine::min_window_packets`).
    /// Absent: no minimum, as in A2, where no link fails and no customer is
    /// ever pushed down to the floor this lifts it from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_match_window_packets: Option<u64>,
    /// A rate-matching customer keeps its rate through a window with no
    /// acks (see `FlowEngine::holds_through_outage`). Absent: false, as in
    /// A2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_match_holds_through_outage: Option<bool>,
}

fn default_capacity() -> u64 {
    1_000
}
fn default_latency() -> u64 {
    100
}
fn default_queue() -> u64 {
    1 << 16
}
fn default_warmup() -> u64 {
    crate::score::DEFAULT_WARMUP_MS
}
fn default_delivery_floor() -> f64 {
    100.0 * crate::score::DEFAULT_DELIVERY_FLOOR
}
fn default_duration() -> u64 {
    10_000
}

impl Default for Params {
    fn default() -> Self {
        Self {
            link_capacity_mbps: default_capacity(),
            link_latency_us: default_latency(),
            queue_capacity_bytes: default_queue(),
            warmup_ms: default_warmup(),
            duration_ms: default_duration(),
            delivery_floor_pct: default_delivery_floor(),
            buffer_budget_packets: None,
            packet_size_bytes: None,
            control_delay_us: None,
            rate_match_window_packets: None,
            rate_match_holds_through_outage: None,
        }
    }
}

impl Params {
    pub fn link_config(&self) -> LinkConfig {
        LinkConfig {
            latency: Duration::from_micros(self.link_latency_us),
            bandwidth_bps: self.link_capacity_mbps * 1_000_000,
            queue_capacity_bytes: self.queue_capacity_bytes,
        }
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.duration_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchSpec {
    pub id: u32,
    /// Which AS owns this switch. Single-AS in A1–A3; A4 uses it.
    #[serde(default)]
    pub as_id: u32,
    /// Per-switch override of `params.queue_capacity_bytes` (each port's
    /// queue, and so the switch's pool). A4 only: a bought buffer upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_capacity_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSpec {
    pub a: u32,
    pub b: u32,
    /// Per-link capacity override, in Mbps. A2 uses this to create
    /// bottlenecks; A1 leaves it unset.
    #[serde(default)]
    pub capacity_mbps: Option<u64>,
    /// Per-link latency override, in microseconds. A4 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Hosts {
    Count(u32),
    Numbers(Vec<u32>),
}

impl Hosts {
    /// The host numbers, `.1` upward for a count.
    pub fn numbers(&self) -> Vec<u32> {
        match self {
            Hosts::Count(n) => (1..=(*n).max(1)).collect(),
            Hosts::Numbers(v) => v.clone(),
        }
    }
}

impl AppSpec {
    /// This app's host numbers: `[1]` unless `hosts` says otherwise.
    pub fn host_numbers(&self) -> Vec<u32> {
        self.hosts.as_ref().map_or_else(|| vec![1], Hosts::numbers)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpec {
    pub id: u32,
    /// Switch this app hangs off.
    pub switch: u32,
    /// The prefix this app owns, in `a.b.c.d/len` form. The app's own
    /// address is the first host in it.
    pub prefix: String,

    // ---- A2 customer rows; ignored under `all_pairs_cbr` ----
    /// Which kind of customer this is. Absent means a pure receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<Preset>,
    /// How it reacts to the network. Absent means it does not (open loop
    /// at `rate_mbps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law: Option<LawKind>,
    /// Offered rate. Required for every preset but `steam`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_mbps: Option<f64>,
    /// `amazon` only: burst length, gap and first-burst offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub off_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ms: Option<u64>,
    /// The app this one sends to. Required for every preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<u32>,
    /// Law knobs. Defaults: initial = `rate_mbps` (or the link rate for
    /// `steam`), increment = a tenth of that, epoch 100 ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_initial_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_increment_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_epoch_ms: Option<u64>,
    /// Size of this customer's data packets. Absent means the workload's
    /// `size_bytes`. Never larger than the world's packet unit, which is
    /// what buffers and queue caps count in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Who this customer is ("Netflix"), written into the run's log. A
    /// truth run's world names its customers; no program is ever told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Send every data packet twice: the same `seq`, a new id.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub echo: bool,
    /// The hosts of this range: a count (`.1` upward) or their numbers
    /// (`[17, 140, 203]`). A sender sends from them in turn; a receiver
    /// is each of them to its senders. One host, `.1`, if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Hosts>,
    /// `"tcp"` or `"udp"`, in place of the preset's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<Proto>,
    /// Starting TTL: packet i starts at `(i mod ttl_ladder) + 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ladder: Option<u8>,
    /// Every packet starts at this TTL (64 if absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_start: Option<u8>,
    /// A sender sends nothing from this time on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_ms: Option<u64>,
    /// A `web` customer's server: it answers every TCP data packet it
    /// receives with a data packet of this many bytes to the request's
    /// source, from the host the request was addressed to. Replies carry
    /// no `seq`, so they are never acked or retransmitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_bytes: Option<u64>,
    /// The reply leaves this long after the request arrived (0 if absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_delay_ms: Option<u64>,
    /// No replies from this time on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_stop_ms: Option<u64>,
    /// No replies for `reply_pause_for_ms` from `reply_pause_at_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_pause_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_pause_for_ms: Option<u64>,
    /// This share (0 to 100) of the requests to this server go to its
    /// host 1; the rest round-robin over its other hosts. Absent means
    /// every host takes its turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_host_pct: Option<u8>,
}

/// A customer's transport. Only TCP is acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn number(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
        }
    }
}

impl AppSpec {
    /// A plain app row: no preset, so under `mixed` it only receives.
    pub fn new(id: u32, switch: u32, prefix: String) -> Self {
        Self {
            id,
            switch,
            prefix,
            preset: None,
            law: None,
            rate_mbps: None,
            on_ms: None,
            off_ms: None,
            start_ms: None,
            peer: None,
            law_initial_mbps: None,
            law_increment_mbps: None,
            law_epoch_ms: None,
            echo: false,
            hosts: None,
            proto: None,
            ttl_ladder: None,
            ttl_start: None,
            size_bytes: None,
            name: None,
            stop_ms: None,
            reply_bytes: None,
            reply_delay_ms: None,
            reply_stop_ms: None,
            reply_pause_at_ms: None,
            reply_pause_for_ms: None,
            hot_host_pct: None,
        }
    }
}

/// The five customers of the A2 handout. Each is a demand shape; the law
/// is chosen separately so any customer can run either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// Steady video: constant rate.
    Netflix,
    /// Shopping bursts: on/off at `rate_mbps`.
    Amazon,
    /// A download: as fast as the law allows.
    Steam,
    /// Tiny, sparse, latency-critical: constant rate, small.
    JaneStreet,
    /// A game: constant rate, small, and a peer that talks back.
    Fortnite,
    /// A monitor's ping: a few small packets a second, and a peer that
    /// answers in kind. Used by the eggs that need a light sender of their
    /// own on a quiet link.
    Ping,
    /// Browsing: a constant rate of small requests, and a peer that
    /// answers each with `reply_bytes` (the server).
    Web,
}

impl Preset {
    /// What the customer runs over: the acknowledged ones are TCP.
    pub fn proto(self) -> Proto {
        match self {
            Preset::Netflix | Preset::Amazon | Preset::Steam | Preset::Web => Proto::Tcp,
            Preset::JaneStreet | Preset::Fortnite | Preset::Ping => Proto::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LawKind {
    Aimd,
    RateMatch,
}

/// What traffic runs. A1 needs only the all-pairs shorthand; A2 lets
/// every `[[app]]` row say what it does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Workload {
    /// Every app sends to every other app, round-robin, at a constant
    /// rate. One line instead of N*(N-1) flow entries.
    AllPairsCbr {
        interval_ms: u64,
        #[serde(default = "default_size")]
        size_bytes: u64,
    },
    /// Each app is a closed-loop customer described by its own row:
    /// `preset`, `law`, `rate_mbps`, `peer` and the on/off fields. Apps
    /// without a preset only receive. Every data packet is `size_bytes`
    /// unless its row gives its own.
    Mixed {
        #[serde(default = "default_size")]
        size_bytes: u64,
    },
    /// An A4 world: every app sends what the `[a4]` section's flow rows
    /// say, open loop.
    A4 {
        #[serde(default = "default_size")]
        size_bytes: u64,
    },
}

impl Workload {
    /// The data packet size every app in this world uses.
    pub fn packet_size_bytes(&self) -> u64 {
        match *self {
            Workload::AllPairsCbr { size_bytes, .. } | Workload::Mixed { size_bytes } | Workload::A4 { size_bytes } => size_bytes,
        }
    }
}

fn default_size() -> u64 {
    100
}

// ---------------------------------------------------------------------------
// Parsed prefixes
// ---------------------------------------------------------------------------

/// Hop counts to `dst` over `adj`, without the link `skip` if given.
fn hops_to(adj: &BTreeMap<u32, Vec<u32>>, dst: u32, skip: Option<(u32, u32)>) -> BTreeMap<u32, u32> {
    let cut = |a: u32, b: u32| skip.is_some_and(|(x, y)| (x, y) == (a, b) || (y, x) == (a, b));
    let mut dist = BTreeMap::from([(dst, 0u32)]);
    let mut frontier = std::collections::VecDeque::from([dst]);
    while let Some(u) = frontier.pop_front() {
        let d = dist[&u];
        for &v in adj.get(&u).map(Vec::as_slice).unwrap_or(&[]) {
            if !cut(u, v) && !dist.contains_key(&v) {
                dist.insert(v, d + 1);
                frontier.push_back(v);
            }
        }
    }
    dist
}

/// The neighbour of `s` one hop closer by `dist`, lowest id first, never
/// across the link to `skip`.
fn next_hop(adj: &BTreeMap<u32, Vec<u32>>, dist: &BTreeMap<u32, u32>, s: u32, skip: Option<u32>) -> Option<u32> {
    let d = *dist.get(&s)?;
    adj.get(&s)?
        .iter()
        .copied()
        .find(|n| Some(*n) != skip && dist.get(n).is_some_and(|dn| dn + 1 == d))
}

/// `addr` with everything past the first `len` bits cleared.
pub fn mask(addr: u32, len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        addr & (u32::MAX << (32 - len.min(32)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: u32,
    pub len: u8,
}

impl Prefix {
    pub fn parse(s: &str) -> Result<Self, WorldError> {
        let (addr_s, len_s) = s
            .split_once('/')
            .ok_or_else(|| WorldError::Prefix(format!("`{s}` has no /len")))?;
        let octets: Vec<&str> = addr_s.split('.').collect();
        if octets.len() != 4 {
            return Err(WorldError::Prefix(format!("`{s}` is not dotted quad")));
        }
        let mut addr: u32 = 0;
        for o in octets {
            let v: u8 = o
                .parse()
                .map_err(|_| WorldError::Prefix(format!("`{s}` has a bad octet")))?;
            addr = (addr << 8) | v as u32;
        }
        let len: u8 = len_s
            .parse()
            .map_err(|_| WorldError::Prefix(format!("`{s}` has a bad prefix length")))?;
        if len > 32 {
            return Err(WorldError::Prefix(format!("`{s}` length exceeds 32")));
        }
        Ok(Self { addr, len })
    }

    fn mask(&self) -> u32 {
        if self.len == 0 {
            0
        } else {
            u32::MAX << (32 - self.len)
        }
    }

    /// First usable host address in the prefix — what the app answers to.
    pub fn first_host(&self) -> u32 {
        self.host(1)
    }

    /// Host `n` of the prefix; a /32 is its one host.
    pub fn host(&self, n: u32) -> u32 {
        if self.len >= 32 {
            return self.addr;
        }
        (self.addr & self.mask()) | n
    }

    /// How many hosts the prefix has room for (`.1` to `.254` in a /24,
    /// one in a /32).
    pub fn room(&self) -> u32 {
        if self.len >= 32 {
            return 1;
        }
        (1u64 << (32 - self.len)).saturating_sub(2).min(u32::MAX as u64) as u32
    }

    pub fn overlaps(&self, other: &Prefix) -> bool {
        let shorter = self.len.min(other.len);
        let m = if shorter == 0 {
            0
        } else {
            u32::MAX << (32 - shorter)
        };
        (self.addr & m) == (other.addr & m)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}/{}",
            (self.addr >> 24) & 0xff,
            (self.addr >> 16) & 0xff,
            (self.addr >> 8) & 0xff,
            self.addr & 0xff,
            self.len
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum WorldError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Prefix(String),
    Invalid(String),
}

impl fmt::Display for WorldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorldError::Io(e) => write!(f, "reading world file: {e}"),
            WorldError::Parse(e) => write!(f, "parsing world file: {e}"),
            WorldError::Prefix(m) => write!(f, "bad prefix: {m}"),
            WorldError::Invalid(m) => write!(f, "invalid world: {m}"),
        }
    }
}

impl std::error::Error for WorldError {}

impl From<std::io::Error> for WorldError {
    fn from(e: std::io::Error) -> Self {
        WorldError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Load, validate, build
// ---------------------------------------------------------------------------

/// What `build` handed to the simulator, so callers can drive failures and
/// score the run without re-deriving anything.
#[derive(Debug, Clone, Default)]
pub struct WorldHandles {
    /// Link id for each `(a, b)` switch pair, in the order the world
    /// declared them. Both orderings are inserted.
    pub links: BTreeMap<(u32, u32), LinkId>,
    /// Every inter-switch link, in declaration order — the failure
    /// schedule indexes into this.
    pub link_order: Vec<LinkId>,
    /// The prefix each app owns.
    pub app_prefixes: BTreeMap<u32, Prefix>,
    /// Which switch each app hangs off.
    pub app_switch: BTreeMap<u32, u32>,
    /// Every AS in the world, in ascending order. A1–A3 have exactly one.
    pub as_ids: Vec<u32>,
}

impl World {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WorldError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_str(&text)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Self, WorldError> {
        let world: World = toml::from_str(text).map_err(WorldError::Parse)?;
        world.validate()?;
        Ok(world)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("world serializes")
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), WorldError> {
        std::fs::write(path, self.to_toml())?;
        Ok(())
    }

    /// Every check that must hold before a world is worth running. The
    /// generator relies on these too — it produces worlds and validates
    /// them rather than trusting itself.
    pub fn validate(&self) -> Result<(), WorldError> {
        let bad = |m: String| Err(WorldError::Invalid(m));

        if self.switches.is_empty() {
            return bad("no switches".into());
        }

        // Unique switch ids.
        let mut seen = BTreeSet::new();
        for s in &self.switches {
            if !seen.insert(s.id) {
                return bad(format!("switch {} declared twice", s.id));
            }
        }

        // Links refer to declared switches, no self-loops, no duplicates.
        let mut edges = BTreeSet::new();
        for l in &self.links {
            if !seen.contains(&l.a) || !seen.contains(&l.b) {
                return bad(format!("link {}-{} names an unknown switch", l.a, l.b));
            }
            if l.a == l.b {
                return bad(format!("switch {} has a link to itself", l.a));
            }
            let key = (l.a.min(l.b), l.a.max(l.b));
            if !edges.insert(key) {
                return bad(format!("link {}-{} declared twice", l.a, l.b));
            }
        }

        // Connected. A partitioned world is unscoreable: the handout
        // promises the network always stays connected.
        if !self.is_connected() {
            return bad("topology is not connected".into());
        }

        // Apps: unique ids, known switches, one app per switch (the app
        // port is fixed, so a second app would silently replace the
        // first), parseable and disjoint prefixes.
        let mut app_ids = BTreeSet::new();
        let mut app_switches = BTreeSet::new();
        let mut prefixes: Vec<(u32, Prefix)> = Vec::new();
        for a in &self.apps {
            if !app_ids.insert(a.id) {
                return bad(format!("app {} declared twice", a.id));
            }
            if !seen.contains(&a.switch) {
                return bad(format!("app {} sits on unknown switch {}", a.id, a.switch));
            }
            // Where the harness forwards, a switch may hold several apps,
            // on ports APP_PORT, APP_PORT + 1, ... in the order listed.
            if !app_switches.insert(a.switch) && self.harness.is_none() && self.a4.is_none() {
                return bad(format!(
                    "switch {} has two apps; every switch has one app port",
                    a.switch
                ));
            }
            let p = Prefix::parse(&a.prefix)?;
            let hosts = a.host_numbers();
            let distinct: BTreeSet<u32> = hosts.iter().copied().collect();
            if hosts.is_empty() || distinct.len() != hosts.len() || hosts.iter().any(|h| *h < 1 || *h > p.room()) {
                return bad(format!("app {}: hosts must be distinct numbers from 1 to {}", a.id, p.room()));
            }
            // Where the harness forwards, a host row may sit inside a
            // customer's range (a /32 of its /24 with its own behaviour):
            // the longest prefix routes to it. Two equal prefixes never.
            for (other_id, other) in &prefixes {
                if p.overlaps(other) && !(self.harness.is_some() && p.len != other.len) {
                    return bad(format!(
                        "app {} prefix {} overlaps app {} prefix {}",
                        a.id, p, other_id, other
                    ));
                }
            }
            prefixes.push((a.id, p));
        }
        if self.apps.len() < 2 {
            return bad("a world needs at least two apps".into());
        }

        if let Some(o) = &self.observe {
            if o.punt_events_per_s == 0 || o.punt_backlog == 0 {
                return bad("[observe] needs punt_events_per_s and punt_backlog above 0".into());
            }
            if o.export_bytes_per_s == 0 || o.export_burst_bytes == 0 {
                return bad("[observe] needs export_bytes_per_s and export_burst_bytes above 0".into());
            }
        }

        if let Some(h) = &self.harness {
            self.validate_harness(h)?;
        }
        crate::sim::plant::validate(self)?;

        // Customer rows: a preset needs a peer that exists and is not
        // itself, a rate unless it is a download, and burst timing if it
        // is a shopper.
        if let Workload::Mixed { .. } = self.workload {
            let mut senders = 0;
            for a in &self.apps {
                let Some(preset) = a.preset else { continue };
                senders += 1;
                match a.peer {
                    None => return bad(format!("app {} has a preset but no peer", a.id)),
                    Some(p) if p == a.id => return bad(format!("app {} peers with itself", a.id)),
                    Some(p) if !app_ids.contains(&p) => {
                        return bad(format!("app {} peers with unknown app {p}", a.id))
                    }
                    _ => {}
                }
                if preset != Preset::Steam && !a.rate_mbps.is_some_and(|r| r > 0.0) {
                    return bad(format!("app {} ({preset:?}) needs rate_mbps > 0", a.id));
                }
                if preset == Preset::Amazon && (a.on_ms.unwrap_or(0) == 0 || a.off_ms.is_none()) {
                    return bad(format!("app {} (Amazon) needs on_ms > 0 and off_ms", a.id));
                }
                if let Some(s) = a.size_bytes {
                    let unit = self.params.packet_size_bytes.unwrap_or_else(|| self.workload.packet_size_bytes());
                    if s == 0 || s > unit {
                        return bad(format!(
                            "app {} size_bytes {s} must be between 1 and the world's packet size {unit}",
                            a.id
                        ));
                    }
                }
            }
            if senders == 0 {
                return bad("a mixed workload needs at least one app with a preset".into());
            }
            // Server rows: the reply and hot-host knobs belong to a web
            // customer's peer and nowhere else.
            let web_peers: BTreeSet<u32> = self
                .apps
                .iter()
                .filter(|a| a.preset == Some(Preset::Web))
                .filter_map(|a| a.peer)
                .collect();
            for a in &self.apps {
                let serves = a.reply_bytes.is_some()
                    || a.reply_delay_ms.is_some()
                    || a.reply_stop_ms.is_some()
                    || a.reply_pause_at_ms.is_some()
                    || a.reply_pause_for_ms.is_some()
                    || a.hot_host_pct.is_some();
                if serves && !web_peers.contains(&a.id) {
                    return bad(format!(
                        "app {}: reply_* and hot_host_pct belong on the peer of a web customer",
                        a.id
                    ));
                }
                if a.hot_host_pct.is_some_and(|p| p > 100) {
                    return bad(format!("app {}: hot_host_pct must be 0 to 100", a.id));
                }
                if a.reply_pause_at_ms.is_some() != a.reply_pause_for_ms.is_some() {
                    return bad(format!("app {}: reply_pause_at_ms and reply_pause_for_ms go together", a.id));
                }
                if let Some(b) = a.reply_bytes {
                    let unit = self.params.packet_size_bytes.unwrap_or_else(|| self.workload.packet_size_bytes());
                    if b == 0 || b > unit {
                        return bad(format!(
                            "app {} reply_bytes {b} must be between 1 and the world's packet size {unit}",
                            a.id
                        ));
                    }
                }
            }
        }

        if let Some(f) = &self.floors {
            for [a, b] in &f.bottlenecks {
                let key = (a.min(b), a.max(b));
                if !edges.contains(&(*key.0, *key.1)) {
                    return bad(format!("bottleneck {a}-{b} is not a declared link"));
                }
            }
            if f.window_ms == 0 {
                return bad("floors.window_ms must be positive".into());
            }
            if self.params.warmup_ms + f.window_ms > self.params.duration_ms {
                return bad("the run is too short for one grading window after warmup".into());
            }
        }

        if self.params.warmup_ms >= self.params.duration_ms {
            return bad("warmup is not shorter than the run".into());
        }

        Ok(())
    }

    /// Breadth-first reachability over the declared links.
    pub fn is_connected(&self) -> bool {
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for s in &self.switches {
            adj.entry(s.id).or_default();
        }
        for l in &self.links {
            adj.entry(l.a).or_default().push(l.b);
            adj.entry(l.b).or_default().push(l.a);
        }
        let start = match self.switches.first() {
            Some(s) => s.id,
            None => return false,
        };
        let mut seen = BTreeSet::new();
        let mut q = VecDeque::new();
        seen.insert(start);
        q.push_back(start);
        while let Some(n) = q.pop_front() {
            for &m in adj.get(&n).map(|v| v.as_slice()).unwrap_or(&[]) {
                if seen.insert(m) {
                    q.push_back(m);
                }
            }
        }
        seen.len() == self.switches.len()
    }

    /// Would the topology stay connected with these edges removed?
    /// The failure-schedule generator asks this before committing a cut.
    pub fn connected_without(&self, down: &BTreeSet<(u32, u32)>) -> bool {
        let norm = |a: u32, b: u32| (a.min(b), a.max(b));
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for s in &self.switches {
            adj.entry(s.id).or_default();
        }
        for l in &self.links {
            if down.contains(&norm(l.a, l.b)) {
                continue;
            }
            adj.entry(l.a).or_default().push(l.b);
            adj.entry(l.b).or_default().push(l.a);
        }
        let start = match self.switches.first() {
            Some(s) => s.id,
            None => return false,
        };
        let mut seen = BTreeSet::new();
        let mut q = VecDeque::new();
        seen.insert(start);
        q.push_back(start);
        while let Some(n) = q.pop_front() {
            for &m in adj.get(&n).map(|v| v.as_slice()).unwrap_or(&[]) {
                if seen.insert(m) {
                    q.push_back(m);
                }
            }
        }
        seen.len() == self.switches.len()
    }

    /// Every bridge (cut edge) in the topology, as normalised `(lo, hi)`
    /// pairs. A bridge is an edge whose removal partitions the network.
    ///
    /// This is the check that matters for Part 2: the handout promises the
    /// network stays connected while links die, so a world with a bridge is
    /// a world where the promise can be broken by a single failure.
    pub fn bridges(&self) -> Vec<(u32, u32)> {
        let ids: Vec<u32> = self.switches.iter().map(|s| s.id).collect();
        let index: BTreeMap<u32, usize> = ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        let n = ids.len();

        // adjacency as (neighbour index, edge index)
        let mut adj: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
        for (e, l) in self.links.iter().enumerate() {
            let (a, b) = match (index.get(&l.a), index.get(&l.b)) {
                (Some(a), Some(b)) => (*a, *b),
                _ => continue,
            };
            adj[a].push((b, e));
            adj[b].push((a, e));
        }

        let mut disc = vec![usize::MAX; n];
        let mut low = vec![usize::MAX; n];
        let mut timer = 0usize;
        let mut found: Vec<usize> = Vec::new();

        fn dfs(
            u: usize,
            parent_edge: usize,
            adj: &[Vec<(usize, usize)>],
            disc: &mut [usize],
            low: &mut [usize],
            timer: &mut usize,
            found: &mut Vec<usize>,
        ) {
            disc[u] = *timer;
            low[u] = *timer;
            *timer += 1;
            for &(v, e) in &adj[u] {
                if e == parent_edge {
                    continue;
                }
                if disc[v] == usize::MAX {
                    dfs(v, e, adj, disc, low, timer, found);
                    low[u] = low[u].min(low[v]);
                    if low[v] > disc[u] {
                        found.push(e);
                    }
                } else {
                    low[u] = low[u].min(disc[v]);
                }
            }
        }

        for s in 0..n {
            if disc[s] == usize::MAX {
                dfs(s, usize::MAX, &adj, &mut disc, &mut low, &mut timer, &mut found);
            }
        }

        found.sort_unstable();
        found
            .into_iter()
            .map(|e| {
                let l = &self.links[e];
                (l.a.min(l.b), l.a.max(l.b))
            })
            .collect()
    }

    /// True when the topology survives any single link failure. Connected
    /// is not enough — a tree is connected and every one of its edges is a
    /// bridge.
    pub fn is_two_edge_connected(&self) -> bool {
        self.is_connected() && self.bridges().is_empty()
    }

    /// Longest shortest-path between any two switches, in hops.
    pub fn diameter(&self) -> u32 {
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for s in &self.switches {
            adj.entry(s.id).or_default();
        }
        for l in &self.links {
            adj.entry(l.a).or_default().push(l.b);
            adj.entry(l.b).or_default().push(l.a);
        }
        let mut best = 0u32;
        for s in &self.switches {
            let mut dist: BTreeMap<u32, u32> = BTreeMap::new();
            dist.insert(s.id, 0);
            let mut q = VecDeque::new();
            q.push_back(s.id);
            while let Some(n) = q.pop_front() {
                let d = dist[&n];
                for &m in adj.get(&n).map(|v| v.as_slice()).unwrap_or(&[]) {
                    if !dist.contains_key(&m) {
                        dist.insert(m, d + 1);
                        best = best.max(d + 1);
                        q.push_back(m);
                    }
                }
            }
        }
        best
    }

    /// Instantiate the world into a fresh simulator.
    ///
    /// Ports are assigned deterministically: inter-switch links take the
    /// next free port on each end, counting from 0, in declaration order.
    /// Apps attach at `APP_PORT` (and, where a switch holds several, the
    /// ports after it, in the order listed). A student program sees exactly
    /// this and nothing more.
    pub fn build(&self, sim: &mut Simulator) -> Result<WorldHandles, WorldError> {
        self.build_with_load(sim, 1.0)
    }

    /// `build`, with every app's offered load multiplied by `load_scale`
    /// (the `--load-scale` knob: the same world at 0.5×, 1×, 2× demand).
    pub fn build_with_load(
        &self,
        sim: &mut Simulator,
        load_scale: f64,
    ) -> Result<WorldHandles, WorldError> {
        use crate::controller::NoopController;
        use crate::switch::{Switch, SwitchConfig};
        use crate::tinyvm::{TinyProgram, TinyVmState};

        if !(load_scale > 0.0 && load_scale.is_finite()) {
            return Err(WorldError::Invalid(format!("load scale {load_scale} is not positive")));
        }
        let lc = self.params.link_config();
        let mut handles = WorldHandles::default();
        handles.as_ids = self
            .switches
            .iter()
            .map(|s| s.as_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        // How many ports each switch needs: one per link, plus the app
        // port. Ports are dense from 0 so `local_ports` reads cleanly.
        let mut degree: BTreeMap<u32, u16> = BTreeMap::new();
        for l in &self.links {
            *degree.entry(l.a).or_insert(0) += 1;
            *degree.entry(l.b).or_insert(0) += 1;
        }

        let size = self.workload.packet_size_bytes();
        let packet_size_bytes = self.params.packet_size_bytes.unwrap_or(size).max(1);

        for s in &self.switches {
            let apps_here = self.apps.iter().filter(|a| a.switch == s.id).count().max(1);
            let ports = (*degree.get(&s.id).unwrap_or(&0) as usize) + apps_here + APP_PORT as usize;
            // Every switch is owned by its AS. `install_program` targets an
            // owner, so a single program lands on the whole AS — which is
            // exactly the A1 premise: one program, every switch.
            let mut cfg = SwitchConfig::defaults(SwitchId::new(s.id));
            if let Some(us) = self.params.control_delay_us {
                cfg.config_pipe_latency = Duration::from_micros(us);
            }
            let mut switch = Switch::new(
                cfg,
                TinyProgram {
                    stages: Vec::new(),
                },
                TinyVmState::default(),
                Box::new(NoopController),
                ports,
                s.queue_capacity_bytes.unwrap_or(self.params.queue_capacity_bytes),
            )
            .with_owner(crate::types::OwnerId::new(s.as_id))
            .with_packet_size_bytes(packet_size_bytes);
            if let Some(b) = self.params.buffer_budget_packets {
                switch = switch.with_buffer_budget_packets(b);
            }
            sim.add_switch(switch);
        }

        // Inter-switch links.
        let mut next_port: BTreeMap<u32, u16> = BTreeMap::new();
        for l in &self.links {
            let pa = *next_port.entry(l.a).or_insert(0);
            let pb = *next_port.entry(l.b).or_insert(0);
            next_port.insert(l.a, pa + 1);
            next_port.insert(l.b, pb + 1);

            let mut cfg = lc;
            if let Some(mbps) = l.capacity_mbps {
                cfg.bandwidth_bps = mbps * 1_000_000;
            }
            if let Some(us) = l.latency_us {
                cfg.latency = Duration::from_micros(us);
            }
            let id = sim.connect(
                Node::Switch(SwitchId::new(l.a)),
                PortId::new(pa),
                Node::Switch(SwitchId::new(l.b)),
                PortId::new(pb),
                cfg,
            );
            handles.links.insert((l.a, l.b), id);
            handles.links.insert((l.b, l.a), id);
            handles.link_order.push(id);
        }

        // Apps. Every app owns a prefix and answers on its first host
        // address; the workload decides who it talks to.
        let mut parsed: Vec<(u32, u32, Prefix)> = Vec::new();
        for a in &self.apps {
            let p = Prefix::parse(&a.prefix)?;
            parsed.push((a.id, a.switch, p));
            handles.app_prefixes.insert(a.id, p);
            handles.app_switch.insert(a.id, a.switch);
        }

        for (id, switch, prefix) in &parsed {
            let app = match self.workload {
                Workload::AllPairsCbr { interval_ms, .. } => {
                    let peers: Vec<IpAddr> = parsed
                        .iter()
                        .filter(|(other, _, _)| other != id)
                        .map(|(_, _, p)| IpAddr(p.first_host()))
                        .collect();
                    // validate() guarantees at least two apps, so peers is non-empty.
                    let mut app = App::new(
                        AppId::new(*id),
                        IpAddr(prefix.first_host()),
                        prefix.len,
                        peers[0],
                        prefix.len,
                        TrafficPattern::ConstantBitrate {
                            interval: Duration::from_millis(interval_ms).div_f64(load_scale),
                            size_bytes: size,
                        },
                    );
                    for peer in &peers[1..] {
                        app.add_destination(*peer);
                    }
                    app
                }
                Workload::A4 { .. } => {
                    let a4 = self.a4.as_ref().ok_or_else(|| WorldError::Invalid("an a4 workload needs an [a4] section".into()))?;
                    a4.app(*id, *prefix, &handles, size, load_scale, self.world.seed)?
                }
                Workload::Mixed { .. } => {
                    let spec = self.apps.iter().find(|a| a.id == *id).expect("parsed from apps");
                    let peer_spec = spec.peer.and_then(|p| self.apps.iter().find(|a| a.id == p));
                    let peer_hosts = peer_spec.map_or_else(|| vec![1], AppSpec::host_numbers);
                    let peer_ip = spec
                        .peer
                        .and_then(|p| parsed.iter().find(|(o, _, _)| *o == p))
                        .map(|(_, _, p)| IpAddr(p.host(peer_hosts[0])))
                        .unwrap_or(IpAddr(prefix.first_host()));
                    let hosts = spec.host_numbers();
                    // The pattern never sends: a customer's traffic is
                    // its flow, and a receiver has none. Every app does
                    // announce itself once, so a customer that starts
                    // late is still learnable while no routes exist.
                    let silent = TrafficPattern::BulkTransfer {
                        total_bytes: 0,
                        sent_bytes: 0,
                        pacing: Duration::from_secs(1),
                        size_bytes: 0,
                    };
                    let mut app = App::new(
                        AppId::new(*id),
                        IpAddr(prefix.host(hosts[0])),
                        prefix.len,
                        peer_ip,
                        prefix.len,
                        silent,
                    )
                    .with_announce();
                    if let Some(flow) = self.flow_for(spec, size, load_scale) {
                        app = app.with_flow(flow);
                    }
                    app.echo = spec.echo;
                    // In a harness world a customer has a transport, and
                    // only TCP is acknowledged; the A2 worlds keep every
                    // packet's protocol at 0 and ack every numbered one.
                    if self.harness.is_some() {
                        let proto = spec.proto.or(spec.preset.map(Preset::proto));
                        app.proto = proto.map_or(0, Proto::number);
                        if let Some(f) = app.flow.as_mut() {
                            f.reliable = proto != Some(Proto::Udp);
                        }
                        app.hosts = hosts;
                        app.ttl_ladder = spec.ttl_ladder.unwrap_or(0);
                        app.ttl_start = spec.ttl_start.unwrap_or(64);
                        // The peer's own length: a host row (/32) sends to a /24.
                        let peer_len = spec.peer.and_then(|p| parsed.iter().find(|(o, _, _)| *o == p)).map_or(prefix.len, |(_, _, p)| p.len);
                        let peer_base = mask(peer_ip.0, peer_len);
                        for h in &peer_hosts[1..] {
                            app.add_destination(IpAddr(peer_base | h));
                        }
                        app.hot_pct = peer_spec.and_then(|p| p.hot_host_pct);
                    }
                    let ms = Duration::from_millis;
                    app.stop = spec.stop_ms.map(ms);
                    app.reply = spec.reply_bytes.map(|bytes| crate::app::Reply {
                        bytes,
                        delay: ms(spec.reply_delay_ms.unwrap_or(0)),
                        stop: spec.reply_stop_ms.map(ms),
                        pause: spec
                            .reply_pause_at_ms
                            .zip(spec.reply_pause_for_ms)
                            .map(|(at, for_ms)| (ms(at), ms(at + for_ms))),
                    });
                    app
                }
            };
            sim.add_app(app);
            if let Some(name) = self.apps.iter().find(|a| a.id == *id).and_then(|a| a.name.as_deref()) {
                sim.name_customer(AppId::new(*id), prefix.addr, prefix.len, name);
            }
            sim.connect(
                Node::App(AppId::new(*id)),
                PortId::new(0),
                Node::Switch(SwitchId::new(*switch)),
                PortId::new(self.app_port(*id)),
                lc,
            );
        }

        sim.customer_contract = self.customer_contract(load_scale)?;
        sim.observe = self.observe.as_ref().map(Observe::limits);
        if let Some(spec) = &self.harness {
            sim.harness = Some(self.harness_runtime()?);
            sim.queue.schedule(Duration::ZERO, crate::event::EventKind::HarnessKeepalive);
            // Rule 9: every switch port gets its report queue, then the
            // world's own queue rows set the customers' caps.
            let ids: Vec<u32> = self.switches.iter().map(|s| s.id).collect();
            for id in ids {
                let ports = sim.switches.get(&SwitchId::new(id)).map(|s| s.egress.len()).unwrap_or(0);
                for port in 0..ports {
                    sim.shape_harness_port(SwitchId::new(id), PortId::new(port as u16), None);
                }
            }
            for q in &spec.queues {
                let port = self.port_toward(q.switch, q.toward).expect("validated");
                sim.set_port_queue(SwitchId::new(q.switch), PortId::new(port), q.packets);
            }
        }
        crate::sim::plant::install(self, sim, load_scale)?;
        Ok(handles)
    }

    /// The local port at `a` whose link leads to switch `b`, numbered as
    /// `build` numbers them: in link order, from 0.
    pub fn port_toward(&self, a: u32, b: u32) -> Option<u16> {
        let mut next: BTreeMap<u32, u16> = BTreeMap::new();
        for l in &self.links {
            let pa = *next.entry(l.a).or_insert(0);
            let pb = *next.entry(l.b).or_insert(0);
            next.insert(l.a, pa + 1);
            next.insert(l.b, pb + 1);
            if (l.a, l.b) == (a, b) {
                return Some(pa);
            }
            if (l.b, l.a) == (a, b) {
                return Some(pb);
            }
        }
        None
    }

    /// Every switch's neighbours, ascending.
    pub fn neighbours(&self) -> BTreeMap<u32, Vec<u32>> {
        let mut adj: BTreeMap<u32, Vec<u32>> = self.switches.iter().map(|s| (s.id, Vec::new())).collect();
        for l in &self.links {
            adj.entry(l.a).or_default().push(l.b);
            adj.entry(l.b).or_default().push(l.a);
        }
        for v in adj.values_mut() {
            v.sort_unstable();
        }
        adj
    }

    fn validate_harness(&self, h: &HarnessSpec) -> Result<(), WorldError> {
        let bad = |m: String| Err(WorldError::Invalid(m));
        if self.observe.is_none() {
            return bad("[harness] needs an [observe] section".into());
        }
        if h.keepalive_ms == 0 {
            return bad("[harness] keepalive_ms must be above 0".into());
        }
        let adj = self.neighbours();
        let is_link = |a: u32, b: u32| adj.get(&a).is_some_and(|n| n.contains(&b));
        for r in &h.routes {
            let p = Prefix::parse(&r.prefix)?;
            if !self.apps.iter().any(|a| Prefix::parse(&a.prefix).ok() == Some(p)) {
                return bad(format!("harness route at {} names {}, which no app owns", r.switch, r.prefix));
            }
            for via in std::iter::once(r.via).chain(r.backup).chain(r.split) {
                if !is_link(r.switch, via) {
                    return bad(format!("harness route at {} goes via {via}, which is not a neighbour", r.switch));
                }
            }
            if r.split == Some(r.via) {
                return bad(format!("harness route at {} splits over its own via {}", r.switch, r.via));
            }
        }
        if h.report_queue_packets == 0 {
            return bad("[harness] report_queue_packets must be above 0".into());
        }
        if h.report_max_bytes == Some(0) {
            return bad("[harness] report_max_bytes must be above 0".into());
        }
        for q in &h.queues {
            if !is_link(q.switch, q.toward) || q.packets == 0 {
                return bad(format!("harness queue {}->{} needs a link and at least one packet", q.switch, q.toward));
            }
        }
        for g in &h.keepalive_gaps {
            if !is_link(g.switch, g.toward) || g.start_ms >= g.end_ms {
                return bad(format!("keepalive gap {}->{} needs a link and start before end", g.switch, g.toward));
            }
        }
        Ok(())
    }

    /// The harness of a `[harness]` world: its routes, keepalives and gaps.
    pub fn harness_runtime(&self) -> Result<crate::harness::Harness, WorldError> {
        use crate::harness::{Gap, Harness, Route};
        let spec = self
            .harness
            .as_ref()
            .ok_or_else(|| WorldError::Invalid("no [harness] section".into()))?;
        let mut h = Harness::new(Duration::from_millis(spec.keepalive_ms));
        h.team_log = crate::team_log::TeamLog::new(spec.log_cap_bytes as usize);
        h.report_queue_packets = spec.report_queue_packets;
        let unit = self.params.packet_size_bytes.unwrap_or_else(|| self.workload.packet_size_bytes()).max(1);
        h.report_max_bytes = spec.report_max_bytes.unwrap_or(unit);
        let adj = self.neighbours();
        let port = |a: u32, b: u32| PortId::new(self.port_toward(a, b).expect("neighbours"));
        for app in &self.apps {
            let p = Prefix::parse(&app.prefix)?;
            let dest = h.add_dest(p.addr, p.len);
            let dist = hops_to(&adj, app.switch, None);
            for s in &self.switches {
                let s = s.id;
                if s == app.switch {
                    let local = Route { primary: PortId::new(self.app_port(app.id)), backup: None, split: None };
                    h.set_route(SwitchId::new(s), dest, local);
                    continue;
                }
                let row = spec
                    .routes
                    .iter()
                    .find(|r| r.switch == s && Prefix::parse(&r.prefix).ok() == Some(p));
                let split = row.and_then(|r| r.split).map(|v| port(s, v));
                let (via, backup) = match row {
                    Some(r) => (Some(r.via), r.backup),
                    None => {
                        let via = next_hop(&adj, &dist, s, None);
                        let backup = via.and_then(|v| {
                            let around = hops_to(&adj, app.switch, Some((s, v)));
                            next_hop(&adj, &around, s, Some(v))
                        });
                        (via, backup)
                    }
                };
                if let Some(via) = via {
                    let route = Route { primary: port(s, via), backup: backup.map(|b| port(s, b)), split };
                    h.set_route(SwitchId::new(s), dest, route);
                }
            }
        }
        for g in &spec.keepalive_gaps {
            h.add_gap(Gap {
                switch: SwitchId::new(g.switch),
                port: port(g.switch, g.toward),
                start: Duration::from_millis(g.start_ms),
                end: Duration::from_millis(g.end_ms),
            });
        }
        Ok(h)
    }

    /// The customer contract: one row for every `[[app]]` with a preset
    /// and a sender law (in an observed world, every one with a preset), in
    /// file order. The rate is what the customer asks for while it is
    /// sending, at this load; `steam` has no limit.
    /// The port app `id` attaches at on its switch: `APP_PORT`, plus how
    /// many apps are listed on that switch before it.
    pub fn app_port(&self, id: u32) -> u16 {
        let Some(me) = self.apps.iter().position(|a| a.id == id) else { return APP_PORT };
        let switch = self.apps[me].switch;
        APP_PORT + self.apps[..me].iter().filter(|a| a.switch == switch).count() as u16
    }

    pub fn customer_contract(
        &self,
        load_scale: f64,
    ) -> Result<Vec<switch_program_types::CustomerW>, WorldError> {
        use switch_program_types::{CcaW, CustomerW};
        let mut rows = Vec::new();
        for spec in &self.apps {
            let Some(preset) = spec.preset else { continue };
            // A sender with no law is listed only where the contract can
            // say so; earlier assignments' programs know two laws.
            if spec.law.is_none() && self.observe.is_none() {
                continue;
            }
            let prefix = Prefix::parse(&spec.prefix)?;
            rows.push(CustomerW {
                prefix_addr: prefix.addr,
                prefix_len: prefix.len,
                // An observed world leaves the law and the ask out: telling
                // customers apart is part of what it grades, and the one
                // AIMD sender or Steam's missing limit would name them.
                cca: match spec.law {
                    _ if self.observe.is_some() => CcaW::Withheld,
                    Some(LawKind::Aimd) => CcaW::Aimd,
                    Some(LawKind::RateMatch) => CcaW::RateMatch,
                    None => CcaW::Fixed,
                },
                ask_bps: match preset {
                    _ if self.observe.is_some() => None,
                    Preset::Steam => None,
                    _ => Some((spec.rate_mbps.unwrap_or(0.0) * 1_000_000.0 * load_scale).round() as u64),
                },
            });
        }
        // In an observed world the list is in address order, not the
        // world's: where ranges are dealt out afresh, the place in the list
        // must not say who a customer is.
        if self.observe.is_some() {
            rows.sort_by_key(|r| (r.prefix_addr, r.prefix_len));
        }
        Ok(rows)
    }

    /// The customer engine one `[[app]]` row asks for, or `None` for a
    /// pure receiver.
    fn flow_for(&self, spec: &AppSpec, size: u64, load_scale: f64) -> Option<FlowEngine> {
        use crate::flow::{Demand, Law};
        let preset = spec.preset?;
        let mbps = |m: f64| m * 1_000_000.0;
        let rate = mbps(spec.rate_mbps.unwrap_or(0.0)) * load_scale;
        let demand = match preset {
            Preset::Netflix | Preset::JaneStreet | Preset::Fortnite | Preset::Ping | Preset::Web => {
                Demand::Constant { bps: rate }
            }
            Preset::Amazon => Demand::OnOff {
                bps: rate,
                on: Duration::from_millis(spec.on_ms.unwrap_or(0)),
                off: Duration::from_millis(spec.off_ms.unwrap_or(0)),
                start: Duration::from_millis(spec.start_ms.unwrap_or(0)),
            },
            Preset::Steam => Demand::Unlimited,
        };
        // A download's natural ceiling is its own link.
        let link_bps = (self.params.link_capacity_mbps * 1_000_000) as f64;
        let initial = spec
            .law_initial_mbps
            .map(mbps)
            .unwrap_or(if preset == Preset::Steam { link_bps } else { rate });
        let law = match spec.law {
            None => Law::Fixed {
                bps: if preset == Preset::Steam { link_bps } else { rate },
            },
            Some(LawKind::Aimd) => Law::Aimd {
                initial_bps: initial,
                increment_bps: spec.law_increment_mbps.map(mbps).unwrap_or(initial / 10.0),
                epoch: Duration::from_millis(spec.law_epoch_ms.unwrap_or(100)),
            },
            Some(LawKind::RateMatch) => Law::RateMatch { initial_bps: initial },
        };
        let mut engine = FlowEngine::new(demand, law, spec.size_bytes.unwrap_or(size));
        engine.min_window_packets = self.params.rate_match_window_packets.unwrap_or(0);
        engine.holds_through_outage = self.params.rate_match_holds_through_outage.unwrap_or(false);
        Some(engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[world]
name = "t"
seed = 1

[params]
duration_ms = 1000
warmup_ms = 100

[[switch]]
id = 0

[[switch]]
id = 1

[[link]]
a = 0
b = 1

[[app]]
id = 10
switch = 0
prefix = "10.1.0.0/24"

[[app]]
id = 11
switch = 1
prefix = "10.1.1.0/24"

[workload]
kind = "all_pairs_cbr"
interval_ms = 10
size_bytes = 100
"#;

    #[test]
    fn parses_sample() {
        let w = World::from_str(SAMPLE).expect("parses");
        assert_eq!(w.switches.len(), 2);
        assert_eq!(w.links.len(), 1);
        assert_eq!(w.apps.len(), 2);
        assert_eq!(w.params.duration_ms, 1000);
    }

    #[test]
    fn a2_params_reach_the_switches() {
        let text = SAMPLE.replace(
            "[params]\n",
            "[params]\nbuffer_budget_packets = 40\npacket_size_bytes = 250\ncontrol_delay_us = 5000\n",
        );
        let w = World::from_str(&text).expect("parses");
        let mut sim = Simulator::new();
        w.build(&mut sim).unwrap();
        for sw in sim.switches.values() {
            assert_eq!(sw.packet_size_bytes, 250);
            assert_eq!(sw.buffer_budget, 40 * 250);
            assert_eq!(sw.config.config_pipe_latency, Duration::from_millis(5));
        }
        // Absent, the buffer does not bind and the packet size is the
        // workload's.
        let w = World::from_str(SAMPLE).unwrap();
        let mut sim = Simulator::new();
        w.build(&mut sim).unwrap();
        let sw = sim.switches.values().next().unwrap();
        assert_eq!(sw.packet_size_bytes, 100);
        assert_eq!(sw.buffer_budget, w.params.queue_capacity_bytes * sw.egress.len() as u64);
        assert_eq!(sw.config.config_pipe_latency, Duration::from_micros(10));
        // And the new fields survive a round trip through TOML.
        let again = World::from_str(&World::from_str(&text).unwrap().to_toml()).unwrap();
        assert_eq!(again.params.control_delay_us, Some(5000));
        assert_eq!(again.params.buffer_budget_packets, Some(40));
    }

    #[test]
    fn rows_carry_their_own_packet_size() {
        let mixed = |size: &str| {
            SAMPLE
                .replace(
                    "prefix = \"10.1.0.0/24\"\n",
                    &format!("prefix = \"10.1.0.0/24\"\npreset = \"jane_street\"\nrate_mbps = 0.2\npeer = 11\nsize_bytes = {size}\n"),
                )
                .replace(
                    "prefix = \"10.1.1.0/24\"\n",
                    "prefix = \"10.1.1.0/24\"\npreset = \"netflix\"\nrate_mbps = 3.0\npeer = 10\n",
                )
                .replace("kind = \"all_pairs_cbr\"\ninterval_ms = 10\nsize_bytes = 100\n", "kind = \"mixed\"\nsize_bytes = 1000\n")
        };
        let w = World::from_str(&mixed("200")).expect("parses");
        let mut sim = Simulator::new();
        w.build(&mut sim).unwrap();
        let mut sizes: Vec<u64> = sim.apps.values().filter_map(|a| a.flow.as_ref()).map(|f| f.packet_size).collect();
        sizes.sort_unstable();
        assert_eq!(sizes, vec![200, 1000], "the trader's row, and the workload's default");
        // The switch's unit stays the full-size packet: queue caps and the
        // buffer count in those whatever a customer sends.
        for sw in sim.switches.values() {
            assert_eq!(sw.packet_size_bytes, 1000);
        }
        assert!(World::from_str(&w.to_toml()).unwrap().to_toml().contains("size_bytes = 200"));
        // Larger than the unit, or zero, is refused.
        for bad in ["5000", "0"] {
            assert!(World::from_str(&mixed(bad)).and_then(|w| w.validate().map(|_| w)).is_err(), "size {bad}");
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let w = World::from_str(SAMPLE).unwrap();
        let again = World::from_str(&w.to_toml()).expect("re-parses");
        assert_eq!(again.switches.len(), w.switches.len());
        assert_eq!(again.apps.len(), w.apps.len());
    }

    #[test]
    fn prefix_parsing() {
        let p = Prefix::parse("10.1.7.0/24").unwrap();
        assert_eq!(p.len, 24);
        assert_eq!(p.first_host(), 0x0a01_0701);
        assert_eq!(p.to_string(), "10.1.7.0/24");
        assert!(Prefix::parse("10.1.7.0").is_err());
        assert!(Prefix::parse("10.1.7/24").is_err());
        assert!(Prefix::parse("10.1.7.0/33").is_err());
    }

    #[test]
    fn overlapping_prefixes_rejected() {
        let bad = SAMPLE.replace(r#"prefix = "10.1.1.0/24""#, r#"prefix = "10.1.0.0/16""#);
        let err = World::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("overlaps"), "{err}");
    }

    #[test]
    fn disconnected_rejected() {
        let bad = SAMPLE.replace("[[link]]\na = 0\nb = 1\n", "");
        let err = World::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("not connected"), "{err}");
    }

    #[test]
    fn duplicate_switch_rejected() {
        let bad = SAMPLE.replace("[[switch]]\nid = 1", "[[switch]]\nid = 0");
        let err = World::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("twice"), "{err}");
    }

    #[test]
    fn unknown_switch_for_app_rejected() {
        let bad = SAMPLE.replace("id = 11\nswitch = 1", "id = 11\nswitch = 9");
        let err = World::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("unknown switch"), "{err}");
    }

    #[test]
    fn connected_without_detects_a_cut() {
        let w = World::from_str(SAMPLE).unwrap();
        let mut down = BTreeSet::new();
        assert!(w.connected_without(&down));
        down.insert((0, 1));
        assert!(!w.connected_without(&down));
    }

    #[test]
    fn builds_into_a_simulator() {
        let w = World::from_str(SAMPLE).unwrap();
        let mut sim = Simulator::new();
        let h = w.build(&mut sim).expect("builds");
        assert_eq!(h.link_order.len(), 1);
        assert_eq!(h.app_prefixes.len(), 2);
        // Each app should target the other.
        sim.run_until(Duration::from_millis(50));
        let sent: u64 = sim.apps.values().map(|a| a.metrics.packets_sent).sum();
        assert!(sent > 0, "apps generated no traffic");
    }
}
