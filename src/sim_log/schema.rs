//! Event-log schema. Postcard-encoded; shared with the browser viewer.
//!
//! Wire layout of a `.simlog` file:
//!
//! ```text
//! [u32 length LE][postcard(LogFrame { at_ns: 0, event: Header(...) })]
//! [u32 length LE][postcard(LogFrame { at_ns, event })]
//! ...
//! ```
//!
//! The first frame is always `LogEvent::Header`. Subsequent frames are
//! ordered by simulator time (monotonic, ties broken by emission order).

use serde::{Deserialize, Serialize};
use switch_program_types as wire;

pub const LOG_MAGIC: u32 = 0x4E45_534D; // 'NESM' (Net-Event-Sim-Meta)
/// Version 2 added `DropReasonW::QueueFull` / `Policy` (appended, so
/// version-1 logs still decode) and moved `PacketEgress` from queue
/// admission to the moment the packet starts onto the wire.
/// Version 4 is a run with an observation layer: it may hold the events
/// appended after `LinkDeclared`. Runs without one still write version 3.
pub const LOG_VERSION: u32 = 4;
/// The oldest version the readers accept.
pub const LOG_VERSION_MIN: u32 = 3;
/// What a run without an observation layer writes.
pub const LOG_VERSION_UNOBSERVED: u32 = 3;

/// Which budget an `ObservationDropped` event ran out of.
pub const CAP_EVENTS: u8 = 0;
pub const CAP_EXPORT: u8 = 1;
/// The report was larger than the harness allows (rule 9).
pub const CAP_REPORT_SIZE: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFrame {
    pub at_ns: u64,
    pub event: LogEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeRefW {
    Switch(u32),
    App(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DropReasonW {
    Ttl,
    NoRoute,
    NoEgressLink,
    /// Link down. (Logs before version 2 also used this for a full queue.)
    LinkDrop,
    SwitchFailed,
    Recirculation,
    /// Egress queue or buffer pool full.
    QueueFull,
    /// The switch program dropped it on purpose.
    Policy,
    /// Lost on the wire of a link that is up: a leak. Since log version 4.
    WireLoss,
}

/// Compact mirror of the simulator's `SwitchConfig`. Includes only fields
/// the viewer needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchConfigW {
    pub stages: u32,
    pub processing_delay_ns: u64,
    pub recirculation_enabled: bool,
    pub max_recirculations: u8,
    pub punt_pipe_latency_ns: u64,
    pub punt_pipe_bandwidth_bps: u64,
    pub config_pipe_latency_ns: u64,
    pub config_pipe_bandwidth_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkConfigW {
    pub latency_ns: u64,
    pub bandwidth_bps: u64,
    pub queue_capacity_bytes: u64,
}

/// Per-hop snapshot of the parts of a packet the viewer renders or shows
/// in the inspector. Payload bytes are deliberately omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSnapshotW {
    pub id: u64,
    pub kind: u8, // PacketKind discriminant
    pub size_bytes: u64,
    pub ip_src: u32,
    pub ip_dst: u32,
    pub ip_proto: u8,
    pub ip_ttl: u8,
    pub label_top: u32,
    pub label_depth: u32,
    /// Since log version 3: the flow and sequence number, so a scorer can
    /// tell a first-time delivery from a retransmitted copy.
    pub flow_id: u64,
    pub seq: Option<u64>,
}

/// AS info for the BGP overlay (only used if `configure_bgp` ran).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsInfoW {
    pub as_id: u32,
    pub border_switch: u32,
    pub bgp_speaker_ip: u32,
    pub owned_prefixes: Vec<(u32, u8)>,
}

/// One match-action table at the moment a program is installed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSnapshotW {
    pub table_id: u32,
    pub kind: wire::MatchKindW,
    pub max_entries: u32,
    pub entries: Vec<wire::TableEntryW>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegSnapshotW {
    pub array_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterSnapshotW {
    pub array_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogEvent {
    /// File header. Always the first frame; `at_ns` is 0.
    Header { magic: u32, version: u32 },

    // ---- topology declarations ----
    AppAdded { id: u32, ip: u32, dst_ip: u32 },
    SwitchAdded {
        id: u32,
        owner: Option<u32>,
        num_ports: u16,
        config: SwitchConfigW,
    },
    LinkAdded {
        id: u32,
        a: NodeRefW,
        a_port: u16,
        b: NodeRefW,
        b_port: u16,
        config: LinkConfigW,
    },
    BgpConfigured { ases: Vec<AsInfoW> },

    // ---- up/down state changes ----
    LinkFailed { id: u32 },
    LinkRestored { id: u32 },
    SwitchFailed { id: u32 },
    CpuFailed { id: u32 },

    // ---- packet life cycle ----
    PacketIngress {
        switch: u32,
        port: u16,
        packet: PacketSnapshotW,
    },
    PacketEgress {
        switch: u32,
        port: u16,
        link: u32,
        packet_id: u64,
        size_bytes: u64,
        arrive_at_ns: u64,
    },
    PacketDropped {
        at: NodeRefW,
        reason: DropReasonW,
        packet_id: u64,
    },
    PacketDelivered { app: u32, packet_id: u64 },
    PacketPunted { switch: u32, reason: u32, packet_id: u64 },

    // ---- TinyVM data plane mutation ----
    ProgramInstalled {
        switch: u32,
        program: wire::TinyProgramW,
        tables: Vec<TableSnapshotW>,
        registers: Vec<RegSnapshotW>,
        counters: Vec<CounterSnapshotW>,
    },
    TableEntryInstalled {
        switch: u32,
        table: u32,
        entry: wire::TableEntryW,
    },
    TableEntryDeleted {
        switch: u32,
        table: u32,
        entry_id: u64,
    },
    /// Pre-version-2 form; no longer emitted, kept so old logs decode.
    QueueConfigChanged {
        switch: u32,
        port: u16,
        capacity_bytes: u64,
    },
    /// A controller's `SetQueueConfig` landed on the data plane.
    /// `queues` is the resulting shape in packets; `unit_bytes` is what
    /// one packet was taken to be when caps were converted to bytes.
    PortQueuesConfigured {
        switch: u32,
        port: u16,
        discipline: u8,
        unit_bytes: u64,
        queues: Vec<wire::QueueSpecW>,
    },
    /// A controller's `DeclareLink` landed: the switch now says the link
    /// on `port` is up (`true`) or down (`false`). Belief, not truth;
    /// `LinkFailed` / `LinkRestored` are the truth.
    LinkDeclared {
        switch: u32,
        port: u16,
        up: bool,
    },

    // ---- the observation layer (version 4) ----
    /// A budget refused something: an event the switch could not hand its
    /// controller (`CAP_EVENTS`), or a packet the controller could not send
    /// (`CAP_EXPORT`).
    ObservationDropped {
        switch: u32,
        cap: u8,
        packet_id: u64,
    },
    /// In a run where the harness forwards: the program's pipeline punted
    /// its copy of a packet, and the copy was sent toward the controller.
    /// The packet itself went on.
    PacketSampled { switch: u32, reason: u32, packet_id: u64 },
    /// A controller asked to make its switch the logging switch; `accepted`
    /// is whether it is.
    LoggingSwitchNamed { switch: u32, accepted: bool },
    /// The logging switch appended `bytes` to the team's log.
    TeamLogWritten { switch: u32, bytes: Vec<u8> },
    /// A write that was not kept: `len` bytes, for the reason `why` (see
    /// `crate::team_log`).
    TeamLogRefused { switch: u32, len: u32, why: u8 },
    /// In a run where the harness forwards: the output port that refused
    /// the packet named by the `PacketDropped` that follows.
    DroppedAtPort {
        switch: u32,
        port: u16,
        packet_id: u64,
    },
    /// The world names a customer: app `app` owns `prefix`/`len` and is
    /// `name` ("Netflix"). Only a truth run's world names its customers;
    /// a program never sees this.
    CustomerNamed {
        app: u32,
        prefix: u32,
        len: u8,
        name: String,
    },
}
