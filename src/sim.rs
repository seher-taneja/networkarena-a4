use crate::app::App;
use crate::controller::{ControllerAction, LinkEvent, PuntEvent};
use crate::event::{Event, EventKind, EventQueue};
use crate::link::{Link, LinkConfig};
use crate::network::{Endpoint, Network, Node};
use crate::packet::{Packet, PacketKind, PuntReason, TrailHop};
use crate::switch::{PipelineOutcome, Switch};
use crate::types::{AppId, LinkId, PortId, SimTime, SwitchId};
use std::collections::HashMap;
use std::time::Duration;

pub mod plant;

/// Top-level simulator. Owns apps, switches, links, the network graph, and
/// the event queue. Time advances by popping events.
/// Rule 9: the queue reports ride in, on every switch port where the
/// harness forwards. Queue 0 is the customers'.
pub const REPORT_QUEUE: u16 = 1;

pub struct Simulator {
    pub now: SimTime,
    pub queue: EventQueue,
    pub apps: HashMap<AppId, App>,
    pub switches: HashMap<SwitchId, Switch>,
    pub links: HashMap<LinkId, Link>,
    pub network: Network,
    next_link_id: u32,

    /// Opt-in BGP state. `None` until the test calls `configure_bgp`.
    /// When `Some`, every packet ingressing a switch is stamped with a
    /// trail hop, every SimpleBGP packet reaching a BGP speaker is
    /// validated/recorded, and every terminated packet is graded for
    /// promise conformance.
    #[cfg(feature = "wasm")]
    pub bgp: Option<crate::bgp::BgpState>,

    #[cfg(feature = "wasm")]
    pub trace: crate::trace::TraceManager,

    /// Optional event log. `None` until `start_logging` is called. When
    /// `Some`, every topology / state-change / packet event is written
    /// to the underlying file in length-prefixed postcard format.
    pub log: Option<crate::sim_log::EventLogger>,

    /// Whether a link going down or coming back notifies the switches on
    /// either end.
    ///
    /// Off by default, and A1 leaves it off. The handout promises that
    /// "there is no alert; the link just goes silent", and detecting that
    /// silence is the skill Part 2 grades. A program that is handed the
    /// answer is solving a different, easier assignment than the one we
    /// set.
    ///
    /// Later assignments introduce failures no alert could describe: links
    /// that slow down, or drop some traffic and forward the rest. Turn this
    /// on there if it earns its place.
    pub notify_link_events: bool,

    /// The customer contract every program is handed at `init`: who the
    /// customers are, how each one slows down, what each asks for. Set by
    /// a world with customers before programs are installed; empty
    /// otherwise.
    pub customer_contract: Vec<switch_program_types::CustomerW>,

    /// The observation layer's budgets, from a world's `[observe]`, the same
    /// for every switch. `None` means there is no layer and nothing below
    /// that depends on it runs. Set before `start_logging` so the log
    /// declares the right version.
    pub observe: Option<switch_program_types::ObserveLimitsW>,
    observe_state: HashMap<SwitchId, crate::observe::SwitchObserve>,

    /// Bytes per second a switch program may inject, with a one-second
    /// burst (an A4 world's `inject_bytes_per_s`). `None`: no ration.
    pub inject_budget: Option<u64>,
    inject_buckets: HashMap<SwitchId, crate::observe::ExportBucket>,

    /// Set by a world with a `[harness]` section: the harness forwards
    /// customer packets and the program only observes. See
    /// `crate::harness`.
    pub harness: Option<crate::harness::Harness>,

    /// An A4 world's per-switch `init` information, by switch id. Set
    /// before programs are installed; empty in every other world.
    pub a4_info: std::collections::BTreeMap<u32, switch_program_types::A4InfoW>,
    /// An A4 world's border meters; `None` in every other world.
    pub a4_meter: Option<crate::a4::meter::Meter>,
}

impl Simulator {
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            queue: EventQueue::new(),
            apps: HashMap::new(),
            switches: HashMap::new(),
            links: HashMap::new(),
            network: Network::new(),
            next_link_id: 0,
            #[cfg(feature = "wasm")]
            bgp: None,
            #[cfg(feature = "wasm")]
            trace: crate::trace::TraceManager::new(),
            log: None,
            notify_link_events: false,
            customer_contract: Vec::new(),
            observe: None,
            observe_state: HashMap::new(),
            inject_budget: None,
            inject_buckets: HashMap::new(),
            harness: None,
            a4_info: std::collections::BTreeMap::new(),
            a4_meter: None,
        }
    }

    /// Begin writing a `.simlog` event stream to `path`. Subsequent
    /// topology, state-change, and packet events are recorded. Existing
    /// switches/apps/links and the BGP registry that have *already* been
    /// added are replayed into the log immediately so the file is
    /// self-contained even if logging starts mid-construction.
    pub fn start_logging(
        &mut self,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        let version = if self.observe.is_some() {
            crate::sim_log::LOG_VERSION
        } else {
            crate::sim_log::LOG_VERSION_UNOBSERVED
        };
        let mut log = crate::sim_log::EventLogger::create_version(path, version)?;
        // Backfill: emit AppAdded/SwitchAdded/LinkAdded for whatever's
        // already in the simulator. Order: apps, switches, links so the
        // viewer has nodes before edges.
        let now_ns = self.now.as_nanos() as u64;
        for (id, app) in &self.apps {
            log.log(now_ns, crate::sim_log::LogEvent::AppAdded {
                id: id.raw(),
                ip: app.ip.0,
                dst_ip: app.destination.0,
            });
        }
        for (id, sw) in &self.switches {
            log.log(now_ns, crate::sim_log::LogEvent::SwitchAdded {
                id: id.raw(),
                owner: sw.owner.map(|o| o.raw()),
                num_ports: sw.egress.len() as u16,
                config: switch_config_to_wire(&sw.config),
            });
        }
        // For links we need to look up their endpoints; iterate over
        // `links` and read the Link's stored src/dst NodeIds.
        for (id, link) in &self.links {
            log.log(now_ns, crate::sim_log::LogEvent::LinkAdded {
                id: id.raw(),
                a: nodeid_to_wire(link.src),
                a_port: link.src_port.raw(),
                b: nodeid_to_wire(link.dst),
                b_port: link.dst_port.raw(),
                config: link_config_to_wire(&link.config),
            });
        }
        self.log = Some(log);
        Ok(())
    }

    /// Enable SimpleBGP bookkeeping with the given AS registry. Must be
    /// called before traffic that should be observed.
    #[cfg(feature = "wasm")]
    pub fn configure_bgp(&mut self, registry: crate::bgp::AsRegistry) {
        let ases: Vec<crate::sim_log::AsInfoW> = registry
            .ases
            .values()
            .map(|info| crate::sim_log::AsInfoW {
                as_id: info.as_id.raw(),
                border_switch: info.border_switch.raw(),
                bgp_speaker_ip: info.bgp_speaker_ip.0,
                owned_prefixes: info
                    .owned_prefixes
                    .iter()
                    .map(|p| (p.addr, p.len))
                    .collect(),
            })
            .collect();
        self.bgp = Some(crate::bgp::BgpState::new(registry));
        self.log_event(crate::sim_log::LogEvent::BgpConfigured { ases });
    }

    /// Set a trace budget for an AS. Must be called for every AS that
    /// will issue traces.
    #[cfg(feature = "wasm")]
    pub fn set_trace_budget(&mut self, as_id: crate::types::AsId, budget: crate::trace::TraceBudget) {
        self.trace.set_budget(as_id, budget);
    }

    /// Issue a trace probe from `requester_as`. The probe is launched
    /// on the requester's border switch and routed by the network. When
    /// it terminates (delivery or drop), a `TraceResult` is published
    /// and can be retrieved with [`take_trace_result`].
    ///
    /// The probe is invisible to switch programs: it travels as a
    /// regular `Data` packet whose `kind` field reads `Data` from
    /// TinyVM's perspective. Path information is recorded in the
    /// hidden trail.
    #[cfg(feature = "wasm")]
    pub fn request_trace(
        &mut self,
        requester_as: crate::types::AsId,
        mut packet_template: Packet,
        max_hops: u16,
    ) -> Result<crate::types::TraceId, crate::trace::TraceError> {
        use crate::trace::TraceError;
        let now = self.now;
        if !self.trace.consume_token(requester_as, now) {
            return Err(TraceError::BudgetExceeded);
        }
        let bgp = self.bgp.as_ref().ok_or(TraceError::UnknownAs)?;
        let info = bgp.registry.ases.get(&requester_as).ok_or(TraceError::UnknownAs)?;
        let border = info.border_switch;

        let id = self.trace.allocate_id();
        packet_template.kind = crate::packet::PacketKind::Data; // invisible to TinyVM
        packet_template.trail = crate::packet::PacketTrail {
            hops: Vec::new(),
            trace_id: Some(id),
            trace_requester_as: Some(requester_as),
            trace_mark_switch: None,
            trace_mark_port: None,
        };
        packet_template.ip_ttl = max_hops as u8;

        // Inject as if the probe entered the border switch on a synthetic
        // ingress port. We use port 0xffff to avoid colliding with real ports.
        let port = PortId::new(u16::MAX);
        self.queue.schedule(now, EventKind::SwitchIngress {
            switch: border,
            port,
            packet: packet_template,
        });
        Ok(id)
    }

    /// Retrieve and consume a completed trace result by id.
    #[cfg(feature = "wasm")]
    pub fn take_trace_result(&mut self, id: crate::types::TraceId) -> Option<crate::trace::TraceResult> {
        self.trace.take(id)
    }

    pub fn add_app(&mut self, mut app: App) {
        let id = app.id;
        let ip = app.ip.0;
        let dst = app.destination.0;
        // If the app's link was connected before the app was added, size
        // its egress queue from that link now.
        if let Some(cap) = self
            .network
            .link_at(Node::App(id), PortId::new(0))
            .and_then(|l| self.links.get(&l))
            .map(|l| l.config.queue_capacity_bytes)
        {
            Self::size_app_egress(&mut app, cap);
        }
        self.apps.insert(id, app);
        // Schedule first tick immediately.
        self.queue.schedule(self.now, EventKind::AppTick { app: id });
        self.log_event(crate::sim_log::LogEvent::AppAdded {
            id: id.raw(),
            ip,
            dst_ip: dst,
        });
    }

    /// Name customer `app`, which owns `prefix`/`len`, in the log. Nothing
    /// in the run sees it; it is for whoever reads the log.
    pub fn name_customer(&mut self, app: AppId, prefix: u32, len: u8, name: &str) {
        self.log_event(crate::sim_log::LogEvent::CustomerNamed {
            app: app.raw(),
            prefix,
            len,
            name: name.to_string(),
        });
    }

    pub fn add_switch(&mut self, switch: Switch) {
        let id = switch.config.switch_id;
        let owner = switch.owner.map(|o| o.raw());
        let num_ports = switch.egress.len() as u16;
        let cfg = switch_config_to_wire(&switch.config);
        self.switches.insert(id, switch);
        self.log_event(crate::sim_log::LogEvent::SwitchAdded {
            id: id.raw(),
            owner,
            num_ports,
            config: cfg,
        });
    }

    pub fn connect(
        &mut self,
        a_node: Node,
        a_port: PortId,
        b_node: Node,
        b_port: PortId,
        config: LinkConfig,
    ) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        let link = Link::new(
            id,
            config,
            a_node.as_node_id(),
            a_port,
            b_node.as_node_id(),
            b_port,
        );
        self.links.insert(id, link);
        self.network.register_link(
            id,
            Endpoint {
                node: a_node,
                port: a_port,
            },
            Endpoint {
                node: b_node,
                port: b_port,
            },
        );
        // An app's egress queue is the drop-tail queue at its end of the
        // link: size it from the link. (Switches size theirs at
        // construction.)
        for n in [a_node, b_node] {
            if let Node::App(a) = n {
                if let Some(app) = self.apps.get_mut(&a) {
                    Self::size_app_egress(app, config.queue_capacity_bytes);
                }
            }
        }
        self.log_event(crate::sim_log::LogEvent::LinkAdded {
            id: id.raw(),
            a: nodeid_to_wire(a_node.as_node_id()),
            a_port: a_port.raw(),
            b: nodeid_to_wire(b_node.as_node_id()),
            b_port: b_port.raw(),
            config: link_config_to_wire(&config),
        });
        id
    }

    fn size_app_egress(app: &mut App, queue_bytes: u64) {
        for q in &mut app.egress.queues {
            q.max_bytes = queue_bytes;
        }
        app.buffer_budget = queue_bytes;
    }

    /// Install an owner's WASM switch program on every switch they own.
    ///
    /// The bytes (`.wasm` or `.wat`) are compiled once and instantiated per
    /// switch, with each switch's `SwitchId` passed into `init`. The
    /// `init`-returned `ProgramSetupW` *replaces* the switch's current
    /// data-plane program and TinyVM state, and the WASM controller is
    /// installed in place of any existing controller.
    ///
    /// Returns the list of switch IDs that were programmed. Errors short the
    /// whole call: if the module fails to compile or any switch's `init`
    /// fails, no switches are mutated.
    #[cfg(feature = "wasm")]
    pub fn install_program(
        &mut self,
        owner: crate::types::OwnerId,
        module_bytes: &[u8],
        limits: crate::wasm::WasmLimits,
    ) -> Result<Vec<SwitchId>, crate::wasm::WasmError> {
        let mut targets: Vec<SwitchId> = self
            .switches
            .iter()
            .filter(|(_, s)| s.owner == Some(owner))
            .map(|(id, _)| *id)
            .collect();
        // In id order, so the log is the same on every run.
        targets.sort();

        // Load every switch's program first; only on full success do we mutate.
        let mut loaded: Vec<(SwitchId, crate::wasm::LoadedProgram)> = Vec::new();
        for sid in &targets {
            let local_ports = self.local_ports_for_switch(*sid);
            let port_capacity_bps = local_ports
                .iter()
                .map(|p| {
                    self.network
                        .link_at(Node::Switch(*sid), PortId::new(*p))
                        .and_then(|l| self.links.get(&l))
                        .map(|l| l.config.bandwidth_bps)
                        .unwrap_or(0)
                })
                .collect();
            let lp = crate::wasm::load_program_observed(
                module_bytes,
                sid.raw(),
                local_ports,
                port_capacity_bps,
                self.customer_contract.clone(),
                self.observe,
                self.harness.as_ref().map(|h| h.info()),
                self.a4_info.get(&sid.raw()).cloned(),
                limits.clone(),
            )?;
            loaded.push((*sid, lp));
        }
        for (sid, lp) in loaded {
            if let Some(switch) = self.switches.get_mut(&sid) {
                switch.program = lp.program;
                switch.state = lp.state;
                switch.controller = Box::new(lp.controller);
                switch.cpu = crate::switch::CpuState::default();
            }
            // Snapshot the new program + tables for the log.
            if self.log.is_some() {
                let switch = self.switches.get(&sid).unwrap();
                let event = program_installed_event(sid, &switch.program, &switch.state);
                self.log_event(event);
            }
        }
        Ok(targets)
    }

    /// All ports on `switch` that have a link attached. Order is stable
    /// (sorted ascending) so the program sees a deterministic view.
    pub fn local_ports_for_switch(&self, switch: SwitchId) -> Vec<u16> {
        let me_node = Node::Switch(switch).as_node_id();
        let mut ports: Vec<u16> = self
            .network
            .endpoint_to_link
            .keys()
            .filter_map(|(node, port)| if *node == me_node { Some(*port) } else { None })
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn schedule_controller_timer(&mut self, switch: SwitchId, at: SimTime) {
        self.queue
            .schedule(at, EventKind::ControllerTimer { switch });
    }

    /// Run the simulator until either the event queue is empty or `until` has
    /// passed.
    pub fn run_until(&mut self, until: SimTime) {
        while let Some(t) = self.queue.peek_time() {
            if t > until {
                break;
            }
            let ev = self.queue.pop().unwrap();
            self.now = ev.time;
            self.handle(ev);
        }
        self.now = until.max(self.now);
        self.finalize_metrics();
    }

    /// Run until queue empties.
    pub fn run(&mut self) {
        while let Some(ev) = self.queue.pop() {
            self.now = ev.time;
            self.handle(ev);
        }
        self.finalize_metrics();
    }

    /// Bring every app's summary metrics up to date. Runs at the end of
    /// `run` / `run_until`; call it yourself after driving events by hand.
    pub fn finalize_metrics(&mut self) {
        for app in self.apps.values_mut() {
            app.metrics.finalize();
        }
    }

    fn handle(&mut self, ev: Event) {
        match ev.kind {
            EventKind::AppTick { app } => self.handle_app_tick(app),
            EventKind::AppDeliver { app, packet } => {
                self.log_event(crate::sim_log::LogEvent::PacketDelivered {
                    app: app.raw(),
                    packet_id: packet.id.raw(),
                });
                self.terminate_packet(&packet);
                if let Some(delay) = self.apps.get(&app).and_then(|a| a.reply_due(&packet)) {
                    let (at, from) = (packet.ip_dst, packet.ip_src);
                    self.queue
                        .schedule(self.now + delay, EventKind::AppReply { app, at, from });
                }
                let ack = match self.apps.get_mut(&app) {
                    Some(a) => a.deliver(packet, self.now),
                    None => None,
                };
                if let Some(ack) = ack {
                    self.send_from_app(app, ack);
                }
            }
            EventKind::SwitchIngress {
                switch,
                port,
                packet,
            } => {
                self.handle_switch_ingress(switch, port, packet);
            }
            EventKind::SwitchPipelineDone {
                switch,
                port,
                queue,
                packet,
            } => {
                self.handle_pipeline_done(switch, port, queue, packet);
            }
            EventKind::LinkSerializationDone {
                link,
                from_src,
                packet,
            } => {
                self.handle_serialization_done(link, from_src, packet);
            }
            EventKind::PuntArrive {
                switch,
                packet,
                port,
                reason,
                arrived,
            } => self.handle_punt_arrive(switch, packet, port, reason, arrived),
            EventKind::SampleArrive {
                switch,
                packet,
                port,
                reason,
                arrived,
            } => self.handle_controller_input(switch, packet, port, reason, true, arrived),
            EventKind::ConfigArrive { switch, action } => {
                self.handle_config_arrive(switch, action);
            }
            EventKind::ControllerTimer { switch } => self.handle_controller_timer(switch),
            EventKind::HarnessKeepalive => self.handle_harness_keepalive(),
            EventKind::PlantTick { tick } => self.plant_tick(tick),
            EventKind::PlantCapacity { link, bps } => {
                if let Some(l) = self.links.get_mut(&link) {
                    l.config.bandwidth_bps = bps;
                }
            }
            EventKind::PlantLink { link, up } => {
                if up {
                    self.restore_link(link)
                } else {
                    self.fail_link(link)
                }
            }
            EventKind::PlantPause { app, until } => {
                if let Some(flow) = self.apps.get_mut(&app).and_then(|a| a.flow.as_mut()) {
                    flow.paused_until = Some(until);
                }
            }
            EventKind::AppReply { app, at, from } => {
                let now = self.now;
                if let Some(reply) = self.apps.get_mut(&app).and_then(|a| a.reply(at, from, now)) {
                    self.send_from_app(app, reply);
                }
            }
        }
    }

    fn handle_app_tick(&mut self, app_id: AppId) {
        let now = self.now;
        let out = match self.apps.get_mut(&app_id) {
            Some(a) => a.tick(now),
            None => return,
        };

        // Schedule the next tick.
        if let Some(next_delay) = out.next {
            self.queue
                .schedule(now + next_delay, EventKind::AppTick { app: app_id });
        }

        // Push packet onto the link out of this app.
        for packet in [out.packet, out.echo].into_iter().flatten() {
            self.send_from_app(app_id, packet);
        }
    }

    fn send_from_app(&mut self, app_id: AppId, packet: Packet) {
        self.enqueue_at_port(Node::App(app_id), PortId::new(0), 0, packet);
    }

    /// The egress port behind `(node, port)`, with the node's buffer pool
    /// (`used`, `budget`). `None` if the node or port does not exist.
    fn egress_mut(
        &mut self,
        node: Node,
        port: PortId,
    ) -> Option<(&mut crate::egress::EgressPort, &mut u64, u64)> {
        match node {
            Node::Switch(s) => {
                let sw = self.switches.get_mut(&s)?;
                let p = sw.egress.get_mut(port.raw() as usize)?;
                Some((p, &mut sw.buffer_used, sw.buffer_budget))
            }
            Node::App(a) => {
                let app = self.apps.get_mut(&a)?;
                if port.raw() != 0 {
                    return None;
                }
                Some((&mut app.egress, &mut app.buffer_used, app.buffer_budget))
            }
        }
    }

    /// Hand a packet to the egress port at `(node, port)`. It is admitted
    /// into queue `queue` if the link is up and both the node's buffer pool
    /// and the queue have room, and dropped (with a logged reason)
    /// otherwise. Nothing about its departure is decided here: if the wire
    /// is idle the port is kicked, and otherwise the packet waits for the
    /// scheduler to pick it when the wire frees up.
    fn enqueue_at_port(&mut self, node: Node, port: PortId, queue: u16, packet: Packet) {
        let link_id = match self.network.link_at(node, port) {
            Some(l) => l,
            None => {
                // An app with nothing plugged in just can't send. A switch
                // forwarding out an unwired port is a routing bug worth a
                // line on the card.
                if let Node::Switch(s) = node {
                    if let Some(sw) = self.switches.get_mut(&s) {
                        sw.packets_dropped_no_egress += 1;
                    }
                    self.log_port_drop(node, port, &packet);
                    self.terminate_packet_with(
                        &packet,
                        Some(crate::trace::DropReason::NoEgressLink),
                    );
                }
                return;
            }
        };

        let from_src = {
            let link = match self.links.get_mut(&link_id) {
                Some(l) => l,
                None => return,
            };
            let from_src = link.is_src(node.as_node_id());
            if link.failed {
                link.record_link_down_drop(from_src, packet.size_bytes);
                self.log_port_drop(node, port, &packet);
                self.terminate_packet_with(&packet, Some(crate::trace::DropReason::LinkDrop));
                return;
            }
            from_src
        };

        let size = packet.size_bytes;
        // Rule 9: a report goes to the report queue, whatever the program
        // asked, and is held against that queue alone.
        let report = self.rides_behind(node, &packet);
        let queue = if report { crate::sim::REPORT_QUEUE } else { queue };
        let idle = {
            let (egress, used, budget) = match self.egress_mut(node, port) {
                Some(x) => x,
                None => return,
            };
            let (pool_used, pool_budget) = if report { (0, u64::MAX) } else { (*used, budget) };
            match egress.admit(queue as usize, packet, pool_used, pool_budget) {
                Ok(()) => {
                    if !report {
                        *used += size;
                    }
                    !egress.transmitting
                }
                Err((refused, why)) => {
                    // Without this the packet just disappears and the
                    // report card has no answer for where it went. A
                    // threshold drop is the program's choice and is
                    // reported as such; the other two are a lack of room.
                    let reason = match why {
                        crate::egress::Refusal::Threshold => crate::trace::DropReason::Policy,
                        _ => crate::trace::DropReason::QueueFull,
                    };
                    self.log_port_drop(node, port, &refused);
                    self.terminate_packet_with(&refused, Some(reason));
                    return;
                }
            }
        };
        if idle {
            self.start_wire(node, port, link_id, from_src);
        }
    }

    /// The wire out of `(node, port)` is idle: ask the port's scheduler
    /// for the next packet and start serializing it. This is the one place
    /// a packet's departure is decided.
    fn start_wire(&mut self, node: Node, port: PortId, link_id: LinkId, from_src: bool) {
        let packet = {
            let (egress, _, _) = match self.egress_mut(node, port) {
                Some(x) => x,
                None => return,
            };
            match egress.pick_next() {
                Some(p) => {
                    egress.transmitting = true;
                    egress.bytes_sent += p.size_bytes;
                    p
                }
                None => {
                    egress.transmitting = false;
                    return;
                }
            }
        };

        let (ser_done, arrive) = match self.links.get(&link_id) {
            Some(l) => {
                let done = self.now + l.config.serialization_delay(packet.size_bytes);
                (done, done + l.latency(from_src))
            }
            None => return,
        };

        // Log the egress: the packet is now on the wire. App-originated
        // packets skip this event; the viewer infers them from the
        // next-hop ingress.
        if let Node::Switch(s) = node {
            self.log_event(crate::sim_log::LogEvent::PacketEgress {
                switch: s.raw(),
                port: port.raw(),
                link: link_id.raw(),
                packet_id: packet.id.raw(),
                size_bytes: packet.size_bytes,
                arrive_at_ns: arrive.as_nanos() as u64,
            });
        }

        self.queue.schedule(
            ser_done,
            EventKind::LinkSerializationDone {
                link: link_id,
                from_src,
                packet,
            },
        );
    }

    /// The packet has fully left the sending port. Release its buffer,
    /// put it on the far end's doorstep after the propagation delay, and
    /// pull the port's next packet.
    fn handle_serialization_done(&mut self, link_id: LinkId, from_src: bool, mut packet: Packet) {
        let (near, near_port, far, far_port, latency) = match self.links.get(&link_id) {
            Some(l) => {
                let (n, np) = l.near_end(from_src);
                let (f, fp) = l.far_end(from_src);
                (Node::from_node_id(n), np, Node::from_node_id(f), fp, l.latency(from_src))
            }
            None => return,
        };

        let report = self.rides_behind(near, &packet);
        if let Some((egress, used, _)) = self.egress_mut(near, near_port) {
            if !report {
                *used = used.saturating_sub(packet.size_bytes);
            }
            egress.transmitting = false;
        }

        // A leaky link loses the packet here: it left the sender whole and
        // never reaches the far end.
        let lost = self.links.get(&link_id).is_some_and(|l| l.loses(packet.id, self.now));
        if lost {
            self.terminate_packet_with(&packet, Some(crate::trace::DropReason::WireLoss));
            self.start_wire(near, near_port, link_id, from_src);
            return;
        }

        let arrive = self.now + latency;
        // An observed run carries no hidden channel between switches: what
        // one switch's data plane wrote into the custom words or labels does
        // not cross the link.
        if self.observe.is_some()
            && matches!(near, Node::Switch(_))
            && matches!(far, Node::Switch(_))
        {
            packet.custom = [0; 4];
            packet.labels.clear();
        }
        match far {
            Node::Switch(switch) => self.queue.schedule(
                arrive,
                EventKind::SwitchIngress {
                    switch,
                    port: far_port,
                    packet,
                },
            ),
            Node::App(app) => self
                .queue
                .schedule(arrive, EventKind::AppDeliver { app, packet }),
        };

        self.start_wire(near, near_port, link_id, from_src);
    }

    fn handle_switch_ingress(&mut self, switch_id: SwitchId, port: PortId, mut packet: Packet) {
        let switch = match self.switches.get_mut(&switch_id) {
            Some(s) => s,
            None => return,
        };
        if switch.failed {
            self.terminate_packet_with(&packet, Some(crate::trace::DropReason::SwitchFailed));
            return;
        }
        // Stamp the hidden trail before any processing.
        self.stamp_trail(&mut packet, switch_id);
        packet.ingress_port = Some(port);

        // Log the ingress event (visible to the viewer).
        self.log_event(crate::sim_log::LogEvent::PacketIngress {
            switch: switch_id.raw(),
            port: port.raw(),
            packet: packet_snapshot(&packet),
        });

        // BGP intercept: a SimpleBGP packet whose ip_dst matches a BGP
        // speaker IP and whose arrival switch is that speaker's border
        // switch counts as "received". This is independent of the
        // controller; the simulator records it directly.
        self.maybe_record_simple_bgp(switch_id, &packet);

        // Where the harness forwards, it forwards everything except what a
        // controller created.
        if self.harness.is_some() && packet.id.raw() & crate::observe::REPORT_ID_BIT == 0 {
            self.harness_ingress(switch_id, port, packet);
            return;
        }

        // TraceReply packets are simulator-synthesized: they bypass the
        // data plane and go straight to the controller as a punt-style
        // event. The bandwidth they consumed on the wire was already
        // accounted for during link enqueue.
        if self.observe.is_none() && matches!(packet.kind, PacketKind::TraceReply) {
            self.queue.schedule(self.now, EventKind::PuntArrive {
                switch: switch_id,
                packet,
                port,
                reason: PuntReason::Custom(0xFFFF_FFFE),
                arrived: self.now,
            });
            return;
        }

        let switch = self.switches.get_mut(&switch_id).unwrap();
        // Pre-decrement TTL to model basic loop protection. Drop if zero.
        if packet.ip_ttl == 0 {
            self.terminate_packet_with(&packet, Some(crate::trace::DropReason::Ttl));
            return;
        }
        packet.ip_ttl -= 1;
        let _ = switch;

        let outcome = switch.process_pipeline(&mut packet);
        let pipeline_delay = switch.pipeline_delay();
        if self.observe.is_some() {
            // No in-band trace in an observed run: paths are measured.
            packet.trail.trace_mark_switch = None;
            packet.trail.trace_mark_port = None;
        }
        let switch = self.switches.get_mut(&switch_id).unwrap();

        match outcome {
            PipelineOutcome::Forward { port: out, queue } => {
                let done_at = self.now + pipeline_delay;
                self.queue.schedule(
                    done_at,
                    EventKind::SwitchPipelineDone {
                        switch: switch_id,
                        port: out,
                        queue: queue.raw(),
                        packet,
                    },
                );
            }
            PipelineOutcome::Drop => {
                self.terminate_packet_with(&packet, Some(crate::trace::DropReason::Policy));
            }
            PipelineOutcome::Punt(reason) if self.observe.is_some() => {
                self.send_to_controller(switch_id, packet, port, reason, false);
            }
            PipelineOutcome::NoEgress if self.observe.is_some() => {
                self.send_to_controller(switch_id, packet, port, PuntReason::NoRoute, false);
            }
            PipelineOutcome::Punt(reason) => {
                // Queue on punt pipe; arrives at CPU after latency + serialization.
                let charged =
                    switch.config.min_control_msg_size_bytes + packet.size_bytes;
                if let Some(arrive) = switch.punt_pipe.schedule(self.now, charged) {
                    let pkt_size = packet.size_bytes;
                    let punt_pipe_drain = arrive;
                    self.queue.schedule(
                        punt_pipe_drain,
                        EventKind::PuntArrive {
                            switch: switch_id,
                            packet,
                            port,
                            reason,
                            arrived: self.now,
                        },
                    );
                    // Release pipe bytes once serialization slot frees.
                    // We approximate by releasing at arrive time too.
                    let switch = self.switches.get_mut(&switch_id).unwrap();
                    let _ = pkt_size;
                    switch.punt_pipe.release(charged);
                }
            }
            PipelineOutcome::Recirculate => {
                if !switch.config.recirculation_enabled {
                    self.terminate_packet_with(&packet, Some(crate::trace::DropReason::Recirculation));
                    return;
                }
                if packet.recirculation_count >= switch.config.max_recirculations {
                    self.terminate_packet_with(&packet, Some(crate::trace::DropReason::Recirculation));
                    return;
                }
                packet.recirculation_count += 1;
                // Re-enter ingress after pipeline_delay (extra processing cost).
                let done_at = self.now + pipeline_delay;
                self.queue.schedule(
                    done_at,
                    EventKind::SwitchIngress {
                        switch: switch_id,
                        port,
                        packet,
                    },
                );
            }
            PipelineOutcome::NoEgress => {
                // No matching action set egress: punt with NoRoute.
                let charged =
                    switch.config.min_control_msg_size_bytes + packet.size_bytes;
                if let Some(arrive) = switch.punt_pipe.schedule(self.now, charged) {
                    self.queue.schedule(
                        arrive,
                        EventKind::PuntArrive {
                            switch: switch_id,
                            packet,
                            port,
                            reason: PuntReason::NoRoute,
                            arrived: self.now,
                        },
                    );
                    let switch = self.switches.get_mut(&switch_id).unwrap();
                    switch.punt_pipe.release(charged);
                }
            }
        }
    }

    fn handle_pipeline_done(
        &mut self,
        switch_id: SwitchId,
        port: PortId,
        queue: u16,
        packet: Packet,
    ) {
        self.enqueue_at_port(Node::Switch(switch_id), port, queue, packet);
    }

    fn handle_punt_arrive(
        &mut self,
        switch_id: SwitchId,
        packet: Packet,
        ingress_port: PortId,
        reason: PuntReason,
        arrived: SimTime,
    ) {
        self.handle_controller_input(switch_id, packet, ingress_port, reason, false, arrived);
    }

    /// Hand a controller a punt event: a punted packet, or, when `sample`,
    /// a copy of a packet the harness forwards (logged when it was made).
    fn handle_controller_input(
        &mut self,
        switch_id: SwitchId,
        packet: Packet,
        ingress_port: PortId,
        reason: PuntReason,
        sample: bool,
        arrived: SimTime,
    ) {
        let now = self.now;
        if !sample {
            self.log_event(crate::sim_log::LogEvent::PacketPunted {
                switch: switch_id.raw(),
                reason: punt_reason_code(reason),
                packet_id: packet.id.raw(),
            });
        }
        let actions = {
            let switch = match self.switches.get_mut(&switch_id) {
                Some(s) => s,
                None => return,
            };
            if switch.failed || switch.cpu.failed {
                return;
            }
            let event = PuntEvent {
                now,
                arrived,
                switch: switch_id,
                ingress_port,
                reason,
                packet,
            };
            switch.controller.on_punt(event)
        };
        self.dispatch_actions(switch_id, actions);
    }

    fn handle_controller_timer(&mut self, switch_id: SwitchId) {
        let now = self.now;
        let actions = {
            let switch = match self.switches.get_mut(&switch_id) {
                Some(s) => s,
                None => return,
            };
            if switch.failed || switch.cpu.failed {
                return;
            }
            let drops = switch.take_drop_deltas();
            if self.observe.is_some() {
                let counters = switch.counter_snapshot();
                switch.controller.on_timer_observed(now, drops, counters)
            } else {
                switch.controller.on_timer_with_drops(now, drops)
            }
        };
        self.dispatch_actions(switch_id, actions);
    }

    fn dispatch_actions(&mut self, switch_id: SwitchId, actions: Vec<ControllerAction>) {
        for action in actions {
            self.dispatch_action(switch_id, action);
        }
    }

    fn dispatch_action(&mut self, switch_id: SwitchId, mut action: ControllerAction) {
        if matches!(action, ControllerAction::NameLoggingSwitch | ControllerAction::LogWrite { .. }) {
            self.team_log_action(switch_id, action);
            return;
        }
        // The harness shapes the queues in a run where it forwards.
        if self.harness.is_some() && matches!(action, ControllerAction::SetQueueConfig { .. }) {
            return;
        }
        if self.observe.is_some() {
            match self.observe_action(switch_id, action) {
                Some(a) => action = a,
                None => return,
            }
        }
        if let (Some(bps), ControllerAction::InjectPacket { packet, .. }) = (self.inject_budget, &action) {
            let now = self.now;
            let bucket = self.inject_buckets.entry(switch_id).or_insert_with(|| crate::observe::ExportBucket::new(bps, bps));
            if !bucket.take(now, packet.size_bytes) {
                self.log_event(crate::sim_log::LogEvent::ObservationDropped {
                    switch: switch_id.raw(),
                    cap: crate::sim_log::CAP_EXPORT,
                    packet_id: packet.id.raw(),
                });
                return;
            }
        }
        let charged = {
            let switch = match self.switches.get_mut(&switch_id) {
                Some(s) => s,
                None => return,
            };
            switch.config.min_control_msg_size_bytes + action.payload_size()
        };

        let arrive = {
            let switch = self.switches.get_mut(&switch_id).unwrap();
            match switch.config_pipe.schedule(self.now, charged) {
                Some(t) => t,
                None => return,
            }
        };
        // Release pipe quota at arrive time (simplification consistent with punt pipe).
        {
            let switch = self.switches.get_mut(&switch_id).unwrap();
            switch.config_pipe.release(charged);
        }

        self.queue.schedule(
            arrive,
            EventKind::ConfigArrive {
                switch: switch_id,
                action,
            },
        );
    }

    fn handle_config_arrive(&mut self, switch_id: SwitchId, action: ControllerAction) {
        // Inject-packet actions need simulator-level scheduling.
        match action {
            ControllerAction::InjectPacket { packet, port, queue } => {
                self.enqueue_at_port(Node::Switch(switch_id), port, queue.raw(), packet);
            }
            ControllerAction::ScheduleTimer { delay } => {
                let at = self.now + delay;
                self.queue.schedule(at, EventKind::ControllerTimer { switch: switch_id });
            }
            ControllerAction::NameLoggingSwitch | ControllerAction::LogWrite { .. } => {
                // Never sent through the config pipe; see `dispatch_action`.
            }
            ControllerAction::DeclareLink { port, up } => {
                self.log_event(crate::sim_log::LogEvent::LinkDeclared {
                    switch: switch_id.raw(),
                    port: port.raw(),
                    up,
                });
            }
            ControllerAction::InstallTableEntry { table_id, entry } => {
                let event = crate::sim_log::LogEvent::TableEntryInstalled {
                    switch: switch_id.raw(),
                    table: table_id.raw(),
                    entry: crate::sim_log::conv::table_entry_to_wire(&entry),
                };
                if let Some(s) = self.switches.get_mut(&switch_id) {
                    s.apply_action(ControllerAction::InstallTableEntry { table_id, entry });
                }
                self.log_event(event);
            }
            ControllerAction::DeleteTableEntry { table_id, entry_id } => {
                if let Some(s) = self.switches.get_mut(&switch_id) {
                    s.apply_action(ControllerAction::DeleteTableEntry { table_id, entry_id });
                }
                self.log_event(crate::sim_log::LogEvent::TableEntryDeleted {
                    switch: switch_id.raw(),
                    table: table_id.raw(),
                    entry_id: entry_id.raw(),
                });
            }
            ControllerAction::SetQueueConfig { port, config } => {
                let unit_bytes = match self.switches.get_mut(&switch_id) {
                    Some(s) => {
                        s.apply_action(ControllerAction::SetQueueConfig {
                            port,
                            config: config.clone(),
                        });
                        s.packet_size_bytes
                    }
                    None => return,
                };
                self.log_event(crate::sim_log::LogEvent::PortQueuesConfigured {
                    switch: switch_id.raw(),
                    port: port.raw(),
                    discipline: config.discipline.to_u8(),
                    unit_bytes,
                    queues: config
                        .queues
                        .iter()
                        .map(|q| switch_program_types::QueueSpecW {
                            max_packets: q.max_packets,
                            weight: q.weight,
                            drop_threshold_packets: q.drop_threshold_packets.unwrap_or(0),
                        })
                        .collect(),
                });
            }
        }
    }

    /// Helper: cause the controller to fail (data plane keeps running).
    pub fn fail_cpu(&mut self, switch: SwitchId) {
        if let Some(s) = self.switches.get_mut(&switch) {
            s.cpu.failed = true;
        }
        self.log_event(crate::sim_log::LogEvent::CpuFailed { id: switch.raw() });
    }

    /// Helper: cause the entire switch to fail (data plane stops too).
    pub fn fail_switch(&mut self, switch: SwitchId) {
        if let Some(s) = self.switches.get_mut(&switch) {
            s.failed = true;
        }
        self.log_event(crate::sim_log::LogEvent::SwitchFailed { id: switch.raw() });
    }

    /// Mark a link failed. Already-enqueued packets still drain; new
    /// enqueues drop. The switches on either end are told nothing unless
    /// [`Simulator::notify_link_events`] is on — see that field.
    pub fn fail_link(&mut self, link: LinkId) {
        self.set_link_failed(link, true);
    }

    /// Reverse of [`fail_link`]: clear the failed flag. Notifies both
    /// switch endpoints only if [`Simulator::notify_link_events`] is on.
    pub fn restore_link(&mut self, link: LinkId) {
        self.set_link_failed(link, false);
    }

    fn set_link_failed(&mut self, link_id: LinkId, failed: bool) {
        let (src_node, src_port, dst_node, dst_port) = match self.links.get_mut(&link_id) {
            Some(l) => {
                if l.failed == failed {
                    return;
                }
                l.failed = failed;
                (l.src, l.src_port, l.dst, l.dst_port)
            }
            None => return,
        };
        self.log_event(if failed {
            crate::sim_log::LogEvent::LinkFailed { id: link_id.raw() }
        } else {
            crate::sim_log::LogEvent::LinkRestored { id: link_id.raw() }
        });
        if !self.notify_link_events {
            return;
        }
        for (node, port) in [(src_node, src_port), (dst_node, dst_port)] {
            if (node.raw() & 0x8000_0000) != 0 {
                let switch_id = SwitchId::new(node.raw() & 0x7fff_ffff);
                let event = if failed {
                    LinkEvent::Down { port }
                } else {
                    LinkEvent::Up { port }
                };
                self.deliver_link_event(switch_id, event);
            }
        }
    }

    // ---- BGP/trace bookkeeping ----

    fn stamp_trail(&self, packet: &mut Packet, switch: SwitchId) {
        // Trails are recorded for every packet — they're cheap and they
        // power both BGP conformance and the in-band trace mechanism.
        #[cfg(feature = "wasm")]
        let as_id = self.bgp.as_ref().and_then(|b| b.registry.as_for_switch(switch));
        #[cfg(not(feature = "wasm"))]
        let as_id = None;
        packet.trail.hops.push(TrailHop {
            switch,
            as_id,
            link_in: None,
            arrived_at: self.now,
        });
    }

    fn maybe_record_simple_bgp(&mut self, switch: SwitchId, packet: &Packet) {
        if !matches!(packet.kind, PacketKind::SimpleBgp) {
            return;
        }
        #[cfg(feature = "wasm")]
        {
            let now = self.now;
            if let Some(bgp) = &mut self.bgp {
                if let Some(asn) = bgp.registry.as_for_ip(packet.ip_dst) {
                    if let Some(info) = bgp.registry.ases.get(&asn) {
                        if info.border_switch == switch {
                            bgp.handle_simple_bgp(switch, packet, now);
                        }
                    }
                }
            }
        }
        let _ = (switch, packet);
    }

    fn terminate_packet(&mut self, packet: &Packet) {
        self.terminate_packet_with(packet, None);
    }

    fn terminate_packet_with(
        &mut self,
        packet: &Packet,
        drop_reason: Option<crate::trace::DropReason>,
    ) {
        if let Some(m) = self.a4_meter.as_mut() {
            m.record(packet, self.now, drop_reason.is_none());
        }
        // Log the drop (deliveries are logged at the AppDeliver branch).
        if let Some(reason) = drop_reason {
            // Locate "where" — the most recent trail hop's switch.
            let at = match packet.trail.hops.last() {
                Some(h) => crate::sim_log::NodeRefW::Switch(h.switch.raw()),
                None => crate::sim_log::NodeRefW::App(0),
            };
            self.log_event(crate::sim_log::LogEvent::PacketDropped {
                at,
                reason: drop_reason_to_wire(reason),
                packet_id: packet.id.raw(),
            });
        }
        #[cfg(feature = "wasm")]
        {
            self.terminate_packet_inner(packet, drop_reason);
        }
        #[cfg(not(feature = "wasm"))]
        {
            let _ = (packet, drop_reason);
        }
    }

    #[cfg(feature = "wasm")]
    fn terminate_packet_inner(
        &mut self,
        packet: &Packet,
        drop_reason: Option<crate::trace::DropReason>,
    ) {
        let now = self.now;
        if let Some(bgp) = &mut self.bgp {
            bgp.grade_packet(packet, now);
        }
        if let (Some(id), Some(req)) = (
            packet.trail.trace_id,
            packet.trail.trace_requester_as,
        ) {
            // Build a TraceResult from the trail.
            use crate::trace::TraceResult;
            let switch_path: Vec<SwitchId> = packet.trail.hops.iter().map(|h| h.switch).collect();
            let mut as_path: Vec<crate::types::AsId> = Vec::new();
            for h in &packet.trail.hops {
                if let Some(asn) = h.as_id {
                    if as_path.last().copied() != Some(asn) {
                        as_path.push(asn);
                    }
                }
            }
            let link_path: Vec<LinkId> = packet
                .trail
                .hops
                .iter()
                .filter_map(|h| h.link_in)
                .collect();
            let mut per_hop_delay: Vec<core::time::Duration> = Vec::new();
            for w in packet.trail.hops.windows(2) {
                per_hop_delay.push(w[1].arrived_at.saturating_sub(w[0].arrived_at));
            }
            let dropped_at = drop_reason.map(|_| {
                packet
                    .trail
                    .hops
                    .last()
                    .map(|h| Node::Switch(h.switch).as_node_id())
                    .unwrap_or_else(|| Node::Switch(SwitchId::new(0)).as_node_id())
            });
            self.trace.record(TraceResult {
                trace_id: id,
                requester_as: req,
                switch_path,
                as_path,
                link_path,
                per_hop_delay,
                delivered: drop_reason.is_none(),
                dropped_at,
                drop_reason,
            });
        }

        // In-band trace mark: synthesize a TraceReply and queue it on the
        // link from the marking switch's egress port. The reply consumes
        // bandwidth on that link as if the far side had sent it back.
        if let (Some(mark_switch), Some(mark_port)) = (
            packet.trail.trace_mark_switch,
            packet.trail.trace_mark_port,
        ) {
            self.synthesize_trace_reply(packet, mark_switch, mark_port, drop_reason);
        }
    }

    #[cfg(feature = "wasm")]
    fn synthesize_trace_reply(
        &mut self,
        original: &Packet,
        mark_switch: SwitchId,
        mark_port: PortId,
        drop_reason: Option<crate::trace::DropReason>,
    ) {
        // Find the link attached to (mark_switch, mark_port). If there
        // isn't one, the marker chose a port with no neighbor — there's
        // no wire for the reply to come back on, so silently skip.
        let link_id = match self.network.link_at(Node::Switch(mark_switch), mark_port) {
            Some(l) => l,
            None => return,
        };
        let link = match self.links.get(&link_id) {
            Some(l) => l,
            None => return,
        };
        // Determine the other endpoint of the link — whoever is on the
        // far side of `mark_switch` is the "magical" sender of the reply.
        let me_is_src = link.is_src(Node::Switch(mark_switch).as_node_id());
        let (far_node_id, far_port) = link.far_end(me_is_src);
        let far_node = Node::from_node_id(far_node_id);

        // Build the TraceReply payload.
        let hops: Vec<switch_program_types::TraceHopW> = original
            .trail
            .hops
            .iter()
            .map(|h| switch_program_types::TraceHopW {
                switch_id: h.switch.raw(),
                arrived_at_ns: h.arrived_at.as_nanos() as u64,
            })
            .collect();
        let drop_code = match drop_reason {
            None => 0,
            Some(crate::trace::DropReason::Ttl) => 1,
            Some(crate::trace::DropReason::NoRoute) => 2,
            Some(crate::trace::DropReason::NoEgressLink) => 3,
            Some(crate::trace::DropReason::LinkDrop) => 4,
            Some(crate::trace::DropReason::SwitchFailed) => 5,
            Some(crate::trace::DropReason::Recirculation) => 6,
            Some(crate::trace::DropReason::QueueFull) => 7,
            Some(crate::trace::DropReason::Policy) => 8,
            Some(crate::trace::DropReason::WireLoss) => 9,
        };
        let reply_wire = switch_program_types::TraceReplyW {
            mark_switch: mark_switch.raw(),
            mark_port: mark_port.raw(),
            hops,
            delivered: drop_reason.is_none(),
            drop_reason: drop_code,
        };
        let payload = postcard::to_allocvec(&reply_wire).expect("postcard encode");

        // Reply packet: addressed back to the marking switch but its
        // routing is irrelevant — the simulator delivers it directly to
        // the marking switch as ingress on `mark_port`. We give it a
        // realistic size so bandwidth bookkeeping is honest.
        let mut reply = Packet::new(
            crate::types::PacketId::new(0),
            self.now,
            (40 + payload.len()) as u64,
        );
        reply.kind = PacketKind::TraceReply;
        reply.ip_proto = 254;
        reply.ip_ttl = 1;
        reply.payload = payload;
        // The reply must NOT carry the original's trace mark; otherwise
        // its own termination would synthesize another reply.
        reply.trail = crate::packet::PacketTrail::default();

        // Send from the far end's port so the SwitchIngress event lands
        // on the marking switch at `mark_port`.
        self.enqueue_at_port(far_node, far_port, 0, reply);
    }


    /// Notify a switch's controller of a link event.
    pub fn deliver_link_event(&mut self, switch_id: SwitchId, event: LinkEvent) {
        let actions = {
            let switch = match self.switches.get_mut(&switch_id) {
                Some(s) => s,
                None => return,
            };
            if switch.failed || switch.cpu.failed {
                return;
            }
            switch.controller.on_link_event(event)
        };
        self.dispatch_actions(switch_id, actions);
    }

    // ---- the harness ----

    /// Shape the output port `switch:port` so its customers' queue holds
    /// `packets` packets. The harness does this for an incident's queues.
    /// The port keeps its report queue (rule 9).
    pub fn set_port_queue(&mut self, switch: SwitchId, port: PortId, packets: u32) {
        let unit = match self.switches.get(&switch) {
            Some(s) => s.packet_size_bytes,
            None => return,
        };
        self.shape_harness_port(switch, port, Some((packets as u64).saturating_mul(unit)));
    }

    /// Rule 9: give `switch:port` two queues under strict priority. Queue 0
    /// is the customers', `customer_bytes` deep (or as deep as it is now);
    /// queue 1 is the reports', `report_queue_packets` deep. Reports are
    /// served only when no customer packet waits, and they never draw on
    /// the switch's shared buffer.
    pub fn shape_harness_port(&mut self, switch: SwitchId, port: PortId, customer_bytes: Option<u64>) {
        let report_packets = match &self.harness {
            Some(h) => h.report_queue_packets,
            None => return,
        };
        let (unit, customer, report) = {
            let Some(sw) = self.switches.get_mut(&switch) else { return };
            let unit = sw.packet_size_bytes;
            let Some(p) = sw.egress.get_mut(port.raw() as usize) else { return };
            let customer = customer_bytes.unwrap_or_else(|| p.queues.first().map_or(0, |q| q.max_bytes));
            let report = (report_packets as u64).saturating_mul(unit);
            let shape = |max_bytes| crate::egress::QueueShape { max_bytes, weight: 1, drop_threshold_bytes: None };
            p.reconfigure(&[shape(customer), shape(report)], crate::egress::Discipline::StrictPriority, unit);
            (unit, customer, report)
        };
        let packets = |bytes: u64| (bytes / unit.max(1)).min(u32::MAX as u64) as u32;
        self.log_event(crate::sim_log::LogEvent::PortQueuesConfigured {
            switch: switch.raw(),
            port: port.raw(),
            discipline: crate::controller::Discipline::StrictPriority.to_u8(),
            unit_bytes: unit,
            queues: vec![
                switch_program_types::QueueSpecW { max_packets: packets(customer), weight: 1, drop_threshold_packets: 0 },
                switch_program_types::QueueSpecW { max_packets: packets(report), weight: 1, drop_threshold_packets: 0 },
            ],
        });
    }

    /// Rule 9: a report (any packet a program made) leaving a switch in a
    /// run where the harness forwards. It rides in the port's second
    /// queue and never draws on the shared buffer.
    fn rides_behind(&self, node: Node, packet: &Packet) -> bool {
        self.harness.is_some()
            && matches!(node, Node::Switch(_))
            && packet.id.raw() & crate::observe::REPORT_ID_BIT != 0
    }

    /// The port a harness route uses now: its primary, or its backup while
    /// the primary's link is down.
    fn harness_port(&self, switch: SwitchId, route: crate::harness::Route) -> PortId {
        let up = |p: PortId| {
            self.network
                .link_at(Node::Switch(switch), p)
                .and_then(|l| self.links.get(&l))
                .is_some_and(|l| !l.failed)
        };
        match route.backup {
            Some(b) if !up(route.primary) && up(b) => b,
            _ => route.primary,
        }
    }

    /// A packet the harness forwards arrives at a switch. The program's
    /// pipeline runs on a copy: what it writes to counters and registers
    /// stays, what it does to the packet does not, and a punt reaches the
    /// controller as a copy (a sample) through the event budget. The
    /// packet itself leaves by the harness's route after a fixed delay, the
    /// same whatever the program is.
    fn harness_ingress(&mut self, switch_id: SwitchId, port: PortId, mut packet: Packet) {
        let keepalive = matches!(packet.kind, PacketKind::Keepalive);
        if !keepalive {
            if packet.ip_ttl == 0 {
                self.terminate_packet_with(&packet, Some(crate::trace::DropReason::Ttl));
                return;
            }
            packet.ip_ttl -= 1;
        }
        let route = match (self.harness.as_mut(), keepalive) {
            (Some(h), false) => h.route(switch_id, packet.ip_dst),
            _ => None,
        };
        let egress = route.map(|r| self.harness_port(switch_id, r));
        packet.harness_egress = egress;

        // A keepalive ends here, and so does an app's announcement to its
        // own switch.
        let from_app = port.raw() >= crate::world::APP_PORT;
        let ends_here = keepalive || (from_app && egress == Some(port));

        let Some(switch) = self.switches.get_mut(&switch_id) else { return };
        // The program's copy carries nothing fixed per customer and nothing
        // that marks a planted packet: it classifies by traffic alone.
        let mut copy = packet.clone();
        copy.app_id = AppId::default();
        copy.flow_id = Default::default();
        // A planted packet has no sequence number of its own (a receiver
        // never acks it); the program reads it numbered like any stream.
        if copy.id.raw() & plant::PLANT_BIT != 0 {
            copy.seq = Some(copy.id.raw() & ((1 << 40) - 1));
        }
        let outcome = switch.process_pipeline(&mut copy);
        let delay = switch
            .config
            .processing_delay_per_stage
            .saturating_mul(switch.config.stages as u32);
        if let PipelineOutcome::Punt(reason) = outcome {
            self.log_event(crate::sim_log::LogEvent::PacketSampled {
                switch: switch_id.raw(),
                reason: punt_reason_code(reason),
                packet_id: copy.id.raw(),
            });
            self.send_to_controller(switch_id, copy, port, reason, true);
        }

        if ends_here {
            return;
        }
        match egress {
            Some(out) => {
                let done = EventKind::SwitchPipelineDone { switch: switch_id, port: out, queue: 0, packet };
                self.queue.schedule(self.now + delay, done);
            }
            None => self.terminate_packet_with(&packet, Some(crate::trace::DropReason::NoRoute)),
        }
    }

    /// Send a keepalive out of every live switch-to-switch port, except
    /// where an incident holds them back, and come back in a period.
    fn handle_harness_keepalive(&mut self) {
        let Some(period) = self.harness.as_ref().map(|h| h.keepalive_period) else { return };
        let now = self.now;
        let mut ids: Vec<LinkId> = self.links.keys().copied().collect();
        ids.sort_by_key(|l| l.raw());
        for id in ids {
            let link = &self.links[&id];
            if link.failed {
                continue;
            }
            let ends = [(link.src, link.src_port), (link.dst, link.dst_port)];
            let ends: Vec<(SwitchId, PortId)> = ends
                .iter()
                .filter_map(|(n, p)| match Node::from_node_id(*n) {
                    Node::Switch(s) => Some((s, *p)),
                    Node::App(_) => None,
                })
                .collect();
            if ends.len() != 2 {
                continue;
            }
            for (s, p) in ends {
                if self.switches.get(&s).is_none_or(|sw| sw.failed) {
                    continue;
                }
                let h = self.harness.as_mut().expect("checked above");
                if h.silenced(s, p, now) {
                    continue;
                }
                let k = h.keepalive(s, p, now);
                self.enqueue_at_port(Node::Switch(s), p, 0, k);
            }
        }
        self.queue.schedule(now + period, EventKind::HarnessKeepalive);
    }

    /// Where the harness forwards, say which output port refused a packet.
    fn log_port_drop(&mut self, node: Node, port: PortId, packet: &Packet) {
        if let (Some(_), Node::Switch(s)) = (&self.harness, node) {
            self.log_event(crate::sim_log::LogEvent::DroppedAtPort {
                switch: s.raw(),
                port: port.raw(),
                packet_id: packet.id.raw(),
            });
        }
    }

    // ---- log helpers ----

    /// This switch's observation budgets. Only called in an observed run.
    fn observe_of(&mut self, switch_id: SwitchId) -> &mut crate::observe::SwitchObserve {
        let limits = self.observe.expect("observed run");
        self.observe_state
            .entry(switch_id)
            .or_insert_with(|| crate::observe::SwitchObserve::new(&limits))
    }

    /// Send a punt, or a sample, toward the controller. An observed run
    /// spends one of the switch's events on it, or loses it when the
    /// backlog is full; otherwise it travels the punt pipe.
    fn send_to_controller(
        &mut self,
        switch_id: SwitchId,
        packet: Packet,
        port: PortId,
        reason: PuntReason,
        sample: bool,
    ) {
        let now = self.now;
        let at = if self.observe.is_some() {
            let latency = match self.switches.get(&switch_id) {
                Some(s) => s.punt_pipe.latency,
                None => return,
            };
            let at = self.observe_of(switch_id).events.admit(now, latency);
            if at.is_none() {
                self.log_event(crate::sim_log::LogEvent::ObservationDropped {
                    switch: switch_id.raw(),
                    cap: crate::sim_log::CAP_EVENTS,
                    packet_id: packet.id.raw(),
                });
            }
            at
        } else {
            let Some(switch) = self.switches.get_mut(&switch_id) else { return };
            let charged = switch.config.min_control_msg_size_bytes + packet.size_bytes;
            let at = switch.punt_pipe.schedule(now, charged);
            if at.is_some() {
                switch.punt_pipe.release(charged);
            }
            at
        };
        let Some(at) = at else { return };
        let switch = switch_id;
        let arrived = now;
        let event = if sample {
            EventKind::SampleArrive { switch, packet, port, reason, arrived }
        } else {
            EventKind::PuntArrive { switch, packet, port, reason, arrived }
        };
        self.queue.schedule(at, event);
    }

    /// What the observation layer does with a controller action before it
    /// enters the config pipe. An injected packet is sized as a real report
    /// and given its own id, and is sent only if the export budget covers
    /// it. Returns the action to send on, if any.
    fn observe_action(&mut self, switch_id: SwitchId, action: ControllerAction) -> Option<ControllerAction> {
        use crate::sim_log::LogEvent;
        match action {
            ControllerAction::InjectPacket { mut packet, port, queue } => {
                let now = self.now;
                packet.size_bytes = packet
                    .size_bytes
                    .max(crate::observe::REPORT_HEADER_BYTES + packet.payload.len() as u64);
                let max = self.harness.as_ref().map_or(u64::MAX, |h| h.report_max_bytes);
                let o = self.observe_of(switch_id);
                packet.id = crate::types::PacketId::new(o.next_report_id(switch_id.raw()));
                if packet.size_bytes > max {
                    self.log_event(LogEvent::ObservationDropped {
                        switch: switch_id.raw(),
                        cap: crate::sim_log::CAP_REPORT_SIZE,
                        packet_id: packet.id.raw(),
                    });
                    return None;
                }
                let o = self.observe_of(switch_id);
                if !o.export.take(now, packet.size_bytes) {
                    self.log_event(LogEvent::ObservationDropped {
                        switch: switch_id.raw(),
                        cap: crate::sim_log::CAP_EXPORT,
                        packet_id: packet.id.raw(),
                    });
                    return None;
                }
                Some(ControllerAction::InjectPacket { packet, port, queue })
            }
            other => Some(other),
        }
    }

    /// Name the logging switch or write to the team's log, at once: the
    /// log is the logging switch's own, so it costs no pipe and no budget.
    /// Ignored unless the harness forwards.
    fn team_log_action(&mut self, switch_id: SwitchId, action: ControllerAction) {
        use crate::sim_log::LogEvent;
        let Some(h) = self.harness.as_mut() else { return };
        let switch = switch_id.raw();
        let event = match action {
            ControllerAction::NameLoggingSwitch => {
                LogEvent::LoggingSwitchNamed { switch, accepted: h.team_log.name(switch_id) }
            }
            ControllerAction::LogWrite { bytes } => match h.team_log.write(switch_id, &bytes) {
                Ok(()) => LogEvent::TeamLogWritten { switch, bytes },
                Err(why) => LogEvent::TeamLogRefused { switch, len: bytes.len() as u32, why },
            },
            _ => return,
        };
        self.log_event(event);
    }

    /// The team's log so far, in a run where the harness forwards.
    pub fn team_log(&self) -> Option<&[u8]> {
        self.harness.as_ref().map(|h| h.team_log.bytes.as_slice())
    }

    fn log_event(&mut self, event: crate::sim_log::LogEvent) {
        if let Some(l) = self.log.as_mut() {
            l.log(self.now.as_nanos() as u64, event);
        }
    }
}

pub(crate) fn switch_config_to_wire(c: &crate::switch::SwitchConfig)
    -> crate::sim_log::SwitchConfigW {
    crate::sim_log::SwitchConfigW {
        stages: c.stages as u32,
        processing_delay_ns: c.processing_delay_per_stage.as_nanos() as u64,
        recirculation_enabled: c.recirculation_enabled,
        max_recirculations: c.max_recirculations,
        punt_pipe_latency_ns: c.punt_pipe_latency.as_nanos() as u64,
        punt_pipe_bandwidth_bps: c.punt_pipe_bandwidth_bps,
        config_pipe_latency_ns: c.config_pipe_latency.as_nanos() as u64,
        config_pipe_bandwidth_bps: c.config_pipe_bandwidth_bps,
    }
}

pub(crate) fn link_config_to_wire(c: &crate::link::LinkConfig)
    -> crate::sim_log::LinkConfigW {
    crate::sim_log::LinkConfigW {
        latency_ns: c.latency.as_nanos() as u64,
        bandwidth_bps: c.bandwidth_bps,
        queue_capacity_bytes: c.queue_capacity_bytes,
    }
}

pub(crate) fn nodeid_to_wire(n: crate::types::NodeId) -> crate::sim_log::NodeRefW {
    if (n.raw() & 0x8000_0000) != 0 {
        crate::sim_log::NodeRefW::Switch(n.raw() & 0x7fff_ffff)
    } else {
        crate::sim_log::NodeRefW::App(n.raw())
    }
}

pub(crate) fn drop_reason_to_wire(r: crate::trace::DropReason) -> crate::sim_log::DropReasonW {
    match r {
        crate::trace::DropReason::Ttl => crate::sim_log::DropReasonW::Ttl,
        crate::trace::DropReason::NoRoute => crate::sim_log::DropReasonW::NoRoute,
        crate::trace::DropReason::NoEgressLink => crate::sim_log::DropReasonW::NoEgressLink,
        crate::trace::DropReason::LinkDrop => crate::sim_log::DropReasonW::LinkDrop,
        crate::trace::DropReason::SwitchFailed => crate::sim_log::DropReasonW::SwitchFailed,
        crate::trace::DropReason::Recirculation => crate::sim_log::DropReasonW::Recirculation,
        crate::trace::DropReason::QueueFull => crate::sim_log::DropReasonW::QueueFull,
        crate::trace::DropReason::Policy => crate::sim_log::DropReasonW::Policy,
        crate::trace::DropReason::WireLoss => crate::sim_log::DropReasonW::WireLoss,
    }
}

#[allow(dead_code)]
pub(crate) fn program_installed_event(
    sid: SwitchId,
    program: &crate::tinyvm::TinyProgram,
    state: &crate::tinyvm::TinyVmState,
) -> crate::sim_log::LogEvent {
    let (tables, registers, counters) = crate::sim_log::conv::state_snapshots(state);
    crate::sim_log::LogEvent::ProgramInstalled {
        switch: sid.raw(),
        program: crate::sim_log::conv::tiny_program_to_wire(program),
        tables,
        registers,
        counters,
    }
}

fn punt_reason_code(r: PuntReason) -> u32 {
    match r {
        PuntReason::NoRoute => 0,
        PuntReason::TtlExpired => 1,
        PuntReason::Custom(c) => c,
    }
}

pub(crate) fn packet_snapshot(p: &crate::packet::Packet) -> crate::sim_log::PacketSnapshotW {
    crate::sim_log::PacketSnapshotW {
        id: p.id.raw(),
        kind: p.kind.as_u8(),
        size_bytes: p.size_bytes,
        ip_src: p.ip_src.0,
        ip_dst: p.ip_dst.0,
        ip_proto: p.ip_proto,
        ip_ttl: p.ip_ttl,
        label_top: p.labels.last().copied().unwrap_or(0),
        label_depth: p.labels.len() as u32,
        flow_id: p.flow_id.raw(),
        seq: p.seq,
    }
}

impl Default for Simulator {
    fn default() -> Self {
        Self::new()
    }
}
