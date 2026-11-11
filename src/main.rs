use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use competitive_net_sim::app::{App, TrafficPattern};
use competitive_net_sim::controller::NoopController;
use competitive_net_sim::link::LinkConfig;
use competitive_net_sim::network::Node;
use competitive_net_sim::packet::{IpAddr, PacketField};
use competitive_net_sim::sim::Simulator;
use competitive_net_sim::switch::{Switch, SwitchConfig};
use competitive_net_sim::tinyvm::{
    Instr, MatchActionTable, MatchKind, StageProgram, TableAction, TableEntry, TinyProgram,
    TinyVmState,
};
use competitive_net_sim::types::{AppId, EntryId, MetaKey, PortId, Reg, SwitchId, TableId};

#[derive(Parser, Debug)]
#[command(
    name = "competitive_net_sim",
    about = "Discrete-event packet network simulator",
    version,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a world file: build the topology it declares, run it, and
    /// report what the apps saw.
    RunWorld {
        /// Path to the world's TOML file.
        world: PathBuf,

        /// Optional path to a `.simlog` file.
        #[arg(long)]
        log: Option<PathBuf>,

        /// Override the world's own run length, in milliseconds.
        #[arg(long)]
        until_ms: Option<u64>,

        /// Path to a failure schedule. Without it, no link ever dies —
        /// that is Part 1.
        #[arg(long)]
        failures: Option<PathBuf>,

        /// Multiply every app's offered load: the same world at 0.5×, 1×,
        /// 2× demand.
        #[arg(long, default_value_t = 1.0)]
        load_scale: f64,

        /// Print a report card at the end. Needs an event log, so one is
        /// written to a scratch file when `--log` is not given.
        #[arg(long)]
        score: bool,

        /// With `--score`, also write the card as JSON to this path (the
        /// grading pipeline reads it; the text card is for people).
        #[arg(long)]
        json: Option<PathBuf>,

        /// In a run where the harness forwards, write the team's log (the
        /// bytes the logging switch wrote) to this path.
        #[arg(long)]
        team_log: Option<PathBuf>,

        /// Ignore packets sent before this point. A program is allowed to
        /// not know the topology yet. Defaults to the world's own value.
        #[arg(long)]
        warmup_ms: Option<u64>,

        /// Whole-run delivery floor, as a percentage. Defaults to the
        /// world's own value.
        #[arg(long)]
        delivery_floor_pct: Option<f64>,

        /// Path to a `.wasm` switch program to install on every switch.
        /// Without it the switches run empty and forward nothing — the
        /// hello-world baseline.
        #[cfg(feature = "wasm")]
        #[arg(long)]
        program: Option<PathBuf>,
    },

    /// Run an A4 world: every AS runs the program its `[[a4.as]]` row
    /// names, the Tier-1 runs its own, and each AS gets a statement.
    #[cfg(feature = "wasm")]
    RunA4 {
        world: PathBuf,
        #[arg(long)]
        until_ms: Option<u64>,
        #[arg(long)]
        failures: Option<PathBuf>,
        #[arg(long, default_value_t = 1.0)]
        load_scale: f64,
        /// Write every AS's statement as JSON to this path.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Run this switch program in the AS given by `--as`, in place of
        /// the one the world file names.
        #[arg(long, requires = "seat")]
        program: Option<PathBuf>,
        #[arg(long = "as", id = "seat", value_name = "AS")]
        seat: Option<u32>,
        /// Write the run's replay (.simlog) here, for the viewer.
        #[arg(long)]
        log: Option<PathBuf>,
    },

    /// Generate world files. Same seed, same bytes, forever.

    /// Generate failure schedules for a world. Separate seed from the
    /// world's, so one topology can host many schedules.

    /// Score a `.simlog` that already exists, and print the report card.
    Score {
        /// Path to the `.simlog` file.
        log: PathBuf,

        /// The world the run was produced from.
        #[arg(long)]
        world: PathBuf,

        /// The failure schedule, if the run had one. Only the recovery
        /// budget is read from it; the events come from the log.
        #[arg(long)]
        failures: Option<PathBuf>,

        /// Ignore packets sent before this point. Defaults to the
        /// world's own value.
        #[arg(long)]
        warmup_ms: Option<u64>,

        /// How long a program gets to recover after each link event.
        /// Taken from the schedule when one is given.
        #[arg(long)]
        recovery_budget_ms: Option<u64>,

        /// Whole-run delivery floor, as a percentage. Defaults to the
        /// world's own value.
        #[arg(long)]
        delivery_floor_pct: Option<f64>,
    },

    /// Run a detector (`detect.wasm`) on a team's log, and print its
    /// answer: `true`, `false`, or why it gave none.
    #[cfg(feature = "wasm")]
    Detect {
        /// The detector.
        program: PathBuf,
        /// The team's log, as `run-world --team-log` writes it.
        log: PathBuf,
    },


    /// Run the built-in demo topology (one app pair through one switch).
    Simulate {
        /// Optional path to a `.simlog` file. When set, every topology
        /// change, link/switch state change, packet ingress/egress,
        /// table edit, and program install is recorded.
        #[arg(long)]
        log: Option<PathBuf>,

        /// How long to run, in milliseconds of simulated time.
        #[arg(long, default_value_t = 100)]
        until_ms: u64,
    },
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Simulate { log, until_ms } => run_demo(log, until_ms),
        #[cfg(feature = "wasm")]
        Cmd::Detect { program, log } => detect(program, log),
        Cmd::Score {
            log,
            world,
            failures,
            warmup_ms,
            recovery_budget_ms,
            delivery_floor_pct,
        } => score_log(
            log,
            world,
            failures,
            warmup_ms,
            recovery_budget_ms,
            delivery_floor_pct,
            None,
        ),
        #[cfg(feature = "wasm")]
        Cmd::RunA4 { world, until_ms, failures, load_scale, json, program, seat, log } => {
            if seat.is_some() && program.is_none() {
                return Err(std::io::Error::other("--as needs --program"));
            }
            run_a4(world, until_ms, failures, load_scale, json, seat, program, log)
        }
        #[cfg(feature = "wasm")]
        Cmd::RunWorld {
            world,
            log,
            until_ms,
            failures,
            load_scale,
            score,
            json,
            team_log,
            warmup_ms,
            delivery_floor_pct,
            program,
        } => run_world(
            world,
            log,
            until_ms,
            failures,
            load_scale,
            score,
            json,
            team_log,
            warmup_ms,
            delivery_floor_pct,
            program,
        ),
        #[cfg(not(feature = "wasm"))]
        Cmd::RunWorld {
            world,
            log,
            until_ms,
            failures,
            load_scale,
            score,
            json,
            team_log,
            warmup_ms,
            delivery_floor_pct,
        } => run_world(
            world,
            log,
            until_ms,
            failures,
            load_scale,
            score,
            json,
            team_log,
            warmup_ms,
            delivery_floor_pct,
        ),
    }
}



#[allow(clippy::too_many_arguments)]
fn run_world(
    path: PathBuf,
    log: Option<PathBuf>,
    until_ms: Option<u64>,
    failures: Option<PathBuf>,
    load_scale: f64,
    score: bool,
    json: Option<PathBuf>,
    team_log: Option<PathBuf>,
    warmup_ms: Option<u64>,
    delivery_floor_pct: Option<f64>,
    #[cfg(feature = "wasm")] program: Option<PathBuf>,
) -> std::io::Result<()> {
    let world = competitive_net_sim::world::World::load(&path).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;

    // The scorer reads a log, so asking for a score means writing one.
    // When the caller did not name a file we put it in the temp directory
    // and delete it afterwards. The name carries the pid: two processes
    // scoring the same world at once (a parallel sweep) would otherwise
    // share one file and read each other's half-written bytes.
    let scratch = std::env::temp_dir().join(format!(
        "{}-{}-score.simlog",
        world.world.name,
        std::process::id()
    ));
    let log_path: Option<PathBuf> = match (&log, score) {
        (Some(p), _) => Some(p.clone()),
        (None, true) => Some(scratch.clone()),
        (None, false) => None,
    };

    let mut sim = Simulator::new();
    // Before logging starts: the log's version says whether the run has an
    // observation layer.
    sim.observe = world.observe.as_ref().map(|o| o.limits());
    if let Some(p) = log_path.as_ref() {
        sim.start_logging(p)?;
    }
    let handles = world.build_with_load(&mut sim, load_scale).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;

    #[cfg(feature = "wasm")]
    if let Some(prog) = program.as_ref() {
        let bytes = std::fs::read(prog)?;
        for as_id in &handles.as_ids {
            sim.install_program(
                competitive_net_sim::types::OwnerId::new(*as_id),
                &bytes,
                competitive_net_sim::wasm::WasmLimits::default(),
            )
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("installing {}: {e:?}", prog.display()),
                )
            })?;
        }
        // Bootstrap one controller timer per switch, in switch-id order
        // (the team's log is named by the first switch to ask); the
        // program re-schedules itself from there.
        let mut ids: Vec<u32> = world.switches.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        for id in ids {
            sim.schedule_controller_timer(SwitchId::new(id), Duration::ZERO);
        }
    }

    // A failure schedule, if one was given. The world is the topology;
    // the schedule is what happens to it. They are separate files so one
    // world can host many schedules.
    let schedule = match failures.as_ref() {
        None => None,
        Some(p) => {
            let s = competitive_net_sim::failures::Schedule::load(p).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            s.validate(&world).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            Some(s)
        }
    };

    // A schedule declares the run length it needs. Running past it pads
    // the delivery rate with clean time and flatters the result, so the
    // schedule wins over the world's own duration unless told otherwise.
    let until = match (until_ms, schedule.as_ref()) {
        (Some(ms), _) => Duration::from_millis(ms),
        (None, Some(s)) => Duration::from_millis(s.schedule.duration_ms),
        (None, None) => world.params.duration(),
    };

    if let Some(sched) = schedule.as_ref() {
        use competitive_net_sim::failures::Action;
        for (at, (a, b), action) in sched.events() {
            let at = Duration::from_millis(at);
            if at > until {
                break;
            }
            sim.run_until(at);
            let link = handles.links[&(a, b)];
            match action {
                Action::Down => sim.fail_link(link),
                Action::Up => sim.restore_link(link),
            }
            println!(
                "  t={:>6} ms  link {a}-{b} {}",
                at.as_millis(),
                match action {
                    Action::Down => "DOWN",
                    Action::Up => "UP",
                }
            );
        }
    }
    sim.run_until(until);

    if let Some(path) = &team_log {
        let bytes = sim.team_log().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "--team-log needs a world with a [harness] section")
        })?;
        std::fs::write(path, bytes)?;
        println!("team log: {} bytes -> {}", bytes.len(), path.display());
    }

    println!(
        "world '{}': {} switches, {} links, {} apps, ran {} ms",
        world.world.name,
        world.switches.len(),
        handles.link_order.len(),
        world.apps.len(),
        until.as_millis()
    );
    let mut sent = 0u64;
    let mut recv = 0u64;
    // By app number, so two runs print the same lines in the same order.
    let mut by_id: Vec<_> = sim.apps.iter().collect();
    by_id.sort_by_key(|(id, _)| id.raw());
    for (id, app) in by_id {
        sent += app.metrics.packets_sent;
        recv += app.metrics.packets_received;
        println!(
            "  app {:>3}  sent {:>6}  received {:>6}",
            id.raw(),
            app.metrics.packets_sent,
            app.metrics.packets_received
        );
    }
    let rate = if sent == 0 {
        0.0
    } else {
        100.0 * recv as f64 / sent as f64
    };
    println!("  total: sent {sent}, received {recv} ({rate:.2}%)");
    if let Some(p) = log.as_ref() {
        println!("event log: {}", p.display());
    }

    // A program that died mid-run has already said so on stderr, at the
    // moment it happened. Repeat the count here so it cannot be lost in
    // the scroll above a failing report card.
    let stopped = sim
        .switches
        .values()
        .filter(|s| s.controller.failure().is_some())
        .count();
    if stopped > 0 {
        eprintln!(
            "\n{stopped} of {} switch programs stopped early.\n\
             \x20 Those switches kept forwarding on the routes they already had;\n\
             \x20 nothing updated them after that. The delivery number below is a\n\
             \x20 symptom -- the cause is in the 'program failed' lines above.",
            sim.switches.len()
        );
    }


    if score {
        // Dropping the logger flushes it. Nothing may read the file
        // before that happens.
        sim.log = None;
        let log_path = log_path.expect("score implies a log");
        let budget = schedule
            .as_ref()
            .map(|s| s.schedule.recovery_budget_ms)
            .unwrap_or(competitive_net_sim::failures::DEFAULT_RECOVERY_BUDGET_MS);
        // Grading parameters live in the world file. The flags override
        // them, for experiments.
        let params = competitive_net_sim::score::ScoreParams {
            warmup_ms: warmup_ms.unwrap_or(world.params.warmup_ms),
            recovery_budget_ms: budget,
            delivery_floor: delivery_floor_pct
                .unwrap_or(world.params.delivery_floor_pct)
                / 100.0,
            ..Default::default()
        };
        #[cfg(feature = "wasm")]
        let prog_name = program.as_ref().map(|p| p.display().to_string());
        #[cfg(not(feature = "wasm"))]
        let prog_name: Option<String> = None;
        // A closed-loop world is graded on the A2 floors; an open-loop
        // one on the A1 criteria.
        let (card, passed, as_json) = match world.workload {
            // A run where the harness forwards has no floors; its eggs are
            // judged by the detector, not here.
            _ if world.harness.is_some() => {
                return Err(std::io::Error::other("a harness run has no report card; run it without --score"));
            }
            competitive_net_sim::world::Workload::A4 { .. } => {
                return Err(std::io::Error::other("an A4 world is run with run-a4"));
            }
            competitive_net_sim::world::Workload::Mixed { .. } => {
                let r = competitive_net_sim::floors::score_file(
                    &log_path,
                    &world,
                    prog_name,
                    load_scale,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                let passed = r.status() == competitive_net_sim::floors::Status::Pass;
                (r.render(), passed, r.to_json())
            }
            competitive_net_sim::world::Workload::AllPairsCbr { .. } => {
                let r = competitive_net_sim::score::score_file(
                    &log_path,
                    &world,
                    schedule.as_ref(),
                    prog_name,
                    &params,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                let passed = r.status() == competitive_net_sim::score::Status::Pass;
                // The A1 card has no JSON form; the pipeline that grades it
                // reads the text. Say so rather than write nothing.
                let j = serde_json::json!({
                    "assignment": "a1",
                    "passed": passed,
                    "status": if passed { "PASS" } else { "FAIL" },
                });
                (r.render(), passed, j)
            }
        };
        if let Some(path) = &json {
            std::fs::write(path, serde_json::to_string_pretty(&as_json)? + "\n")?;
        }
        println!();
        print!("{card}");
        if log.is_none() {
            let _ = std::fs::remove_file(&log_path);
        }
        if !passed {
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Score a `.simlog` that already exists.
#[allow(clippy::too_many_arguments)]
fn score_log(
    log: PathBuf,
    world_path: PathBuf,
    failures: Option<PathBuf>,
    warmup_ms: Option<u64>,
    recovery_budget_ms: Option<u64>,
    delivery_floor_pct: Option<f64>,
    program: Option<String>,
) -> std::io::Result<()> {
    let invalid = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidData, m);

    let world = competitive_net_sim::world::World::load(&world_path)
        .map_err(|e| invalid(e.to_string()))?;
    let schedule = match failures.as_ref() {
        None => None,
        Some(p) => {
            let s = competitive_net_sim::failures::Schedule::load(p)
                .map_err(|e| invalid(e.to_string()))?;
            Some(s)
        }
    };

    let budget = recovery_budget_ms
        .or_else(|| schedule.as_ref().map(|s| s.schedule.recovery_budget_ms))
        .unwrap_or(competitive_net_sim::failures::DEFAULT_RECOVERY_BUDGET_MS);
    let params = competitive_net_sim::score::ScoreParams {
        warmup_ms: warmup_ms.unwrap_or(world.params.warmup_ms),
        recovery_budget_ms: budget,
        delivery_floor: delivery_floor_pct
            .unwrap_or(world.params.delivery_floor_pct)
            / 100.0,
        ..Default::default()
    };
    let report = competitive_net_sim::score::score_file(
        &log,
        &world,
        schedule.as_ref(),
        program,
        &params,
    )
    .map_err(|e| invalid(e.to_string()))?;
    print!("{}", report.render());
    if report.status() != competitive_net_sim::score::Status::Pass {
        std::process::exit(1);
    }
    Ok(())
}

fn run_demo(log: Option<PathBuf>, until_ms: u64) -> std::io::Result<()> {
    let mut sim = Simulator::new();
    if let Some(path) = log.as_ref() {
        sim.start_logging(path)?;
    }

    let app_a = AppId::new(1);
    let app_b = AppId::new(2);
    let switch_id = SwitchId::new(0);

    let a = App::new(
        app_a,
        IpAddr(0x0a000001),
        32,
        IpAddr(0x0a000002),
        32,
        TrafficPattern::ConstantBitrate {
            interval: Duration::from_millis(10),
            size_bytes: 100,
        },
    );
    let b = App::new(
        app_b,
        IpAddr(0x0a000002),
        32,
        IpAddr(0x0a000001),
        32,
        TrafficPattern::BulkTransfer {
            total_bytes: 0,
            sent_bytes: 0,
            pacing: Duration::ZERO,
            size_bytes: 0,
        },
    );

    let mut state = TinyVmState::default();
    let mut table = MatchActionTable::new(TableId::new(1), MatchKind::Exact, 16);
    table
        .install(TableEntry {
            id: EntryId::new(1),
            key: 0x0a000002,
            prefix_len: 32,
            priority: 0,
            action: TableAction::SetEgress {
                port: PortId::new(1),
            },
        })
        .unwrap();
    state.tables.push(table);

    let prog = TinyProgram {
        stages: vec![StageProgram {
            instrs: vec![
                Instr::LoadField {
                    dst: Reg::new(0),
                    field: PacketField::IpDst,
                },
                Instr::TableLookup {
                    table_id: TableId::new(1),
                    key_reg: Reg::new(0),
                    result_meta: MetaKey::new(0),
                },
            ],
            max_alu_ops: 0,
            max_memory_accesses: 1,
        }],
    };

    let switch = Switch::new(
        SwitchConfig::defaults(switch_id),
        prog,
        state,
        Box::new(NoopController),
        4,
        1 << 16,
    );

    sim.add_switch(switch);
    sim.add_app(a);
    sim.add_app(b);

    sim.connect(
        Node::App(app_a),
        PortId::new(0),
        Node::Switch(switch_id),
        PortId::new(0),
        LinkConfig {
            latency: Duration::from_micros(100),
            bandwidth_bps: 1_000_000_000,
            queue_capacity_bytes: 1 << 16,
        },
    );
    sim.connect(
        Node::Switch(switch_id),
        PortId::new(1),
        Node::App(app_b),
        PortId::new(0),
        LinkConfig {
            latency: Duration::from_micros(100),
            bandwidth_bps: 1_000_000_000,
            queue_capacity_bytes: 1 << 16,
        },
    );

    sim.run_until(Duration::from_millis(until_ms));

    let metrics_a = &sim.apps[&app_a].metrics;
    let metrics_b = &sim.apps[&app_b].metrics;
    println!(
        "A: sent {} packets, B: received {} packets, avg delay {:?}",
        metrics_a.packets_sent, metrics_b.packets_received, metrics_b.avg_delay
    );
    if let Some(p) = log {
        println!("event log: {}", p.display());
    }
    Ok(())
}

/// Run one detector on one log and print the answer. Exits 2 when the
/// detector gave none.
#[cfg(feature = "wasm")]
fn detect(program: PathBuf, log: PathBuf) -> std::io::Result<()> {
    let module = std::fs::read(&program)?;
    let bytes = std::fs::read(&log)?;
    let answer = competitive_net_sim::detect::run(&module, &bytes, &Default::default());
    println!("{answer}");
    if matches!(answer, competitive_net_sim::detect::Answer::Failed(_)) {
        std::process::exit(2);
    }
    Ok(())
}


#[cfg(feature = "wasm")]
fn run_a4(
    path: PathBuf,
    until_ms: Option<u64>,
    failures: Option<PathBuf>,
    load_scale: f64,
    json: Option<PathBuf>,
    seat: Option<u32>,
    program: Option<PathBuf>,
    log: Option<PathBuf>,
) -> std::io::Result<()> {
    use competitive_net_sim::types::OwnerId;
    let bad = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    let world = competitive_net_sim::world::World::load(&path).map_err(|e| bad(e.to_string()))?;
    let spec = world.a4.clone().ok_or_else(|| bad("no [a4] section".into()))?;
    let base = path.parent().unwrap_or(std::path::Path::new("."));
    let started = std::time::Instant::now();
    let mut sim = Simulator::new();
    if let Some(p) = log.as_ref() {
        sim.start_logging(p)?;
    }
    let handles = world.build_with_load(&mut sim, load_scale).map_err(|e| bad(e.to_string()))?;
    if let Some(as_id) = seat {
        if !spec.ases.iter().any(|a| a.id == as_id) {
            return Err(bad(format!("no AS {as_id} in this world")));
        }
    }
    // Each AS's switch program: the one given for --as, else its row's.
    let mut programs: Vec<(u32, PathBuf)> = spec.ases.iter().map(|a| (a.id, base.join(&a.program))).collect();
    if let (Some(as_id), Some(prog)) = (seat, program) {
        programs.iter_mut().find(|(a, _)| *a == as_id).unwrap().1 = prog;
    }
    let mut cache: std::collections::BTreeMap<PathBuf, Vec<u8>> = std::collections::BTreeMap::new();
    for (_, prog) in &programs {
        if !cache.contains_key(prog) {
            cache.insert(prog.clone(), std::fs::read(prog).map_err(|e| bad(format!("{}: {e}", prog.display())))?);
        }
    }
    // Each AS's routing policy is in its switch program; a program without
    // the policy exports gets the usual one. A policy that cannot start
    // counts as failed.
    let mut policies: std::collections::BTreeMap<u32, Box<dyn competitive_net_sim::a4::policy::Policy>> =
        std::collections::BTreeMap::new();
    let mut no_start: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    let compiled: std::collections::BTreeMap<&PathBuf, _> =
        cache.iter().map(|(p, bytes)| (p, competitive_net_sim::a4::policy::WasmPolicy::new(bytes))).collect();
    for (as_id, prog) in &programs {
        match &compiled[prog] {
            Ok(Some(p)) => {
                policies.insert(*as_id, Box::new(p.clone()));
            }
            Ok(None) => {}
            Err(e) => {
                no_start.insert(*as_id, e.clone());
            }
        }
    }
    let mut routing =
        competitive_net_sim::a4::prepare(&world, &handles, &mut sim, &mut policies).map_err(|e| bad(e.to_string()))?;
    routing.failed.extend(no_start);
    // A4 programs read a whole AS's routes at init and install many entries.
    let limits = competitive_net_sim::wasm::WasmLimits {
        fuel_per_call: 400_000_000,
        max_output_bytes: 1 << 20,
        max_table_entries: 1 << 16,
        ..Default::default()
    };
    programs.push((spec.tier1_as, base.join(&spec.tier1_program)));
    for (as_id, prog) in &programs {
        if !cache.contains_key(prog) {
            cache.insert(prog.clone(), std::fs::read(prog).map_err(|e| bad(format!("{}: {e}", prog.display())))?);
        }
        let mut limits = limits.clone();
        if let Some(m) = spec.ases.iter().find(|a| a.id == *as_id).and_then(|a| a.memory_bytes) {
            limits.max_memory_bytes = m;
        }
        sim.install_program(OwnerId::new(*as_id), &cache[prog], limits)
            .map_err(|e| bad(format!("AS {as_id}, {}: {e:?}", prog.display())))?;
    }
    let mut ids: Vec<u32> = world.switches.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    for id in ids {
        sim.schedule_controller_timer(SwitchId::new(id), Duration::ZERO);
    }
    let loaded = started.elapsed();
    let schedule = match failures.as_ref() {
        None => None,
        Some(p) => Some(competitive_net_sim::failures::Schedule::load(p).map_err(|e| bad(e.to_string()))?),
    };
    let until = Duration::from_millis(until_ms.unwrap_or(world.params.duration_ms));
    if let Some(sched) = schedule.as_ref() {
        use competitive_net_sim::failures::Action;
        for (at, (a, b), action) in sched.events() {
            let at = Duration::from_millis(at);
            if at > until {
                break;
            }
            sim.run_until(at);
            let link = handles.links[&(a, b)];
            match action {
                Action::Down => sim.fail_link(link),
                Action::Up => sim.restore_link(link),
            }
        }
    }
    sim.run_until(until);
    sim.log = None; // flushes the replay
    let stopped = sim.switches.values().filter(|s| s.controller.failure().is_some()).count();
    let mut settlements: std::collections::BTreeMap<String, Vec<u8>> = std::collections::BTreeMap::new();
    for g in &spec.agreements {
        if !settlements.contains_key(&g.program) {
            let p = base.join(&g.program);
            settlements.insert(g.program.clone(), std::fs::read(&p).map_err(|e| bad(format!("{}: {e}", p.display())))?);
        }
    }
    let settled = competitive_net_sim::a4::settle_all(&world, &sim, schedule.as_ref(), until.as_millis() as u64, &settlements);
    let mut st = competitive_net_sim::a4::statement(&world, &sim, &settled);
    for s in &mut st {
        s.routes_unsettled = !routing.settled;
        s.policy_failed = routing.failed.get(&s.as_id).cloned();
    }
    println!(
        "A4 world '{}': {} switches, {} ASes, ran {} ms in {:.1} s (load {:.1} s); {stopped} programs stopped",
        world.world.name,
        world.switches.len(),
        spec.ases.len(),
        until.as_millis(),
        started.elapsed().as_secs_f64(),
        loaded.as_secs_f64()
    );
    for s in &st {
        let on: f64 = s.on_time_mb.values().sum();
        let off: f64 = s.offered_mb.values().sum();
        println!(
            "  AS {:>3}  utility ${:>7.0}  value ${:>6.0} (homes {:>5.0}, companies {:>4.0})  in {:>5.0}  out {:>5.0}  Tier-1 {:>5.0}  home traffic on time {:>5.1}%",
            s.as_id,
            s.utility,
            s.value,
            s.homes.values().sum::<f64>(),
            s.companies.values().sum::<f64>(),
            s.paid_by.values().sum::<f64>(),
            s.paid_to.values().sum::<f64>(),
            s.tier1_fee,
            if off > 0.0 { 100.0 * on / off } else { 0.0 }
        );
    }
    if routing.settled {
        println!("  routes settled after {} passes", routing.passes);
    } else {
        println!("  routes did not settle: used pass {} of {}", routing.passes, competitive_net_sim::a4::MAX_PASSES);
    }
    for (as_id, why) in &routing.failed {
        println!("  AS {as_id}'s policy failed, so it used the usual one: {why}");
    }
    for s in settled.iter().filter(|s| s.error.is_some()) {
        println!("  agreement {}-{} paid nothing: {}", s.a, s.b, s.error.as_deref().unwrap_or(""));
    }
    println!("  drops by link: {:?}", competitive_net_sim::a4::drops(&world, &sim));
    if let Some(p) = json {
        std::fs::write(p, serde_json::to_string_pretty(&st)? + "\n")?;
    }
    Ok(())
}
