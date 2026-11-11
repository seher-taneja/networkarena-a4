//! Bought hardware (A4) is lines in the world file: what a switch program
//! sees of it in `input.a4`, and that it works. The lines are the API
//! guide's "Hardware you bought" section, on the full ring.

#![cfg(feature = "wasm")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use competitive_net_sim::sim::Simulator;
use competitive_net_sim::types::SwitchId;
use competitive_net_sim::world::World;
use switch_program_types as wire;

/// A wasm crate under the repo, built once into its own target dir.
fn build(crate_dir: &str) {
    let dir = format!("{}/{crate_dir}", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(env!("CARGO"));
    for (k, _) in std::env::vars() {
        if k.starts_with("CARGO_") {
            cmd.env_remove(k);
        }
    }
    let status = cmd
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .args(["--manifest-path", &format!("{dir}/Cargo.toml"), "--target-dir", &format!("{dir}/target")])
        .status()
        .unwrap_or_else(|e| panic!("cargo build of {crate_dir}: {e}"));
    assert!(status.success());
}

/// The programs the worlds below name: the starter, the Tier-1, peering.
fn programs() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        for c in ["examples/a4_starter", "examples/a4_tier1", "examples/settlements/peering"] {
            build(c);
        }
    });
}

/// A practice world's text (`practice` or `full`), its program paths made
/// absolute so a copy runs from anywhere. In the repo the worlds are under
/// worlds/a4/practice/, in the kit under worlds/practice/.
fn world_text(name: &str) -> String {
    let root = env!("CARGO_MANIFEST_DIR");
    let dir = ["worlds/a4/practice", "worlds/practice"]
        .iter()
        .map(|d| PathBuf::from(root).join(d))
        .find(|d| d.join(format!("{name}.toml")).exists())
        .expect("practice worlds");
    let text = std::fs::read_to_string(dir.join(format!("{name}.toml"))).unwrap();
    text.replace("\"../", &format!("\"{}/../", dir.display()))
}

fn peering(a: u32, b: u32) -> String {
    let p = format!(
        "{}/examples/settlements/peering/target/wasm32-unknown-unknown/release/settle_peering.wasm",
        env!("CARGO_MANIFEST_DIR")
    );
    format!("\n[[a4.agreement]]\nkind = \"peer\"\na = {a}\nb = {b}\nprogram = \"{p}\"\nterms = {{ }}\nmax = 1000\n")
}

/// AS 1 of the full ring buys a microwave link across the ring from its
/// hub 11 (at X0) to X4 and a buffer upgrade on the new switch, and peers
/// with AS 17 and AS 13 there.
fn across_the_ring() -> String {
    let mut w = world_text("full");
    w += "\n[[switch]]\nid = 15\nas_id = 1\nqueue_capacity_bytes = 25000\n";
    w += "\n[[link]]\na = 11\nb = 15\ncapacity_mbps = 5\nlatency_us = 12000\n";
    for hub in [171, 181, 191, 201, 132, 142, 152, 162] {
        w += &format!("\n[[link]]\na = 15\nb = {hub}\ncapacity_mbps = 20\nlatency_us = 1000\n");
    }
    w + &peering(1, 17) + &peering(1, 13)
}

#[test]
fn a_link_across_the_ring_is_in_input_a4() {
    let world = World::from_str(&across_the_ring()).unwrap();
    let mut sim = Simulator::new();
    let handles = world.build(&mut sim).unwrap();
    competitive_net_sim::a4::prepare(&world, &handles, &mut sim, &mut Default::default()).unwrap();
    let info = &sim.a4_info[&11];
    assert!(info.switches.contains(&15));
    assert!(info.internal.iter().any(|l| (l.a, l.b) == (11, 15)));
    // The far switch's ports leave the AS, to every AS at X4; the agreement
    // decides which of them offer routes.
    let far: Vec<_> = info.borders.iter().filter(|b| b.switch == 15).collect();
    assert_eq!(far.len(), 8);
    assert!(far.iter().any(|b| b.peer_as == 17 && b.rel == wire::A4_PEER));
    assert!(far.iter().any(|b| b.peer_as == 18 && b.rel == 0));
    assert!(info.routes.iter().any(|r| r.switch == 15 && r.as_path == [17]));
    assert!(!info.routes.iter().any(|r| r.switch == 15 && r.as_path == [18]));
    // The buffer upgrade: the new switch's ports, and its pool, are larger.
    assert_eq!(sim.a4_info[&15].queue_bytes, 25_000);
    assert_eq!(info.queue_bytes, world.params.queue_capacity_bytes);
    let sw = &sim.switches[&SwitchId::new(15)];
    assert_eq!(sw.buffer_budget, 25_000 * sw.egress.len() as u64);
}

fn run_a4(text: &str, name: &str, args: &[&str]) -> (bool, String) {
    programs();
    let dir = std::env::temp_dir().join(format!("a4-hardware-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, text).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_competitive_net_sim"))
        .arg("run-a4")
        .arg(&path)
        .args(args)
        .output()
        .unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

/// AS `id`'s utility from a run's summary line.
fn utility(out: &str, id: u32) -> i64 {
    let line = out.lines().find(|l| l.starts_with(&format!("  AS {id:>3}  utility"))).unwrap_or_else(|| panic!("{out}"));
    line.split('$').nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap()
}

#[test]
fn a_link_across_the_ring_pays_once_there_is_an_agreement_at_the_far_ixp() {
    // The first 4 s of the run are enough to see it.
    let (ok, base) = run_a4(&world_text("full"), "base", &["--until-ms", "4000"]);
    assert!(ok, "{base}");
    let (ok, bought) = run_a4(&across_the_ring(), "across", &["--until-ms", "4000"]);
    assert!(ok, "{bought}");
    for id in [1, 17, 13] {
        assert!(utility(&bought, id) > utility(&base, id) + 300, "AS {id}\n{base}\n{bought}");
    }
}

#[test]
fn program_memory_is_set_per_as() {
    let row = "[[a4.as]]\nid = 1\n";
    let with = |bytes: u64| world_text("practice").replacen(row, &format!("{row}memory_bytes = {bytes}\n"), 1);
    let (ok, out) = run_a4(&with(64 << 10), "small", &["--until-ms", "200"]);
    assert!(!ok && out.contains("AS 1,") && out.contains("memory"), "a program over its memory does not start\n{out}");
    let (ok, out) = run_a4(&with(256 << 20), "large", &["--until-ms", "200"]);
    assert!(ok, "{out}");
}
