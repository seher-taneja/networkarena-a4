//! The A4 settlement templates (examples/settlements), built with the SDK's
//! `settlement_program!` and run on meter readings by
//! `competitive_net_sim::a4::settle`.

#![cfg(feature = "wasm")]

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use competitive_net_sim::a4::settle::{run, SettleLimits};
use switch_program_types::{ReadingW, SettleInputW};

/// Template `name`, built once.
fn template(name: &str) -> Vec<u8> {
    static BUILT: OnceLock<Mutex<BTreeMap<String, Vec<u8>>>> = OnceLock::new();
    let mut built = BUILT.get_or_init(Default::default).lock().unwrap();
    built
        .entry(name.to_string())
        .or_insert_with(|| {
            let dir = format!("{}/examples/settlements/{name}", env!("CARGO_MANIFEST_DIR"));
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
                .expect("cargo build of a settlement template");
            assert!(status.success(), "template {name} did not build");
            let path = format!("{dir}/target/wasm32-unknown-unknown/release/settle_{name}.wasm");
            std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
        })
        .clone()
}

const MB: u64 = 125_000; // bytes in a megabit
const DOLLAR: i64 = 1_000_000;

fn reading(from: u32, to: u32, epoch: u32, mb: u64, on_time_mb: u64) -> ReadingW {
    ReadingW { from, to, epoch, class: 1, bytes: mb * MB, on_time: on_time_mb * MB, lost: (mb - on_time_mb) * MB, ..Default::default() }
}

fn input(terms: &[(&str, f64)], readings: Vec<ReadingW>) -> SettleInputW {
    SettleInputW {
        a: 1,
        b: 2,
        terms: terms.iter().map(|(k, v)| (k.to_string(), (v * 1e6).round() as i64)).collect(),
        epoch_ms: 1000,
        round_ms: 4000,
        readings,
        outages: Vec::new(),
    }
}

fn settle(name: &str, input: &SettleInputW) -> i64 {
    run(&template(name), input, &SettleLimits::default()).unwrap()
}

#[test]
fn transit_charges_per_mb_in_both_directions() {
    let i = input(&[("price", 2.0)], vec![reading(1, 2, 0, 8, 8), reading(2, 1, 1, 4, 4)]);
    assert_eq!(settle("transit", &i), 24 * DOLLAR);
}

#[test]
fn transit_refund_applies_only_below_the_promised_on_time_share() {
    let terms = [("price", 2.0), ("min_on_time", 0.9), ("refund", 5.0)];
    let good = input(&terms, vec![reading(1, 2, 0, 10, 10)]);
    let bad = input(&terms, vec![reading(1, 2, 0, 10, 5)]);
    assert_eq!(settle("transit", &good), 20 * DOLLAR);
    assert_eq!(settle("transit", &bad), 15 * DOLLAR);
    let unset = input(&[("price", 2.0)], vec![reading(1, 2, 0, 10, 0)]);
    assert_eq!(settle("transit", &unset), 20 * DOLLAR, "refund is off unless set");
}

#[test]
fn peering_pays_nothing() {
    assert_eq!(settle("peering", &input(&[], vec![reading(1, 2, 0, 50, 50)])), 0);
}

#[test]
fn paid_peering_charges_the_side_over_the_ratio_for_the_excess() {
    let terms = [("ratio", 2.0), ("price", 1.0)];
    // a sends 24 Mb, receives 8: 8 Mb over twice what it receives.
    let a_heavy = input(&terms, vec![reading(1, 2, 0, 24, 24), reading(2, 1, 0, 8, 8)]);
    assert_eq!(settle("paid_peering", &a_heavy), 8 * DOLLAR);
    let b_heavy = input(&terms, vec![reading(1, 2, 0, 8, 8), reading(2, 1, 0, 24, 24)]);
    assert_eq!(settle("paid_peering", &b_heavy), -8 * DOLLAR, "b pays a");
    let even = input(&terms, vec![reading(1, 2, 0, 10, 10), reading(2, 1, 0, 10, 10)]);
    assert_eq!(settle("paid_peering", &even), 0);
}

#[test]
fn backup_charges_its_fee_and_per_mb_only_for_the_buyers_traffic_it_carried_back() {
    let terms = [("fee", 20.0), ("price", 1.0), ("min_on_time", 0.9), ("refund", 5.0)];
    // Peering traffic both ways, none of it returned: the fee alone.
    let calm = vec![reading(1, 2, 0, 40, 40), reading(2, 1, 0, 40, 40)];
    assert_eq!(settle("backup", &input(&terms, calm.clone())), 20 * DOLLAR);
    // The buyer's crossing failed: 16 Mb of its own traffic went out to the
    // seller and straight back, all on time. Peering traffic is not billed.
    let mut failed = calm.clone();
    failed.push(ReadingW { returned: 16 * MB, returned_on_time: 16 * MB, ..reading(1, 2, 1, 16, 16) });
    assert_eq!(settle("backup", &input(&terms, failed)), 36 * DOLLAR);
    // Half of it late: below 90% on time, so the refund applies.
    let mut slow = calm;
    slow.push(ReadingW { returned: 16 * MB, returned_on_time: 8 * MB, ..reading(1, 2, 1, 16, 8) });
    assert_eq!(settle("backup", &input(&terms, slow)), 31 * DOLLAR);
}

#[test]
fn a_settlement_that_traps_or_lacks_an_export_fails() {
    let wat = |body: &str| format!("(module (memory (export \"memory\") 1) {body})").into_bytes();
    let buffer = "(func (export \"settle_buffer\") (param i32) (result i32) i32.const 16)";
    let i = input(&[], vec![]);
    let traps = wat(&format!("{buffer} (func (export \"settle\") (param i32 i32) (result i64) unreachable)"));
    let e = run(&traps, &i, &SettleLimits::default()).unwrap_err();
    assert!(e.contains("trap"), "{e}");
    let loops = wat(&format!("{buffer} (func (export \"settle\") (param i32 i32) (result i64) (loop (br 0)) i64.const 0)"));
    assert_eq!(run(&loops, &i, &SettleLimits::default()).unwrap_err(), "out of fuel");
    let missing = wat(buffer);
    assert_eq!(run(&missing, &i, &SettleLimits::default()).unwrap_err(), "missing export: settle");
}
