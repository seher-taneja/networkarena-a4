//! Paid peering: if one side sends more than `ratio` times what it
//! receives, it pays `price` per Mb for the excess.
use switch_program_sdk::wire::{self, SettleInputW};

fn settle(input: &SettleInputW) -> i64 {
    let a_sends = input.sum(input.a, input.b, |_| true).bytes as i128;
    let b_sends = input.sum(input.b, input.a, |_| true).bytes as i128;
    let ratio = input.term("ratio") as i128;
    // Excess over ratio x received; the ratio is in millionths.
    let excess = |sent: i128, got: i128| ((sent * 1_000_000 - ratio * got) / 1_000_000).max(0) as u64;
    wire::per_mb(input.term("price"), excess(a_sends, b_sends)) - wire::per_mb(input.term("price"), excess(b_sends, a_sends))
}

switch_program_sdk::settlement_program!(settle);
