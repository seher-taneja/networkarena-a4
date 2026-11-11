//! Backup transit: the buyer (`a`) pays the seller (`b`) `fee` each round,
//! plus `price` per Mb of the buyer's own traffic the seller carried
//! between the buyer's two towns (traffic that crossed to the seller and
//! came straight back).
//!
//! Refund, off unless set: if less than `min_on_time` (a fraction) of that
//! traffic arrives on time end to end, the seller pays `refund` back.
use switch_program_sdk::wire::{self, SettleInputW};

fn settle(input: &SettleInputW) -> i64 {
    let carried = input.sum(input.a, input.b, |_| true);
    let mut owed = input.term("fee") + wire::per_mb(input.term("price"), carried.returned);
    let (n, ok) = (carried.returned as i128, carried.returned_on_time as i128);
    if n > 0 && ok * 1_000_000 < input.term("min_on_time") as i128 * n {
        owed -= input.term("refund");
    }
    owed
}

switch_program_sdk::settlement_program!(settle);
