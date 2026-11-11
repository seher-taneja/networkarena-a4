//! Transit: the customer (`a`) pays the provider (`b`) `price` per Mb
//! crossing between them, in either direction.
//!
//! Refund, off unless set: if less than `min_on_time` (a fraction) of that
//! traffic arrives on time end to end, the provider pays `refund` back.
use switch_program_sdk::wire::{self, SettleInputW};

fn settle(input: &SettleInputW) -> i64 {
    let (up, down) = (input.sum(input.a, input.b, |_| true), input.sum(input.b, input.a, |_| true));
    let bytes = up.bytes + down.bytes;
    let mut owed = wire::per_mb(input.term("price"), bytes);
    let on_time = (up.on_time + down.on_time) as i128;
    if bytes > 0 && on_time * 1_000_000 < input.term("min_on_time") as i128 * bytes as i128 {
        owed -= input.term("refund");
    }
    owed
}

switch_program_sdk::settlement_program!(settle);
