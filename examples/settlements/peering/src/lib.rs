//! Peering: no payment. Each side carries traffic to the other's customers.
use switch_program_sdk::wire::SettleInputW;

fn settle(_input: &SettleInputW) -> i64 {
    0
}

switch_program_sdk::settlement_program!(settle);
