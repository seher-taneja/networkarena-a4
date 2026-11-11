//! Your routing policy, which lives in this switch program: the usual
//! rule. A switch program that leaves out `policy_program!` gets exactly
//! this.
//!
//! Before a round, the platform works out every AS's routes together. Over
//! and over, until nothing changes, it asks each AS:
//! - `rank`: of the routes your neighbours announced to you for one
//!   destination AS (and the Tier-1, always last in the list), which do you
//!   use? Your switches then forward that destination's traffic to that
//!   neighbour; which of the links to it they use is up to the switch code.
//! - `announce`: do you tell this neighbour about the route you use? If
//!   you do, it may send you traffic for that destination, and you carry it.
//!
//! You are only offered routes over your signed agreements. Routes through
//! the Tier-1 are never passed on. Every call runs on a fresh copy of your
//! program: the policy keeps nothing between calls and shares nothing with
//! your running switches.
use switch_program_sdk::wire::{self, AnnounceInputW, RankInputW};

/// Gao-Rexford: customer, then peer, then provider (cheapest first), with
/// the Tier-1 last; then the shortest AS path; then the lowest AS path, so
/// the choice never depends on the order of the list.
pub fn rank(input: &RankInputW) -> usize {
    let cost = |rel: u8| match rel {
        wire::A4_CUSTOMER => 1, // a customer pays you to carry it
        wire::A4_PEER => 2,     // free
        _ => 3,                 // a provider charges you
    };
    (0..input.routes.len())
        .min_by_key(|&i| {
            let r = &input.routes[i];
            (r.rel == wire::A4_TIER1, cost(r.rel), r.as_path.len(), r.as_path.clone())
        })
        .unwrap_or(0)
}

/// Gao-Rexford: tell everyone about your own blocks and your customers'
/// (carrying traffic to them earns money); tell your customers about
/// everything; never pass a peer's or provider's route to another peer or
/// provider, or you carry traffic between two other networks for free.
pub fn announce(input: &AnnounceInputW) -> bool {
    matches!(input.route.rel, wire::A4_OWN | wire::A4_CUSTOMER) || input.to_rel == wire::A4_CUSTOMER
}
