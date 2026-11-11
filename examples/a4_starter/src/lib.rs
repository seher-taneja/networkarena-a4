//! The A4 starter switch program. It runs on every switch of your AS.
//!
//! At start-up the simulator tells each switch (in `input.a4`) which AS it
//! is in, the AS's switches and internal links, its border ports, where its
//! own address blocks are, and the routes your routing policy (`policy.rs`,
//! in this same program) chose: for each destination, the one neighbour it uses,
//! offered on every link to that neighbour. The Tier-1 always offers
//! 0.0.0.0/0, which carries everything your policy sent to the Tier-1.
//!
//! What the starter does with that:
//! - traffic for your own blocks goes to them inside the AS;
//! - everything else takes an offered route through the nearest exit
//!   (fewest hops inside your AS), and the Tier-1 only where nothing more
//!   specific is offered. With no agreements that is the Tier-1, at the hub
//!   nearest the switch.
//!
//! What it does not do: notice a failed link (no failover), use backup
//! routes, or queue by class (one plain queue per port). Those are yours.
//! `router.rs` has the helpers: shortest paths inside the AS, the
//! forwarding table, the data-plane program, and table updates.
//! `policy.rs` is the routing policy: the usual rule.
mod policy;
mod router;
use switch_program_sdk::*;

pub struct Starter;

/// Lower is better; `None` refuses the route. `inside` is the number of
/// hops inside your AS from this switch to the border switch of the route.
fn rank(r: &wire::A4RouteW, inside: u32) -> Option<u64> {
    if r.rel == wire::A4_BACKUP {
        return None; // backup routes are for failover, which the starter lacks
    }
    let tier1 = (r.rel == wire::A4_TIER1) as u64;
    Some(r.as_path.len() as u64 * 1_000_000 + tier1 * 1_000 + inside as u64)
}

impl SwitchProgram for Starter {
    fn init(_: u32, _: Vec<u16>) -> (Self, ProgramSetup) {
        (Starter, router::setup(&[], false))
    }
    fn init_with(input: InitInput) -> (Self, ProgramSetup) {
        let Some(info) = input.a4.as_ref() else { return Self::init(0, vec![]) };
        let no_failed_links = Default::default();
        let routes = router::table(info, input.switch_id, &no_failed_links, rank);
        (Starter, router::setup(&routes, false))
    }
}

switch_program!(Starter);
switch_program_sdk::policy_program!(policy::rank, policy::announce);
