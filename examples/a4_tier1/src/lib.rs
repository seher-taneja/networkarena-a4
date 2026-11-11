//! The Tier-1's program. It is part of the world, not yours: you never
//! change it. It delivers each AS's blocks on the link that AS named
//! nearest them (lowest MED), and external content from its own ports.
//! It never peers.
#[path = "../../a4_starter/src/router.rs"]
mod router;
use switch_program_sdk::*;

pub struct Tier1;

impl SwitchProgram for Tier1 {
    fn init(_: u32, _: Vec<u16>) -> (Self, ProgramSetup) {
        (Tier1, router::setup(&[], false))
    }
    fn init_with(input: InitInput) -> (Self, ProgramSetup) {
        let Some(info) = input.a4.as_ref() else { return Self::init(0, vec![]) };
        let none = Default::default();
        let routes = router::table(info, input.switch_id, &none, |r, _| {
            (r.rel == wire::A4_CUSTOMER).then_some(r.med as u64)
        });
        (Tier1, router::setup(&routes, false))
    }
}

switch_program!(Tier1);
