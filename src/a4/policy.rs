//! A team's routing policy (A4): which route its AS uses to each
//! destination, and which of those routes it announces to each neighbour.
//!
//! The policy lives in the team's switch program. A program that exports
//! none of the three functions below gets the usual policy
//! (`wire::usual_rank`, `wire::usual_announce`).
//!
//! # ABI
//!
//! Beside its switch exports, the module exports a linear `memory` and
//! three functions:
//!
//! ```text
//! // A buffer of `len` bytes the host may write an input into.
//! policy_buffer(len: i32) -> i32
//!
//! // Read a postcard `RankInputW` at ptr..ptr+len; return the index of
//! // the route the AS uses.
//! rank(ptr: i32, len: i32) -> i32
//!
//! // Read a postcard `AnnounceInputW`; return 1 to announce, 0 not to.
//! announce(ptr: i32, len: i32) -> i32
//! ```
//!
//! A trap, running out of fuel or memory, some of the three exports but
//! not all, an index out of range or an answer other than 0 or 1 is a
//! failed policy: the AS gets
//! the usual policy for the whole round.

use switch_program_types as wire;

pub trait Policy {
    fn rank(&mut self, input: &wire::RankInputW) -> Result<usize, String>;
    fn announce(&mut self, input: &wire::AnnounceInputW) -> Result<bool, String>;
}

/// The usual policy.
pub struct Usual;

impl Policy for Usual {
    fn rank(&mut self, input: &wire::RankInputW) -> Result<usize, String> {
        Ok(wire::usual_rank(input))
    }
    fn announce(&mut self, input: &wire::AnnounceInputW) -> Result<bool, String> {
        Ok(wire::usual_announce(input))
    }
}

#[cfg(feature = "wasm")]
pub use wasm_policy::WasmPolicy;

#[cfg(feature = "wasm")]
mod wasm_policy {
    use super::*;
    use crate::detect::{trapped, Host};
    use wasmtime::{Engine, InstancePre, Linker, Module, Store};

    /// Fuel for one call, and the memory ceiling.
    const FUEL_PER_CALL: u64 = 10_000_000;
    const MAX_MEMORY: usize = 32 * 1024 * 1024;

    const EXPORTS: [&str; 3] = ["policy_buffer", "rank", "announce"];

    /// A switch program's policy, compiled once. Every call runs on a
    /// fresh instance, so the policy keeps nothing from one call to the
    /// next, nor from the running switches: its answers depend on its
    /// input alone.
    #[derive(Clone)]
    pub struct WasmPolicy {
        engine: Engine,
        pre: InstancePre<Host>,
    }

    impl WasmPolicy {
        /// The policy in a switch program; `None` if it exports none of
        /// the policy functions, so the AS gets the usual policy.
        pub fn new(module_bytes: &[u8]) -> Result<Option<Self>, String> {
            let mut config = wasmtime::Config::new();
            config.consume_fuel(true);
            let engine = Engine::new(&config).map_err(|e| e.to_string())?;
            let module = Module::new(&engine, module_bytes).map_err(|e| format!("not a wasm module: {e}"))?;
            if !module.exports().any(|e| EXPORTS.contains(&e.name())) {
                return Ok(None);
            }
            let pre = Linker::<Host>::new(&engine).instantiate_pre(&module).map_err(|e| format!("cannot start: {e}"))?;
            let p = Self { engine, pre };
            // Check the exports once, so a broken module fails here.
            let mut store = p.store();
            let instance = p.pre.instantiate(&mut store).map_err(|e| format!("cannot start: {e}"))?;
            instance.get_memory(&mut store, "memory").ok_or("missing export: memory")?;
            for name in EXPORTS {
                instance.get_func(&mut store, name).ok_or_else(|| format!("missing export: {name}"))?;
            }
            Ok(Some(p))
        }

        fn store(&self) -> Store<Host> {
            let mut store = Store::new(&self.engine, Host::new(MAX_MEMORY));
            store.limiter(|h| h);
            store
        }

        fn call<T: serde::Serialize>(&mut self, name: &str, input: &T) -> Result<i32, String> {
            let bytes = postcard::to_allocvec(input).map_err(|e| e.to_string())?;
            let len = i32::try_from(bytes.len()).map_err(|_| "input too large")?;
            let mut store = self.store();
            store.set_fuel(FUEL_PER_CALL).map_err(|e| e.to_string())?;
            let instance = self.pre.instantiate(&mut store).map_err(|e| trapped(&store, e))?;
            let memory = instance.get_memory(&mut store, "memory").ok_or("missing export: memory")?;
            let buffer = instance
                .get_typed_func::<i32, i32>(&mut store, "policy_buffer")
                .map_err(|_| "missing export: policy_buffer")?;
            let f = instance.get_typed_func::<(i32, i32), i32>(&mut store, name).map_err(|_| format!("missing export: {name}"))?;
            let ptr = buffer.call(&mut store, len).map_err(|e| trapped(&store, e))?;
            memory
                .write(&mut store, ptr as u32 as usize, &bytes)
                .map_err(|_| format!("policy_buffer gave {ptr}, which does not hold {len} bytes"))?;
            f.call(&mut store, (ptr, len)).map_err(|e| trapped(&store, e))
        }
    }

    impl Policy for WasmPolicy {
        fn rank(&mut self, input: &wire::RankInputW) -> Result<usize, String> {
            let i = self.call("rank", input)?;
            usize::try_from(i)
                .ok()
                .filter(|&i| i < input.routes.len())
                .ok_or_else(|| format!("rank returned {i} for {} routes", input.routes.len()))
        }
        fn announce(&mut self, input: &wire::AnnounceInputW) -> Result<bool, String> {
            match self.call("announce", input)? {
                0 => Ok(false),
                1 => Ok(true),
                n => Err(format!("announce returned {n}, not 1 or 0")),
            }
        }
    }
}
