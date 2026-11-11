//! Running an agreement's settlement program (A4).
//!
//! # ABI
//!
//! The module exports a linear `memory` and two functions:
//!
//! ```text
//! // A buffer of `len` bytes the host may write the input into.
//! settle_buffer(len: i32) -> i32
//!
//! // Read a postcard `SettleInputW` at ptr..ptr+len; return what AS `a`
//! // pays AS `b`, in millionths of a dollar (negative: `b` pays `a`).
//! settle(ptr: i32, len: i32) -> i64
//! ```
//!
//! A trap, running out of fuel or memory, or a missing export is a failed
//! settlement: the agreement pays nothing that round.

use switch_program_types as wire;
use wasmtime::TypedFunc;

use crate::detect::{start, trapped};

#[derive(Debug, Clone)]
pub struct SettleLimits {
    /// Fuel for both calls together.
    pub fuel: u64,
    pub max_memory_bytes: usize,
}

impl Default for SettleLimits {
    fn default() -> Self {
        // A round's readings for one pair are kilobytes. Not yet measured
        // against real programs.
        Self { fuel: 50_000_000, max_memory_bytes: 32 * 1024 * 1024 }
    }
}

/// Run the settlement program in `module_bytes` on `input`.
pub fn run(module_bytes: &[u8], input: &wire::SettleInputW, limits: &SettleLimits) -> Result<i64, String> {
    let bytes = postcard::to_allocvec(input).map_err(|e| e.to_string())?;
    let (mut store, instance, memory) = start(module_bytes, limits.fuel, limits.max_memory_bytes)?;
    let buffer: TypedFunc<i32, i32> =
        instance.get_typed_func(&mut store, "settle_buffer").map_err(|_| "missing export: settle_buffer")?;
    let settle: TypedFunc<(i32, i32), i64> =
        instance.get_typed_func(&mut store, "settle").map_err(|_| "missing export: settle")?;
    let len = i32::try_from(bytes.len()).map_err(|_| "input too large")?;
    let ptr = buffer.call(&mut store, len).map_err(|e| trapped(&store, e))?;
    memory
        .write(&mut store, ptr as u32 as usize, &bytes)
        .map_err(|_| format!("settle_buffer gave {ptr}, which does not hold {len} bytes"))?;
    settle.call(&mut store, (ptr, len)).map_err(|e| trapped(&store, e))
}
