//! Running a team's detector, `detect.wasm`, on a team's log.
//!
//! After a run, the detector reads the log the team's logging switch wrote
//! (`crate::team_log`) and answers one bit. It sees nothing else.
//!
//! # ABI
//!
//! The module exports a linear `memory` and two functions:
//!
//! ```text
//! // A buffer of `len` bytes the host may write the log into.
//! detect_buffer(len: i32) -> i32
//!
//! // Read the log at ptr..ptr+len; return 1 for true, 0 for false.
//! detect(ptr: i32, len: i32) -> i32
//! ```
//!
//! Any other return value, a trap, running out of fuel or memory, or a
//! missing export is a failed answer, which is never right.

use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, Trap, TypedFunc};

#[derive(Debug, Clone)]
pub struct DetectLimits {
    /// Fuel for both calls together. The detector runs once per run, so
    /// this is far above a switch program's per-call budget.
    pub fuel: u64,
    pub max_memory_bytes: usize,
}

impl Default for DetectLimits {
    fn default() -> Self {
        // A log is kilobytes; 100M fuel lets a detector make thousands of
        // passes over one. Not yet measured against real detectors.
        Self { fuel: 100_000_000, max_memory_bytes: 64 * 1024 * 1024 }
    }
}

/// What a detector said about one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    True,
    False,
    /// No answer, and why.
    Failed(String),
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::True => write!(f, "true"),
            Answer::False => write!(f, "false"),
            Answer::Failed(why) => write!(f, "failed: {why}"),
        }
    }
}

/// A one-shot program's store state: its memory ceiling, and whether a
/// growth past it was refused. Settlement programs (A4) use it too.
pub(crate) struct Host {
    max_memory_bytes: usize,
    memory_denied: bool,
}

impl Host {
    pub(crate) fn new(max_memory_bytes: usize) -> Self {
        Self { max_memory_bytes, memory_denied: false }
    }
}

impl wasmtime::ResourceLimiter for Host {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        self.memory_denied |= desired > self.max_memory_bytes;
        Ok(desired <= self.max_memory_bytes)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= 1 << 16)
    }
}

/// Run the detector in `module_bytes` on `log`.
pub fn run(module_bytes: &[u8], log: &[u8], limits: &DetectLimits) -> Answer {
    match try_run(module_bytes, log, limits) {
        Ok(1) => Answer::True,
        Ok(0) => Answer::False,
        Ok(n) => Answer::Failed(format!("detect returned {n}, not 1 or 0")),
        Err(why) => Answer::Failed(why),
    }
}

/// Start a one-shot program with `fuel` for all its calls and a memory
/// ceiling: its store, its instance and its exported memory.
pub(crate) fn start(module_bytes: &[u8], fuel: u64, max_memory_bytes: usize) -> Result<(Store<Host>, Instance, Memory), String> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| e.to_string())?;
    let module = Module::new(&engine, module_bytes).map_err(|e| format!("not a wasm module: {e}"))?;
    let mut store = Store::new(&engine, Host::new(max_memory_bytes));
    store.limiter(|h| h);
    store.set_fuel(fuel).map_err(|e| e.to_string())?;
    let instance = Linker::<Host>::new(&engine)
        .instantiate(&mut store, &module)
        .map_err(|e| format!("cannot start: {e}"))?;
    let memory = instance.get_memory(&mut store, "memory").ok_or("missing export: memory")?;
    Ok((store, instance, memory))
}

/// Why a call into a one-shot program failed, in words.
pub(crate) fn trapped(store: &Store<Host>, e: wasmtime::Error) -> String {
    if store.data().memory_denied {
        return format!("over the memory limit of {} bytes", store.data().max_memory_bytes);
    }
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => "out of fuel".into(),
        Some(t) => format!("trap: {t}"),
        None => format!("trap: {e}"),
    }
}

fn try_run(module_bytes: &[u8], log: &[u8], limits: &DetectLimits) -> Result<i32, String> {
    let (mut store, instance, memory) = start(module_bytes, limits.fuel, limits.max_memory_bytes)?;
    let buffer: TypedFunc<i32, i32> =
        instance.get_typed_func(&mut store, "detect_buffer").map_err(|_| "missing export: detect_buffer")?;
    let detect: TypedFunc<(i32, i32), i32> =
        instance.get_typed_func(&mut store, "detect").map_err(|_| "missing export: detect")?;

    let len = i32::try_from(log.len()).map_err(|_| "log too large")?;
    let ptr = buffer.call(&mut store, len).map_err(|e| trapped(&store, e))?;
    memory
        .write(&mut store, ptr as u32 as usize, log)
        .map_err(|_| format!("detect_buffer gave {ptr}, which does not hold {len} bytes"))?;
    detect.call(&mut store, (ptr, len)).map_err(|e| trapped(&store, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module in the text format, with one page of memory. `Module::new`
    /// takes text as well as binary.
    fn wat(body: &str) -> Vec<u8> {
        format!("(module (memory (export \"memory\") 1) {body})").into_bytes()
    }

    const BUFFER_AT_16: &str = "(func (export \"detect_buffer\") (param i32) (result i32) i32.const 16)";

    #[test]
    fn only_one_or_zero_is_an_answer() {
        let m = wat(&format!("{BUFFER_AT_16} (func (export \"detect\") (param i32 i32) (result i32) i32.const 7)"));
        assert_eq!(run(&m, b"x", &DetectLimits::default()), Answer::Failed("detect returned 7, not 1 or 0".into()));
    }

    #[test]
    fn the_detector_reads_the_bytes_where_it_asked_for_them() {
        // True when the log's first byte is 42.
        let m = wat(&format!(
            "{BUFFER_AT_16} (func (export \"detect\") (param i32 i32) (result i32)
                local.get 0 i32.load8_u i32.const 42 i32.eq)"
        ));
        assert_eq!(run(&m, &[42, 0], &DetectLimits::default()), Answer::True);
        assert_eq!(run(&m, &[41, 0], &DetectLimits::default()), Answer::False);
    }

    #[test]
    fn a_buffer_that_does_not_hold_the_log_fails() {
        let m = wat(&format!("{BUFFER_AT_16} (func (export \"detect\") (param i32 i32) (result i32) i32.const 1)"));
        // One 64 KiB page, the buffer at 16: 70 000 bytes do not fit.
        match run(&m, &vec![0; 70_000], &DetectLimits::default()) {
            Answer::Failed(w) => assert!(w.contains("does not hold"), "{w}"),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn a_module_without_the_exports_fails() {
        let m = wat("(func (export \"detect\") (param i32 i32) (result i32) i32.const 1)");
        assert_eq!(run(&m, b"", &DetectLimits::default()), Answer::Failed("missing export: detect_buffer".into()));
        assert!(matches!(run(b"not wasm", b"", &DetectLimits::default()), Answer::Failed(w) if w.starts_with("not a wasm module")));
    }
}
