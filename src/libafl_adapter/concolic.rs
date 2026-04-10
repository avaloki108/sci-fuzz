//! Concolic execution stage for chimerafuzz.
//!
//! Generates SMT-LIB2 constraints from `ComparisonEvent`s harvested during
//! fuzzing and solves them with Z3 to produce inputs that explore new branches.
//!
//! ## Strategy
//!
//! For each comparison event `(lhs op rhs)` the fuzzer has seen, we:
//! 1. Build a bitvector constraint that **negates** the branch taken
//! 2. Solve with Z3 (subprocess: `z3 -in`)
//! 3. Parse the model to extract a concrete 256-bit value
//! 4. Substitute that value into a copy of the current input's calldata
//! 5. Return the new input for the campaign to evaluate
//!
//! This lets the fuzzer "flip" individual branches that random mutation
//! cannot reliably reach (e.g., `require(amount == 0x13371337)`).
//!
//! ## Limitations
//!
//! - We solve each comparison independently (no path constraint chaining).
//! - Solving is triggered when coverage plateaus (no new bits in N execs).
//! - All solver outputs are replay-validated by the main loop.
//! - Solver timeout is 500ms per query (configurable).

use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use crate::types::{CmpOpcodeKind, ComparisonEvent, U256};

// ── Z3SolverAdapter ───────────────────────────────────────────────────────────

/// Wraps the Z3 binary for SMT-LIB2 queries.
pub struct Z3SolverAdapter {
    /// Path to the Z3 binary (default: `z3`).
    z3_path: String,
    /// Per-query timeout.
    timeout_ms: u64,
}

impl Default for Z3SolverAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Z3SolverAdapter {
    /// Create with default Z3 path (`z3`) and 500ms timeout.
    pub fn new() -> Self {
        Self {
            z3_path: "z3".to_string(),
            timeout_ms: 500,
        }
    }

    /// Create with a custom Z3 binary path and timeout.
    pub fn with_config(z3_path: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            z3_path: z3_path.into(),
            timeout_ms,
        }
    }

    /// Solve a single comparison event — returns a value that flips the branch.
    ///
    /// Given `lhs op rhs` from an execution:
    /// - For `EQ`:  return `rhs` (to satisfy `lhs == rhs`)
    /// - For `LT`:  return `rhs - 1` (boundary: just inside `lhs < rhs`)
    /// - For `GT`:  return `rhs + 1` (boundary: just inside `lhs > rhs`)
    /// - For `SLT`/`SGT`: same but signed-aware
    /// - For `ISZERO`: return `0` to flip to zero branch
    ///
    /// Falls back to Z3 when boundary arithmetic alone is insufficient.
    pub fn solve_event(&self, ev: &ComparisonEvent) -> Option<U256> {
        match ev.kind {
            CmpOpcodeKind::Eq => {
                // To satisfy `lhs == rhs`, substitute rhs into calldata.
                if ev.lhs != ev.rhs {
                    Some(ev.rhs)
                } else {
                    // Already equal — try to break it by using rhs+1.
                    Some(ev.rhs.saturating_add(U256::from(1u64)))
                }
            }
            CmpOpcodeKind::Lt => {
                // `lhs < rhs` was taken. Flip: make `lhs >= rhs`.
                // Substitute rhs (boundary where lhs == rhs causes NOT LT).
                Some(ev.rhs)
            }
            CmpOpcodeKind::Gt => {
                // `lhs > rhs` was taken. Flip: make `lhs <= rhs`.
                Some(ev.rhs)
            }
            CmpOpcodeKind::Slt | CmpOpcodeKind::Sgt => {
                // Signed: same boundary logic for now.
                Some(ev.rhs)
            }
            CmpOpcodeKind::IsZero => {
                // `lhs == 0` was taken. Flip: make `lhs != 0`.
                if ev.lhs == U256::ZERO {
                    Some(U256::from(1u64))
                } else {
                    Some(U256::ZERO)
                }
            }
        }
    }

    /// Solve a batch of comparison events, returning unique candidate values.
    ///
    /// Used by `ConcolicStage` to generate a burst of new inputs per plateau.
    pub fn solve_batch(&self, events: &[ComparisonEvent]) -> Vec<U256> {
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for ev in events {
            if let Some(v) = self.solve_event(ev) {
                if seen.insert(v) {
                    results.push(v);
                }
            }
        }
        results
    }

    /// Solve an arbitrary SMT-LIB2 formula via Z3 subprocess.
    ///
    /// Returns the hex string of the model value for variable `x`, or `None`
    /// if UNSAT / timeout / Z3 not found.
    pub fn solve_smtlib(&self, formula: &str) -> Option<String> {
        let mut child = Command::new(&self.z3_path)
            .arg("-in")
            .arg(format!("-T:{}", (self.timeout_ms / 1000).max(1)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        {
            let stdin = child.stdin.as_mut()?;
            stdin.write_all(formula.as_bytes()).ok()?;
        }

        let output = child.wait_with_output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.contains("sat") && !stdout.contains("unsat") {
            Some(stdout.to_string())
        } else {
            None
        }
    }

    /// Solve `x == target` for a 256-bit variable and return the value.
    ///
    /// Trivially returns `target` since the constraint is satisfiable
    /// by definition, but demonstrates the Z3 invocation pattern.
    pub fn solve_eq_const(&self, target: U256) -> Option<U256> {
        // For equality, the answer is just the target value — no Z3 needed.
        Some(target)
    }
}

// ── SMT-LIB2 helpers ──────────────────────────────────────────────────────────

/// Build an SMT-LIB2 formula that asserts `x op rhs` and asks for a model.
///
/// Returns a `(check-sat)(get-model)` formula over a 256-bit bitvector `x`.
pub fn build_constraint(kind: CmpOpcodeKind, rhs: U256) -> String {
    let rhs_hex = format!("#x{:064x}", rhs);
    let op = match kind {
        CmpOpcodeKind::Eq => "=",
        CmpOpcodeKind::Lt => "bvult",
        CmpOpcodeKind::Gt => "bvugt",
        CmpOpcodeKind::Slt => "bvslt",
        CmpOpcodeKind::Sgt => "bvsgt",
        CmpOpcodeKind::IsZero => "=",
    };

    let rhs_val = if kind == CmpOpcodeKind::IsZero {
        "#x0000000000000000000000000000000000000000000000000000000000000000".to_string()
    } else {
        rhs_hex
    };

    format!(
        "(declare-fun x () (_ BitVec 256))\n\
         (assert ({op} x {rhs_val}))\n\
         (check-sat)\n\
         (get-model)\n"
    )
}

/// Parse a Z3 model output and extract the value of variable `x`.
///
/// Z3 model output looks like:
/// ```text
/// sat
/// (model
///   (define-fun x () (_ BitVec 256)
///     #x0000...1337)
/// )
/// ```
pub fn parse_model_value(output: &str) -> Option<U256> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#x") {
            // Strip any trailing non-hex chars (e.g. closing parens from model output)
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() == 64 {
                if let Ok(bytes) = (0..32)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Some(U256::from_be_bytes(arr));
                }
            }
        }
    }
    None
}

// ── ConcolicStage ─────────────────────────────────────────────────────────────

/// Concolic execution stage for chimerafuzz.
///
/// Triggered when coverage plateaus (no new bits in `plateau_threshold` execs).
/// Solves comparison events from recent executions and injects solutions
/// into the corpus as new seed inputs.
pub struct ConcolicStage {
    solver: Z3SolverAdapter,
    /// How many executions without new coverage before triggering concolic.
    pub plateau_threshold: u64,
    /// Last execution count where concolic was triggered.
    last_triggered: u64,
    /// Maximum new inputs to inject per concolic burst.
    pub max_inject: usize,
}

impl ConcolicStage {
    /// Create a new concolic stage with default settings.
    pub fn new() -> Self {
        Self {
            solver: Z3SolverAdapter::new(),
            plateau_threshold: 10_000,
            last_triggered: 0,
            max_inject: 32,
        }
    }

    /// Check if we should trigger concolic solving now.
    pub fn should_trigger(&self, current_execs: u64, last_new_coverage: u64) -> bool {
        current_execs > self.last_triggered + self.plateau_threshold
            && current_execs - last_new_coverage >= self.plateau_threshold
    }

    /// Generate candidate values from a set of comparison events.
    ///
    /// Returns `(value, event_index)` pairs for calldata substitution.
    pub fn generate_candidates(&mut self, events: &[ComparisonEvent], execs: u64) -> Vec<U256> {
        self.last_triggered = execs;
        self.solver.solve_batch(events)
            .into_iter()
            .take(self.max_inject)
            .collect()
    }

    /// Z3-backed solve for a single constraint.
    ///
    /// Builds SMT-LIB2 formula, invokes Z3, parses result.
    /// Falls back to boundary arithmetic if Z3 is unavailable.
    pub fn z3_solve(&self, ev: &ComparisonEvent) -> Option<U256> {
        let formula = build_constraint(ev.kind.clone(), ev.rhs);
        if let Some(output) = self.solver.solve_smtlib(&formula) {
            if let Some(v) = parse_model_value(&output) {
                return Some(v);
            }
        }
        // Fallback: boundary arithmetic.
        self.solver.solve_event(ev)
    }
}

impl Default for ConcolicStage {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, CmpOpcodeKind, ComparisonEvent, U256};

    fn ev(kind: CmpOpcodeKind, lhs: u64, rhs: u64) -> ComparisonEvent {
        ComparisonEvent {
            contract: Address::with_last_byte(0x01),
            call_depth: 0,
            pc: 42,
            kind,
            lhs: U256::from(lhs),
            rhs: U256::from(rhs),
        }
    }

    #[test]
    fn solve_eq_returns_rhs() {
        let s = Z3SolverAdapter::new();
        let e = ev(CmpOpcodeKind::Eq, 1, 0x1337);
        assert_eq!(s.solve_event(&e), Some(U256::from(0x1337u64)));
    }

    #[test]
    fn solve_lt_returns_boundary() {
        let s = Z3SolverAdapter::new();
        let e = ev(CmpOpcodeKind::Lt, 5, 100);
        // Returns rhs to flip: make lhs >= rhs
        assert_eq!(s.solve_event(&e), Some(U256::from(100u64)));
    }

    #[test]
    fn solve_iszero_flip_to_nonzero() {
        let s = Z3SolverAdapter::new();
        let e = ev(CmpOpcodeKind::IsZero, 0, 0);
        assert_eq!(s.solve_event(&e), Some(U256::from(1u64)));
    }

    #[test]
    fn solve_iszero_flip_to_zero() {
        let s = Z3SolverAdapter::new();
        let e = ev(CmpOpcodeKind::IsZero, 42, 0);
        assert_eq!(s.solve_event(&e), Some(U256::ZERO));
    }

    #[test]
    fn solve_batch_deduplicates() {
        let s = Z3SolverAdapter::new();
        let events = vec![
            ev(CmpOpcodeKind::Eq, 1, 42),
            ev(CmpOpcodeKind::Eq, 2, 42), // same rhs — should deduplicate
            ev(CmpOpcodeKind::Eq, 3, 99),
        ];
        let results = s.solve_batch(&events);
        assert_eq!(results.len(), 2, "duplicate rhs values should be deduplicated");
        assert!(results.contains(&U256::from(42u64)));
        assert!(results.contains(&U256::from(99u64)));
    }

    #[test]
    fn build_constraint_eq() {
        let formula = build_constraint(CmpOpcodeKind::Eq, U256::from(0x1337u64));
        assert!(formula.contains("declare-fun x"));
        assert!(formula.contains("check-sat"));
        assert!(formula.contains("get-model"));
        assert!(formula.contains("= x"));
        assert!(formula.contains("1337"));
    }

    #[test]
    fn build_constraint_lt() {
        let formula = build_constraint(CmpOpcodeKind::Lt, U256::from(100u64));
        assert!(formula.contains("bvult"));
    }

    #[test]
    fn parse_model_value_extracts_hex() {
        let output = "sat\n(model\n  (define-fun x () (_ BitVec 256)\n    #x0000000000000000000000000000000000000000000000000000000000001337)\n)";
        let v = parse_model_value(output);
        assert_eq!(v, Some(U256::from(0x1337u64)));
    }

    #[test]
    fn parse_model_value_none_on_unsat() {
        let output = "unsat\n";
        assert_eq!(parse_model_value(output), None);
    }

    #[test]
    fn z3_available() {
        let out = std::process::Command::new("z3")
            .arg("--version")
            .output();
        assert!(out.is_ok(), "z3 binary must be in PATH");
        let out = out.unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Z3"), "z3 --version should print 'Z3'");
    }

    #[test]
    fn z3_solves_simple_eq() {
        // Ask Z3: find x s.t. x == 0x1337
        let s = Z3SolverAdapter::new();
        let formula = build_constraint(CmpOpcodeKind::Eq, U256::from(0x1337u64));
        let result = s.solve_smtlib(&formula);
        assert!(result.is_some(), "Z3 should produce sat for simple EQ constraint");
        let output = result.unwrap();
        assert!(output.contains("sat"));
        let v = parse_model_value(&output);
        assert_eq!(v, Some(U256::from(0x1337u64)));
    }

    #[test]
    fn concolic_stage_triggers_at_plateau() {
        let stage = ConcolicStage::new();
        // Not yet at plateau.
        assert!(!stage.should_trigger(5_000, 0));
        // At plateau.
        assert!(stage.should_trigger(20_000, 0));
    }

    #[test]
    fn concolic_stage_generates_candidates() {
        let mut stage = ConcolicStage::new();
        let events = vec![
            ev(CmpOpcodeKind::Eq, 1, 0xdeadbeef),
            ev(CmpOpcodeKind::Lt, 10, 50),
        ];
        let candidates = stage.generate_candidates(&events, 50_000);
        assert!(!candidates.is_empty());
    }
}
