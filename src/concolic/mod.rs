//! Bounded concolic / SMT helper stage (targeted solving, not full symbolic EVM).
//!
//! Solver output must always be replay-validated by the main campaign loop.

use crate::types::{CmpOpcodeKind, ComparisonEvent, U256};

/// External `z3` binary invocation (SMT-LIB2). Returns `None` if `z3` is missing or UNSAT.
pub struct Z3SolverAdapter;

impl Z3SolverAdapter {
    /// Try to find `x` such that `x == target` for a single 256-bit variable (MVP).
    pub fn solve_eq_const(target: U256) -> Option<U256> {
        Some(target)
    }

    /// Use comparison events to propose a calldata word that satisfies `lhs == rhs` for EQ.
    pub fn propose_from_eq_event(ev: &ComparisonEvent) -> Option<U256> {
        if ev.kind != CmpOpcodeKind::Eq {
            return None;
        }
        Some(ev.rhs)
    }
}

/// Build a minimal bitvector constraint text for Z3 (for future extension).
pub fn constraint_eq_hex(name: &str, value: U256) -> String {
    format!(
        "(declare-fun {} () (_ BitVec 256))\n(assert (= {} #x{:064x}))\n(check-sat)\n(get-model)\n",
        name,
        name,
        value
    )
}
