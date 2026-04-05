//! # sci-fuzz — Smart Contract Invariant Fuzzer
//!
//! A coverage-guided, snapshot-based fuzzer for EVM smart contracts that
//! automatically discovers invariant violations with minimal manual
//! specification.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐
//! │   Campaign   │  orchestrates the fuzzing loop
//! └──────┬──────┘
//!        │
//!   ┌────┴─────┐
//!   │ Executor  │  wraps revm for fast EVM execution + snapshots
//!   └────┬─────┘
//!        │
//!   ┌────┴─────┐
//!   │ Snapshot  │  manages a corpus of interesting EVM states
//!   └────┬─────┘
//!        │
//!   ┌────┴─────┐
//!   │ Oracles   │  detect invariant violations (templates, economic, …)
//!   └──────────┘
//! ```

// ── Foundation modules (no internal dependencies) ────────────────────────

pub mod error;
pub mod types;

// ── EVM execution layer ─────────────────────────────────────────────────

pub mod evm;

// ── State management ────────────────────────────────────────────────────

pub mod snapshot;

// ── Feedback & guidance ─────────────────────────────────────────────────

pub mod feedback;
pub mod flashloan;
pub mod mutator;
pub mod shrinker;

// ── Invariant / oracle system ───────────────────────────────────────────

pub mod invariant;
pub mod oracle;

// ── Fuzzing campaign ────────────────────────────────────────────────────

pub mod campaign;

// ── On-chain forking & Etherscan integration ────────────────────────────

pub mod rpc;

// ── Benchmark scoreboard ────────────────────────────────────────────────

pub mod benchmark;
pub mod scoreboard;

// ── Foundry integration ─────────────────────────────────────────────────

pub mod project;

// ── CLI (feature-gated) ─────────────────────────────────────────────────

#[cfg(feature = "cli")]
pub mod cli;

// ── Convenience re-exports ──────────────────────────────────────────────

pub use benchmark::{
    efcf_demo_plan, plan_for_foundry_project, run_benchmark_plan, write_benchmark_artifacts,
    BenchmarkCase, BenchmarkPlanEntry, FindingMatcher,
};
pub use campaign::Campaign;
pub use campaign::{CampaignFindingRecord, CampaignReport};
pub use error::{Error, Result};
pub use evm::EvmExecutor;
pub use scoreboard::{
    BenchmarkEngine, BenchmarkStatus, MultiSeedSummary, Scoreboard, ScorecardEntry,
};
pub use shrinker::SequenceShrinker;
pub use types::{
    Address, Bytes, CampaignConfig, ContractInfo, CoverageMap, ExecutionResult, Finding, Log,
    Severity, StateDiff, StateSnapshot, Transaction, B256, U256,
};
