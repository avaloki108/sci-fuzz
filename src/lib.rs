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

/// Ordered dynamic path hashing (per-tx and per-sequence).
pub mod path_id;

// ── EVM execution layer ─────────────────────────────────────────────────

/// Forge VM cheatcode interceptor (`vm.prank`, `vm.deal`, `vm.warp`, etc.).
pub mod cheatcodes;

pub mod evm;

// ── State management ────────────────────────────────────────────────────

pub mod snapshot;

// ── Feedback & guidance ─────────────────────────────────────────────────

pub mod feedback;
pub mod flashloan;
pub mod mutator;
pub mod shrinker;

// ── Invariant / oracle system ───────────────────────────────────────────

pub mod conservation;
pub mod conservation_oracles;
pub mod economic;
pub mod protocol_probes;
pub mod protocol_semantics;
pub use conservation_oracles::{
    AmmSyncExplainedOracle, Erc4626DepositVsUnderlyingTransferOracle,
    Erc4626FirstDepositorInflationOracle,
};
pub use economic::{
    Erc20BalanceStorageWithoutTransferOracle, Erc20BurnWithoutSupplyWriteOracle,
    Erc20MintWithoutSupplyWriteOracle, Erc4626EventAnomalyOracle, Erc4626ExchangeRateJumpOracle,
    Erc4626PreviewVsDepositEventOracle, Erc4626RateJumpWithoutTokenFlowOracle,
    Erc4626SameTransactionDepositRateSpreadOracle, Erc4626WithdrawRateJumpOracle,
    PairwiseStorageDriftOracle, ProtocolProfileMap, UniswapV2StyleSwapReserveOracle,
    UniswapV2StyleSyncVsGetReservesOracle, MIN_LARGE_TOKEN_MOVE, OZ_ERC20_TOTAL_SUPPLY_SLOT,
};
pub use protocol_semantics::{
    build_protocol_profiles, classify_json_abi, topic_erc20_transfer, topic_erc4626_deposit,
    topic_erc4626_withdraw, topic_uni_v2_swap, topic_uni_v2_sync, ContractProtocolProfile,
    ProtocolKind,
};
pub mod invariant;
pub mod inferred_invariants;
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

/// Foundry harness `setUp()` execution helpers (`run_setup`, selector).
pub mod harness;

// ── CI output formatters ────────────────────────────────────────────────

pub mod output;

// ── Source map & source-linked coverage ────────────────────────────────

pub mod source_map;

// ── Differential execution ──────────────────────────────────────────────

pub mod diff;
pub mod config;

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
pub use feedback::PathFeedback;
pub use path_id::{fold_sequence, native_flashloan_path_id, tx_path_id_from_stream};
pub use project::{abi_has_echidna_property, abi_has_set_up, FuzzBootstrap};
pub use scoreboard::{
    BenchmarkEngine, BenchmarkStatus, MultiSeedSummary, Scoreboard, ScorecardEntry,
};
pub use shrinker::SequenceShrinker;
pub use types::{
    contract_info_for_mutator, strip_abi_functions_named, Address, Bytes, CampaignConfig,
    ContractInfo, CoverageMap, ExecutionResult, Finding, Log, Severity, StateDiff, StateSnapshot,
    Transaction, B256, U256,
};
