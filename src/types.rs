//! Core types for sci-fuzz — Smart Contract Invariant Fuzzer.
//!
//! This module defines the fundamental data structures referenced throughout the
//! crate.  All Ethereum primitives come from [`alloy_primitives`] so that every
//! module speaks the same "language" without conversion boilerplate.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── Re-exports ───────────────────────────────────────────────────────────────
// Consumers can `use sci_fuzz::types::{Address, U256, …}` without pulling in
// alloy-primitives directly.

pub use alloy_primitives::{Address, Bytes, B256, U256};

// ── Type Aliases ─────────────────────────────────────────────────────────────

/// Per-contract storage: each contract address maps to its slot → value table.
pub type Storage = HashMap<Address, HashMap<U256, U256>>;

// ── Contract Info ────────────────────────────────────────────────────────────

/// Metadata about a deployed smart contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// On-chain address of the contract.
    pub address: Address,
    /// Deployed (runtime) bytecode.
    pub deployed_bytecode: Bytes,
    /// Creation/init bytecode, when available from a compiler artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_bytecode: Option<Bytes>,
    /// Human-readable name, e.g. `"Vault"`.
    pub name: Option<String>,
    /// Source path reported by the build system, relative to project root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Full JSON ABI (as produced by `solc --abi`).
    pub abi: Option<serde_json::Value>,
}

// ── Transaction ──────────────────────────────────────────────────────────────

/// A transaction to execute against the EVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// The `msg.sender` for this call.
    pub sender: Address,
    /// Destination address.  `None` represents a contract-creation tx.
    pub to: Option<Address>,
    /// Calldata (selector + encoded arguments, or init-code).
    pub data: Bytes,
    /// Ether value attached (`msg.value`).
    pub value: U256,
    /// Maximum gas the transaction may consume.
    pub gas_limit: u64,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            sender: Address::ZERO,
            to: None,
            data: Bytes::new(),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }
    }
}

// ── Execution Result ─────────────────────────────────────────────────────────

/// The outcome of executing a single [`Transaction`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// `true` when the EVM reported a successful execution (no revert).
    pub success: bool,
    /// Return data (or revert reason bytes).
    pub output: Bytes,
    /// Gas actually consumed.
    pub gas_used: u64,
    /// Event logs emitted during execution.
    pub logs: Vec<Log>,
    /// Real EVM instruction hitcounts collected during this execution.
    pub coverage: CoverageMap,
    /// Storage & balance mutations caused by this execution.
    pub state_diff: StateDiff,
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self {
            success: true,
            output: Bytes::new(),
            gas_used: 0,
            logs: Vec::new(),
            coverage: CoverageMap::new(),
            state_diff: StateDiff::default(),
        }
    }
}

// ── Log ──────────────────────────────────────────────────────────────────────

/// An EVM log entry (event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Address of the contract that emitted this log.
    pub address: Address,
    /// Indexed topics (topic0 is typically the event selector).
    pub topics: Vec<B256>,
    /// Non-indexed data payload.
    pub data: Bytes,
}

// ── State Diff ───────────────────────────────────────────────────────────────

/// State mutations produced by a single transaction execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateDiff {
    /// Storage writes: contract → (slot → new_value).
    pub storage_writes: HashMap<Address, HashMap<U256, U256>>,
    /// Balance changes: account → (old_balance, new_balance).
    pub balance_changes: HashMap<Address, (U256, U256)>,
}

impl StateDiff {
    /// Returns `true` when the diff contains no mutations at all.
    pub fn is_empty(&self) -> bool {
        self.storage_writes.is_empty() && self.balance_changes.is_empty()
    }
}

// ── State Snapshot ───────────────────────────────────────────────────────────

/// A complete point-in-time snapshot of the EVM world state.
///
/// Snapshots form a tree (via `parent_id`) so the fuzzer can fork execution
/// from any previously interesting state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Unique, monotonically-increasing identifier.
    pub id: u64,
    /// Parent snapshot this was derived from (`None` for the root).
    pub parent_id: Option<u64>,
    /// Full storage image.
    pub storage: Storage,
    /// Account balances.
    pub balances: HashMap<Address, U256>,
    /// Block number at the time of the snapshot.
    pub block_number: u64,
    /// Block timestamp at the time of the snapshot.
    pub timestamp: u64,
    /// Cumulative code coverage at this point.
    pub coverage: CoverageMap,
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self {
            id: 0,
            parent_id: None,
            storage: HashMap::new(),
            balances: HashMap::new(),
            block_number: 0,
            timestamp: 0,
            coverage: CoverageMap::new(),
        }
    }
}

// ── Coverage Map ─────────────────────────────────────────────────────────────

/// Tracks real EVM instruction hitcounts for each contract address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageMap {
    /// contract address → program counter → raw hitcount.
    pub map: HashMap<Address, HashMap<usize, u32>>,
}

impl CoverageMap {
    /// Create an empty coverage map.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Record a single instruction hit.
    pub fn record_hit(&mut self, address: Address, pc: usize) {
        self.record_hitcount(address, pc, 1);
    }

    /// Record `count` hits for a single `(address, pc)` pair.
    pub fn record_hitcount(&mut self, address: Address, pc: usize, count: u32) {
        if count == 0 {
            return;
        }

        let entry = self.map.entry(address).or_default().entry(pc).or_insert(0);
        *entry = entry.saturating_add(count);
    }

    /// Merge all coverage from `other` into `self`.
    pub fn merge(&mut self, other: &CoverageMap) {
        for (addr, pcs) in &other.map {
            let dst = self.map.entry(*addr).or_default();
            for (&pc, &count) in pcs {
                let entry = dst.entry(pc).or_insert(0);
                *entry = entry.saturating_add(count);
            }
        }
    }

    /// Total number of unique (address, pc) pairs covered.
    pub fn len(&self) -> usize {
        self.map.values().map(|s| s.len()).sum()
    }

    /// Returns `true` when no coverage has been recorded.
    pub fn is_empty(&self) -> bool {
        self.map.values().all(|s| s.is_empty())
    }

    /// Return the raw hitcount for `(address, pc)`, or `0` if unseen.
    pub fn hitcount(&self, address: Address, pc: usize) -> u32 {
        self.map
            .get(&address)
            .and_then(|pcs| pcs.get(&pc))
            .copied()
            .unwrap_or(0)
    }

    /// Returns `true` if `other` contains at least one (address, pc) pair
    /// that is **not** present in `self`.
    pub fn has_new_coverage(&self, other: &CoverageMap) -> bool {
        for (addr, pcs) in &other.map {
            match self.map.get(addr) {
                None => {
                    if !pcs.is_empty() {
                        return true;
                    }
                }
                Some(existing) => {
                    if pcs.keys().any(|pc| !existing.contains_key(pc)) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ── Severity ─────────────────────────────────────────────────────────────────

/// Severity rating for a discovered vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational observation — not directly exploitable.
    Info,
    /// Low-risk issue.
    Low,
    /// Medium-risk issue.
    Medium,
    /// High-risk issue.
    High,
    /// Critical-risk — likely exploitable with direct fund loss.
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Info
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

// ── Finding ──────────────────────────────────────────────────────────────────

/// A vulnerability discovered during a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// How severe the issue is.
    pub severity: Severity,
    /// Short human-readable title, e.g. `"Reentrancy in Vault.withdraw"`.
    pub title: String,
    /// Longer description explaining the root cause and impact.
    pub description: String,
    /// Address of the affected contract.
    pub contract: Address,
    /// Minimal transaction sequence that reproduces the bug.
    pub reproducer: Vec<Transaction>,
    /// Estimated attacker profit (wei), if applicable.
    pub exploit_profit: Option<U256>,
}

impl Finding {
    /// Serialize this finding to a JSON file.
    ///
    /// The file is named `finding_{severity}_{slug}.json` where the slug is
    /// derived from the first 32 alphanumeric characters of the title.
    pub fn save_to_dir(&self, dir: &std::path::Path) -> crate::error::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let slug = self
            .title
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .take(32)
            .collect::<String>();
        let filename = format!("finding_{}_{}.json", format!("{}", self.severity), slug,);
        let path = dir.join(&filename);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Compute a deduplication hash for this finding.
    ///
    /// Two findings that share the same contract address, the first 40
    /// characters of the title (the "property identity"), and the same
    /// reproducer sequence length are considered duplicates.
    pub fn dedup_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.contract.hash(&mut h);
        // Use first 40 chars of title as the "property identity".
        let title_key: String = self.title.chars().take(40).collect();
        title_key.hash(&mut h);
        // Sequence length (not exact content — same bug, different noise txs).
        self.reproducer.len().hash(&mut h);
        h.finish()
    }

    /// A sequence-length-independent identifier for the underlying failure.
    ///
    /// This is intentionally coarser than [`dedup_hash`](Self::dedup_hash):
    /// shrinkers and replay checks use it to ask "did we preserve the same
    /// bug class on the same contract?" even if the exact title text changes
    /// as values shrink.
    pub fn failure_id(&self) -> String {
        format!("{}:{}", self.contract, self.failure_class())
    }

    /// Returns `true` when both findings represent the same failure class on
    /// the same contract, ignoring reproducer length.
    pub fn same_root_cause_as(&self, other: &Finding) -> bool {
        self.contract == other.contract && self.failure_class() == other.failure_class()
    }

    fn failure_class(&self) -> String {
        let title = self.title.as_str();

        if title.starts_with("Unexpected balance increase of ") {
            return "balance-increase".into();
        }
        if title == "Unexpected revert" {
            return "unexpected-revert".into();
        }
        if title.starts_with("Possible selfdestruct of ") {
            return "selfdestruct".into();
        }
        if title == "Echidna property violation" {
            return "echidna-assertion-event".into();
        }
        if title == "Assertion failure (Panic 0x01)" {
            return "echidna-panic-0x01".into();
        }
        if let Some(name) = title
            .strip_prefix("Echidna property `")
            .and_then(|rest| rest.strip_suffix("` violated"))
        {
            return format!("echidna-static:{name}");
        }
        if title.starts_with("Large token mint at ") {
            return "erc20-large-mint".into();
        }
        if title.starts_with("Large token burn at ") {
            return "erc20-large-burn".into();
        }

        title.to_string()
    }
}

// ── Campaign Config ──────────────────────────────────────────────────────────

/// Top-level configuration for a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Maximum wall-clock time the campaign may run.
    pub timeout: Duration,
    /// Optional deterministic execution budget. When set, the campaign stops
    /// once this many EVM executions have completed.
    pub max_execs: Option<u64>,
    /// Maximum transaction-sequence depth per exploration path.
    pub max_depth: u32,
    /// Upper bound on the number of retained state snapshots.
    pub max_snapshots: usize,
    /// Number of parallel fuzzing workers.
    pub workers: usize,
    /// Deterministic seed for the PRNG.
    pub seed: u64,
    /// Contracts under test.
    pub targets: Vec<ContractInfo>,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_execs: None,
            max_depth: 64,
            max_snapshots: 4096,
            workers: 1,
            seed: 0,
            targets: Vec::new(),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_map_basics() {
        let mut a = CoverageMap::new();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);

        let addr = Address::ZERO;
        a.record_hit(addr, 0);
        a.record_hit(addr, 42);
        assert_eq!(a.len(), 2);
        assert!(!a.is_empty());

        // Duplicate hit does not increase the number of covered PCs.
        a.record_hit(addr, 42);
        assert_eq!(a.len(), 2);
        assert_eq!(a.hitcount(addr, 42), 2);
    }

    #[test]
    fn coverage_map_merge() {
        let addr = Address::ZERO;

        let mut a = CoverageMap::new();
        a.record_hit(addr, 0);

        let mut b = CoverageMap::new();
        b.record_hit(addr, 1);
        b.record_hit(addr, 0);

        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.hitcount(addr, 0), 2);
    }

    #[test]
    fn coverage_map_has_new_coverage() {
        let addr = Address::ZERO;

        let mut base = CoverageMap::new();
        base.record_hit(addr, 0);
        base.record_hit(addr, 1);

        // Subset — no new coverage.
        let mut subset = CoverageMap::new();
        subset.record_hit(addr, 0);
        assert!(!base.has_new_coverage(&subset));

        // Superset — has new coverage.
        let mut superset = CoverageMap::new();
        superset.record_hit(addr, 0);
        superset.record_hit(addr, 99);
        assert!(base.has_new_coverage(&superset));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn default_campaign_config_is_sensible() {
        let cfg = CampaignConfig::default();
        assert!(cfg.timeout.as_secs() > 0);
        assert!(cfg.max_depth > 0);
        assert!(cfg.max_snapshots > 0);
    }

    #[test]
    fn state_diff_is_empty() {
        let diff = StateDiff::default();
        assert!(diff.is_empty());
    }

    #[test]
    fn transaction_default() {
        let tx = Transaction::default();
        assert_eq!(tx.sender, Address::ZERO);
        assert!(tx.to.is_none());
        assert_eq!(tx.value, U256::ZERO);
        assert!(tx.gas_limit > 0);
    }

    #[test]
    fn coverage_map_serde_roundtrip() {
        let addr = Address::ZERO;
        let mut cm = CoverageMap::new();
        cm.record_hit(addr, 10);
        cm.record_hit(addr, 20);

        let json = serde_json::to_string(&cm).expect("serialize");
        let restored: CoverageMap = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn finding_failure_id_ignores_dynamic_balance_amounts() {
        let a = Finding {
            severity: Severity::Critical,
            title: "Unexpected balance increase of 10 wei".into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: Some(U256::from(10u64)),
        };
        let b = Finding {
            severity: Severity::Critical,
            title: "Unexpected balance increase of 999 wei".into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![Transaction::default()],
            exploit_profit: Some(U256::from(999u64)),
        };

        assert!(a.same_root_cause_as(&b));
        assert_eq!(a.failure_id(), b.failure_id());
    }
}
