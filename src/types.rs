//! Core types for sci-fuzz — Smart Contract Invariant Fuzzer.
//!
//! This module defines the fundamental data structures referenced throughout the
//! crate.  All Ethereum primitives come from [`alloy_primitives`] so that every
//! module speaks the same "language" without conversion boilerplate.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Testing mode controlling which oracles are registered and how the campaign
/// interprets results.
///
/// The default is `Property`, which preserves all pre-existing behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum TestMode {
    /// Check `echidna_*` / `invariant_*` bool properties + all economic oracles.
    /// This is the default and matches legacy sci-fuzz behavior.
    #[default]
    Property,
    /// Check assertion/panic failures only (`EchidnaProperty` events + property
    /// callers). Economic and balance oracles are not registered.
    Assertion,
    /// Like `Property` but also discovers `invariant_*` functions (Foundry
    /// convention). All oracles are registered; both `echidna_*` and
    /// `invariant_*` prefixes are matched by the property caller.
    FoundryInvariant,
    /// Track a numeric optimization objective (scaffold — Phase 2 adds full
    /// objective tracking). Oracle registration matches `Property` for now.
    Optimization,
    /// Pure coverage-guided exploration. No oracles or property callers are
    /// registered. Useful for building a corpus before switching modes.
    Exploration,
}

/// Executor mode controlling how strictly EVM rules are enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ExecutorMode {
    /// Minimal checks — best for exploration. Disables balance checks,
    /// gas limits, EIP-3607, base fee. This is the default.
    #[default]
    Fast,
    /// Enforce balance/value plausibility. Still disables gas price but
    /// checks that callers have sufficient balance for `msg.value`.
    /// Best for validation and reducing false positives.
    Realistic,
}

// ── Re-exports ───────────────────────────────────────────────────────────────
// Consumers can `use sci_fuzz::types::{Address, U256, …}` without pulling in
// alloy-primitives directly.

pub use alloy_primitives::{Address, Bytes, B256, U256};

// ── Type Aliases ─────────────────────────────────────────────────────────────

/// Per-contract storage: each contract address maps to its slot → value table.
pub type Storage = HashMap<Address, HashMap<U256, U256>>;

// ── Contract Info ────────────────────────────────────────────────────────────

/// Metadata about a deployed smart contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Solidity source map for the deployed bytecode (semicolon-separated
    /// instruction entries).  Used for PC → source-line mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployed_source_map: Option<String>,
    /// Ordered list of source file paths corresponding to file indices in
    /// `deployed_source_map`.  Index 0 matches file_index=0 in the source map.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_file_list: Vec<String>,
    /// Full JSON ABI (as produced by `solc --abi`).
    pub abi: Option<serde_json::Value>,
}

/// Clone `contract` and replace its ABI with one that omits named functions
/// (e.g. `setUp`) so the mutator does not generate setup calls mid-campaign.
/// Other uses (e.g. `echidna_*` discovery) should keep the original [`ContractInfo::abi`].
pub fn contract_info_for_mutator(contract: &ContractInfo, strip_names: &[&str]) -> ContractInfo {
    let abi = contract
        .abi
        .as_ref()
        .and_then(|a| strip_abi_functions_named(a, strip_names));
    ContractInfo {
        address: contract.address,
        deployed_bytecode: contract.deployed_bytecode.clone(),
        creation_bytecode: contract.creation_bytecode.clone(),
        name: contract.name.clone(),
        source_path: contract.source_path.clone(),
        deployed_source_map: contract.deployed_source_map.clone(),
        source_file_list: contract.source_file_list.clone(),
        abi,
    }
}

/// Return a copy of a JSON ABI array with `function` entries whose `name` is
/// in `strip_names` removed.
pub fn strip_abi_functions_named(
    abi: &serde_json::Value,
    strip_names: &[&str],
) -> Option<serde_json::Value> {
    let arr = abi.as_array()?;
    let filtered: Vec<serde_json::Value> = arr
        .iter()
        .filter(|entry| {
            if entry.get("type").and_then(|t| t.as_str()) != Some("function") {
                return true;
            }
            let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
            !strip_names.contains(&name)
        })
        .cloned()
        .collect();
    Some(serde_json::Value::Array(filtered))
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
    /// Per-edge control-flow coverage for this execution (see [`CoverageMap`]).
    pub coverage: CoverageMap,
    /// Dataflow waypoints reached during execution.
    pub dataflow: DataflowWaypoints,
    /// Storage & balance mutations caused by this execution.
    pub state_diff: StateDiff,
    /// Logs from all transactions in the current fuzz sequence up to and
    /// including this execution. Populated by the campaign loop and shrink
    /// replay; the EVM executor leaves this empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sequence_cumulative_logs: Vec<Log>,
    /// Executor-backed `static_call` probes at post-transaction state (see
    /// [`crate::protocol_probes::fill_protocol_probes`]).
    #[serde(default, skip_serializing_if = "ProtocolProbeReport::is_empty")]
    pub protocol_probes: ProtocolProbeReport,
    /// Ordered dynamic control-flow path fingerprint for this transaction (see [`crate::path_id`]).
    #[serde(default)]
    pub tx_path_id: B256,
    /// `true` when `vm.assume(false)` was triggered during this transaction.
    /// The campaign loop should skip invariant checks and treat the sequence
    /// as if it reverted (precondition guard).
    #[serde(default)]
    pub assume_violated: bool,
    /// `true` when the transaction reverted and an `vm.expectRevert()` was
    /// active. The campaign loop should not treat this revert as anomalous.
    pub revert_was_expected: bool,
    /// `true` when an `SSTORE` opcode fired while at least one external call
    /// frame was active (call_depth > 0 in the Inspector). Used by the
    /// reentrancy oracle as a necessary-condition signal: state was written
    /// back to a contract while that contract (or an ancestor) still had an
    /// active call frame pending return.
    #[serde(default)]
    pub sstore_in_nested_call: bool,
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self {
            success: true,
            output: Bytes::new(),
            gas_used: 0,
            logs: Vec::new(),
            coverage: CoverageMap::new(),
            dataflow: DataflowWaypoints::new(),
            state_diff: StateDiff::default(),
            sequence_cumulative_logs: Vec::new(),
            protocol_probes: ProtocolProbeReport::default(),
            tx_path_id: B256::ZERO,
            assume_violated: false,
            revert_was_expected: false,
            sstore_in_nested_call: false,
        }
    }
}

// ── Protocol probes (static_call) ───────────────────────────────────────────

/// Result of a single view probe (decoded scalar).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeScalar {
    U256(U256),
    Address(Address),
}

/// Outcome of one `static_call` probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeStatus {
    Ok(ProbeScalar),
    Reverted,
    DecodeFailed,
    Skipped,
}

/// One ERC-4626 `Deposit` event correlated with `previewDeposit` / `convertToShares` probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Erc4626DepositProbeRow {
    pub assets: U256,
    pub shares_emitted: U256,
    pub preview_deposit_shares: Option<ProbeStatus>,
    pub convert_to_shares: Option<ProbeStatus>,
}

/// One ERC-4626 `Withdraw` event correlated with preview probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Erc4626WithdrawProbeRow {
    pub assets: U256,
    pub shares_burned: U256,
    pub preview_withdraw_shares: Option<ProbeStatus>,
    pub preview_redeem_assets: Option<ProbeStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Erc4626ProbeSnapshot {
    pub asset: Option<ProbeStatus>,
    pub total_assets: Option<ProbeStatus>,
    /// `balanceOf(vault)` on the underlying asset (post-state), when `asset` resolves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_balance_of_vault: Option<ProbeStatus>,
    pub convert_to_shares: Option<ProbeStatus>,
    pub convert_to_assets: Option<ProbeStatus>,
    pub deposit_rows: Vec<Erc4626DepositProbeRow>,
    pub withdraw_rows: Vec<Erc4626WithdrawProbeRow>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Erc20ProbeSnapshot {
    pub total_supply: Option<ProbeStatus>,
    pub balance_of_caller: Option<ProbeStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmmProbeSnapshot {
    pub reserve0: Option<ProbeStatus>,
    pub reserve1: Option<ProbeStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractProbeSnapshot {
    pub erc4626: Option<Erc4626ProbeSnapshot>,
    pub erc20: Option<Erc20ProbeSnapshot>,
    pub amm: Option<AmmProbeSnapshot>,
}

/// Per-step `static_call` probe bundle attached to an [`ExecutionResult`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolProbeReport {
    pub per_contract: HashMap<Address, ContractProbeSnapshot>,
}

impl ProtocolProbeReport {
    pub fn is_empty(&self) -> bool {
        self.per_contract.is_empty()
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
    /// Cumulative control-flow edge coverage at this point.
    pub coverage: CoverageMap,
    /// Dataflow waypoints reached across this snapshot's history.
    pub dataflow: DataflowWaypoints,
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
            dataflow: DataflowWaypoints::new(),
        }
    }
}

// ── Coverage Map ─────────────────────────────────────────────────────────────

/// Per-contract control-flow edge coverage with raw hitcounts.
///
/// Each key is a directed edge `(prev_pc, current_pc)` within that contract's
/// bytecode (attributed execution context). Hitcounts accumulate per edge when
/// the same transition is taken multiple times (e.g. loops).
#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    /// Contract address → `(prev_pc, current_pc)` edge → raw transition count.
    pub map: HashMap<Address, HashMap<(usize, usize), u32>>,
}

#[derive(Serialize, Deserialize)]
struct CoverageMapShadow {
    map: HashMap<Address, Vec<((usize, usize), u32)>>,
}

impl Serialize for CoverageMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut shadow = CoverageMapShadow {
            map: HashMap::new(),
        };
        for (addr, edges) in &self.map {
            let vec: Vec<_> = edges.iter().map(|(&k, &v)| (k, v)).collect();
            shadow.map.insert(*addr, vec);
        }
        shadow.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoverageMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shadow = CoverageMapShadow::deserialize(deserializer)?;
        let mut map = HashMap::new();
        for (addr, vec) in shadow.map {
            let inner_map: HashMap<_, _> = vec.into_iter().collect();
            map.insert(addr, inner_map);
        }
        Ok(CoverageMap { map })
    }
}

impl CoverageMap {
    /// Create an empty coverage map.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Record a single instruction edge hit.
    pub fn record_hit(&mut self, address: Address, prev_pc: usize, current_pc: usize) {
        self.record_hitcount(address, prev_pc, current_pc, 1);
    }

    /// Record `count` hits for a single `(prev_pc, current_pc)` pair.
    pub fn record_hitcount(
        &mut self,
        address: Address,
        prev_pc: usize,
        current_pc: usize,
        count: u32,
    ) {
        if count == 0 {
            return;
        }

        let entry = self
            .map
            .entry(address)
            .or_default()
            .entry((prev_pc, current_pc))
            .or_insert(0);
        *entry = entry.saturating_add(count);
    }

    /// Merge all coverage from `other` into `self`.
    pub fn merge(&mut self, other: &CoverageMap) {
        for (addr, edges) in &other.map {
            let dst = self.map.entry(*addr).or_default();
            for (&edge, &count) in edges {
                let entry = dst.entry(edge).or_insert(0);
                *entry = entry.saturating_add(count);
            }
        }
    }

    /// Total number of unique (address, edge) pairs covered.
    pub fn len(&self) -> usize {
        self.map.values().map(|s| s.len()).sum()
    }

    /// Returns `true` when no coverage has been recorded.
    pub fn is_empty(&self) -> bool {
        self.map.values().all(|s| s.is_empty())
    }

    /// Return the raw hitcount for `(address, prev_pc, current_pc)`, or `0` if unseen.
    pub fn hitcount(&self, address: Address, prev_pc: usize, current_pc: usize) -> u32 {
        self.map
            .get(&address)
            .and_then(|edges| edges.get(&(prev_pc, current_pc)))
            .copied()
            .unwrap_or(0)
    }

    /// Returns `true` if `other` contains at least one (address, edge) pair
    /// that is **not** present in `self`.
    pub fn has_new_coverage(&self, other: &CoverageMap) -> bool {
        for (addr, edges) in &other.map {
            match self.map.get(addr) {
                None => {
                    if !edges.is_empty() {
                        return true;
                    }
                }
                Some(existing) => {
                    if edges.keys().any(|edge| !existing.contains_key(edge)) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ── Dataflow Waypoints ───────────────────────────────────────────────────────

/// Tracks which storage slots have been accessed (dataflow waypoints).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataflowWaypoints {
    /// contract address -> set of accessed slot keys
    pub map: HashMap<Address, std::collections::HashSet<U256>>,
}

impl DataflowWaypoints {
    /// Create an empty dataflow waypoints tracker.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Record a storage slot access.
    pub fn record_access(&mut self, address: Address, slot: U256) {
        self.map.entry(address).or_default().insert(slot);
    }

    /// Merge all waypoints from `other` into `self`.
    pub fn merge(&mut self, other: &DataflowWaypoints) {
        for (addr, slots) in &other.map {
            self.map.entry(*addr).or_default().extend(slots);
        }
    }

    /// Total number of unique (address, slot) pairs accessed.
    pub fn len(&self) -> usize {
        self.map.values().map(|s| s.len()).sum()
    }

    /// Returns `true` when no waypoints have been recorded.
    pub fn is_empty(&self) -> bool {
        self.map.values().all(|s| s.is_empty())
    }

    /// Returns `true` if `other` contains at least one (address, slot)
    /// that is **not** present in `self`.
    pub fn has_new_waypoints(&self, other: &DataflowWaypoints) -> bool {
        for (addr, slots) in &other.map {
            match self.map.get(addr) {
                None => {
                    if !slots.is_empty() {
                        return true;
                    }
                }
                Some(existing) => {
                    if slots.iter().any(|slot| !existing.contains(slot)) {
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
        if title.starts_with("Economic: ERC-4626 impossible Deposit") {
            return "economic-erc4626-impossible-deposit".into();
        }
        if title.starts_with("Economic: ERC-4626 impossible Withdraw") {
            return "economic-erc4626-impossible-withdraw".into();
        }
        if title.starts_with("Economic: ERC-20 large mint without totalSupply") {
            return "economic-erc20-mint-no-supply".into();
        }
        if title.starts_with("Economic: ERC-20 balance storage write without Transfer") {
            return "economic-erc20-balance-no-transfer".into();
        }
        if title.starts_with("Economic: ERC-4626 exchange rate jump") {
            return "economic-erc4626-rate-jump".into();
        }
        if title.starts_with("Economic: ERC-4626 exchange rate plunge") {
            return "economic-erc4626-rate-plunge".into();
        }
        if title.starts_with("Economic: lending debt exceeds collateral") {
            return "economic-lending-pairwise-drift".into();
        }
        if title.starts_with("Economic: ERC-20 large burn without totalSupply") {
            return "economic-erc20-burn-no-supply".into();
        }
        if title.starts_with("Economic: ERC-4626 withdraw exchange rate jump") {
            return "economic-erc4626-withdraw-rate-jump".into();
        }
        if title.starts_with("Economic: ERC-4626 withdraw exchange rate plunge") {
            return "economic-erc4626-withdraw-rate-plunge".into();
        }
        if title.starts_with("Economic: ERC-4626 same-tx Deposit rate spread") {
            return "economic-erc4626-same-tx-deposit-spread".into();
        }
        if title.starts_with("Economic: AMM swap exceeds Sync reserves") {
            return "economic-amm-swap-reserve-bounds".into();
        }
        if title.starts_with("Economic: ERC-4626 rate shock without Transfer to vault") {
            return "economic-erc4626-rate-jump-no-token-flow".into();
        }
        if title.starts_with("Economic: ERC-4626 probe previewDeposit vs Deposit event") {
            return "economic-erc4626-probe-deposit-mismatch".into();
        }
        if title.starts_with("Economic: AMM Sync reserves vs getReserves") {
            return "economic-amm-sync-vs-getreserves".into();
        }
        if title.starts_with("Economic: AMM Sync reserve change without Swap/Mint/Burn") {
            return "economic-amm-sync-explained".into();
        }
        if title.starts_with("Economic: ERC-4626 Deposit assets vs underlying Transfer") {
            return "economic-erc4626-deposit-vs-transfer".into();
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
    /// Number of parallel fuzzing workers. Values greater than `1` spawn
    /// threads that share coverage feedback, the snapshot corpus, saved DB
    /// snapshots, and deduplicated findings. Ordering is not reproducible across
    /// runs when `workers > 1`. If `rpc_url` is set, the campaign forces a
    /// single worker (RPC fork state is not shared across threads).
    pub workers: usize,
    /// Deterministic seed for the PRNG.
    pub seed: u64,
    /// Runtime contracts to deploy first (typically `src/` artifacts). Does not
    /// include the optional harness — that is deployed after these when
    /// [`Self::harness`] is set.
    pub targets: Vec<ContractInfo>,
    /// Optional Foundry-style test harness (`test/` artifact with `setUp()`).
    /// When set, it is deployed after [`Self::targets`], then `setUp()` is
    /// executed once before the campaign root snapshot. Fuzzing and property
    /// checks use the merged deployed list (runtime + harness).
    #[serde(default)]
    pub harness: Option<ContractInfo>,
    /// Executor mode (Fast vs Realistic).
    #[serde(default)]
    pub mode: ExecutorMode,
    /// Optional RPC URL for forking state during audits.
    #[serde(default)]
    pub rpc_url: Option<String>,
    /// Optional block number to pin the fork to.
    #[serde(default)]
    pub rpc_block_number: Option<u64>,
    /// When forking: if `true`, keep the attacker's balance from chain state instead of overwriting it in the overlay DB.
    #[serde(default)]
    pub fork_preserve_attacker_balance: bool,
    /// When forking and [`Self::fork_preserve_attacker_balance`] is `false`: balance written for the attacker (default 100 ETH).
    #[serde(default = "default_fork_attacker_balance_wei")]
    pub fork_attacker_balance_wei: U256,
    /// When forking: copy `eth_getCode` into [`ContractInfo::deployed_bytecode`] for targets with empty bytecode (logs / value dict; execution already uses RPC).
    #[serde(default = "default_true")]
    pub fork_hydrate_deployed_bytecode: bool,
    /// Optional: warn when `eth_chainId` differs (wrong endpoint for intended network).
    #[serde(default)]
    pub fork_expected_chain_id: Option<u64>,
    /// Optional funded fuzzer EOA (`msg.sender` pool). When `None`, uses the
    /// default test address `0x42…42`.
    #[serde(default)]
    pub attacker_address: Option<Address>,
    /// Optional directory for corpus persistence.  When set, the campaign
    /// saves its sequence corpus to `{corpus_dir}/seq_corpus.json` at the
    /// end of every run and loads it back at the start of the next run.
    /// Directory is created if it does not exist.
    #[serde(default)]
    pub corpus_dir: Option<std::path::PathBuf>,
    /// Testing mode: controls which oracles are registered and how invariant
    /// checks are gated in the fuzzing loop.
    #[serde(default)]
    pub test_mode: TestMode,
    /// System-level fuzzing: fuzz ALL deployed contracts uniformly, not just the
    /// primary targets.  When `true`, every contract in `targets` is treated as
    /// an equal fuzzing target regardless of harness selection heuristics.
    #[serde(default)]
    pub system_mode: bool,
    /// Automatically synthesize invariants from ABI patterns (access control,
    /// pause state, supply integrity, getter stability).  Enabled by default
    /// when not in exploration/assertion mode.
    #[serde(default = "default_true")]
    pub infer_invariants: bool,
    /// Per-target call weight overrides.  Maps deployed contract address to a
    /// relative weight (1 = default, 2 = twice as likely to be called).  Addresses
    /// not in this map use weight 1.
    #[serde(default)]
    pub target_weights: std::collections::HashMap<Address, u32>,
    /// Per-selector call weight overrides.  Maps 4-byte selector to a relative
    /// weight.  Selectors not in this map use weight 1.
    #[serde(default)]
    pub selector_weights: std::collections::HashMap<[u8; 4], u32>,
    /// Additional funded senders beyond the attacker.  Each address is funded
    /// with `sender_balance_wei` at campaign start.  Allows multi-actor
    /// simulations (e.g. attacker + victim + liquidator).
    #[serde(default)]
    pub extra_senders: Vec<Address>,
    /// Balance to fund each address in `extra_senders` (default 10 ETH).
    #[serde(default = "default_sender_balance_wei")]
    pub sender_balance_wei: U256,
}

fn default_true() -> bool {
    true
}

fn default_fork_attacker_balance_wei() -> U256 {
    U256::from(100_000_000_000_000_000_000_u128)
}

fn default_sender_balance_wei() -> U256 {
    U256::from(10_000_000_000_000_000_000_u128) // 10 ETH
}

impl CampaignConfig {
    /// Funded fuzzer EOA used for deploy, `msg.sender`, and balance oracles.
    ///
    /// [`Self::attacker_address`] when set; otherwise the default test address
    /// `0x4242…4242` (20 bytes of `0x42`).
    pub fn resolved_attacker(&self) -> Address {
        self.attacker_address
            .unwrap_or_else(|| Address::repeat_byte(0x42))
    }
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
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            fork_preserve_attacker_balance: false,
            fork_attacker_balance_wei: default_fork_attacker_balance_wei(),
            fork_hydrate_deployed_bytecode: true,
            fork_expected_chain_id: None,
            attacker_address: None,
            corpus_dir: None,
            test_mode: TestMode::default(),
            system_mode: false,
            infer_invariants: true,
            target_weights: std::collections::HashMap::new(),
            selector_weights: std::collections::HashMap::new(),
            extra_senders: Vec::new(),
            sender_balance_wei: default_sender_balance_wei(),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_config_resolved_attacker_default() {
        let cfg = CampaignConfig::default();
        assert_eq!(cfg.resolved_attacker(), Address::repeat_byte(0x42));
    }

    #[test]
    fn campaign_config_resolved_attacker_override() {
        let custom = Address::with_last_byte(0x77);
        let cfg = CampaignConfig {
            attacker_address: Some(custom),
            ..CampaignConfig::default()
        };
        assert_eq!(cfg.resolved_attacker(), custom);
    }

    #[test]
    fn coverage_map_basics() {
        let mut a = CoverageMap::new();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);

        let addr = Address::ZERO;
        a.record_hit(addr, 0, 1);
        a.record_hit(addr, 42, 43);
        assert_eq!(a.len(), 2);
        assert!(!a.is_empty());

        // Duplicate hit does not increase the number of covered edges.
        a.record_hit(addr, 42, 43);
        assert_eq!(a.len(), 2);
        assert_eq!(a.hitcount(addr, 42, 43), 2);
    }

    #[test]
    fn coverage_map_merge() {
        let addr = Address::ZERO;

        let mut a = CoverageMap::new();
        a.record_hit(addr, 0, 1);

        let mut b = CoverageMap::new();
        b.record_hit(addr, 1, 2);
        b.record_hit(addr, 0, 1);

        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.hitcount(addr, 0, 1), 2);
    }

    #[test]
    fn coverage_map_has_new_coverage() {
        let addr = Address::ZERO;

        let mut base = CoverageMap::new();
        base.record_hit(addr, 0, 1);
        base.record_hit(addr, 1, 2);

        // Subset — no new coverage.
        let mut subset = CoverageMap::new();
        subset.record_hit(addr, 0, 1);
        assert!(!base.has_new_coverage(&subset));

        // Superset — has new coverage.
        let mut superset = CoverageMap::new();
        superset.record_hit(addr, 0, 1);
        superset.record_hit(addr, 99, 100);
        assert!(base.has_new_coverage(&superset));
    }

    /// Two runs can visit the same set of PCs but follow different edges; that must count as new coverage.
    #[test]
    fn coverage_map_distinguishes_paths_with_same_pc_set_different_edges() {
        let addr = Address::ZERO;

        let mut path_ab = CoverageMap::new();
        path_ab.record_hit(addr, 0, 1);
        path_ab.record_hit(addr, 1, 2);

        let mut path_acb = CoverageMap::new();
        path_acb.record_hit(addr, 0, 2);
        path_acb.record_hit(addr, 2, 1);

        assert!(path_ab.has_new_coverage(&path_acb));
        assert!(path_acb.has_new_coverage(&path_ab));
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
        assert!(cfg.harness.is_none());
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
        cm.record_hit(addr, 10, 11);
        cm.record_hit(addr, 20, 21);

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

    #[test]
    fn finding_failure_class_maps_economic_oracle_titles() {
        let f = Finding {
            severity: Severity::High,
            title: "Economic: ERC-20 large burn without totalSupply storage update (0x0000000000000000000000000000000000000001)".into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: None,
        };
        assert_eq!(f.failure_class(), "economic-erc20-burn-no-supply");

        let g = Finding {
            severity: Severity::High,
            title: "Economic: ERC-4626 probe previewDeposit vs Deposit event (0x0000000000000000000000000000000000000001)"
                .into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: None,
        };
        assert_eq!(g.failure_class(), "economic-erc4626-probe-deposit-mismatch");

        let h = Finding {
            severity: Severity::High,
            title: "Economic: AMM Sync reserves vs getReserves (0x0000000000000000000000000000000000000002)"
                .into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: None,
        };
        assert_eq!(h.failure_class(), "economic-amm-sync-vs-getreserves");

        let i = Finding {
            severity: Severity::High,
            title: "Economic: AMM Sync reserve change without Swap/Mint/Burn (0x0000000000000000000000000000000000000003)"
                .into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: None,
        };
        assert_eq!(i.failure_class(), "economic-amm-sync-explained");

        let j = Finding {
            severity: Severity::High,
            title: "Economic: ERC-4626 Deposit assets vs underlying Transfer (0x0000000000000000000000000000000000000004)"
                .into(),
            description: String::new(),
            contract: Address::ZERO,
            reproducer: vec![],
            exploit_profit: None,
        };
        assert_eq!(j.failure_class(), "economic-erc4626-deposit-vs-transfer");
    }
}
