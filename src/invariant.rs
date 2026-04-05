//! Invariant templates for common smart contract patterns.
//!
//! Each invariant implements the [`Invariant`] trait and is checked after every
//! execution.  The [`InvariantRegistry`] collects them and runs them in bulk.

use std::collections::HashMap;

use tiny_keccak::{Hasher, Keccak};

use crate::conservation_oracles::{
    AmmSyncExplainedOracle, Erc4626DepositVsUnderlyingTransferOracle,
};
use crate::economic::{
    Erc20BalanceStorageWithoutTransferOracle, Erc20BurnWithoutSupplyWriteOracle,
    Erc20MintWithoutSupplyWriteOracle, Erc4626EventAnomalyOracle, Erc4626ExchangeRateJumpOracle,
    Erc4626PreviewVsDepositEventOracle, Erc4626RateJumpWithoutTokenFlowOracle,
    Erc4626SameTransactionDepositRateSpreadOracle, Erc4626WithdrawRateJumpOracle,
    ProtocolProfileMap, UniswapV2StyleSwapReserveOracle, UniswapV2StyleSyncVsGetReservesOracle,
};
use crate::types::{Address, ExecutionResult, Finding, Severity, Transaction, B256, U256};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for invariant checkers that run after each execution.
pub trait Invariant: Send + Sync {
    /// Human-readable name for this invariant (used in findings).
    fn name(&self) -> &str;

    /// Check whether the invariant holds.
    ///
    /// * `pre_balances` — account balances *before* the execution.
    /// * `result`       — outcome of the most recent execution.
    /// * `sequence`     — full transaction sequence that led here.
    ///
    /// Returns `Some(finding)` when the invariant is violated.
    fn check(
        &self,
        pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding>;
}

// ---------------------------------------------------------------------------
// Built-in: BalanceIncrease
// ---------------------------------------------------------------------------

/// Detects when an address gains more ETH than a configurable threshold.
pub struct BalanceIncrease {
    /// The address to monitor (typically the attacker / fuzzer sender).
    pub attacker: Address,
    /// Minimum gain (in wei) that triggers a finding.
    pub threshold: U256,
}

impl Invariant for BalanceIncrease {
    fn name(&self) -> &str {
        "balance-increase"
    }

    fn check(
        &self,
        pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        let &(_old_reported, new) = result.state_diff.balance_changes.get(&self.attacker)?;

        // Ignore balance increases if a flashloan was active in the sequence.
        // The FlashloanEconomicOracle handles flashloan-based profit validation.
        use crate::flashloan::MOCK_FLASHLOAN_POOL;
        if sequence.iter().any(|tx| tx.to == Some(MOCK_FLASHLOAN_POOL)) {
            return None;
        }

        let old = pre_balances
            .get(&self.attacker)
            .copied()
            .unwrap_or(U256::ZERO);

        if new <= old {
            return None;
        }
        let gain = new - old;
        if gain < self.threshold {
            return None;
        }

        Some(Finding {
            severity: Severity::Critical,
            title: format!("Unexpected balance increase of {gain} wei"),
            description: format!(
                "Address {} gained {gain} wei over a sequence of {} transaction(s)",
                self.attacker,
                sequence.len(),
            ),
            contract: self.attacker,
            reproducer: sequence.to_vec(),
            exploit_profit: Some(gain),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: UnexpectedRevert
// ---------------------------------------------------------------------------

/// Flags executions that revert when they were expected to succeed.
///
/// This is a low-severity informational check — useful for surfacing
/// potential overflow / underflow conditions in pre-0.8 contracts.
pub struct UnexpectedRevert;

impl Invariant for UnexpectedRevert {
    fn name(&self) -> &str {
        "unexpected-revert"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if result.success || sequence.is_empty() {
            return None;
        }
        let last = sequence.last()?;
        let to = last.to?;

        Some(Finding {
            severity: Severity::Low,
            title: "Unexpected revert".into(),
            description: format!(
                "Transaction to {to} reverted unexpectedly (gas used: {})",
                result.gas_used,
            ),
            contract: to,
            reproducer: sequence.to_vec(),
            exploit_profit: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: SelfDestructDetector
// ---------------------------------------------------------------------------

/// Detects when a contract's balance drops to zero — a heuristic for
/// `SELFDESTRUCT`.
pub struct SelfDestructDetector;

impl Invariant for SelfDestructDetector {
    fn name(&self) -> &str {
        "selfdestruct"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        for (&addr, &(old, new)) in &result.state_diff.balance_changes {
            if old > U256::ZERO && new == U256::ZERO {
                return Some(Finding {
                    severity: Severity::High,
                    title: format!("Possible selfdestruct of {addr}"),
                    description: format!("Contract {addr} balance went from {old} to 0",),
                    contract: addr,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the Keccak-256 hash of `input` and return it as a [`B256`].
fn keccak256(input: &[u8]) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    B256::from(output)
}

/// Convert an [`Address`] into a left-padded [`B256`] (for topic comparison).
fn address_to_b256(addr: Address) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(addr.as_slice());
    B256::from(bytes)
}

// ---------------------------------------------------------------------------
// Built-in: EchidnaProperty
// ---------------------------------------------------------------------------

/// Detects Echidna-style property violations.
///
/// Monitors execution logs for:
/// - `AssertionFailed()` event (keccak256 topic)
/// - Solidity `Panic(uint256)` with code 0x01 (assertion failure)
/// - `AssertionFailed(string)` event
///
/// Compatible with contracts that use `assert()` or emit `AssertionFailed`.
pub struct EchidnaProperty;

impl Invariant for EchidnaProperty {
    fn name(&self) -> &str {
        "echidna-property"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        let assertion_failed_topic = keccak256(b"AssertionFailed()");
        let assertion_failed_string_topic = keccak256(b"AssertionFailed(string)");
        let panic_topic = keccak256(b"Panic(uint256)");

        for log in &result.logs {
            if log.topics.is_empty() {
                continue;
            }
            let topic0 = log.topics[0];

            // AssertionFailed() or AssertionFailed(string)
            if topic0 == assertion_failed_topic || topic0 == assertion_failed_string_topic {
                let target = sequence.last().and_then(|tx| tx.to).unwrap_or(log.address);
                return Some(Finding {
                    severity: Severity::High,
                    title: "Echidna property violation".into(),
                    description: format!("Contract {} emitted AssertionFailed event", log.address,),
                    contract: target,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None,
                });
            }

            // Panic(uint256) with code 0x01 — assertion failure
            if topic0 == panic_topic && log.data.len() >= 32 {
                let code = U256::from_be_slice(&log.data[..32]);
                if code == U256::from(1u64) {
                    let target = sequence.last().and_then(|tx| tx.to).unwrap_or(log.address);
                    return Some(Finding {
                        severity: Severity::High,
                        title: "Assertion failure (Panic 0x01)".into(),
                        description: format!(
                            "Contract {} triggered Panic(0x01) — assertion failure",
                            log.address,
                        ),
                        contract: target,
                        reproducer: sequence.to_vec(),
                        exploit_profit: None,
                    });
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// EchidnaPropertyCaller — calls echidna_* functions via static_call
// ---------------------------------------------------------------------------

/// Real Echidna-compatible property testing.
///
/// After each transaction, calls all registered `echidna_*` functions on
/// the target contract via `static_call`. If any returns `false` (the ABI
/// encoding of `bool false` = 32 zero bytes), that property has been
/// violated.
///
/// This is the full Echidna workflow:
/// 1. Discover functions named `echidna_*` (from ABI)
/// 2. Call them after each transaction sequence
/// 3. Require bool return
/// 4. Treat `false` as failure
pub struct EchidnaPropertyCaller {
    /// Target contract address.
    pub target: Address,
    /// List of (selector, function_name) pairs for echidna_* functions.
    pub properties: Vec<([u8; 4], String)>,
}

impl EchidnaPropertyCaller {
    /// Create from ABI JSON — extracts all functions starting with `"echidna_"`
    /// that take no arguments and return `bool`.
    ///
    /// Returns `None` if no such functions are found.
    pub fn from_abi(target: Address, abi: &serde_json::Value) -> Option<Self> {
        let arr = abi.as_array()?;
        let mut properties = Vec::new();

        for entry in arr {
            // Must be a function.
            let ty = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ty != "function" {
                continue;
            }

            // Name must start with "echidna_".
            let name = match entry.get("name").and_then(|v| v.as_str()) {
                Some(n) if n.starts_with("echidna_") => n,
                _ => continue,
            };

            // Must take no arguments.
            let inputs = entry.get("inputs").and_then(|v| v.as_array());
            if inputs.is_none_or(|a| !a.is_empty()) {
                continue;
            }

            // Must return a single bool.
            let outputs = entry.get("outputs").and_then(|v| v.as_array());
            let returns_bool = outputs.is_some_and(|a| {
                a.len() == 1
                    && a[0]
                        .get("type")
                        .and_then(|v| v.as_str())
                        .is_some_and(|t| t == "bool")
            });
            if !returns_bool {
                continue;
            }

            // Compute selector: keccak256("name()")[0..4].
            let sig = format!("{name}()");
            let hash = keccak256(sig.as_bytes());
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&hash.as_slice()[..4]);

            properties.push((selector, name.to_string()));
        }

        if properties.is_empty() {
            None
        } else {
            Some(Self { target, properties })
        }
    }

    /// Check all properties by calling them via the executor's `static_call`.
    ///
    /// Returns findings for any property that returns `false`.
    ///
    /// Semantics follow Echidna:
    /// - If the call succeeds and output decodes to `false` → **violation**.
    /// - If the call reverts → property holds (conservative, same as Echidna).
    pub fn check_properties(
        &self,
        executor: &crate::evm::EvmExecutor,
        caller: Address,
        sequence: &[Transaction],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (selector, name) in &self.properties {
            let data = crate::types::Bytes::from(selector.to_vec());
            let call_result = executor.static_call(caller, self.target, data);

            match call_result {
                Ok((true, output)) => {
                    // Decode ABI bool: 32 bytes, last byte == 0x00 means false.
                    if output.len() >= 32 && output[31] == 0x00 {
                        findings.push(Finding {
                            severity: Severity::High,
                            title: format!("Echidna property `{name}` violated"),
                            description: format!(
                                "Property function `{name}` on contract {} returned false",
                                self.target,
                            ),
                            contract: self.target,
                            reproducer: sequence.to_vec(),
                            exploit_profit: None,
                        });
                    }
                }
                Ok((false, _)) => {
                    // Call reverted — Echidna treats this as "property holds".
                }
                Err(_) => {
                    // Execution error — skip silently.
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Built-in: FlashloanEconomicOracle
// ---------------------------------------------------------------------------

/// Detects when a flashloan-wrapped sequence results in net profit for the
/// attacker after accounting for the loan fee.
///
/// The oracle watches for sequences containing both a `BORROW` and `REPAY`
/// to the [`MOCK_FLASHLOAN_POOL`] address and checks: if the attacker's
/// post-sequence balance exceeds their pre-sequence balance, the difference
/// is pure profit — a strong signal of an exploitable logic flaw.
pub struct FlashloanEconomicOracle {
    /// Address monitored for anomalous profit.
    pub attacker: Address,
    /// Minimum net profit (in wei) above loan fee that triggers a finding.
    pub min_profit: U256,
}

impl Invariant for FlashloanEconomicOracle {
    fn name(&self) -> &str {
        "flashloan-economic-oracle"
    }

    fn check(
        &self,
        pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        use crate::flashloan::{BORROW_SELECTOR, MOCK_FLASHLOAN_POOL, REPAY_SELECTOR};

        // Only fire on sequences that contain a complete flashloan scaffold (borrow AND repay).
        let has_borrow = sequence.iter().any(|tx| {
            tx.to == Some(MOCK_FLASHLOAN_POOL)
                && tx.data.len() >= 4
                && tx.data[..4] == BORROW_SELECTOR
        });
        let has_repay = sequence.iter().any(|tx| {
            tx.to == Some(MOCK_FLASHLOAN_POOL)
                && tx.data.len() >= 4
                && tx.data[..4] == REPAY_SELECTOR
        });

        if !has_borrow || !has_repay {
            return None;
        }

        // Extract borrowed amount from the first borrow tx.
        let borrowed = sequence
            .iter()
            .find(|tx| {
                tx.to == Some(MOCK_FLASHLOAN_POOL)
                    && tx.data.len() >= 36
                    && tx.data[..4] == BORROW_SELECTOR
            })
            .map(|tx| U256::from_be_slice(&tx.data[4..36]))
            .unwrap_or(U256::ZERO);

        // The fee the attacker had to repay (0.1% approximation).
        let fee = borrowed / U256::from(1000u64);

        // Compare attacker balance before vs after the sequence.
        let pre = pre_balances
            .get(&self.attacker)
            .copied()
            .unwrap_or(U256::ZERO);
        let &(_old, post) = result.state_diff.balance_changes.get(&self.attacker)?;

        if post <= pre {
            return None;
        }

        // net = (post - pre) - fee
        let gross_profit = post - pre;
        if gross_profit <= fee {
            return None;
        }
        let net_profit = gross_profit - fee;
        if net_profit < self.min_profit {
            return None;
        }

        Some(Finding {
            severity: Severity::Critical,
            title: format!("Flashloan-assisted net profit of {net_profit} wei"),
            description: format!(
                "Attacker {} extracted {net_profit} wei net profit in a flashloan sequence of {} txs \
                 (borrowed {borrowed}, fee {fee}, gross gain {gross_profit}).",
                self.attacker,
                sequence.len(),
            ),
            contract: self.attacker,
            reproducer: sequence.to_vec(),
            exploit_profit: Some(net_profit),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: ERC20SupplyInvariant
// ---------------------------------------------------------------------------

/// Checks that ERC20 totalSupply hasn't changed unexpectedly.
///
/// This is a template invariant — it monitors for the `Transfer` event
/// from/to `address(0)` which indicates minting/burning.  If tokens appear
/// without a proper mint event, it flags a supply violation.
pub struct ERC20SupplyInvariant {
    /// The ERC-20 token contract to monitor.
    pub token_address: Address,
}

/// Minimum transfer value (in token units) that triggers a finding.
const LARGE_TRANSFER_THRESHOLD: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

impl Invariant for ERC20SupplyInvariant {
    fn name(&self) -> &str {
        "erc20-supply"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        let transfer_topic = keccak256(b"Transfer(address,address,uint256)");
        let zero_b256 = address_to_b256(Address::ZERO);

        for log in &result.logs {
            if log.address != self.token_address {
                continue;
            }
            if log.topics.len() < 3 || log.topics[0] != transfer_topic {
                continue;
            }
            if log.data.len() < 32 {
                continue;
            }

            let from = log.topics[1];
            let to = log.topics[2];
            let value = U256::from_be_slice(&log.data[..32]);

            if value < LARGE_TRANSFER_THRESHOLD {
                continue;
            }

            // Mint: from == address(0)
            if from == zero_b256 {
                return Some(Finding {
                    severity: Severity::Medium,
                    title: format!("Large token mint at {}", self.token_address),
                    description: format!(
                        "Token {} minted {value} units (from zero address)",
                        self.token_address,
                    ),
                    contract: self.token_address,
                    reproducer: sequence.to_vec(),
                    exploit_profit: Some(value),
                });
            }

            // Burn: to == address(0)
            if to == zero_b256 {
                return Some(Finding {
                    severity: Severity::Medium,
                    title: format!("Large token burn at {}", self.token_address),
                    description: format!(
                        "Token {} burned {value} units (to zero address)",
                        self.token_address,
                    ),
                    contract: self.token_address,
                    reproducer: sequence.to_vec(),
                    exploit_profit: Some(value),
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A collection of [`Invariant`] checkers that can be evaluated in bulk.
pub struct InvariantRegistry {
    invariants: Vec<Box<dyn Invariant>>,
}

impl InvariantRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            invariants: Vec::new(),
        }
    }

    /// Append a single invariant checker.
    pub fn add(&mut self, inv: Box<dyn Invariant>) {
        self.invariants.push(inv);
    }

    /// Run every registered invariant and collect all violations.
    pub fn check_all(
        &self,
        pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Vec<Finding> {
        self.invariants
            .iter()
            .filter_map(|inv| inv.check(pre_balances, result, sequence))
            .collect()
    }

    /// Convenience constructor that registers the built-in invariants.
    pub fn with_defaults(attacker: Address) -> Self {
        Self::with_defaults_and_profiles(attacker, None)
    }

    /// Like [`Self::with_defaults`] but attaches optional ABI-derived protocol profiles for economic triage and gating.
    pub fn with_defaults_and_profiles(
        attacker: Address,
        profiles: Option<ProtocolProfileMap>,
    ) -> Self {
        let pmap = profiles;

        let mut reg = Self::new();
        reg.add(Box::new(BalanceIncrease {
            attacker,
            threshold: U256::from(1u64),
        }));
        reg.add(Box::new(UnexpectedRevert));
        reg.add(Box::new(SelfDestructDetector));
        reg.add(Box::new(EchidnaProperty));
        reg.add(Box::new(FlashloanEconomicOracle {
            attacker,
            // Only fire when profit > 1 wei after accounting for the fee.
            min_profit: U256::from(1u64),
        }));
        reg.add(Box::new(Erc4626EventAnomalyOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc20MintWithoutSupplyWriteOracle {
            min_mint: crate::economic::MIN_LARGE_TOKEN_MOVE,
            total_supply_slot: crate::economic::OZ_ERC20_TOTAL_SUPPLY_SLOT,
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc20BalanceStorageWithoutTransferOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626ExchangeRateJumpOracle {
            max_multiplier: U256::from(5u64),
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc20BurnWithoutSupplyWriteOracle {
            min_burn: crate::economic::MIN_LARGE_TOKEN_MOVE,
            total_supply_slot: crate::economic::OZ_ERC20_TOTAL_SUPPLY_SLOT,
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626WithdrawRateJumpOracle {
            max_multiplier: U256::from(5u64),
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626SameTransactionDepositRateSpreadOracle {
            max_multiplier: U256::from(5u64),
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(UniswapV2StyleSwapReserveOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(AmmSyncExplainedOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626PreviewVsDepositEventOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(UniswapV2StyleSyncVsGetReservesOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626RateJumpWithoutTokenFlowOracle {
            max_multiplier: U256::from(5u64),
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626DepositVsUnderlyingTransferOracle {
            profiles: pmap,
        }));
        reg
    }

    /// Number of registered invariants.
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Returns `true` when no invariants have been registered.
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Create a registry with defaults plus ERC20 invariants for the given tokens.
    pub fn with_erc20(attacker: Address, tokens: &[Address]) -> Self {
        let mut reg = Self::with_defaults(attacker);
        for &token in tokens {
            reg.add(Box::new(ERC20SupplyInvariant {
                token_address: token,
            }));
        }
        reg
    }
}

impl Default for InvariantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Bytes, CoverageMap, Log, StateDiff};
    use serde_json::json;

    /// Helper — build a minimal [`ExecutionResult`].
    fn make_result(
        success: bool,
        balance_changes: HashMap<Address, (U256, U256)>,
    ) -> ExecutionResult {
        ExecutionResult {
            success,
            output: Bytes::new(),
            gas_used: 21_000,
            logs: Vec::new(),
            coverage: CoverageMap::new(),
            dataflow: Default::default(),
            state_diff: StateDiff {
                storage_writes: HashMap::new(),
                balance_changes,
            },
            sequence_cumulative_logs: Vec::new(),
            protocol_probes: Default::default(),
            tx_path_id: crate::types::B256::ZERO,
        }
    }

    fn dummy_sequence(to: Address) -> Vec<Transaction> {
        vec![Transaction {
            sender: Address::ZERO,
            to: Some(to),
            data: Bytes::new(),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }]
    }

    #[test]
    fn balance_increase_triggers_on_gain() {
        let attacker = Address::repeat_byte(0xAA);
        let inv = BalanceIncrease {
            attacker,
            threshold: U256::from(100u64),
        };

        let mut pre = HashMap::new();
        pre.insert(attacker, U256::from(1000u64));

        let mut bc = HashMap::new();
        bc.insert(attacker, (U256::from(1000u64), U256::from(2000u64)));

        let result = make_result(true, bc);
        let seq = dummy_sequence(attacker);

        let finding = inv.check(&pre, &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.exploit_profit.is_some());
    }

    #[test]
    fn balance_increase_ignores_below_threshold() {
        let attacker = Address::repeat_byte(0xBB);
        let inv = BalanceIncrease {
            attacker,
            threshold: U256::from(500u64),
        };

        let mut pre = HashMap::new();
        pre.insert(attacker, U256::from(1000u64));

        let mut bc = HashMap::new();
        bc.insert(attacker, (U256::from(1000u64), U256::from(1100u64)));

        let result = make_result(true, bc);
        let seq = dummy_sequence(attacker);

        assert!(inv.check(&pre, &result, &seq).is_none());
    }

    #[test]
    fn unexpected_revert_fires_on_failure() {
        let inv = UnexpectedRevert;
        let target = Address::repeat_byte(0xCC);
        let result = make_result(false, HashMap::new());
        let seq = dummy_sequence(target);

        let finding = inv.check(&HashMap::new(), &result, &seq);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Low);
    }

    #[test]
    fn unexpected_revert_silent_on_success() {
        let inv = UnexpectedRevert;
        let result = make_result(true, HashMap::new());
        let seq = dummy_sequence(Address::ZERO);

        assert!(inv.check(&HashMap::new(), &result, &seq).is_none());
    }

    #[test]
    fn selfdestruct_detects_balance_zeroing() {
        let inv = SelfDestructDetector;
        let contract = Address::repeat_byte(0xDD);

        let mut bc = HashMap::new();
        bc.insert(contract, (U256::from(5000u64), U256::ZERO));

        let result = make_result(true, bc);
        let seq = dummy_sequence(contract);

        let finding = inv.check(&HashMap::new(), &result, &seq);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn registry_with_defaults_has_expected_count() {
        let reg = InvariantRegistry::with_defaults(Address::ZERO);
        // BalanceIncrease, UnexpectedRevert, SelfDestructDetector, EchidnaProperty,
        // FlashloanEconomicOracle, Erc4626EventAnomaly, Erc20MintWithoutSupplyWrite,
        // Erc20BalanceStorageWithoutTransfer, Erc4626ExchangeRateJump,
        // Erc20BurnWithoutSupplyWrite, Erc4626WithdrawRateJump, Erc4626SameTransactionDepositRateSpread,
        // UniswapV2StyleSwapReserve, AmmSyncExplained, Erc4626PreviewVsDepositEvent,
        // UniswapV2StyleSyncVsGetReserves, Erc4626RateJumpWithoutTokenFlow,
        // Erc4626DepositVsUnderlyingTransfer (18 total)
        assert_eq!(reg.len(), 18);
        assert!(!reg.is_empty());
    }

    #[test]
    fn registry_check_all_collects_violations() {
        let attacker = Address::repeat_byte(0xEE);
        let reg = InvariantRegistry::with_defaults(attacker);

        let mut pre = HashMap::new();
        pre.insert(attacker, U256::from(100u64));

        let mut bc = HashMap::new();
        bc.insert(attacker, (U256::from(100u64), U256::from(9999u64)));

        let result = make_result(true, bc);
        let seq = dummy_sequence(attacker);

        let findings = reg.check_all(&pre, &result, &seq);
        // At least the balance-increase invariant should fire.
        assert!(!findings.is_empty());
    }

    #[test]
    fn empty_registry_returns_no_findings() {
        let reg = InvariantRegistry::new();
        let result = make_result(true, HashMap::new());
        assert!(reg.check_all(&HashMap::new(), &result, &[]).is_empty());
    }

    // -- EchidnaProperty & ERC20SupplyInvariant tests -------------------------

    /// Build an [`ExecutionResult`] with custom logs.
    fn make_result_with_logs(success: bool, logs: Vec<Log>) -> ExecutionResult {
        ExecutionResult {
            success,
            output: Bytes::new(),
            gas_used: 21_000,
            logs,
            coverage: CoverageMap::new(),
            dataflow: Default::default(),
            state_diff: StateDiff {
                storage_writes: HashMap::new(),
                balance_changes: HashMap::new(),
            },
            sequence_cumulative_logs: Vec::new(),
            protocol_probes: Default::default(),
            tx_path_id: crate::types::B256::ZERO,
        }
    }

    #[test]
    fn echidna_property_detects_assertion_failed() {
        let inv = EchidnaProperty;
        let topic = keccak256(b"AssertionFailed()");
        let contract = Address::repeat_byte(0x11);

        let log = Log {
            address: contract,
            topics: vec![topic],
            data: Bytes::new(),
        };
        let result = make_result_with_logs(true, vec![log]);
        let seq = dummy_sequence(contract);

        let finding = inv.check(&HashMap::new(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("Echidna"));
    }

    #[test]
    fn echidna_property_detects_panic_0x01() {
        let inv = EchidnaProperty;
        let topic = keccak256(b"Panic(uint256)");
        let contract = Address::repeat_byte(0x22);

        // ABI-encoded uint256 with value 1
        let mut data = vec![0u8; 32];
        data[31] = 1;

        let log = Log {
            address: contract,
            topics: vec![topic],
            data: Bytes::from(data),
        };
        let result = make_result_with_logs(true, vec![log]);
        let seq = dummy_sequence(contract);

        let finding = inv.check(&HashMap::new(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("Panic"));
    }

    #[test]
    fn echidna_property_ignores_panic_other_codes() {
        let inv = EchidnaProperty;
        let topic = keccak256(b"Panic(uint256)");
        let contract = Address::repeat_byte(0x33);

        // Panic code 0x11 (overflow) — should NOT be flagged
        let mut data = vec![0u8; 32];
        data[31] = 0x11;

        let log = Log {
            address: contract,
            topics: vec![topic],
            data: Bytes::from(data),
        };
        let result = make_result_with_logs(true, vec![log]);
        let seq = dummy_sequence(contract);

        assert!(inv.check(&HashMap::new(), &result, &seq).is_none());
    }

    #[test]
    fn erc20_supply_detects_large_mint() {
        let token = Address::repeat_byte(0x44);
        let inv = ERC20SupplyInvariant {
            token_address: token,
        };

        let transfer_topic = keccak256(b"Transfer(address,address,uint256)");
        // from = address(0) → mint
        let from_topic = B256::ZERO;
        // to = some recipient
        let mut to_bytes = [0u8; 32];
        to_bytes[12..].copy_from_slice(Address::repeat_byte(0x55).as_slice());
        let to_topic = B256::from(to_bytes);

        // value = 2 * 10^18
        let value = U256::from(2_000_000_000_000_000_000u64);
        let data = Bytes::from(value.to_be_bytes::<32>().to_vec());

        let log = Log {
            address: token,
            topics: vec![transfer_topic, from_topic, to_topic],
            data,
        };
        let result = make_result_with_logs(true, vec![log]);
        let seq = dummy_sequence(token);

        let finding = inv.check(&HashMap::new(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.title.contains("mint"));
    }

    #[test]
    fn erc20_supply_ignores_other_contracts() {
        let token = Address::repeat_byte(0x66);
        let other = Address::repeat_byte(0x77);
        let inv = ERC20SupplyInvariant {
            token_address: token,
        };

        let transfer_topic = keccak256(b"Transfer(address,address,uint256)");
        let from_topic = B256::ZERO;
        let mut to_bytes = [0u8; 32];
        to_bytes[12..].copy_from_slice(Address::repeat_byte(0x88).as_slice());
        let to_topic = B256::from(to_bytes);

        let value = U256::from(2_000_000_000_000_000_000u64);
        let data = Bytes::from(value.to_be_bytes::<32>().to_vec());

        // Log emitted by `other`, not `token`
        let log = Log {
            address: other,
            topics: vec![transfer_topic, from_topic, to_topic],
            data,
        };
        let result = make_result_with_logs(true, vec![log]);
        let seq = dummy_sequence(other);

        assert!(inv.check(&HashMap::new(), &result, &seq).is_none());
    }

    #[test]
    fn registry_with_erc20_adds_token_invariants() {
        let attacker = Address::repeat_byte(0x99);
        let tokens = vec![Address::repeat_byte(0xA1), Address::repeat_byte(0xA2)];
        let reg = InvariantRegistry::with_erc20(attacker, &tokens);
        // 18 defaults + 2 ERC20Supply invariants
        assert_eq!(reg.len(), 20);
    }

    // -- EchidnaPropertyCaller tests ------------------------------------------

    #[test]
    fn echidna_caller_from_abi_extracts_properties() {
        let abi = json!([
            {
                "type": "function",
                "name": "echidna_test_balance",
                "inputs": [],
                "outputs": [{"type": "bool"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "echidna_no_overflow",
                "inputs": [],
                "outputs": [{"type": "bool"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "deposit",
                "inputs": [{"type": "uint256", "name": "amount"}],
                "outputs": [],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "echidna_with_arg",
                "inputs": [{"type": "uint256", "name": "x"}],
                "outputs": [{"type": "bool"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "echidna_returns_uint",
                "inputs": [],
                "outputs": [{"type": "uint256"}],
                "stateMutability": "view"
            },
            {
                "type": "event",
                "name": "echidna_event",
                "inputs": []
            }
        ]);

        let target = Address::repeat_byte(0xAB);
        let caller = EchidnaPropertyCaller::from_abi(target, &abi);
        assert!(caller.is_some());
        let caller = caller.unwrap();
        assert_eq!(caller.properties.len(), 2);
        assert_eq!(caller.target, target);

        let names: Vec<&str> = caller.properties.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"echidna_test_balance"));
        assert!(names.contains(&"echidna_no_overflow"));
    }

    #[test]
    fn echidna_caller_from_abi_returns_none_when_empty() {
        let abi = json!([
            {
                "type": "function",
                "name": "withdraw",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable"
            }
        ]);
        let result = EchidnaPropertyCaller::from_abi(Address::ZERO, &abi);
        assert!(result.is_none());
    }

    #[test]
    fn echidna_caller_selector_matches_keccak() {
        let abi = json!([
            {
                "type": "function",
                "name": "echidna_state",
                "inputs": [],
                "outputs": [{"type": "bool"}],
                "stateMutability": "view"
            }
        ]);
        let caller = EchidnaPropertyCaller::from_abi(Address::repeat_byte(0x01), &abi).unwrap();
        assert_eq!(caller.properties.len(), 1);

        let (selector, name) = &caller.properties[0];
        assert_eq!(name, "echidna_state");

        // Verify selector is first 4 bytes of keccak256("echidna_state()")
        let expected_hash = keccak256(b"echidna_state()");
        assert_eq!(selector, &expected_hash.as_slice()[..4]);
    }
}
