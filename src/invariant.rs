//! Invariant templates for common smart contract patterns.
//!
//! Each invariant implements the [`Invariant`] trait and is checked after every
//! execution.  The [`InvariantRegistry`] collects them and runs them in bulk.

use std::collections::HashMap;

use tiny_keccak::{Hasher, Keccak};

use crate::conservation_oracles::{
    AmmSyncExplainedOracle, Erc4626DepositVsUnderlyingTransferOracle,
    Erc4626FirstDepositorInflationOracle, Erc4626StrictAccountingDriftOracle,
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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

/// Flags executions that revert with meaningful gas usage.
///
/// Low-gas reverts (< 5000 gas) are typically just "no matching function
/// selector" or basic argument validation — not interesting. Only fires
/// when the EVM got at least deep enough to do real work before reverting,
/// which suggests an overflow / underflow / unexpected state.
pub struct UnexpectedRevert {
    /// Minimum gas consumed before a revert is worth flagging.
    /// Default: 5000. Set to 0 to capture all reverts (very noisy).
    pub min_gas_threshold: u64,
}

impl Default for UnexpectedRevert {
    fn default() -> Self {
        Self {
            // EVM base tx cost is 21,000 gas. A revert immediately after costs
            // ~21,100-21,200. Only flag reverts that consumed real work — set
            // threshold well above the base cost so trivial "bad selector" calls
            // don't flood findings.
            min_gas_threshold: 30_000,
        }
    }
}

impl Invariant for UnexpectedRevert {
    fn name(&self) -> &str {
        "unexpected-revert"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if result.success || sequence.is_empty() {
            return None;
        }
        // Low-gas reverts are almost always invalid selector / arg validation.
        // Skip them — they flood findings with noise.
        if result.gas_used < self.min_gas_threshold {
            return None;
        }
        let last = sequence.last()?;
        let to = last.to?;

        Some(Finding {
            severity: Severity::Low,
            title: "Unexpected revert".into(),
            description: format!(
                "Transaction to {to} reverted after consuming {} gas — possible assertion/overflow",
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
///
/// Only fires when:
/// 1. The balance drop is substantial (> 1e15 wei / 0.001 ETH) to filter
///    out mock tokens whose dust balances drain legitimately.
/// 2. The balance of the *attacker* increased in the same execution —
///    the typical selfdestruct-drain pattern.
pub struct SelfDestructDetector {
    /// Address of the attacker/fuzzer sender (for profit cross-check).
    pub attacker: Address,
}

impl Invariant for SelfDestructDetector {
    fn name(&self) -> &str {
        "selfdestruct"
    }

    fn check(
        &self,
        pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        // Minimum ETH drain worth flagging: 0.001 ETH.
        let min_drain = U256::from(1_000_000_000_000_000u128);

        for (&addr, &(old, new)) in &result.state_diff.balance_changes {
            // Skip the attacker's own address and zero-balance contracts.
            if addr == self.attacker || old <= min_drain || new != U256::ZERO {
                continue;
            }
            // Require that the attacker's balance also went up — confirms profit,
            // reduces false positives from legitimate fee collection or burns.
            let attacker_old = pre_balances
                .get(&self.attacker)
                .copied()
                .unwrap_or(U256::ZERO);
            let attacker_new = result
                .state_diff
                .balance_changes
                .get(&self.attacker)
                .map(|&(_, n)| n)
                .unwrap_or(attacker_old);
            if attacker_new <= attacker_old {
                continue;
            }

            return Some(Finding {
                severity: Severity::High,
                title: format!("Possible selfdestruct of {addr}"),
                description: format!(
                    "Contract {addr} balance drained from {old} to 0; attacker gained {} wei",
                    attacker_new.saturating_sub(attacker_old),
                ),
                contract: addr,
                reproducer: sequence.to_vec(),
                exploit_profit: Some(attacker_new.saturating_sub(attacker_old)),
            });
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
// Built-in: AccessControlOracle
// ---------------------------------------------------------------------------

/// Privileged function name patterns that non-owners should not be able to call.
///
/// All comparisons are performed **lowercase** on the function name only; the
/// selector is computed from the full `name(...)` signature in the ABI.
static PRIVILEGED_FN_NAMES: &[&str] = &[
    "setowner",
    "transferownership",
    "renounceownership",
    "pause",
    "unpause",
    "pauseall",
    "unpauseall",
    "upgradeto",
    "upgradetoandcall",
    "_authorizeupgrade",
    "setadmin",
    "setoperator",
    "setminter",
    "setfee",
    "setfees",
    "setprotocolfee",
    "settreasury",
    "setvault",
    "grantrole",
    "revokerole",
    "renouncerole",
    "emergencywithdraw",
    "emergencyshutdown",
    "emergencyexit",
    "initialize",
    "reinitialize",
];

fn is_privileged_fn(name: &str) -> bool {
    let lower = name.to_lowercase();
    PRIVILEGED_FN_NAMES.contains(&lower.as_str())
}

/// Detects when the attacker successfully calls a privileged function.
///
/// At campaign setup, supply this oracle with all privilege-gated selectors
/// from the target ABI.  It then fires whenever the attacker (any address
/// *other* than `deployer`) succeeds in calling one of them.
pub struct AccessControlOracle {
    /// The canonical owner / deployer address that *is* allowed to call
    /// privileged functions.
    pub deployer: Address,
    /// The fuzzer attacker address (or any address that should be rejected).
    pub attacker: Address,
    /// `(selector, human-readable function name)` pairs derived from the ABI
    /// for functions whose names match [`PRIVILEGED_FN_NAMES`].
    ///
    /// Build this via [`AccessControlOracle::from_abi`].
    pub privileged_selectors: Vec<([u8; 4], String)>,
}

impl AccessControlOracle {
    /// Build from a JSON ABI array — extracts functions whose lowercase names
    /// appear in [`PRIVILEGED_FN_NAMES`] and computes their 4-byte selectors.
    ///
    /// Returns `None` if no privileged functions are found.
    pub fn from_abi(deployer: Address, attacker: Address, abi: &serde_json::Value) -> Option<Self> {
        let arr = abi.as_array()?;
        let mut privileged_selectors = Vec::new();

        for entry in arr {
            let ty = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ty != "function" {
                continue;
            }
            let name = match entry.get("name").and_then(|v| v.as_str()) {
                Some(n) if is_privileged_fn(n) => n,
                _ => continue,
            };
            // Build the ABI signature: `name(type0,type1,...)`.
            let inputs = entry.get("inputs").and_then(|v| v.as_array());
            let param_types: String = inputs
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.get("type").and_then(|v| v.as_str()))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let sig = format!("{name}({param_types})");
            let hash = keccak256(sig.as_bytes());
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&hash.as_slice()[..4]);
            privileged_selectors.push((selector, name.to_string()));
        }

        if privileged_selectors.is_empty() {
            None
        } else {
            Some(Self {
                deployer,
                attacker,
                privileged_selectors,
            })
        }
    }
}

impl Invariant for AccessControlOracle {
    fn name(&self) -> &str {
        "access-control"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let last = sequence.last()?;
        // The deployer (owner) calling privileged functions is expected behaviour.
        if last.sender == self.deployer {
            return None;
        }
        if last.data.len() < 4 {
            return None;
        }
        let sel: [u8; 4] = last.data[..4].try_into().ok()?;
        for (priv_sel, fn_name) in &self.privileged_selectors {
            if sel == *priv_sel {
                let contract = last.to.unwrap_or(Address::ZERO);
                return Some(Finding {
                    severity: Severity::Critical,
                    title: format!(
                        "Access control violation: `{fn_name}` called by non-owner succeeded"
                    ),
                    description: format!(
                        "Non-owner {} successfully called privileged function `{fn_name}` on \
                         contract {contract}. The deployer/owner is {deployer}. \
                         This indicates a missing or broken access control guard.",
                        last.sender,
                        deployer = self.deployer,
                    ),
                    contract,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Built-in: ReentrancyOracle
// ---------------------------------------------------------------------------

/// Detects profitable reentrancy — SSTORE in a nested call frame combined with
/// attacker ETH profit.
///
/// Uses [`ExecutionResult::sstore_in_nested_call`] (set by the EVM inspector)
/// as the *necessary condition* (state was written while a call was in
/// progress) and attacker balance gain as the *sufficient condition*.
///
/// False-positive rate is kept low because **both** conditions must hold:
/// most legitimate multi-hop protocols do not result in attacker ETH profit.
pub struct ReentrancyOracle {
    /// Address monitored for ETH profit.
    pub attacker: Address,
}

impl Invariant for ReentrancyOracle {
    fn name(&self) -> &str {
        "reentrancy"
    }

    fn check(
        &self,
        pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.sstore_in_nested_call {
            return None;
        }
        // Only fire when the attacker also shows ETH profit — anti-noise gate.
        let pre = pre_balances
            .get(&self.attacker)
            .copied()
            .unwrap_or(U256::ZERO);
        let post = result
            .state_diff
            .balance_changes
            .get(&self.attacker)
            .map(|&(_, n)| n)
            .unwrap_or(pre);
        if post <= pre {
            return None;
        }
        let profit = post - pre;
        // Skip dust gains that are probably just gas refunds.
        if profit < U256::from(1_000u64) {
            return None;
        }
        let contract = sequence
            .last()
            .and_then(|tx| tx.to)
            .unwrap_or(Address::ZERO);
        Some(Finding {
            severity: Severity::High,
            title: format!("Reentrancy: SSTORE in nested call with ETH profit ({contract})"),
            description: format!(
                "An SSTORE opcode fired while at least one external call frame was on the stack \
                 (call_depth > 0), combined with attacker {} gaining {profit} wei. \
                 This pattern is consistent with a cross-function or classic reentrancy \
                 vulnerability — verify state mutation ordering against checks-effects-interactions.",
                self.attacker,
            ),
            contract,
            reproducer: sequence.to_vec(),
            exploit_profit: Some(profit),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: TokenFlowConservationOracle
// ---------------------------------------------------------------------------

/// Detects when ERC-20 tokens flow OUT of a target contract more than they flow
/// IN across a fuzz sequence.
///
/// Uses [`ExecutionResult::sequence_cumulative_logs`] so it sees every
/// `Transfer` event in the full sequence, not just the last transaction.
///
/// A non-zero `excess_out` means tokens were drained that were not deposited
/// by the fuzzer — a strong signal of an unauthorised withdrawal or accounting
/// bug.
pub struct TokenFlowConservationOracle {
    /// Contract address whose token balances to monitor.
    pub target: Address,
    /// Minimum excess-out amount (in token base units) below which the finding
    /// is suppressed.  Filters dust / rounding artefacts.
    pub min_excess: U256,
}

impl Default for TokenFlowConservationOracle {
    fn default() -> Self {
        Self {
            target: Address::ZERO,
            min_excess: U256::from(1_000u64),
        }
    }
}

impl Invariant for TokenFlowConservationOracle {
    fn name(&self) -> &str {
        "token-flow-conservation"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let xfer_t = keccak256(b"Transfer(address,address,uint256)");
        let target_padded = address_to_b256(self.target);

        // Per-token accumulate: (in_flow, out_flow).
        let mut flows: std::collections::HashMap<Address, (U256, U256)> =
            std::collections::HashMap::new();

        let logs = if result.sequence_cumulative_logs.is_empty() {
            &result.logs
        } else {
            &result.sequence_cumulative_logs
        };

        for log in logs {
            if log.topics.get(0).copied() != Some(xfer_t) || log.topics.len() < 3 {
                continue;
            }
            if log.data.len() < 32 {
                continue;
            }
            let from = log.topics[1];
            let to = log.topics[2];
            let amount = U256::from_be_slice(&log.data[..32]);
            if amount.is_zero() {
                continue;
            }
            let token = log.address;
            let entry = flows.entry(token).or_insert((U256::ZERO, U256::ZERO));
            if to == target_padded {
                entry.0 = entry.0.saturating_add(amount); // in
            }
            if from == target_padded {
                entry.1 = entry.1.saturating_add(amount); // out
            }
        }

        for (token, (in_flow, out_flow)) in &flows {
            if out_flow <= in_flow {
                continue;
            }
            let excess = out_flow - in_flow;
            if excess < self.min_excess {
                continue;
            }
            return Some(Finding {
                severity: Severity::High,
                title: format!(
                    "Token flow conservation violated: {token} drained from {}",
                    self.target
                ),
                description: format!(
                    "Token {token}: {out_flow} units transferred OUT of {} but only {in_flow} \
                     transferred IN during this fuzz sequence (excess drain: {excess} units). \
                     Tokens present before the sequence may have been unauthorisedly drained.",
                    self.target,
                ),
                contract: self.target,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Built-in: LendingHealthOracle (Phase 6)
// ---------------------------------------------------------------------------

/// Detects uncollateralised or anomalous borrow patterns in lending protocols.
///
/// Monitors cumulative sequence logs for [`Borrow`] and [`Repay`]/[`RepayBorrow`]
/// events, accumulates net unbacked debt, and fires when the net borrow amount
/// exceeds [`min_net_borrow`].  Profile-gated: when [`profiles`] is provided,
/// only logs emitted by contracts classified as lending-like (see
/// [`crate::protocol_semantics::ContractProtocolProfile::is_lending_like`]) are
/// considered.
///
/// Recognised event signatures (amount always decoded from `data[0..32]`):
/// - `Borrow(address,address,uint256)` — simplified / generic
/// - `Borrow(address,uint256,uint256,uint256)` — Compound-v2 style
/// - `Repay(address,address,uint256)` — simplified / generic
/// - `RepayBorrow(address,address,uint256,uint256,uint256)` — Compound-v2 style
pub struct LendingHealthOracle {
    /// Minimum net-unbacked borrow (in token base units) required to fire.
    pub min_net_borrow: U256,
    /// Optional ABI-derived protocol profiles for lending-contract gating.
    /// When `None` the oracle considers every matching borrow event.
    pub profiles: Option<ProtocolProfileMap>,
    /// Fuzzer-controlled attacker address.  Used to escalate severity to
    /// [`Severity::High`] when the attacker also gains ETH in the sequence.
    pub attacker: Address,
}

impl Invariant for LendingHealthOracle {
    fn name(&self) -> &str {
        "lending-health"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        let borrow_t_a = keccak256(b"Borrow(address,address,uint256)");
        let borrow_t_b = keccak256(b"Borrow(address,uint256,uint256,uint256)");
        let repay_t_a = keccak256(b"Repay(address,address,uint256)");
        let repay_t_b = keccak256(b"RepayBorrow(address,address,uint256,uint256,uint256)");

        let logs = if result.sequence_cumulative_logs.is_empty() {
            &result.logs
        } else {
            &result.sequence_cumulative_logs
        };

        let mut total_borrow = U256::ZERO;
        let mut total_repay = U256::ZERO;

        for log in logs {
            let Some(&topic0) = log.topics.first() else {
                continue;
            };

            // Profile gating: only consider events from lending-like contracts
            // when profile data is available.
            if let Some(ref pmap) = self.profiles {
                match pmap.get(&log.address) {
                    Some(p) if p.is_lending_like() => {}
                    _ => continue,
                }
            }

            if log.data.len() < 32 {
                continue;
            }
            let amount = U256::from_be_slice(&log.data[..32]);
            if amount.is_zero() {
                continue;
            }

            if topic0 == borrow_t_a || topic0 == borrow_t_b {
                total_borrow = total_borrow.saturating_add(amount);
            } else if topic0 == repay_t_a || topic0 == repay_t_b {
                total_repay = total_repay.saturating_add(amount);
            }
        }

        let net_borrow = total_borrow.saturating_sub(total_repay);
        if net_borrow < self.min_net_borrow {
            return None;
        }

        // Escalate to High if the attacker also gained ETH this sequence.
        let attacker_profit = result
            .state_diff
            .balance_changes
            .get(&self.attacker)
            .and_then(|(pre, post)| post.checked_sub(*pre))
            .unwrap_or(U256::ZERO);

        let severity = if attacker_profit > U256::ZERO {
            Severity::High
        } else {
            Severity::Medium
        };

        let contract = sequence
            .first()
            .and_then(|tx| tx.to)
            .unwrap_or(Address::ZERO);

        Some(Finding {
            severity,
            title: format!(
                "Lending health violation: {net_borrow} net unbacked borrow units detected"
            ),
            description: format!(
                "Net uncollateralised borrow: {net_borrow} base units \
                 (total borrow {total_borrow}, repaid {total_repay}). \
                 Lending position may be undercollateralised or an unbacked \
                 flash-borrow left residual debt.{}",
                if attacker_profit > U256::ZERO {
                    format!(" Attacker profit: {attacker_profit} wei.")
                } else {
                    String::new()
                },
            ),
            contract,
            reproducer: sequence.to_vec(),
            exploit_profit: if attacker_profit > U256::ZERO {
                Some(attacker_profit)
            } else {
                None
            },
        })
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
        pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Vec<Finding> {
        self.invariants
            .iter()
            .filter_map(|inv| inv.check(pre_balances, pre_probes, result, sequence))
            .collect()
    }

    /// Like [`Self::check_all`] but returns per-invariant run and hit counts for telemetry.
    pub fn check_all_tracked(
        &self,
        pre_balances: &HashMap<Address, U256>,
        pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> (
        Vec<Finding>,
        HashMap<String, u64>,
        HashMap<String, u64>,
    ) {
        let mut findings = Vec::new();
        let mut runs: HashMap<String, u64> = HashMap::new();
        let mut hits: HashMap<String, u64> = HashMap::new();
        for inv in &self.invariants {
            let name = inv.name().to_string();
            *runs.entry(name.clone()).or_insert(0) += 1;
            if let Some(f) = inv.check(pre_balances, pre_probes, result, sequence) {
                *hits.entry(name).or_insert(0) += 1;
                findings.push(f);
            }
        }
        (findings, runs, hits)
    }

    /// Convenience constructor that registers the built-in invariants.
    pub fn with_defaults(attacker: Address) -> Self {
        Self::with_defaults_and_profiles(attacker, None)
    }

    /// Assertion-mode registry: only registers EchidnaProperty and UnexpectedRevert.
    /// Used when `TestMode::Assertion` is active to suppress economic oracle noise.
    pub fn with_assertion_mode(_attacker: Address) -> Self {
        let mut reg = Self::new();
        reg.add(Box::new(UnexpectedRevert::default()));
        reg.add(Box::new(EchidnaProperty));
        reg
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
        reg.add(Box::new(UnexpectedRevert::default()));
        reg.add(Box::new(SelfDestructDetector { attacker }));
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
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626FirstDepositorInflationOracle {
            profiles: pmap.clone(),
        }));
        reg.add(Box::new(Erc4626StrictAccountingDriftOracle {
            profiles: pmap.clone(),
        }));
        // Phase 3 additions: reentrancy oracle (always on — profit gate reduces noise).
        reg.add(Box::new(ReentrancyOracle { attacker }));
        // Phase 6: LendingHealthOracle (profile-gated — no-op on non-lending targets).
        reg.add(Box::new(LendingHealthOracle {
            min_net_borrow: U256::from(1_000_000_000_000_000_000u64), // 1 token unit (18 dp)
            profiles: pmap,
            attacker,
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
            assume_violated: false,
            revert_was_expected: false,
            sstore_in_nested_call: false,
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

        let finding = inv.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq);
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

        assert!(inv.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn unexpected_revert_fires_on_high_gas_failure() {
        // High-gas revert (above threshold) should fire.
        let inv = UnexpectedRevert {
            min_gas_threshold: 0, // no threshold for this test
        };
        let target = Address::repeat_byte(0xCC);
        let result = make_result(false, HashMap::new());
        let seq = dummy_sequence(target);

        let finding = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Low);
    }

    #[test]
    fn unexpected_revert_silent_on_low_gas_failure() {
        // Default threshold (5000 gas) should suppress low-gas reverts.
        let inv = UnexpectedRevert::default();
        let target = Address::repeat_byte(0xCC);
        let mut result = make_result(false, HashMap::new());
        result.gas_used = 100; // way below threshold

        let seq = dummy_sequence(target);
        // Should be None because gas_used < min_gas_threshold
        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn unexpected_revert_silent_on_success() {
        let inv = UnexpectedRevert::default();
        let result = make_result(true, HashMap::new());
        let seq = dummy_sequence(Address::ZERO);

        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn selfdestruct_detects_balance_zeroing_with_attacker_profit() {
        let attacker = Address::repeat_byte(0xAA);
        let inv = SelfDestructDetector { attacker };
        let contract = Address::repeat_byte(0xDD);

        // Contract loses big balance, attacker gains it.
        let drain = U256::from(2_000_000_000_000_000u128); // 0.002 ETH
        let mut bc = HashMap::new();
        bc.insert(contract, (drain, U256::ZERO));
        bc.insert(attacker, (U256::ZERO, drain));

        let result = make_result(true, bc);
        let pre = {
            let mut m = HashMap::new();
            m.insert(attacker, U256::ZERO);
            m
        };
        let seq = dummy_sequence(contract);

        let finding = inv.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn selfdestruct_ignores_dust_drain() {
        let attacker = Address::repeat_byte(0xAA);
        let inv = SelfDestructDetector { attacker };
        let contract = Address::repeat_byte(0xDD);

        // Tiny balance (below threshold) — should not fire.
        let mut bc = HashMap::new();
        bc.insert(contract, (U256::from(100u64), U256::ZERO));
        bc.insert(attacker, (U256::ZERO, U256::from(100u64)));

        let result = make_result(true, bc);
        let pre = HashMap::new();
        let seq = dummy_sequence(contract);

        assert!(inv.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
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
        // Erc4626DepositVsUnderlyingTransfer, Erc4626FirstDepositorInflation,
        // ReentrancyOracle, LendingHealthOracle (22 total)
        assert_eq!(reg.len(), 22);
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

        let findings = reg.check_all(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq);
        // At least the balance-increase invariant should fire.
        assert!(!findings.is_empty());
    }

    #[test]
    fn empty_registry_returns_no_findings() {
        let reg = InvariantRegistry::new();
        let result = make_result(true, HashMap::new());
        assert!(reg.check_all(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &[]).is_empty());
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
            assume_violated: false,
            revert_was_expected: false,
            sstore_in_nested_call: false,
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

        let finding = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
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

        let finding = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
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

        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
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

        let finding = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
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

        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn registry_with_erc20_adds_token_invariants() {
        let attacker = Address::repeat_byte(0x99);
        let tokens = vec![Address::repeat_byte(0xA1), Address::repeat_byte(0xA2)];
        let reg = InvariantRegistry::with_erc20(attacker, &tokens);
        // 22 defaults + 2 ERC20Supply invariants
        assert_eq!(reg.len(), 24);
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

    // -- AccessControlOracle tests --------------------------------------------

    #[test]
    fn access_control_fires_when_non_owner_calls_privileged_fn() {
        let deployer = Address::repeat_byte(0x01);
        let attacker = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);

        let abi = json!([{
            "type": "function",
            "name": "pause",
            "inputs": [],
            "outputs": [],
            "stateMutability": "nonpayable"
        }]);

        let oracle = AccessControlOracle::from_abi(deployer, attacker, &abi).unwrap();
        assert_eq!(oracle.privileged_selectors.len(), 1);

        // Build selector for pause()
        let expected_hash = keccak256(b"pause()");
        let sel: [u8; 4] = expected_hash.as_slice()[..4].try_into().unwrap();

        let result = make_result(true, HashMap::new());
        let seq = vec![Transaction {
            sender: attacker, // non-owner!
            to: Some(contract),
            data: Bytes::from(sel.to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }];

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("pause"));
    }

    #[test]
    fn access_control_silent_when_deployer_calls_privileged_fn() {
        let deployer = Address::repeat_byte(0x01);
        let attacker = Address::repeat_byte(0xAA);

        let abi = json!([{
            "type": "function", "name": "pause",
            "inputs": [], "outputs": [], "stateMutability": "nonpayable"
        }]);
        let oracle = AccessControlOracle::from_abi(deployer, attacker, &abi).unwrap();

        let hash = keccak256(b"pause()");
        let sel: [u8; 4] = hash.as_slice()[..4].try_into().unwrap();

        let result = make_result(true, HashMap::new());
        let seq = vec![Transaction {
            sender: deployer, // owner — should be allowed
            to: Some(Address::repeat_byte(0xCC)),
            data: Bytes::from(sel.to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }];

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn access_control_silent_on_revert() {
        let deployer = Address::repeat_byte(0x01);
        let attacker = Address::repeat_byte(0xAA);
        let abi = json!([{
            "type": "function", "name": "pause",
            "inputs": [], "outputs": [], "stateMutability": "nonpayable"
        }]);
        let oracle = AccessControlOracle::from_abi(deployer, attacker, &abi).unwrap();
        let hash = keccak256(b"pause()");
        let sel: [u8; 4] = hash.as_slice()[..4].try_into().unwrap();
        // Reverted — access control was enforced
        let result = make_result(false, HashMap::new());
        let seq = vec![Transaction {
            sender: attacker,
            to: Some(Address::repeat_byte(0xCC)),
            data: Bytes::from(sel.to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }];
        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn access_control_from_abi_returns_none_for_non_privileged_abi() {
        let abi = json!([{
            "type": "function", "name": "deposit",
            "inputs": [{"type": "uint256", "name": "amount"}],
            "outputs": [],
            "stateMutability": "nonpayable"
        }]);
        assert!(AccessControlOracle::from_abi(Address::ZERO, Address::ZERO, &abi).is_none());
    }

    // -- ReentrancyOracle tests -----------------------------------------------

    fn make_result_with_sstore_in_nested_call(
        balance_changes: HashMap<Address, (U256, U256)>,
        sstore_in_nested_call: bool,
    ) -> ExecutionResult {
        ExecutionResult {
            success: true,
            output: Bytes::new(),
            gas_used: 50_000,
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
            assume_violated: false,
            revert_was_expected: false,
            sstore_in_nested_call,
        }
    }

    #[test]
    fn reentrancy_fires_when_sstore_in_nested_and_profit() {
        let attacker = Address::repeat_byte(0xBB);
        let oracle = ReentrancyOracle { attacker };

        let mut pre = HashMap::new();
        pre.insert(attacker, U256::from(1_000u64));

        let mut bc = HashMap::new();
        bc.insert(attacker, (U256::from(1_000u64), U256::from(100_000u64)));

        let result = make_result_with_sstore_in_nested_call(bc, true);
        let seq = dummy_sequence(Address::repeat_byte(0xCC));

        let finding = oracle.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("Reentrancy"));
    }

    #[test]
    fn reentrancy_silent_without_sstore_flag() {
        let attacker = Address::repeat_byte(0xBB);
        let oracle = ReentrancyOracle { attacker };

        let mut pre = HashMap::new();
        pre.insert(attacker, U256::from(1_000u64));

        let mut bc = HashMap::new();
        bc.insert(attacker, (U256::from(1_000u64), U256::from(100_000u64)));

        // sstore_in_nested_call = false — no reentrancy signal
        let result = make_result_with_sstore_in_nested_call(bc, false);
        let seq = dummy_sequence(Address::repeat_byte(0xCC));

        assert!(oracle.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn reentrancy_silent_without_profit() {
        let attacker = Address::repeat_byte(0xBB);
        let oracle = ReentrancyOracle { attacker };

        let pre: HashMap<Address, U256> = HashMap::new();
        // No balance change for attacker → no profit
        let result = make_result_with_sstore_in_nested_call(HashMap::new(), true);
        let seq = dummy_sequence(Address::repeat_byte(0xCC));

        assert!(oracle.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    // -- TokenFlowConservationOracle tests ------------------------------------

    fn make_transfer_log(token: Address, from: Address, to: Address, amount: U256) -> Log {
        let xfer_t = keccak256(b"Transfer(address,address,uint256)");
        Log {
            address: token,
            topics: vec![xfer_t, address_to_b256(from), address_to_b256(to)],
            data: Bytes::from(amount.to_be_bytes::<32>().to_vec()),
        }
    }

    #[test]
    fn token_flow_fires_when_out_exceeds_in() {
        let target = Address::repeat_byte(0xDD);
        let token = Address::repeat_byte(0x44);
        let attacker = Address::repeat_byte(0xAA);
        let oracle = TokenFlowConservationOracle {
            target,
            min_excess: U256::from(100u64),
        };

        // Attacker deposits 500, then withdraws 2000 — excess out = 1500
        let logs = vec![
            make_transfer_log(token, attacker, target, U256::from(500u64)),
            make_transfer_log(token, target, attacker, U256::from(2000u64)),
        ];
        let mut result = make_result(true, HashMap::new());
        result.logs = logs.clone();
        result.sequence_cumulative_logs = logs;
        let seq = dummy_sequence(target);

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("drained"));
    }

    #[test]
    fn token_flow_silent_when_out_equals_in() {
        let target = Address::repeat_byte(0xDD);
        let token = Address::repeat_byte(0x44);
        let attacker = Address::repeat_byte(0xAA);
        let oracle = TokenFlowConservationOracle {
            target,
            min_excess: U256::from(100u64),
        };

        let logs = vec![
            make_transfer_log(token, attacker, target, U256::from(1000u64)),
            make_transfer_log(token, target, attacker, U256::from(1000u64)),
        ];
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = logs;
        let seq = dummy_sequence(target);

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn token_flow_silent_below_min_excess() {
        let target = Address::repeat_byte(0xDD);
        let token = Address::repeat_byte(0x44);
        let attacker = Address::repeat_byte(0xAA);
        let oracle = TokenFlowConservationOracle {
            target,
            min_excess: U256::from(10_000u64), // high threshold
        };

        let logs = vec![
            make_transfer_log(token, attacker, target, U256::from(1000u64)),
            make_transfer_log(token, target, attacker, U256::from(1050u64)), // only 50 excess
        ];
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = logs;
        let seq = dummy_sequence(target);

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    // -- LendingHealthOracle tests --------------------------------------------

    fn make_borrow_log(contract: Address, amount: U256) -> Log {
        let borrow_t = keccak256(b"Borrow(address,address,uint256)");
        Log {
            address: contract,
            topics: vec![borrow_t],
            data: Bytes::from(amount.to_be_bytes::<32>().to_vec()),
        }
    }

    fn make_repay_log(contract: Address, amount: U256) -> Log {
        let repay_t = keccak256(b"Repay(address,address,uint256)");
        Log {
            address: contract,
            topics: vec![repay_t],
            data: Bytes::from(amount.to_be_bytes::<32>().to_vec()),
        }
    }

    #[test]
    fn lending_health_fires_on_simple_borrow_event() {
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);
        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: None,
            attacker,
        };

        let log = make_borrow_log(lending, U256::from(1_000_000u64));
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.title.contains("Lending health"));
    }

    #[test]
    fn lending_health_fires_on_compound_style_borrow_event() {
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);
        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: None,
            attacker,
        };

        // Compound-v2 style: Borrow(address,uint256,uint256,uint256)
        // data = [borrowAmount, accountBorrows, totalBorrows] (each 32 bytes)
        let borrow_t = keccak256(b"Borrow(address,uint256,uint256,uint256)");
        let amount = U256::from(5_000_000u64);
        let mut data = vec![0u8; 96];
        data[..32].copy_from_slice(&amount.to_be_bytes::<32>());
        let log = Log {
            address: lending,
            topics: vec![borrow_t],
            data: Bytes::from(data),
        };

        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.title.contains("unbacked"));
    }

    #[test]
    fn lending_health_suppressed_below_threshold() {
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);
        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1_000_000_000_000_000_000u64), // 1e18
            profiles: None,
            attacker,
        };

        let log = make_borrow_log(lending, U256::from(100u64)); // dust
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn lending_health_suppressed_when_fully_repaid() {
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);
        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: None,
            attacker,
        };

        let borrow_log = make_borrow_log(lending, U256::from(1_000_000u64));
        let repay_log = make_repay_log(lending, U256::from(1_000_000u64)); // fully repaid
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![borrow_log, repay_log];
        let seq = dummy_sequence(lending);

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn lending_health_escalates_to_high_with_attacker_profit() {
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);
        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: None,
            attacker,
        };

        let log = make_borrow_log(lending, U256::from(1_000_000u64));
        // Attacker gained 1 ETH during the sequence.
        let mut bc = HashMap::new();
        bc.insert(
            attacker,
            (U256::ZERO, U256::from(1_000_000_000_000_000_000u64)),
        );
        let mut result = make_result(true, bc);
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.exploit_profit.is_some());
    }

    #[test]
    fn lending_health_suppressed_on_non_lending_profile() {
        use std::sync::Arc;
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);

        // Profile says ERC20, not lending.
        let mut profile = crate::protocol_semantics::ContractProtocolProfile::default();
        profile.erc20_score = 5;
        profile.lending_score = 0;
        let mut pmap = HashMap::new();
        pmap.insert(lending, profile);

        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: Some(Arc::new(pmap)),
            attacker,
        };

        let log = make_borrow_log(lending, U256::from(1_000_000u64));
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        assert!(oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq).is_none());
    }

    #[test]
    fn lending_health_fires_on_lending_profile() {
        use std::sync::Arc;
        let attacker = Address::repeat_byte(0xAA);
        let lending = Address::repeat_byte(0x10);

        // Profile says lending_score = 4 → is_lending_like() returns true.
        let mut profile = crate::protocol_semantics::ContractProtocolProfile::default();
        profile.lending_score = 4;
        let mut pmap = HashMap::new();
        pmap.insert(lending, profile);

        let oracle = LendingHealthOracle {
            min_net_borrow: U256::from(1u64),
            profiles: Some(Arc::new(pmap)),
            attacker,
        };

        let log = make_borrow_log(lending, U256::from(1_000_000u64));
        let mut result = make_result(true, HashMap::new());
        result.sequence_cumulative_logs = vec![log];
        let seq = dummy_sequence(lending);

        let finding = oracle.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &result, &seq);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }
}

// ---------------------------------------------------------------------------
// Opt-in Timelock support
// ---------------------------------------------------------------------------

impl InvariantRegistry {
    /// Opt-in registry with the generic TimelockStateMachineOracle.
    /// Keeps the default registry low-noise. Use this when auditing
    /// timelocked reward distributors, governance queues, or delayed execution contracts.
    pub fn with_timelock(mut self) -> Self {
        self.add(Box::new(crate::inferred_invariants::TimelockStateMachineOracle::new()));
        self
    }
}
