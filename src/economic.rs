//! Exploit-oriented economic oracles using execution logs and storage diffs.
//!
//! These invariants use [`ExecutionResult::sequence_cumulative_logs`] for
//! sequence-level event analysis (filled by the campaign and shrink replay).

use std::collections::HashMap;
use std::sync::Arc;

use tiny_keccak::{Hasher, Keccak};

use crate::invariant::Invariant;
use crate::protocol_semantics::{
    append_triage_simple, topic_uni_v2_swap, topic_uni_v2_sync, u112_from_word,
    ContractProtocolProfile,
};
use crate::types::{Address, ExecutionResult, Finding, Severity, Transaction, B256, U256};

/// Optional per-address ABI-derived protocol hints (from campaign targets).
pub type ProtocolProfileMap = Arc<HashMap<Address, ContractProtocolProfile>>;

fn lookup_profile<'a>(
    profiles: &'a Option<ProtocolProfileMap>,
    addr: Address,
) -> Option<&'a ContractProtocolProfile> {
    profiles.as_ref().and_then(|m| m.get(&addr))
}

/// Suppress ERC-4626 **rate-style** oracles when ABI exists but shows no vault semantics.
fn suppress_erc4626_rate_gated(p: Option<&ContractProtocolProfile>) -> bool {
    matches!(p, Some(pr) if pr.abi_present && pr.erc4626_score == 0)
}

/// Suppress ERC-20 balance-slot heuristic when ABI exists but contract is not ERC-20-like.
fn suppress_erc20_balance_gated(p: Option<&ContractProtocolProfile>) -> bool {
    matches!(p, Some(pr) if pr.abi_present && !pr.is_erc20_like())
}

fn transfer_to_vault_observed(logs: &[crate::types::Log], vault: Address) -> bool {
    let t = transfer_topic();
    let vault_t = address_to_b256(vault);
    for log in logs {
        if log.topics.get(0).copied() != Some(t) || log.topics.len() < 3 {
            continue;
        }
        if log.topics[2] == vault_t {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Keccak / ERC-20 event topics
// ---------------------------------------------------------------------------

fn keccak256(input: &[u8]) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    B256::from(output)
}

fn address_to_b256(addr: Address) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(addr.as_slice());
    B256::from(bytes)
}

/// OpenZeppelin `ERC20`: `_balances` at slot 0, `_allowances` at 1, `_totalSupply` at 2.
pub const OZ_ERC20_TOTAL_SUPPLY_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);

/// Minimum mint/burn amount (token base units) to consider for supply-write checks.
pub const MIN_LARGE_TOKEN_MOVE: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

fn transfer_topic() -> B256 {
    keccak256(b"Transfer(address,address,uint256)")
}

fn deposit_topic() -> B256 {
    keccak256(b"Deposit(address,address,uint256,uint256)")
}

fn withdraw_topic() -> B256 {
    keccak256(b"Withdraw(address,address,address,uint256,uint256)")
}

/// `keccak256(abi.encode(holder, uint256(0)))` for `mapping(address => uint256)` at slot 0.
fn erc20_balance_storage_key(holder: Address) -> U256 {
    let mut enc = [0u8; 64];
    enc[12..32].copy_from_slice(holder.as_slice());
    let h = keccak256(&enc);
    U256::from_be_slice(h.as_slice())
}

// ---------------------------------------------------------------------------
// ERC-4626: impossible Deposit / Withdraw
// ---------------------------------------------------------------------------

/// Flags impossible or highly suspicious ERC-4626 `Deposit` / `Withdraw` tuples.
pub struct Erc4626EventAnomalyOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626EventAnomalyOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for Erc4626EventAnomalyOracle {
    fn name(&self) -> &str {
        "economic-erc4626-events"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let dep = deposit_topic();
        let wit = withdraw_topic();

        for log in &result.logs {
            if log.topics.get(0).copied() == Some(dep) && log.data.len() >= 64 {
                let assets = U256::from_be_slice(&log.data[..32]);
                let shares = U256::from_be_slice(&log.data[32..64]);
                if assets > U256::ZERO && shares == U256::ZERO {
                    let base = format!(
                        "Vault {} emitted Deposit with assets={assets} and shares=0 — share mint should not be zero when assets are positive (possible accounting break).",
                        log.address
                    );
                    let desc = append_triage_simple(
                        base,
                        log.address,
                        lookup_profile(&self.profiles, log.address),
                        "ERC-4626 Deposit tuple: positive assets require positive minted shares.",
                        "Deposit event log data (assets, shares).",
                        "Does not prove exploit without protocol context; verify share ledger and rounding.",
                    );
                    return Some(Finding {
                        severity: Severity::High,
                        title: "Economic: ERC-4626 impossible Deposit (assets>0, shares=0)".into(),
                        description: desc,
                        contract: log.address,
                        reproducer: sequence.to_vec(),
                        exploit_profit: None,
                    });
                }
            }

            if log.topics.get(0).copied() == Some(wit) && log.data.len() >= 64 {
                let assets = U256::from_be_slice(&log.data[..32]);
                let shares = U256::from_be_slice(&log.data[32..64]);
                if shares > U256::ZERO && assets == U256::ZERO {
                    let base = format!(
                        "Vault {} emitted Withdraw with shares={shares} and assets=0 — asset payout should not be zero when shares are burned (possible redemption break).",
                        log.address
                    );
                    let desc = append_triage_simple(
                        base,
                        log.address,
                        lookup_profile(&self.profiles, log.address),
                        "ERC-4626 Withdraw tuple: burning shares should pay out assets.",
                        "Withdraw event log data (assets, shares).",
                        "False positives possible for fee-on-transfer or wrapped native edge cases; triage.",
                    );
                    return Some(Finding {
                        severity: Severity::High,
                        title: "Economic: ERC-4626 impossible Withdraw (shares>0, assets=0)".into(),
                        description: desc,
                        contract: log.address,
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
// ERC-20: large mint without totalSupply storage write (OZ slot heuristic)
// ---------------------------------------------------------------------------

/// Detects large mints from `address(0)` without a matching `_totalSupply` storage update.
pub struct Erc20MintWithoutSupplyWriteOracle {
    /// Minimum mint amount to treat as economically meaningful.
    pub min_mint: U256,
    /// Storage slot for `_totalSupply` (OpenZeppelin ERC20 uses 2).
    pub total_supply_slot: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc20MintWithoutSupplyWriteOracle {
    fn default() -> Self {
        Self {
            min_mint: MIN_LARGE_TOKEN_MOVE,
            total_supply_slot: OZ_ERC20_TOTAL_SUPPLY_SLOT,
            profiles: None,
        }
    }
}

impl Invariant for Erc20MintWithoutSupplyWriteOracle {
    fn name(&self) -> &str {
        "economic-erc20-mint-supply"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let transfer_t = transfer_topic();
        let zero = address_to_b256(Address::ZERO);

        for log in &result.logs {
            if log.topics.len() < 3 || log.topics[0] != transfer_t {
                continue;
            }
            if log.data.len() < 32 {
                continue;
            }
            let from = log.topics[1];
            if from != zero {
                continue;
            }
            let value = U256::from_be_slice(&log.data[..32]);
            if value < self.min_mint {
                continue;
            }
            let token = log.address;
            let has_supply_write = result
                .state_diff
                .storage_writes
                .get(&token)
                .is_some_and(|m| m.contains_key(&self.total_supply_slot));
            if has_supply_write {
                continue;
            }
            let abi_note = match lookup_profile(&self.profiles, token) {
                Some(p) if p.abi_present && has_function_named(p, "totalSupply") => {
                    "ABI lists totalSupply() — expects on-chain supply to track mints."
                }
                Some(p) if p.abi_present => {
                    "ABI has no totalSupply(); OpenZeppelin slot-2 heuristic only."
                }
                _ => "No ABI profile; using OpenZeppelin _totalSupply slot-2 heuristic only.",
            };
            let base = format!(
                "Token {token} logged a large mint (from zero) of {value} units but slot {} (_totalSupply heuristic) was not written this transaction — supply accounting may be inconsistent with balances. {abi_note}",
                self.total_supply_slot
            );
            let desc = append_triage_simple(
                base,
                token,
                lookup_profile(&self.profiles, token),
                "ERC-20: mint (Transfer from zero) should update total supply ledger.",
                "Transfer mint log + absence of write to heuristic totalSupply slot.",
                "Slot layout may differ (proxy, upgradeable token); verify with storage trace.",
            );
            return Some(Finding {
                severity: Severity::Critical,
                title: format!(
                    "Economic: ERC-20 large mint without totalSupply storage update ({token})"
                ),
                description: desc,
                contract: token,
                reproducer: sequence.to_vec(),
                exploit_profit: Some(value),
            });
        }
        None
    }
}

fn has_function_named(p: &ContractProtocolProfile, name: &str) -> bool {
    p.signals.iter().any(|s| s == &format!("fn:{name}"))
}

// ---------------------------------------------------------------------------
// ERC-20: balance mapping storage touched without any Transfer in the same tx
// ---------------------------------------------------------------------------

/// Flags when ERC-20 balance storage (OZ mapping slot 0) changes but no `Transfer` was emitted by the token in that tx.
pub struct Erc20BalanceStorageWithoutTransferOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc20BalanceStorageWithoutTransferOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for Erc20BalanceStorageWithoutTransferOracle {
    fn name(&self) -> &str {
        "economic-erc20-balance-without-transfer"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }

        let transfer_t = transfer_topic();
        let mut tokens_with_transfer: std::collections::HashSet<Address> =
            std::collections::HashSet::new();
        for log in &result.logs {
            if log.topics.len() >= 3 && log.topics[0] == transfer_t {
                tokens_with_transfer.insert(log.address);
            }
        }

        for (&token, slots) in &result.state_diff.storage_writes {
            if tokens_with_transfer.contains(&token) {
                continue;
            }
            // Any write that looks like a balance slot (keccak preimage slot 0).
            for slot_key in slots.keys() {
                let last = sequence.last()?;
                let mut candidates = vec![last.sender];
                if let Some(to) = last.to {
                    candidates.push(to);
                }
                for holder in candidates {
                    if erc20_balance_storage_key(holder) == *slot_key {
                        if suppress_erc20_balance_gated(lookup_profile(&self.profiles, token)) {
                            continue;
                        }
                        let base = format!(
                            "Token {token} wrote balance storage (slot key {slot_key:#x}) for {holder}, but this transaction emitted no `Transfer` from {token}. \
                             This can indicate direct balance manipulation, callback ordering bugs, or a non-standard token — triage against your ABI.",
                            holder = holder,
                            slot_key = slot_key,
                            token = token
                        );
                        let desc = append_triage_simple(
                            base,
                            token,
                            lookup_profile(&self.profiles, token),
                            "ERC-20 balance mapping changes should align with Transfer events (OZ layout heuristic).",
                            "state_diff balance-slot key vs absence of Transfer log for token.",
                            "Suppressed when ABI classifies contract as non-ERC-20-like; mapping slot may differ.",
                        );
                        return Some(Finding {
                            severity: Severity::High,
                            title: format!(
                                "Economic: ERC-20 balance storage write without Transfer ({token})"
                            ),
                            description: desc,
                            contract: token,
                            reproducer: sequence.to_vec(),
                            exploit_profit: None,
                        });
                    }
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ERC-4626: extreme exchange-rate jump across cumulative Deposits
// ---------------------------------------------------------------------------

/// Compares implied exchange rates between the last two `Deposit` events for the same vault.
pub struct Erc4626ExchangeRateJumpOracle {
    /// Maximum multiplier between consecutive implied asset/share rates (e.g. 5 = report if rate jumps more than 5x or below 1/5x).
    pub max_multiplier: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626ExchangeRateJumpOracle {
    fn default() -> Self {
        Self {
            max_multiplier: U256::from(5u64),
            profiles: None,
        }
    }
}

fn wad() -> U256 {
    U256::from(10u128.pow(18))
}

impl Invariant for Erc4626ExchangeRateJumpOracle {
    fn name(&self) -> &str {
        "economic-erc4626-rate-jump"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let dep = deposit_topic();
        let logs = if result.sequence_cumulative_logs.is_empty() {
            &result.logs[..]
        } else {
            result.sequence_cumulative_logs.as_slice()
        };

        let mut last_two: Vec<(Address, U256, U256)> = Vec::new();
        let w = wad();
        for log in logs {
            if log.topics.get(0).copied() != Some(dep) || log.data.len() < 64 {
                continue;
            }
            let assets = U256::from_be_slice(&log.data[..32]);
            let shares = U256::from_be_slice(&log.data[32..64]);
            if shares == U256::ZERO {
                continue;
            }
            let rate = assets
                .saturating_mul(w)
                .checked_div(shares)
                .unwrap_or(U256::MAX);
            last_two.push((log.address, assets, rate));
            if last_two.len() > 2 {
                last_two.remove(0);
            }
        }

        if last_two.len() < 2 {
            return None;
        }
        let (vault, _, r1) = last_two[0];
        let (vault_b, _, r2) = last_two[1];
        if vault != vault_b {
            return None;
        }
        if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
            return None;
        }
        if r1 == U256::ZERO {
            return None;
        }
        let up = r2 / r1;
        let down = r1 / r2;
        if r2 > r1.saturating_mul(self.max_multiplier) {
            let base = format!(
                "Vault {vault}: cumulative `Deposit` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} between consecutive deposits — factor ~{up}x. \
                 Investigate rounding, donation attacks, or read-only reentrancy windows.",
                vault = vault,
                r1 = r1,
                r2 = r2,
                up = up
            );
            let desc = append_triage_simple(
                base,
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626: implied exchange rate (assets/shares) should not jump wildly between consecutive Deposit events on the same vault.",
                "Last two Deposit logs in sequence_cumulative_logs; WAD-scaled rate ratio.",
                "First-deposit rounding and donation economics can move rates; verify with asset() and share math.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 exchange rate jump ({vault})"),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        if r1 > r2.saturating_mul(self.max_multiplier) {
            let base = format!(
                "Vault {vault}: cumulative `Deposit` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} — factor ~{down}x down.",
                vault = vault,
                r1 = r1,
                r2 = r2,
                down = down
            );
            let desc = append_triage_simple(
                base,
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626: implied exchange rate plunge across consecutive Deposit events.",
                "Last two Deposit logs in sequence_cumulative_logs.",
                "Rounding and fee-on-transfer can affect implied rates; triage with vault code.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 exchange rate plunge ({vault})"),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }

        None
    }
}

// ---------------------------------------------------------------------------
// ERC-20: large burn to address(0) without totalSupply storage write
// ---------------------------------------------------------------------------

/// Detects large burns to `address(0)` without a matching `_totalSupply` storage update (OpenZeppelin slot 2 heuristic).
///
/// Symmetric to [`Erc20MintWithoutSupplyWriteOracle`]: supply ledger should move on mint and burn.
pub struct Erc20BurnWithoutSupplyWriteOracle {
    /// Minimum burn amount to treat as economically meaningful.
    pub min_burn: U256,
    /// Storage slot for `_totalSupply` (OpenZeppelin ERC20 uses 2).
    pub total_supply_slot: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc20BurnWithoutSupplyWriteOracle {
    fn default() -> Self {
        Self {
            min_burn: MIN_LARGE_TOKEN_MOVE,
            total_supply_slot: OZ_ERC20_TOTAL_SUPPLY_SLOT,
            profiles: None,
        }
    }
}

impl Invariant for Erc20BurnWithoutSupplyWriteOracle {
    fn name(&self) -> &str {
        "economic-erc20-burn-supply"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let transfer_t = transfer_topic();
        let zero = address_to_b256(Address::ZERO);

        for log in &result.logs {
            if log.topics.len() < 3 || log.topics[0] != transfer_t {
                continue;
            }
            if log.data.len() < 32 {
                continue;
            }
            let to = log.topics[2];
            if to != zero {
                continue;
            }
            let value = U256::from_be_slice(&log.data[..32]);
            if value < self.min_burn {
                continue;
            }
            let token = log.address;
            let has_supply_write = result
                .state_diff
                .storage_writes
                .get(&token)
                .is_some_and(|m| m.contains_key(&self.total_supply_slot));
            if has_supply_write {
                continue;
            }
            let abi_note = match lookup_profile(&self.profiles, token) {
                Some(p) if p.abi_present && has_function_named(p, "totalSupply") => {
                    "ABI lists totalSupply() — expects supply to decrease on burn."
                }
                Some(p) if p.abi_present => "ABI has no totalSupply(); slot heuristic only.",
                _ => "No ABI profile; slot-2 heuristic only.",
            };
            let base = format!(
                "Token {token} logged a large burn (to zero) of {value} units but slot {} (_totalSupply heuristic) was not written this transaction — supply accounting may be inconsistent with balances (value destruction / ledger break). {abi_note}",
                self.total_supply_slot
            );
            let desc = append_triage_simple(
                base,
                token,
                lookup_profile(&self.profiles, token),
                "ERC-20: burn (Transfer to zero) should update total supply ledger.",
                "Transfer burn log + absence of heuristic totalSupply slot write.",
                "Proxy / non-OZ layouts may differ; verify with storage trace.",
            );
            return Some(Finding {
                severity: Severity::Critical,
                title: format!(
                    "Economic: ERC-20 large burn without totalSupply storage update ({token})"
                ),
                description: desc,
                contract: token,
                reproducer: sequence.to_vec(),
                exploit_profit: Some(value),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ERC-4626: extreme exchange-rate jump across cumulative Withdraws
// ---------------------------------------------------------------------------

/// Compares implied exchange rates between the last two `Withdraw` events for the same vault (assets per share, WAD-scaled).
pub struct Erc4626WithdrawRateJumpOracle {
    /// Maximum multiplier between consecutive implied asset/share rates (same semantics as [`Erc4626ExchangeRateJumpOracle`]).
    pub max_multiplier: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626WithdrawRateJumpOracle {
    fn default() -> Self {
        Self {
            max_multiplier: U256::from(5u64),
            profiles: None,
        }
    }
}

impl Invariant for Erc4626WithdrawRateJumpOracle {
    fn name(&self) -> &str {
        "economic-erc4626-withdraw-rate-jump"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let wit = withdraw_topic();
        let logs = if result.sequence_cumulative_logs.is_empty() {
            &result.logs[..]
        } else {
            result.sequence_cumulative_logs.as_slice()
        };

        let mut last_two: Vec<(Address, U256, U256)> = Vec::new();
        let w = wad();
        for log in logs {
            // Withdraw(address indexed caller, address indexed owner, address indexed receiver, uint256 assets, uint256 shares)
            if log.topics.get(0).copied() != Some(wit)
                || log.topics.len() < 4
                || log.data.len() < 64
            {
                continue;
            }
            let assets = U256::from_be_slice(&log.data[..32]);
            let shares = U256::from_be_slice(&log.data[32..64]);
            if shares == U256::ZERO {
                continue;
            }
            let rate = assets
                .saturating_mul(w)
                .checked_div(shares)
                .unwrap_or(U256::MAX);
            last_two.push((log.address, assets, rate));
            if last_two.len() > 2 {
                last_two.remove(0);
            }
        }

        if last_two.len() < 2 {
            return None;
        }
        let (vault, _, r1) = last_two[0];
        let (vault_b, _, r2) = last_two[1];
        if vault != vault_b {
            return None;
        }
        if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
            return None;
        }
        if r1 == U256::ZERO {
            return None;
        }
        let up = r2 / r1;
        let down = r1 / r2;
        if r2 > r1.saturating_mul(self.max_multiplier) {
            let base = format!(
                "Vault {vault}: cumulative `Withdraw` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} between consecutive withdrawals — factor ~{up}x. \
                 Investigate rounding, donation attacks, or read-only reentrancy windows.",
                vault = vault,
                r1 = r1,
                r2 = r2,
                up = up
            );
            let desc = append_triage_simple(
                base,
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626: implied assets/shares on Withdraw should not jump wildly between consecutive events.",
                "Last two Withdraw logs in sequence_cumulative_logs.",
                "Fee-on-transfer and rounding can affect implied rates.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 withdraw exchange rate jump ({vault})"),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        if r1 > r2.saturating_mul(self.max_multiplier) {
            let base = format!(
                "Vault {vault}: cumulative `Withdraw` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} — factor ~{down}x down.",
                vault = vault,
                r1 = r1,
                r2 = r2,
                down = down
            );
            let desc = append_triage_simple(
                base,
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626: withdraw implied rate plunge across consecutive Withdraw events.",
                "Last two Withdraw logs in sequence_cumulative_logs.",
                "Rounding and slippage can affect implied rates.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 withdraw exchange rate plunge ({vault})"),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }

        None
    }
}

// ---------------------------------------------------------------------------
// ERC-4626: multiple Deposits in one tx with inconsistent implied rates
// ---------------------------------------------------------------------------

/// Flags when two or more `Deposit` events from the same vault in **this** transaction imply wildly different assets/share exchange rates (callback / reentrancy / broken mint path).
pub struct Erc4626SameTransactionDepositRateSpreadOracle {
    pub max_multiplier: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626SameTransactionDepositRateSpreadOracle {
    fn default() -> Self {
        Self {
            max_multiplier: U256::from(5u64),
            profiles: None,
        }
    }
}

impl Invariant for Erc4626SameTransactionDepositRateSpreadOracle {
    fn name(&self) -> &str {
        "economic-erc4626-same-tx-deposit-spread"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let dep = deposit_topic();
        let w = wad();

        let mut by_vault: HashMap<Address, Vec<U256>> = HashMap::new();
        for log in &result.logs {
            if log.topics.get(0).copied() != Some(dep) || log.data.len() < 64 {
                continue;
            }
            let assets = U256::from_be_slice(&log.data[..32]);
            let shares = U256::from_be_slice(&log.data[32..64]);
            if shares == U256::ZERO {
                continue;
            }
            let rate = assets
                .saturating_mul(w)
                .checked_div(shares)
                .unwrap_or(U256::MAX);
            by_vault.entry(log.address).or_default().push(rate);
        }

        for (vault, rates) in by_vault {
            if rates.len() < 2 {
                continue;
            }
            if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
                continue;
            }
            let mut min_r = U256::MAX;
            let mut max_r = U256::ZERO;
            for r in &rates {
                min_r = min_r.min(*r);
                max_r = max_r.max(*r);
            }
            if min_r == U256::ZERO {
                continue;
            }
            if max_r > min_r.saturating_mul(self.max_multiplier) {
                let spread = max_r / min_r;
                let base = format!(
                    "Vault {vault}: {n} `Deposit` events in one transaction imply assets-per-share rates (WAD-scaled) ranging ~{min_r} to ~{max_r} (spread ~{spread}x). \
                     Inconsistent pricing within a single call tree is suspicious for read-only reentrancy, stale oracle use, or accounting bugs.",
                    vault = vault,
                    n = rates.len(),
                    min_r = min_r,
                    max_r = max_r,
                    spread = spread
                );
                let desc = append_triage_simple(
                    base,
                    vault,
                    lookup_profile(&self.profiles, vault),
                    "ERC-4626: multiple Deposit events in one tx should use consistent pricing.",
                    "Multiple Deposit logs in result.logs for same vault address.",
                    "Multi-step deposits with different rounding paths can widen spread benignly.",
                );
                return Some(Finding {
                    severity: Severity::High,
                    title: format!("Economic: ERC-4626 same-tx Deposit rate spread ({vault})"),
                    description: desc,
                    contract: vault,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Uniswap V2–style: swap amount out vs last Sync reserves (single tx)
// ---------------------------------------------------------------------------

/// Flags when a V2-shaped `Swap` takes more than the prior `Sync` reserves (impossible without minting).
pub struct UniswapV2StyleSwapReserveOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for UniswapV2StyleSwapReserveOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for UniswapV2StyleSwapReserveOracle {
    fn name(&self) -> &str {
        "economic-amm-swap-reserve-bounds"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let sync_t = topic_uni_v2_sync();
        let swap_t = topic_uni_v2_swap();
        let mut reserves: HashMap<Address, (U256, U256)> = HashMap::new();

        for log in &result.logs {
            if log.topics.get(0).copied() == Some(sync_t) && log.data.len() >= 64 {
                let r0 = u112_from_word(&log.data[..32]);
                let r1 = u112_from_word(&log.data[32..64]);
                reserves.insert(log.address, (r0, r1));
                continue;
            }
            if log.topics.get(0).copied() == Some(swap_t)
                && log.topics.len() == 3
                && log.data.len() >= 128
            {
                let pair = log.address;
                let (r0, r1) = reserves
                    .get(&pair)
                    .copied()
                    .unwrap_or((U256::ZERO, U256::ZERO));
                let amount0_out = U256::from_be_slice(&log.data[64..96]);
                let amount1_out = U256::from_be_slice(&log.data[96..128]);

                if amount0_out > r0 || amount1_out > r1 {
                    let base = format!(
                        "Pair {pair}: Swap requests amount0Out={amount0_out} amount1Out={amount1_out} but last Sync reserves were reserve0={r0} reserve1={r1} — amount out cannot exceed prior reserves (Uniswap V2–style event sanity)."
                    );
                    let desc = append_triage_simple(
                        base,
                        pair,
                        lookup_profile(&self.profiles, pair),
                        "AMM: swap output cannot exceed pool reserves before the swap.",
                        "Swap event vs preceding Sync reserves in same transaction log order.",
                        "Forks with different event layouts or missing Sync in tx will not match; not full conservation modeling.",
                    );
                    return Some(Finding {
                        severity: Severity::High,
                        title: format!("Economic: AMM swap exceeds Sync reserves ({pair})"),
                        description: desc,
                        contract: pair,
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
// ERC-4626: large cumulative rate jump without any ERC-20 Transfer to vault
// ---------------------------------------------------------------------------

/// Flags donation / pricing anomalies: large `Deposit` rate move in cumulative logs with no visible token delivery to the vault.
pub struct Erc4626RateJumpWithoutTokenFlowOracle {
    pub max_multiplier: U256,
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626RateJumpWithoutTokenFlowOracle {
    fn default() -> Self {
        Self {
            max_multiplier: U256::from(5u64),
            profiles: None,
        }
    }
}

impl Invariant for Erc4626RateJumpWithoutTokenFlowOracle {
    fn name(&self) -> &str {
        "economic-erc4626-rate-jump-no-token-flow"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let dep = deposit_topic();
        let logs = if result.sequence_cumulative_logs.is_empty() {
            &result.logs[..]
        } else {
            result.sequence_cumulative_logs.as_slice()
        };

        let mut last_two: Vec<(Address, U256, U256)> = Vec::new();
        let w = wad();
        for log in logs {
            if log.topics.get(0).copied() != Some(dep) || log.data.len() < 64 {
                continue;
            }
            let assets = U256::from_be_slice(&log.data[..32]);
            let shares = U256::from_be_slice(&log.data[32..64]);
            if shares == U256::ZERO {
                continue;
            }
            let rate = assets
                .saturating_mul(w)
                .checked_div(shares)
                .unwrap_or(U256::MAX);
            last_two.push((log.address, assets, rate));
            if last_two.len() > 2 {
                last_two.remove(0);
            }
        }
        if last_two.len() < 2 {
            return None;
        }
        let (vault, _, r1) = last_two[0];
        let (vault_b, _, r2) = last_two[1];
        if vault != vault_b {
            return None;
        }
        if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
            return None;
        }
        if r1 == U256::ZERO {
            return None;
        }
        if r2 <= r1.saturating_mul(self.max_multiplier)
            && r1 <= r2.saturating_mul(self.max_multiplier)
        {
            return None;
        }
        if transfer_to_vault_observed(logs, vault) {
            return None;
        }
        let base = format!(
            "Vault {vault}: consecutive cumulative `Deposit` events imply a large assets/share rate move, but no ERC-20 `Transfer` to the vault appears in the same cumulative log stream — possible donation-style rate manipulation or missing underlying transfer visibility (native ETH / wrapped paths not modeled)."
        );
        let desc = append_triage_simple(
            base,
            vault,
            lookup_profile(&self.profiles, vault),
            "ERC-4626: visible underlying flow should often accompany deposits that move the exchange rate.",
            "sequence_cumulative_logs: Deposit-implied rate jump + scan for Transfer to vault address.",
            "Some vaults use ETH, ERC-777, or internal mint paths without standard Transfer; triage.",
        );
        Some(Finding {
            severity: Severity::Medium,
            title: format!("Economic: ERC-4626 rate shock without Transfer to vault ({vault})"),
            description: desc,
            contract: vault,
            reproducer: sequence.to_vec(),
            exploit_profit: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Lending-style: collateral vs debt raw storage divergence (heuristic)
// ---------------------------------------------------------------------------

/// Heuristic for lending-like systems: flags when a configured "debt" slot value exceeds a "collateral" slot value in the same transaction (same decimals assumed).
pub struct PairwiseStorageDriftOracle {
    pub contract: Address,
    pub slot_collateral: U256,
    pub slot_debt: U256,
    /// Minimum debt value to report (reduces noise).
    pub min_debt: U256,
}

impl Invariant for PairwiseStorageDriftOracle {
    fn name(&self) -> &str {
        "economic-lending-pairwise-drift"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let slots = result.state_diff.storage_writes.get(&self.contract)?;
        let col = *slots.get(&self.slot_collateral)?;
        let debt = *slots.get(&self.slot_debt)?;
        if debt < self.min_debt {
            return None;
        }
        if debt > col {
            return Some(Finding {
                severity: Severity::Medium,
                title: format!("Economic: lending debt exceeds collateral slot ({})", self.contract),
                description: format!(
                    "In one transaction, storage slot {} (debt-like) is {debt} while slot {} (collateral-like) is {col} — raw values suggest debt above collateral under the configured slot layout (heuristic; verify decimals and semantics).",
                    self.slot_debt,
                    self.slot_collateral,
                    debt = debt,
                    col = col
                ),
                contract: self.contract,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_semantics::classify_json_abi;
    use crate::types::{Bytes, Log};
    use alloy_json_abi::JsonAbi;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn tx_dummy() -> Transaction {
        Transaction {
            sender: Address::repeat_byte(0x01),
            to: Some(Address::repeat_byte(0x02)),
            data: Bytes::new(),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }
    }

    #[test]
    fn erc4626_impossible_deposit_fires() {
        let vault = Address::repeat_byte(0xAB);
        let t0 = deposit_topic();
        let log = Log {
            address: vault,
            topics: vec![t0, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[31] = 1; // assets = 1
                Bytes::copy_from_slice(&d)
            },
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(log);
        let inv = Erc4626EventAnomalyOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("impossible Deposit"));
    }

    #[test]
    fn erc20_mint_without_supply_write_fires() {
        let token = Address::repeat_byte(0xCD);
        let tt = transfer_topic();
        let z = address_to_b256(Address::ZERO);
        let log = Log {
            address: token,
            topics: vec![tt, z, address_to_b256(Address::repeat_byte(0xEE))],
            data: Bytes::from(MIN_LARGE_TOKEN_MOVE.to_be_bytes::<32>().to_vec()),
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(log);
        // No storage_writes for token — triggers
        let inv = Erc20MintWithoutSupplyWriteOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("totalSupply"));
    }

    #[test]
    fn erc20_balance_without_transfer_fires() {
        let token = Address::repeat_byte(0x77);
        let holder = Address::repeat_byte(0x01);
        let key = erc20_balance_storage_key(holder);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.state_diff
            .storage_writes
            .insert(token, HashMap::from([(key, U256::from(999u64))]));
        let mut tx = tx_dummy();
        tx.sender = holder;
        let inv = Erc20BalanceStorageWithoutTransferOracle::default();
        let f = inv.check(&HashMap::new(), &r, &[tx]).expect("finding");
        assert!(f.title.contains("without Transfer"));
    }

    #[test]
    fn pairwise_drift_fires_when_debt_gt_collateral() {
        let c = Address::repeat_byte(0x33);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.state_diff.storage_writes.insert(
            c,
            HashMap::from([
                (U256::ZERO, U256::from(100u64)),
                (U256::from(1u64), U256::from(500u64)),
            ]),
        );
        let inv = PairwiseStorageDriftOracle {
            contract: c,
            slot_collateral: U256::ZERO,
            slot_debt: U256::from(1u64),
            min_debt: U256::from(10u64),
        };
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("debt exceeds collateral"));
    }

    #[test]
    fn erc4626_rate_jump_uses_cumulative_logs() {
        let vault = Address::repeat_byte(0x55);
        let dep = deposit_topic();
        let mk_dep = |assets: u64, shares: u64| Log {
            address: vault,
            topics: vec![dep, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[24..32].copy_from_slice(&assets.to_be_bytes());
                d[56..64].copy_from_slice(&shares.to_be_bytes());
                Bytes::copy_from_slice(&d)
            },
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(mk_dep(100, 100));
        r.logs.push(mk_dep(900, 10)); // rate 10x jump
        r.sequence_cumulative_logs = r.logs.clone();

        let inv = Erc4626ExchangeRateJumpOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("exchange rate"));
    }

    #[test]
    fn erc20_burn_without_supply_write_fires() {
        let token = Address::repeat_byte(0xCE);
        let tt = transfer_topic();
        let z = address_to_b256(Address::ZERO);
        let log = Log {
            address: token,
            topics: vec![tt, address_to_b256(Address::repeat_byte(0xEE)), z],
            data: Bytes::from(MIN_LARGE_TOKEN_MOVE.to_be_bytes::<32>().to_vec()),
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(log);
        let inv = Erc20BurnWithoutSupplyWriteOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("burn"));
        assert!(f.title.contains("totalSupply"));
    }

    #[test]
    fn erc4626_withdraw_rate_jump_uses_cumulative_logs() {
        let vault = Address::repeat_byte(0x66);
        let wit = withdraw_topic();
        let mk_wd = |assets: u64, shares: u64| Log {
            address: vault,
            topics: vec![wit, B256::ZERO, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[24..32].copy_from_slice(&assets.to_be_bytes());
                d[56..64].copy_from_slice(&shares.to_be_bytes());
                Bytes::copy_from_slice(&d)
            },
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(mk_wd(100, 100));
        r.logs.push(mk_wd(900, 10)); // rate 9x jump
        r.sequence_cumulative_logs = r.logs.clone();

        let inv = Erc4626WithdrawRateJumpOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("withdraw"));
        assert!(f.title.contains("jump") || f.title.contains("plunge"));
    }

    #[test]
    fn erc4626_same_tx_deposit_spread_fires() {
        let vault = Address::repeat_byte(0x77);
        let dep = deposit_topic();
        let mk_dep = |assets: u64, shares: u64| Log {
            address: vault,
            topics: vec![dep, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[24..32].copy_from_slice(&assets.to_be_bytes());
                d[56..64].copy_from_slice(&shares.to_be_bytes());
                Bytes::copy_from_slice(&d)
            },
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        // rate 1:1 then 10:1 -> 10x spread
        r.logs.push(mk_dep(100, 100));
        r.logs.push(mk_dep(1000, 100));

        let inv = Erc4626SameTransactionDepositRateSpreadOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("same-tx"));
        assert!(f.title.contains("spread"));
    }

    #[test]
    fn amm_swap_exceeds_reserves_fires() {
        let pair = Address::repeat_byte(0xAA);
        let sync_t = topic_uni_v2_sync();
        let swap_t = topic_uni_v2_swap();
        let mut sync_data = vec![0u8; 64];
        let r = U256::from(100u64);
        sync_data[0..32].copy_from_slice(&r.to_be_bytes::<32>());
        sync_data[32..64].copy_from_slice(&r.to_be_bytes::<32>());
        let mut swap_data = vec![0u8; 128];
        let out = U256::from(200u64);
        swap_data[64..96].copy_from_slice(&out.to_be_bytes::<32>());

        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(Log {
            address: pair,
            topics: vec![sync_t],
            data: Bytes::from(sync_data),
        });
        r.logs.push(Log {
            address: pair,
            topics: vec![swap_t, B256::ZERO, B256::ZERO],
            data: Bytes::from(swap_data),
        });
        let inv = UniswapV2StyleSwapReserveOracle::default();
        let f = inv
            .check(&HashMap::new(), &r, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("AMM swap"));
    }

    #[test]
    fn erc4626_rate_jump_no_token_flow_fires() {
        let vault = Address::repeat_byte(0xBB);
        let dep = deposit_topic();
        let mk_dep = |assets: u64, shares: u64| Log {
            address: vault,
            topics: vec![dep, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[24..32].copy_from_slice(&assets.to_be_bytes());
                d[56..64].copy_from_slice(&shares.to_be_bytes());
                Bytes::copy_from_slice(&d)
            },
        };
        let mut res = ExecutionResult::default();
        res.success = true;
        res.logs.push(mk_dep(100, 100));
        res.logs.push(mk_dep(900, 10));
        res.sequence_cumulative_logs = res.logs.clone();

        let inv = Erc4626RateJumpWithoutTokenFlowOracle::default();
        let f = inv
            .check(&HashMap::new(), &res, &[tx_dummy()])
            .expect("finding");
        assert!(f.title.contains("rate shock"));
    }

    #[test]
    fn erc4626_rate_jump_suppressed_when_abi_not_vault() {
        let vault = Address::repeat_byte(0xCC);
        let dep = deposit_topic();
        let mk_dep = |assets: u64, shares: u64| Log {
            address: vault,
            topics: vec![dep, B256::ZERO, B256::ZERO],
            data: {
                let mut d = [0u8; 64];
                d[24..32].copy_from_slice(&assets.to_be_bytes());
                d[56..64].copy_from_slice(&shares.to_be_bytes());
                Bytes::copy_from_slice(&d)
            },
        };
        let mut res = ExecutionResult::default();
        res.success = true;
        res.logs.push(mk_dep(100, 100));
        res.logs.push(mk_dep(900, 10));
        res.sequence_cumulative_logs = res.logs.clone();

        let abi: JsonAbi = serde_json::from_value(json!([])).expect("abi");
        let mut p = classify_json_abi(&abi, Some("Random"), None);
        p.abi_present = true;
        p.erc4626_score = 0;
        let mut m = HashMap::new();
        m.insert(vault, p);
        let inv = Erc4626ExchangeRateJumpOracle {
            max_multiplier: U256::from(5u64),
            profiles: Some(Arc::new(m)),
        };
        assert!(inv.check(&HashMap::new(), &res, &[tx_dummy()]).is_none());
    }

    #[test]
    fn erc20_balance_suppressed_when_abi_non_token() {
        let token = Address::repeat_byte(0x77);
        let holder = Address::repeat_byte(0x01);
        let key = erc20_balance_storage_key(holder);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.state_diff
            .storage_writes
            .insert(token, HashMap::from([(key, U256::from(999u64))]));
        let mut tx = tx_dummy();
        tx.sender = holder;

        let abi: JsonAbi = serde_json::from_value(json!([])).expect("abi");
        let mut p = classify_json_abi(&abi, Some("NotAToken"), None);
        p.abi_present = true;
        p.erc20_score = 0;
        let mut m = HashMap::new();
        m.insert(token, p);
        let inv = Erc20BalanceStorageWithoutTransferOracle {
            profiles: Some(Arc::new(m)),
        };
        assert!(inv.check(&HashMap::new(), &r, &[tx]).is_none());
    }
}
