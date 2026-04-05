//! Exploit-oriented economic oracles using execution logs and storage diffs.
//!
//! These invariants use [`ExecutionResult::sequence_cumulative_logs`] for
//! sequence-level event analysis (filled by the campaign and shrink replay).

use std::collections::HashMap;

use tiny_keccak::{Hasher, Keccak};

use crate::invariant::Invariant;
use crate::types::{Address, ExecutionResult, Finding, Severity, Transaction, B256, U256};

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
pub struct Erc4626EventAnomalyOracle;

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
                    return Some(Finding {
                        severity: Severity::High,
                        title: "Economic: ERC-4626 impossible Deposit (assets>0, shares=0)".into(),
                        description: format!(
                            "Vault {} emitted Deposit with assets={assets} and shares=0 — share mint should not be zero when assets are positive (possible accounting break).",
                            log.address
                        ),
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
                    return Some(Finding {
                        severity: Severity::High,
                        title: "Economic: ERC-4626 impossible Withdraw (shares>0, assets=0)".into(),
                        description: format!(
                            "Vault {} emitted Withdraw with shares={shares} and assets=0 — asset payout should not be zero when shares are burned (possible redemption break).",
                            log.address
                        ),
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
}

impl Default for Erc20MintWithoutSupplyWriteOracle {
    fn default() -> Self {
        Self {
            min_mint: MIN_LARGE_TOKEN_MOVE,
            total_supply_slot: OZ_ERC20_TOTAL_SUPPLY_SLOT,
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
            return Some(Finding {
                severity: Severity::Critical,
                title: format!("Economic: ERC-20 large mint without totalSupply storage update ({token})"),
                description: format!(
                    "Token {token} logged a large mint (from zero) of {value} units but slot {} (_totalSupply heuristic) was not written this transaction — supply accounting may be inconsistent with balances.",
                    self.total_supply_slot
                ),
                contract: token,
                reproducer: sequence.to_vec(),
                exploit_profit: Some(value),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ERC-20: balance mapping storage touched without any Transfer in the same tx
// ---------------------------------------------------------------------------

/// Flags when ERC-20 balance storage (OZ mapping slot 0) changes but no `Transfer` was emitted by the token in that tx.
pub struct Erc20BalanceStorageWithoutTransferOracle;

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
                        return Some(Finding {
                            severity: Severity::High,
                            title: format!(
                                "Economic: ERC-20 balance storage write without Transfer ({token})"
                            ),
                            description: format!(
                                "Token {token} wrote balance storage (slot key {slot_key:#x}) for {holder}, but this transaction emitted no `Transfer` from {token}. \
                                 This can indicate direct balance manipulation, callback ordering bugs, or a non-standard token — triage against your ABI.",
                                holder = holder,
                                slot_key = slot_key,
                                token = token
                            ),
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
}

impl Default for Erc4626ExchangeRateJumpOracle {
    fn default() -> Self {
        Self {
            max_multiplier: U256::from(5u64),
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
            let rate = assets.saturating_mul(w).checked_div(shares).unwrap_or(U256::MAX);
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
        if r1 == U256::ZERO {
            return None;
        }
        let up = r2 / r1;
        let down = r1 / r2;
        if r2 > r1.saturating_mul(self.max_multiplier) {
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 exchange rate jump ({vault})"),
                description: format!(
                    "Vault {vault}: cumulative `Deposit` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} between consecutive deposits — factor ~{up}x. \
                     Investigate rounding, donation attacks, or read-only reentrancy windows.",
                    vault = vault,
                    r1 = r1,
                    r2 = r2,
                    up = up
                ),
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        if r1 > r2.saturating_mul(self.max_multiplier) {
            return Some(Finding {
                severity: Severity::High,
                title: format!("Economic: ERC-4626 exchange rate plunge ({vault})"),
                description: format!(
                    "Vault {vault}: cumulative `Deposit` logs imply assets-per-share (WAD-scaled) moved from ~{r1} to ~{r2} — factor ~{down}x down.",
                    vault = vault,
                    r1 = r1,
                    r2 = r2,
                    down = down
                ),
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }

        None
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
    use crate::types::{Bytes, Log};

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
        let inv = Erc4626EventAnomalyOracle;
        let f = inv.check(&HashMap::new(), &r, &[tx_dummy()]).expect("finding");
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
        let f = inv.check(&HashMap::new(), &r, &[tx_dummy()]).expect("finding");
        assert!(f.title.contains("totalSupply"));
    }

    #[test]
    fn erc20_balance_without_transfer_fires() {
        let token = Address::repeat_byte(0x77);
        let holder = Address::repeat_byte(0x01);
        let key = erc20_balance_storage_key(holder);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.state_diff.storage_writes.insert(
            token,
            HashMap::from([(key, U256::from(999u64))]),
        );
        let mut tx = tx_dummy();
        tx.sender = holder;
        let inv = Erc20BalanceStorageWithoutTransferOracle;
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
        let f = inv.check(&HashMap::new(), &r, &[tx_dummy()]).expect("finding");
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
}
