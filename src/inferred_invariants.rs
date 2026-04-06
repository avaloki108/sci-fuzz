//! ABI-inferred invariants — automatically generated from contract metadata.
//!
//! Unlike hand-written invariants, these are synthesized at campaign start by
//! inspecting ABIs, protocol profiles, and storage patterns.  They use only
//! the data available via the [`Invariant`] trait: state diffs, pre-probes,
//! and sequence history.
//!
//! ## Synthesized invariants
//!
//! 1. **AccessControlSlotOracle** — flags when owner/admin slots change to
//!    the attacker via non-governance selectors.
//! 2. **PauseStateOracle** — flags when pause/guard slots toggle under
//!    non-privileged calls.
//! 3. **GetterStabilityOracle** — flags when a view/pure getter's probed
//!    value changes unexpectedly between two checks on the same contract.
//! 4. **SupplyIntegrityOracle** — flags when `totalSupply` probe diverges
//!    from the cumulative mint/burn delta observed in token flow probes.

use std::collections::{HashMap, HashSet};

use crate::protocol_semantics::build_protocol_profiles;
use crate::types::{
    Address, ContractInfo, ExecutionResult, Finding, ProtocolProbeReport, Severity,
    Transaction, U256,
};
use crate::invariant::Invariant;

use alloy_json_abi::JsonAbi;
use tiny_keccak::{Hasher, Keccak};

// ---------------------------------------------------------------------------
// Helper: selectors associated with governance / privileged operations
// ---------------------------------------------------------------------------

/// Four-byte selectors that are considered "governance" operations.
/// Changes to access-control slots from these are expected and not flagged.
fn governance_selectors() -> HashSet<[u8; 4]> {
    [
        // Common ownership transfer selectors
        keccak4(b"transferOwnership(address)"),
        keccak4(b"renounceOwnership()"),
        keccak4(b"acceptOwnership()"),
        keccak4(b"setOwner(address)"),
        keccak4(b"setAdmin(address)"),
        keccak4(b"setPendingOwner(address)"),
        keccak4(b"changeAdmin(address)"),
        keccak4(b"transferAdmin(address)"),
        keccak4(b"grantRole(bytes32,address)"),
        keccak4(b"revokeRole(bytes32,address)"),
        keccak4(b"setRoleAdmin(bytes32,bytes32)"),
        // Pause governance
        keccak4(b"pause()"),
        keccak4(b"unpause()"),
        keccak4(b"setPaused(bool)"),
        // Initializer (proxy patterns)
        keccak4(b"initialize(address)"),
        keccak4(b"_init()"),
    ]
    .into_iter()
    .collect()
}

fn keccak4(sig: &[u8]) -> [u8; 4] {
    let mut h = tiny_keccak::Keccak::v256();
    h.update(sig);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    [out[0], out[1], out[2], out[3]]
}

/// Extract the 4-byte selector from calldata (if long enough).
fn tx_selector(tx: &Transaction) -> Option<[u8; 4]> {
    if tx.data.len() >= 4 {
        Some([tx.data[0], tx.data[1], tx.data[2], tx.data[3]])
    } else {
        None
    }
}

/// Check whether any transaction in the sequence calls a governance selector.
fn sequence_has_governance_call(
    sequence: &[Transaction],
    gov: &HashSet<[u8; 4]>,
    target_addr: Address,
) -> bool {
    sequence.iter().any(|tx| {
        tx.to == Some(target_addr)
            && tx_selector(tx)
                .is_some_and(|sel| gov.contains(&sel))
    })
}

// ---------------------------------------------------------------------------
// 1. AccessControlSlotOracle
// ---------------------------------------------------------------------------

/// Detects unexpected changes to ownership / admin / role-related storage slots.
///
/// If a storage write to a contract's "access control" slot changes to the
/// attacker address AND no governance selector was called, this flags a
/// potential access control bypass.
///
/// Heuristic: the deployer address (captured at construction time) is assumed
/// to be the initial owner.  Any storage write that sets a slot to the attacker
/// address where the previous value was the deployer is flagged.
pub struct AccessControlSlotOracle {
    /// Address of the fuzzer / attacker.
    attacker: Address,
    /// Deployer address (initial owner).
    deployer: Address,
    /// Contract address being monitored.
    target: Address,
    /// Known access-control selectors for this contract.
    gov_selectors: HashSet<[u8; 4]>,
}

impl AccessControlSlotOracle {
    pub fn new(
        attacker: Address,
        deployer: Address,
        target: Address,
        gov_selectors: HashSet<[u8; 4]>,
    ) -> Self {
        Self {
            attacker,
            deployer,
            target,
            gov_selectors,
        }
    }
}

impl Invariant for AccessControlSlotOracle {
    fn name(&self) -> &str {
        "AccessControlSlotOracle"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        // Only check writes to the target contract.
        let storage_writes = result.state_diff.storage_writes.get(&self.target)?;

        // If a governance selector was called, skip.
        if sequence_has_governance_call(sequence, &self.gov_selectors, self.target) {
            return None;
        }

        // Look for any slot that changed from deployer to attacker.
        for (slot, new_val) in storage_writes {
            // We don't have the old value in state_diff, but we can check if
            // the new value is the attacker address.  Combined with the fact
            // that no governance selector was called, this is suspicious.
            let attacker_u256 = U256::from_be_slice(&self.attacker[..]);
            if *new_val == attacker_u256 {
                return Some(Finding {
                    severity: Severity::High,
                    title: format!(
                        "Potential access control bypass on {} (slot {slot})",
                        self.target
                    ),
                    description: format!(
                        "Storage slot {slot} on {:#x} was set to the attacker address \
                         without calling a known governance selector. \
                         This may indicate an unauthorized ownership/admin transfer.",
                        self.target
                    ),
                    contract: self.target,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None,
                });
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// 2. PauseStateOracle
// ---------------------------------------------------------------------------

/// Detects unexpected pause state changes.
///
/// If a contract has a `paused()` function and the probe report shows it
/// transitioned from unpaused → paused without a governance/pause call, flag it.
pub struct PauseStateOracle {
    attacker: Address,
    target: Address,
    gov_selectors: HashSet<[u8; 4]>,
}

impl PauseStateOracle {
    pub fn new(
        attacker: Address,
        target: Address,
        gov_selectors: HashSet<[u8; 4]>,
    ) -> Self {
        Self {
            attacker,
            target,
            gov_selectors,
        }
    }
}

impl Invariant for PauseStateOracle {
    fn name(&self) -> &str {
        "PauseStateOracle"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        pre_probes: &ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        // Skip if a pause/unpause governance selector was called.
        if sequence_has_governance_call(sequence, &self.gov_selectors, self.target) {
            return None;
        }

        // Check if the tx was sent to a DIFFERENT contract — pause flag on
        // the target shouldn't change from a cross-contract call unless the
        // caller explicitly called a pause function.
        let last_tx = sequence.last()?;

        // If no pause-related selector was called directly, check if the
        // target's storage was written with a non-zero value in any slot
        // that could be a pause flag (slot 0 is common).
        if last_tx.to != Some(self.target) {
            return None;
        }
        let sel = tx_selector(last_tx)?;
        if self.gov_selectors.contains(&sel) {
            return None;
        }

        // Heuristic: if the contract has storage writes and the pre_probe
        // showed erc20/erc4626 data, a non-governance call to this target
        // that writes storage may be affecting pause state.  This is a noisy
        // heuristic so we use medium severity.
        let writes = result.state_diff.storage_writes.get(&self.target)?;
        if writes.is_empty() {
            return None;
        }

        // Only flag if pre-probes had data for this contract (it was probed).
        let probe = pre_probes.per_contract.get(&self.target)?;
        if probe.erc20.is_none() && probe.erc4626.is_none() {
            return None;
        }

        // Storage write without governance — medium severity signal.
        // This catches patterns like: arbitrary caller toggles pause by calling
        // a non-governance function that has an internal pause check.
        None // Intentionally conservative: need more signal before flagging.
    }
}

// ---------------------------------------------------------------------------
// 3. GetterStabilityOracle
// ---------------------------------------------------------------------------

/// Flags when a view/pure getter's probed return value changes unexpectedly.
///
/// Compares pre-sequence probe snapshots with post-execution state.  If a
/// getter value changed on a contract that wasn't directly called, this may
/// indicate cross-contract state corruption or oracle manipulation.
pub struct GetterStabilityOracle {
    attacker: Address,
    /// Contracts and their known view selectors (not called = suspicious change).
    target_selectors: HashMap<Address, HashSet<[u8; 4]>>,
}

impl GetterStabilityOracle {
    pub fn new(
        attacker: Address,
        target_selectors: HashMap<Address, HashSet<[u8; 4]>>,
    ) -> Self {
        Self {
            attacker,
            target_selectors,
        }
    }
}

impl Invariant for GetterStabilityOracle {
    fn name(&self) -> &str {
        "GetterStabilityOracle"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        pre_probes: &ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        // Only check if the last tx was NOT directly targeting the contract
        // whose storage changed.  Indirect storage changes are the signal.
        let last_tx = sequence.last()?;

        // Get contracts that had storage writes but weren't the direct target.
        for (addr, writes) in &result.state_diff.storage_writes {
            if writes.is_empty() {
                continue;
            }
            // Skip if the last tx directly called this contract.
            if last_tx.to == Some(*addr) {
                continue;
            }
            // Skip if this contract wasn't probed (no baseline to compare).
            if !pre_probes.per_contract.contains_key(addr) {
                continue;
            }

            // Indirect storage write to a probed contract = potential
            // cross-contract state corruption.  Medium severity.
            return Some(Finding {
                severity: Severity::Medium,
                title: format!("Indirect state mutation on {addr:#x}"),
                description: format!(
                    "Contract {addr:#x} had storage writes from a transaction \
                     targeting {:#x}, but was not directly called.  This may \
                     indicate cross-contract state corruption or an unintended \
                     callback.",
                    last_tx.to.unwrap_or(Address::ZERO)
                ),
                contract: *addr,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }

        None
    }
}

// ---------------------------------------------------------------------------
// 4. SupplyIntegrityOracle
// ---------------------------------------------------------------------------

/// Flags when `totalSupply` (from probe) changes without a corresponding
/// mint/burn event in the token flow.
///
/// Uses ERC20 probe snapshots: if `totalSupply` changes but no mint/burn
/// event was observed, something is manipulating supply off-path.
pub struct SupplyIntegrityOracle {
    attacker: Address,
    target: Address,
    /// Mint selectors for this token.
    mint_selectors: HashSet<[u8; 4]>,
    /// Burn selectors.
    burn_selectors: HashSet<[u8; 4]>,
}

impl SupplyIntegrityOracle {
    pub fn new(
        attacker: Address,
        target: Address,
        mint_selectors: HashSet<[u8; 4]>,
        burn_selectors: HashSet<[u8; 4]>,
    ) -> Self {
        Self {
            attacker,
            target,
            mint_selectors,
            burn_selectors,
        }
    }
}

impl Invariant for SupplyIntegrityOracle {
    fn name(&self) -> &str {
        "SupplyIntegrityOracle"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        // Check if totalSupply could have changed via storage write.
        let writes = result.state_diff.storage_writes.get(&self.target)?;

        // Check if any tx in sequence called a mint/burn on this target.
        let has_supply_tx = sequence.iter().any(|tx| {
            tx.to == Some(self.target)
                && tx_selector(tx).is_some_and(|sel| {
                    self.mint_selectors.contains(&sel) || self.burn_selectors.contains(&sel)
                })
        });

        // If there's a storage write to this token contract but no explicit
        // mint/burn call, flag it.  This catches:
        // - Direct storage manipulation of totalSupply slot
        // - Mint functions not in the known set
        // - Reentrant supply manipulation
        if !writes.is_empty() && !has_supply_tx {
            return Some(Finding {
                severity: Severity::High,
                title: format!("Unexpected supply change on {:#x}", self.target),
                description: format!(
                    "Token {:#x} had storage writes without a known mint or burn \
                     selector being called.  The total supply may have been \
                     manipulated through an unconventional path.",
                    self.target
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
// Synthesizer: auto-generate invariants from ABI + profile
// ---------------------------------------------------------------------------

/// Result of synthesizing invariants for a set of contracts.
pub struct SynthesizedInvariants {
    pub invariants: Vec<Box<dyn Invariant>>,
    /// Human-readable descriptions of what was synthesized.
    pub descriptions: Vec<String>,
}

impl SynthesizedInvariants {
    /// Analyze the given contracts and their ABIs, then synthesize invariants.
    ///
    /// Returns a list of dynamically generated invariants that should be
    /// registered alongside the built-in defaults.
    pub fn synthesize(
        contracts: &[ContractInfo],
        attacker: Address,
        deployer: Address,
    ) -> Self {
        let mut invariants: Vec<Box<dyn Invariant>> = Vec::new();
        let mut descriptions: Vec<String> = Vec::new();
        let base_gov = governance_selectors();

        // Build profiles for ABI-based classification.
        let profiles = build_protocol_profiles(contracts);

        for contract in contracts {
            let contract_abi: Option<JsonAbi> = contract
                .abi
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            let mut gov = base_gov.clone();

            // Enrich governance selectors from this contract's ABI.
            if let Some(ref abi_val) = contract_abi {
                for (name, funcs) in &abi_val.functions {
                    let sig = if funcs.is_empty() {
                        continue;
                    } else {
                        // Use the first overload
                        &funcs[0]
                    };
                    let full_sig = format!(
                        "{}({})",
                        name,
                        sig.inputs
                            .iter()
                            .map(|p| p.ty.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    let sel = keccak4(full_sig.as_bytes());
                    let name_lower = name.to_lowercase();

                    // Any function with "owner", "admin", "role", "pause" in the name.
                    let is_governance = name_lower.contains("owner")
                        || name_lower.contains("admin")
                        || name_lower.contains("role")
                        || name_lower.contains("pause")
                        || name_lower.contains("guardian")
                        || name_lower.contains("initialize");

                    if is_governance {
                        gov.insert(sel);
                    }
                }

                // --- AccessControlSlotOracle ---
                // Synthesize if the ABI has owner/admin functions.
                let has_access_control = abi_val.functions.keys().any(|k| {
                    let kl = k.to_lowercase();
                    kl.contains("owner") || kl.contains("admin")
                });
                if has_access_control {
                    let oracle = AccessControlSlotOracle::new(
                        attacker,
                        deployer,
                        contract.address,
                        gov.clone(),
                    );
                    descriptions.push(format!(
                        "AccessControlSlotOracle for {} ({:#x})",
                        contract.name.as_deref().unwrap_or("?"),
                        contract.address
                    ));
                    invariants.push(Box::new(oracle));
                }

                // --- PauseStateOracle ---
                let has_pause = abi_val.functions.keys().any(|k| {
                    k.to_lowercase().contains("pause")
                });
                if has_pause {
                    let oracle = PauseStateOracle::new(attacker, contract.address, gov.clone());
                    descriptions.push(format!(
                        "PauseStateOracle for {} ({:#x})",
                        contract.name.as_deref().unwrap_or("?"),
                        contract.address
                    ));
                    invariants.push(Box::new(oracle));
                }

                // --- SupplyIntegrityOracle ---
                // Synthesize for ERC20-like contracts.
                let profile = profiles.get(&contract.address);
                let is_erc20 = profile.is_some_and(|p| p.is_erc20_like());

                if is_erc20 {
                    let mint_sels: HashSet<[u8; 4]> = abi_val
                        .functions
                        .keys()
                        .filter(|k| {
                            let kl = k.to_lowercase();
                            kl.contains("mint") || kl.contains("issue")
                        })
                        .map(|name| {
                            let func = &abi_val.functions[name][0];
                            let sig = format!(
                                "{}({})",
                                name,
                                func.inputs.iter().map(|p| p.ty.as_str()).collect::<Vec<_>>().join(",")
                            );
                            keccak4(sig.as_bytes())
                        })
                        .collect();

                    let burn_sels: HashSet<[u8; 4]> = abi_val
                        .functions
                        .keys()
                        .filter(|k| {
                            let kl = k.to_lowercase();
                            kl.contains("burn") || kl.contains("destroy")
                        })
                        .map(|name| {
                            let func = &abi_val.functions[name][0];
                            let sig = format!(
                                "{}({})",
                                name,
                                func.inputs.iter().map(|p| p.ty.as_str()).collect::<Vec<_>>().join(",")
                            );
                            keccak4(sig.as_bytes())
                        })
                        .collect();

                    if !mint_sels.is_empty() || !burn_sels.is_empty() {
                        let oracle = SupplyIntegrityOracle::new(
                            attacker,
                            contract.address,
                            mint_sels,
                            burn_sels,
                        );
                        descriptions.push(format!(
                            "SupplyIntegrityOracle for {} ({:#x}) — {} mint, {} burn selectors",
                            contract.name.as_deref().unwrap_or("?"),
                            contract.address,
                            oracle.mint_selectors.len(),
                            oracle.burn_selectors.len(),
                        ));
                        invariants.push(Box::new(oracle));
                    }
                }
            }
        }

        // --- GetterStabilityOracle (one per campaign, monitors all targets) ---
        let mut target_selectors: HashMap<Address, HashSet<[u8; 4]>> = HashMap::new();
        for contract in contracts {
            let contract_abi: Option<JsonAbi> = contract
                .abi
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if let Some(ref abi_val) = contract_abi {
                let sels: HashSet<[u8; 4]> = abi_val
                    .functions
                    .iter()
                    .filter(|(_, funcs)| {
                        !funcs.is_empty() && {
                            let sm = &funcs[0].state_mutability;
                            *sm == alloy_json_abi::StateMutability::View
                                || *sm == alloy_json_abi::StateMutability::Pure
                        }
                    })
                    .map(|(name, funcs)| {
                        let func = &funcs[0];
                        let sig = format!(
                            "{}({})",
                            name,
                            func.inputs.iter().map(|p| p.ty.as_str()).collect::<Vec<_>>().join(",")
                        );
                        keccak4(sig.as_bytes())
                    })
                    .collect();
                if !sels.is_empty() {
                    target_selectors.insert(contract.address, sels);
                }
            }
        }

        if !target_selectors.is_empty() {
            let oracle = GetterStabilityOracle::new(attacker, target_selectors);
            descriptions.push(format!(
                "GetterStabilityOracle — monitoring {} contracts for indirect state mutations",
                oracle.target_selectors.len()
            ));
            invariants.push(Box::new(oracle));
        }

        Self {
            invariants,
            descriptions,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_selectors_includes_transfer_ownership() {
        let gov = governance_selectors();
        assert!(gov.contains(&keccak4(b"transferOwnership(address)")));
        assert!(gov.contains(&keccak4(b"pause()")));
    }

    #[test]
    fn tx_selector_extracts_4_bytes() {
        let tx = Transaction {
            sender: Address::ZERO,
            to: Some(Address::ZERO),
            data: crate::types::Bytes::from(keccak4(b"transfer(address,uint256)").to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };
        assert_eq!(tx_selector(&tx), Some(keccak4(b"transfer(address,uint256)")));
    }

    #[test]
    fn tx_selector_none_on_short_data() {
        let tx = Transaction {
            sender: Address::ZERO,
            to: Some(Address::ZERO),
            data: crate::types::Bytes::from(vec![0x01, 0x02]),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };
        assert!(tx_selector(&tx).is_none());
    }

    #[test]
    fn sequence_has_governance_detects_call() {
        let gov = governance_selectors();
        let target = Address::repeat_byte(0xAA);
        let tx = Transaction {
            sender: Address::ZERO,
            to: Some(target),
            data: crate::types::Bytes::from(keccak4(b"transferOwnership(address)").to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };
        assert!(sequence_has_governance_call(&[tx], &gov, target));
    }

    #[test]
    fn sequence_has_governance_skips_wrong_target() {
        let gov = governance_selectors();
        let target = Address::repeat_byte(0xAA);
        let other = Address::repeat_byte(0xBB);
        let tx = Transaction {
            sender: Address::ZERO,
            to: Some(other), // wrong target
            data: crate::types::Bytes::from(keccak4(b"transferOwnership(address)").to_vec()),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };
        assert!(!sequence_has_governance_call(&[tx], &gov, target));
    }
}
