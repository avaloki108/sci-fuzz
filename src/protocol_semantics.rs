//! Best-effort protocol classification from ABIs and standard event topics.
//!
//! Used to enrich economic-oracle triage and reduce false positives when ABI
//! metadata is available. Does **not** infer storage layout from ABI.

use std::collections::HashMap;

use alloy_json_abi::JsonAbi;
use tiny_keccak::{Hasher, Keccak};

use crate::types::{Address, B256, U256};

// ---------------------------------------------------------------------------
// Keccak helpers (match economic.rs style)
// ---------------------------------------------------------------------------

fn keccak256(input: &[u8]) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    B256::from(output)
}

/// Topic0 for `Transfer(address,address,uint256)`.
pub fn topic_erc20_transfer() -> B256 {
    keccak256(b"Transfer(address,address,uint256)")
}

/// Topic0 for ERC-4626 `Deposit(address,address,uint256,uint256)`.
pub fn topic_erc4626_deposit() -> B256 {
    keccak256(b"Deposit(address,address,uint256,uint256)")
}

/// Topic0 for ERC-4626 `Withdraw(address,address,address,uint256,uint256)`.
pub fn topic_erc4626_withdraw() -> B256 {
    keccak256(b"Withdraw(address,address,address,uint256,uint256)")
}

/// Uniswap V2–style `Sync(uint112,uint112)`.
pub fn topic_uni_v2_sync() -> B256 {
    keccak256(b"Sync(uint112,uint112)")
}

/// Uniswap V2–style `Swap(address,uint256,uint256,uint256,uint256,address)`.
pub fn topic_uni_v2_swap() -> B256 {
    keccak256(b"Swap(address,uint256,uint256,uint256,uint256,address)")
}

/// Uniswap V2–style `Mint(address,uint256,uint256)`.
pub fn topic_uni_v2_mint() -> B256 {
    keccak256(b"Mint(address,uint256,uint256)")
}

/// Uniswap V2–style `Burn(address,uint256,uint256,address)`.
pub fn topic_uni_v2_burn() -> B256 {
    keccak256(b"Burn(address,uint256,uint256,address)")
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Coarse protocol family for triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolKind {
    #[default]
    Unknown,
    Erc20Like,
    Erc4626Like,
    AmmPairLike,
    LendingLike,
}

/// Per-contract hints from ABI (+ optional name/path heuristics).
#[derive(Debug, Clone, Default)]
pub struct ContractProtocolProfile {
    /// True when classification used a non-empty parsed ABI.
    pub abi_present: bool,
    pub erc20_score: u8,
    pub erc4626_score: u8,
    pub amm_score: u8,
    pub lending_score: u8,
    pub primary: ProtocolKind,
    /// Human-readable signals for findings, e.g. `fn:totalAssets`, `event:Swap`.
    pub signals: Vec<String>,
}

impl ContractProtocolProfile {
    /// Strong enough ERC-4626 cues to treat gated vault oracles as applicable.
    pub fn is_erc4626_like(&self) -> bool {
        self.erc4626_score >= 3
    }

    pub fn is_erc20_like(&self) -> bool {
        self.erc20_score >= 3
    }

    pub fn is_amm_pair_like(&self) -> bool {
        self.amm_score >= 3
    }

    pub fn is_lending_like(&self) -> bool {
        self.lending_score >= 3
    }
}

fn push_signal(signals: &mut Vec<String>, s: impl Into<String>) {
    let t = s.into();
    if !signals.iter().any(|x| x == &t) {
        signals.push(t);
    }
}

fn has_function(abi: &JsonAbi, name: &str) -> bool {
    abi.functions.contains_key(name)
}

fn has_any_function(abi: &JsonAbi, names: &[&str]) -> bool {
    names.iter().any(|n| has_function(abi, n))
}

fn has_event(abi: &JsonAbi, name: &str) -> bool {
    abi.events.contains_key(name)
}

/// Classify a contract from its JSON ABI and optional artifact metadata.
pub fn classify_json_abi(
    abi: &JsonAbi,
    contract_name: Option<&str>,
    source_path: Option<&str>,
) -> ContractProtocolProfile {
    let mut p = ContractProtocolProfile {
        abi_present: true,
        ..Default::default()
    };

    // ERC-4626
    let f462 = [
        "totalAssets",
        "convertToShares",
        "convertToAssets",
        "previewDeposit",
        "previewMint",
        "previewWithdraw",
        "previewRedeem",
        "deposit",
        "mint",
        "withdraw",
        "redeem",
        "asset",
    ];
    for n in f462 {
        if has_function(abi, n) {
            p.erc4626_score = p.erc4626_score.saturating_add(1);
            push_signal(&mut p.signals, format!("fn:{n}"));
        }
    }
    for ev in ["Deposit", "Withdraw"] {
        if has_event(abi, ev) {
            p.erc4626_score = p.erc4626_score.saturating_add(2);
            push_signal(&mut p.signals, format!("event:{ev}"));
        }
    }

    // ERC-20
    for n in [
        "totalSupply",
        "balanceOf",
        "transfer",
        "transferFrom",
        "allowance",
        "approve",
    ] {
        if has_function(abi, n) {
            p.erc20_score = p.erc20_score.saturating_add(1);
            push_signal(&mut p.signals, format!("fn:{n}"));
        }
    }
    if has_event(abi, "Transfer") {
        p.erc20_score = p.erc20_score.saturating_add(2);
        push_signal(&mut p.signals, "event:Transfer");
    }
    if has_event(abi, "Approval") {
        p.erc20_score = p.erc20_score.saturating_add(1);
        push_signal(&mut p.signals, "event:Approval");
    }

    // AMM / pair
    for n in ["token0", "token1", "getReserves", "swap", "skim", "sync"] {
        if has_function(abi, n) {
            p.amm_score = p.amm_score.saturating_add(1);
            push_signal(&mut p.signals, format!("fn:{n}"));
        }
    }
    for ev in ["Sync", "Swap", "Mint", "Burn"] {
        if has_event(abi, ev) {
            p.amm_score = p.amm_score.saturating_add(2);
            push_signal(&mut p.signals, format!("event:{ev}"));
        }
    }

    // Lending (best-effort)
    let lend_f = [
        "borrow",
        "repay",
        "repayBorrow",
        "liquidationCall",
        "liquidate",
        "flashLoan",
    ];
    for n in lend_f {
        if has_function(abi, n) {
            p.lending_score = p.lending_score.saturating_add(2);
            push_signal(&mut p.signals, format!("fn:{n}"));
        }
    }
    if has_any_function(abi, &["deposit", "withdraw"])
        && has_any_function(abi, &["borrow", "repay"])
    {
        p.lending_score = p.lending_score.saturating_add(1);
        push_signal(&mut p.signals, "fn:deposit+withdraw+borrow/repay");
    }
    for ev in ["Borrow", "Repay", "LiquidationCall", "RepayBorrow"] {
        if has_event(abi, ev) {
            p.lending_score = p.lending_score.saturating_add(2);
            push_signal(&mut p.signals, format!("event:{ev}"));
        }
    }

    // Soft name/path hints (low weight — never alone enough for primary)
    let mut soft = 0u8;
    let name_l = contract_name.unwrap_or("").to_lowercase();
    let path_l = source_path.unwrap_or("").to_lowercase();
    for needle in ["vault", "erc4626", "yearn"] {
        if name_l.contains(needle) || path_l.contains(needle) {
            soft = soft.saturating_add(1);
        }
    }
    if soft > 0 {
        p.erc4626_score = p.erc4626_score.saturating_add(1);
        push_signal(&mut p.signals, "hint:vault-name/path");
    }
    for needle in ["pair", "pool", "amm", "uniswap", "curve"] {
        if name_l.contains(needle) || path_l.contains(needle) {
            p.amm_score = p.amm_score.saturating_add(1);
            push_signal(&mut p.signals, "hint:amm-name/path");
            break;
        }
    }

    // Primary kind: highest score wins; tie-break: ERC4626 > AMM > Lending > ERC20
    let mut best = (ProtocolKind::Unknown, 0u8);
    let candidates = [
        (ProtocolKind::Erc4626Like, p.erc4626_score),
        (ProtocolKind::AmmPairLike, p.amm_score),
        (ProtocolKind::LendingLike, p.lending_score),
        (ProtocolKind::Erc20Like, p.erc20_score),
    ];
    for (k, s) in candidates {
        if s > best.1 {
            best = (k, s);
        }
    }
    if best.1 > 0 {
        p.primary = best.0;
    }

    p
}

/// Build a map of deployed address → profile from campaign targets.
pub fn build_protocol_profiles(
    targets: &[crate::types::ContractInfo],
) -> std::sync::Arc<HashMap<Address, ContractProtocolProfile>> {
    let mut m = HashMap::new();
    for t in targets {
        let profile = if let Some(ref abi_val) = t.abi {
            if let Ok(abi) = serde_json::from_value::<JsonAbi>(abi_val.clone()) {
                classify_json_abi(&abi, t.name.as_deref(), t.source_path.as_deref())
            } else {
                ContractProtocolProfile::default()
            }
        } else {
            ContractProtocolProfile::default()
        };
        m.insert(t.address, profile);
    }
    std::sync::Arc::new(m)
}

// ---------------------------------------------------------------------------
// Triage text
// ---------------------------------------------------------------------------

/// Short label for primary protocol kind.
pub fn protocol_kind_label(k: ProtocolKind) -> &'static str {
    match k {
        ProtocolKind::Unknown => "unknown",
        ProtocolKind::Erc20Like => "ERC20-like",
        ProtocolKind::Erc4626Like => "ERC4626-like",
        ProtocolKind::AmmPairLike => "AMM/pair-like",
        ProtocolKind::LendingLike => "lending-like",
    }
}

/// Simpler triage append when we only have profile + invariant line.
pub fn append_triage_simple(
    base: String,
    _contract: Address,
    profile: Option<&ContractProtocolProfile>,
    invariant: &str,
    evidence: &str,
    limitations: &str,
) -> String {
    let head = if let Some(p) = profile {
        format!(
            "Protocol classification (sci-fuzz): {} (erc4626_score={}, erc20_score={}, amm_score={}).\n",
            protocol_kind_label(p.primary),
            p.erc4626_score,
            p.erc20_score,
            p.amm_score
        )
    } else {
        "Protocol classification (sci-fuzz): unknown (no ABI profile).\n".to_string()
    };
    format!(
        "{base}\n\n{head}\
         Invariant: {invariant}\n\
         Evidence: {evidence}\n\
         Exploitability notes: Review logs and storage diffs; economic oracles are heuristic.\n\
         Limitations: {limitations}",
        base = base,
        head = head,
        invariant = invariant,
        evidence = evidence,
        limitations = limitations
    )
}

/// Expand uint112 (last 14 bytes in 32-byte word) to U256.
pub fn u112_from_word(word: &[u8]) -> U256 {
    if word.len() < 32 {
        return U256::ZERO;
    }
    U256::from_be_slice(&word[32 - 14..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn abi_from_json(j: serde_json::Value) -> JsonAbi {
        serde_json::from_value(j).expect("abi json")
    }

    #[test]
    fn classifies_erc20() {
        let abi = abi_from_json(json!([
            {"type":"function","name":"totalSupply","inputs":[],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"balanceOf","inputs":[{"name":"a","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"v","type":"uint256"}],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"},
            {"type":"event","name":"Transfer","anonymous":false,"inputs":[
                {"name":"from","type":"address","indexed":true},
                {"name":"to","type":"address","indexed":true},
                {"name":"value","type":"uint256","indexed":false}
            ]}
        ]));
        let p = classify_json_abi(&abi, Some("Token"), None);
        assert!(p.erc20_score >= 3);
        assert_eq!(p.primary, ProtocolKind::Erc20Like);
    }

    #[test]
    fn classifies_erc4626() {
        let abi = abi_from_json(json!([
            {"type":"function","name":"asset","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},
            {"type":"function","name":"totalAssets","inputs":[],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"convertToShares","inputs":[{"name":"a","type":"uint256"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"deposit","inputs":[{"name":"a","type":"uint256"},{"name":"r","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"nonpayable"},
            {"type":"event","name":"Deposit","anonymous":false,"inputs":[
                {"name":"sender","type":"address","indexed":true},
                {"name":"owner","type":"address","indexed":true},
                {"name":"assets","type":"uint256","indexed":false},
                {"name":"shares","type":"uint256","indexed":false}
            ]}
        ]));
        let p = classify_json_abi(&abi, Some("Vault"), None);
        assert!(p.is_erc4626_like());
        assert_eq!(p.primary, ProtocolKind::Erc4626Like);
    }

    #[test]
    fn classifies_amm_pair() {
        let abi = abi_from_json(json!([
            {"type":"function","name":"token0","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},
            {"type":"function","name":"token1","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},
            {"type":"function","name":"getReserves","inputs":[],"outputs":[{"type":"uint112"},{"type":"uint112"},{"type":"uint32"}],"stateMutability":"view"},
            {"type":"function","name":"swap","inputs":[{"name":"a0","type":"uint256"},{"name":"a1","type":"uint256"},{"name":"to","type":"address"},{"name":"b","type":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},
            {"type":"event","name":"Sync","anonymous":false,"inputs":[
                {"name":"r0","type":"uint112","indexed":false},
                {"name":"r1","type":"uint112","indexed":false}
            ]},
            {"type":"event","name":"Swap","anonymous":false,"inputs":[
                {"name":"sender","type":"address","indexed":true},
                {"name":"a0In","type":"uint256","indexed":false},
                {"name":"a1In","type":"uint256","indexed":false},
                {"name":"a0Out","type":"uint256","indexed":false},
                {"name":"a1Out","type":"uint256","indexed":false},
                {"name":"to","type":"address","indexed":true}
            ]}
        ]));
        let p = classify_json_abi(&abi, Some("UniswapV2Pair"), None);
        assert!(p.is_amm_pair_like());
    }

    #[test]
    fn topic_hashes_stable() {
        assert_eq!(
            topic_erc20_transfer(),
            keccak256(b"Transfer(address,address,uint256)")
        );
    }
}
