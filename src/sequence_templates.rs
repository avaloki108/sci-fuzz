//! Guided multi-step patterns (deposit→withdraw, borrow→repay, …).

use rand::Rng;

use crate::mutator::TxMutator;
use crate::types::{Transaction, U256};

/// Built-in template ids (string keys for `CampaignConfig::sequence_template_weights`).
pub const T_DEPOSIT_WITHDRAW: &str = "deposit_withdraw";
pub const T_APPROVE_TRANSFER: &str = "approve_transfer";
pub const T_BORROW_REPAY: &str = "borrow_repay";
pub const T_STAKE_CLAIM: &str = "stake_claim";
pub const T_MINT_BURN: &str = "mint_burn";

/// Pick a template name using config weights (default equal if unset).
pub fn pick_template(rng: &mut impl Rng, weights: &std::collections::HashMap<String, f64>) -> &'static str {
    const DEFAULTS: &[&str] = &[
        T_DEPOSIT_WITHDRAW,
        T_APPROVE_TRANSFER,
        T_BORROW_REPAY,
        T_STAKE_CLAIM,
        T_MINT_BURN,
    ];
    let weighted: Vec<(&'static str, f64)> = DEFAULTS
        .iter()
        .map(|&n| (n, *weights.get(n).unwrap_or(&1.0)))
        .collect();
    let sum: f64 = weighted.iter().map(|(_, w)| w.max(0.0)).sum();
    if sum <= 0.0 {
        return DEFAULTS[rng.gen_range(0..DEFAULTS.len())];
    }
    let r = rng.gen::<f64>() * sum;
    let mut acc = 0.0;
    for (name, w) in weighted {
        acc += w.max(0.0);
        if r <= acc {
            return name;
        }
    }
    DEFAULTS[0]
}

/// Build a short sequence biased toward a DeFi-shaped pattern.
pub fn build_sequence(
    template: &str,
    mutator: &TxMutator,
    max_depth: u32,
    rng: &mut impl Rng,
) -> Vec<Transaction> {
    let n = (max_depth.min(8)).max(2);
    let mut seq = Vec::with_capacity(n as usize);
    let hints: &[&str] = match template {
        x if x == T_DEPOSIT_WITHDRAW => &["deposit", "mint", "withdraw", "redeem"],
        x if x == T_APPROVE_TRANSFER => &["approve", "transfer", "transferFrom"],
        x if x == T_BORROW_REPAY => &["borrow", "repay", "liquidat"],
        x if x == T_STAKE_CLAIM => &["stake", "deposit", "claim", "unstake", "withdraw"],
        _ => &["mint", "burn"],
    };

    let mut prev_sender: Option<crate::types::Address> = None;
    let hints_len = hints.len() as u32;
    for i in 0..n {
        let tx = if i < hints_len {
            let hint = hints[i as usize];
            let candidates = mutator.selectors_matching_name(hint);
            if let Some(&sel) = candidates.first() {
                mutator.generate_in_sequence_with_selector(sel, prev_sender, rng)
            } else {
                mutator.generate_in_sequence(prev_sender, rng)
            }
        } else {
            mutator.generate_in_sequence(prev_sender, rng)
        };
        prev_sender = Some(tx.sender);
        seq.push(tx);
    }
    seq
}

/// True if any tx looks value-moving (payable or common deposit).
pub fn sequence_moves_value(seq: &[Transaction]) -> bool {
    seq.iter().any(|tx| tx.value > U256::ZERO)
}
