//! Score contracts for fuzz priority (mutating calls, tokens, oracles, proxies).

use std::collections::HashMap;

use crate::types::{ContractInfo, TargetRankEntry, Address};

/// Compute a priority score and human-readable signals per target.
pub fn rank_targets(targets: &[ContractInfo]) -> Vec<TargetRankEntry> {
    let mut out: Vec<TargetRankEntry> = targets.iter().map(|t| score_contract(t)).collect();
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out
}

/// Build address → weight map for [`crate::types::CampaignConfig::target_weights`].
pub fn weights_from_rankings(entries: &[TargetRankEntry], min_w: u32, max_w: u32) -> HashMap<Address, u32> {
    if entries.is_empty() {
        return HashMap::new();
    }
    let min_score = entries.iter().map(|e| e.score).min().unwrap_or(0);
    let max_score = entries.iter().map(|e| e.score).max().unwrap_or(1);
    let span = (max_score - min_score).max(1);
    entries
        .iter()
        .map(|e| {
            let t = (e.score - min_score) as f64 / span as f64;
            let w = ((min_w as f64 + t * (max_w - min_w) as f64).round() as u32).max(1);
            (e.address, w)
        })
        .collect()
}

fn score_contract(t: &ContractInfo) -> TargetRankEntry {
    let mut score: u32 = 0;
    let mut signals: Vec<String> = Vec::new();

    if !t.deployed_bytecode.is_empty() {
        score += 1;
    }

    let Some(abi) = &t.abi else {
        return TargetRankEntry {
            address: t.address,
            name: t.name.clone(),
            score,
            signals: vec!["no_abi".into()],
        };
    };

    let Some(entries) = abi.as_array() else {
        return TargetRankEntry {
            address: t.address,
            name: t.name.clone(),
            score,
            signals,
        };
    };

    for entry in entries {
        if entry.get("type").and_then(|x| x.as_str()) != Some("function") {
            continue;
        }
        let state = entry
            .get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if state == "nonpayable" || state == "payable" {
            score += 2;
        }

        if state == "payable" {
            score += 3;
            signals.push("payable_fn".into());
        }

        for kw in [
            "transfer",
            "approve",
            "mint",
            "burn",
            "deposit",
            "withdraw",
            "redeem",
            "borrow",
            "repay",
            "liquidat",
            "swap",
            "stake",
            "unstake",
            "claim",
            "oracle",
            "price",
            "pause",
            "unpause",
            "upgrade",
            "initialize",
            "execute",
            "vote",
            "propose",
        ] {
            if name.contains(kw) {
                score += 4;
                signals.push(format!("fn:{kw}"));
                break;
            }
        }

        if name.contains("onlyowner") || name.contains("role") || name.contains("admin") {
            score += 2;
            signals.push("access_gated".into());
        }
    }

    let spath = t.source_path.as_deref().unwrap_or("");
    if spath.contains("proxy") || spath.contains("Proxy") {
        score += 1;
        signals.push("proxy_path_hint".into());
    }

    TargetRankEntry {
        address: t.address,
        name: t.name.clone(),
        score,
        signals,
    }
}
