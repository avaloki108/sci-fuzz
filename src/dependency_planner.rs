//! Dynamic dependency hints for sequence planning (ConFuzzius-style, MVP).
//!
//! Summaries are learned from concrete [`crate::types::DataflowWaypoints`] and can be
//! merged by the campaign to bias call order.

use std::collections::{HashMap, HashSet};

use crate::types::{Address, DataflowWaypoints, U256};

/// Observed storage touch slots per contract (from dataflow waypoints).
#[derive(Debug, Clone, Default)]
pub struct DynamicRwSummary {
    /// contract → slots read or written
    pub slots_touched: HashMap<Address, HashSet<U256>>,
}

impl DynamicRwSummary {
    pub fn merge_from_dataflow(&mut self, df: &DataflowWaypoints) {
        for (addr, slots) in &df.map {
            self.slots_touched
                .entry(*addr)
                .or_default()
                .extend(slots.iter().copied());
        }
    }

    /// Heuristic: prefer calling contracts that touch fewer slots first (setup), then heavy writers.
    pub fn suggest_order(&self, contracts: &[Address]) -> Vec<Address> {
        let mut v: Vec<Address> = contracts.to_vec();
        v.sort_by_key(|a| self.slots_touched.get(a).map(|s| s.len()).unwrap_or(0));
        v
    }
}
