//! Benchmark scoreboard — machine-readable campaign results.
//!
//! The scoreboard tracks findings per-target and emits CSV for the
//! benchmark matrix. The format is designed to answer:
//!   - which bug classes sci-fuzz actually finds
//!   - how quickly (both wall-clock and exec count)
//!   - by which oracle/mechanism
//!   - with what reproducer quality
//!   - under which executor mode and seed
//!
//! Schema (12 columns):
//!   target, property, category, mode, seed,
//!   detected, first_hit_execs, time_to_first_hit_ms, total_execs,
//!   sequence_len, distinct_reproducer_hash, detection_mechanism

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::types::Finding;

// ---------------------------------------------------------------------------
// ScorecardEntry
// ---------------------------------------------------------------------------

/// One row in the scoreboard CSV.
///
/// `first_hit_execs` is the primary timing metric — it is machine- and
/// load-independent.  `time_to_first_hit_ms` is a secondary metric; it
/// collapses to zero for fast targets so exec count carries more signal.
///
/// `detection_mechanism` records the oracle or rule that produced the
/// finding (e.g. `"EchidnaPropertyCaller"`, `"BalanceIncrease"`,
/// `"UnexpectedRevert"`).  This is important for distinguishing a robust
/// permission oracle from a heuristic side-effect trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorecardEntry {
    /// Short name of the target contract.
    pub target: String,
    /// Property or invariant being tested (oracle name or property function).
    pub property: String,
    /// Bug class (e.g. `"PropertyViolation"`, `"Reentrancy"`, `"AccessControl"`).
    pub category: String,
    /// Executor mode used (`"fast"` or `"realistic"`).
    pub mode: String,
    /// Random seed used for this run.
    pub seed: u64,
    /// Whether the property/bug was detected.
    pub detected: bool,
    /// Number of EVM executions before the first finding (primary timing metric).
    /// Zero when `detected == false`.
    pub first_hit_execs: u64,
    /// Wall-clock milliseconds to first finding (secondary metric).
    /// Zero when `detected == false` or when the hit was instantaneous.
    pub time_to_first_hit_ms: u64,
    /// Total EVM executions over the full campaign run.
    pub total_execs: u64,
    /// Length of the reproducer transaction sequence.
    /// Zero when `detected == false`.
    pub sequence_len: usize,
    /// Deduplication hash of the finding (`Finding::dedup_hash()`).
    /// Zero when `detected == false`.
    pub distinct_reproducer_hash: u64,
    /// Name of the oracle or rule that produced the finding.
    /// Empty string when `detected == false`.
    ///
    /// Examples:
    ///   - `"EchidnaPropertyCaller"` — echidna_* bool property returned false
    ///   - `"BalanceIncrease"` — attacker ETH balance increased abnormally
    ///   - `"SelfDestructDetector"` — contract balance dropped to zero
    ///   - `"UnexpectedRevert"` — transaction reverted unexpectedly
    ///   - `"ERC20Supply"` — abnormal mint/burn event detected
    pub detection_mechanism: String,
}

impl ScorecardEntry {
    /// Build an entry for a property that was **not** detected.
    pub fn not_found(
        target: &str,
        property: &str,
        category: &str,
        mode: &str,
        seed: u64,
        total_execs: u64,
    ) -> Self {
        Self {
            target: target.into(),
            property: property.into(),
            category: category.into(),
            mode: mode.into(),
            seed,
            detected: false,
            first_hit_execs: 0,
            time_to_first_hit_ms: 0,
            total_execs,
            sequence_len: 0,
            distinct_reproducer_hash: 0,
            detection_mechanism: String::new(),
        }
    }

    /// Build an entry for a property that **was** detected.
    pub fn found(
        target: &str,
        property: &str,
        category: &str,
        mode: &str,
        seed: u64,
        first_hit_execs: u64,
        time_ms: u64,
        total_execs: u64,
        finding: &Finding,
        detection_mechanism: &str,
    ) -> Self {
        Self {
            target: target.into(),
            property: property.into(),
            category: category.into(),
            mode: mode.into(),
            seed,
            detected: true,
            first_hit_execs,
            time_to_first_hit_ms: time_ms,
            total_execs,
            sequence_len: finding.reproducer.len(),
            distinct_reproducer_hash: finding.dedup_hash(),
            detection_mechanism: detection_mechanism.into(),
        }
    }

    /// Serialize as a single CSV line (no header).
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.target,
            self.property,
            self.category,
            self.mode,
            self.seed,
            self.detected,
            self.first_hit_execs,
            self.time_to_first_hit_ms,
            self.total_execs,
            self.sequence_len,
            self.distinct_reproducer_hash,
            self.detection_mechanism,
        )
    }

    /// CSV header line.
    pub fn csv_header() -> &'static str {
        "target,property,category,mode,seed,detected,first_hit_execs,time_to_first_hit_ms,\
total_execs,sequence_len,distinct_reproducer_hash,detection_mechanism"
    }
}

// ---------------------------------------------------------------------------
// MultiSeedSummary
// ---------------------------------------------------------------------------

/// Aggregate statistics across multiple seeds for one (target, property) pair.
///
/// Used to distinguish "lucky on seed 42" from "robust across seeds".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSeedSummary {
    /// Target contract name.
    pub target: String,
    /// Property or invariant being tested.
    pub property: String,
    /// Bug class.
    pub category: String,
    /// Executor mode.
    pub mode: String,
    /// Total seeds attempted.
    pub seeds_run: usize,
    /// Number of seeds that produced a finding.
    pub seeds_hit: usize,
    /// Hit rate (0.0–1.0): `seeds_hit / seeds_run`.
    pub hit_rate: f64,
    /// Median executions to first hit across successful seeds.
    /// Zero if no seed hit.
    pub median_first_hit_execs: u64,
    /// Median wall-clock ms to first hit across successful seeds.
    /// Zero if no seed hit.
    pub median_time_ms: u64,
    /// Number of distinct reproducer hashes observed across all seeds.
    pub distinct_repros: usize,
    /// Minimum sequence length seen across successful seeds.
    pub min_sequence_len: usize,
    /// Maximum sequence length seen across successful seeds.
    pub max_sequence_len: usize,
}

impl MultiSeedSummary {
    /// CSV header for multi-seed summary rows.
    pub fn csv_header() -> &'static str {
        "target,property,category,mode,seeds_run,seeds_hit,hit_rate,\
median_first_hit_execs,median_time_ms,distinct_repros,min_seq_len,max_seq_len"
    }

    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{:.2},{},{},{},{},{}",
            self.target,
            self.property,
            self.category,
            self.mode,
            self.seeds_run,
            self.seeds_hit,
            self.hit_rate,
            self.median_first_hit_execs,
            self.median_time_ms,
            self.distinct_repros,
            self.min_sequence_len,
            self.max_sequence_len,
        )
    }

    /// Compute a summary from a slice of per-seed [`ScorecardEntry`]s that
    /// all share the same `(target, property, category, mode)` tuple.
    ///
    /// Panics if `entries` is empty.
    pub fn from_entries(entries: &[ScorecardEntry]) -> Self {
        assert!(!entries.is_empty(), "entries must be non-empty");

        let first = &entries[0];
        let seeds_run = entries.len();
        let seeds_hit = entries.iter().filter(|e| e.detected).count();
        let hit_rate = seeds_hit as f64 / seeds_run as f64;

        // Collect per-seed data only from hits.
        let mut hit_execs: Vec<u64> = entries
            .iter()
            .filter(|e| e.detected)
            .map(|e| e.first_hit_execs)
            .collect();
        let mut hit_times: Vec<u64> = entries
            .iter()
            .filter(|e| e.detected)
            .map(|e| e.time_to_first_hit_ms)
            .collect();
        let seq_lens: Vec<usize> = entries
            .iter()
            .filter(|e| e.detected)
            .map(|e| e.sequence_len)
            .collect();

        hit_execs.sort_unstable();
        hit_times.sort_unstable();

        let median_first_hit_execs = median_u64(&hit_execs);
        let median_time_ms = median_u64(&hit_times);
        let min_sequence_len = seq_lens.iter().copied().min().unwrap_or(0);
        let max_sequence_len = seq_lens.iter().copied().max().unwrap_or(0);

        let distinct_repros: std::collections::HashSet<u64> = entries
            .iter()
            .filter(|e| e.detected && e.distinct_reproducer_hash != 0)
            .map(|e| e.distinct_reproducer_hash)
            .collect();

        Self {
            target: first.target.clone(),
            property: first.property.clone(),
            category: first.category.clone(),
            mode: first.mode.clone(),
            seeds_run,
            seeds_hit,
            hit_rate,
            median_first_hit_execs,
            median_time_ms,
            distinct_repros: distinct_repros.len(),
            min_sequence_len,
            max_sequence_len,
        }
    }
}

/// Compute the median of a sorted slice.  Returns 0 for empty input.
fn median_u64(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

// ---------------------------------------------------------------------------
// Scoreboard
// ---------------------------------------------------------------------------

/// Collects scorecard entries, handles deduplication, and emits CSV output.
#[derive(Debug, Default)]
pub struct Scoreboard {
    entries: Vec<ScorecardEntry>,
    seen_hashes: HashSet<u64>,
}

impl Scoreboard {
    /// Create an empty scoreboard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry, skipping exact-duplicate detected findings.
    ///
    /// Two entries are considered duplicates when both have `detected = true`
    /// and share the same `distinct_reproducer_hash`.  `not_found` entries
    /// (hash == 0) are always kept so the full property matrix is preserved.
    pub fn add(&mut self, entry: ScorecardEntry) {
        if entry.detected && entry.distinct_reproducer_hash != 0 {
            if !self.seen_hashes.insert(entry.distinct_reproducer_hash) {
                return; // duplicate — discard
            }
        }
        self.entries.push(entry);
    }

    /// Write the scoreboard as CSV to `path` (creates or overwrites).
    pub fn write_csv(&self, path: &Path) -> crate::error::Result<()> {
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "{}", ScorecardEntry::csv_header()).unwrap();
        for entry in &self.entries {
            writeln!(out, "{}", entry.to_csv_row()).unwrap();
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Print the scoreboard as CSV to stderr for immediate inspection.
    pub fn print_csv(&self) {
        eprintln!("{}", ScorecardEntry::csv_header());
        for entry in &self.entries {
            eprintln!("{}", entry.to_csv_row());
        }
    }

    /// Print multi-seed summary rows for all unique (target, property) pairs.
    pub fn print_summary(&self) {
        // Group entries by (target, property).
        let mut groups: std::collections::HashMap<(String, String), Vec<&ScorecardEntry>> =
            std::collections::HashMap::new();
        for e in &self.entries {
            groups
                .entry((e.target.clone(), e.property.clone()))
                .or_default()
                .push(e);
        }

        eprintln!();
        eprintln!("{}", MultiSeedSummary::csv_header());
        let mut keys: Vec<_> = groups.keys().collect();
        keys.sort();
        for key in keys {
            let group_entries: Vec<ScorecardEntry> =
                groups[key].iter().map(|e| (*e).clone()).collect();
            let summary = MultiSeedSummary::from_entries(&group_entries);
            eprintln!("{}", summary.to_csv_row());
        }
    }

    /// Total number of entries (including `not_found` rows).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no entries have been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries where `detected == true`.
    pub fn detected_count(&self) -> usize {
        self.entries.iter().filter(|e| e.detected).count()
    }

    /// All entries (read-only).
    pub fn entries(&self) -> &[ScorecardEntry] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Finding, Severity};

    fn dummy_finding(title: &str, reproducer_len: usize) -> Finding {
        Finding {
            severity: Severity::High,
            title: title.into(),
            description: "test".into(),
            contract: Address::ZERO,
            reproducer: vec![crate::types::Transaction::default(); reproducer_len],
            exploit_profit: None,
        }
    }

    #[test]
    fn scoreboard_csv_header_has_correct_columns() {
        let header = ScorecardEntry::csv_header();
        // The header contains a line-continuation backslash in the source —
        // the actual string has no newline, just a continuous line.
        // Split on commas and count.
        let cols: Vec<&str> = header.split(',').collect();
        assert_eq!(
            cols.len(),
            12,
            "header must have exactly 12 columns, got: {header}"
        );
        assert_eq!(cols[0], "target");
        assert_eq!(cols[1], "property");
        assert_eq!(cols[2], "category");
        assert_eq!(cols[3], "mode");
        assert_eq!(cols[4], "seed");
        assert_eq!(cols[5], "detected");
        assert_eq!(cols[6], "first_hit_execs");
        assert_eq!(cols[7], "time_to_first_hit_ms");
        assert_eq!(cols[8], "total_execs");
        assert_eq!(cols[9], "sequence_len");
        assert_eq!(cols[10], "distinct_reproducer_hash");
        assert_eq!(cols[11], "detection_mechanism");
    }

    #[test]
    fn scorecard_entry_csv_row_column_count() {
        let entry = ScorecardEntry::not_found("T", "P", "C", "fast", 7, 42);
        let row = entry.to_csv_row();
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(cols.len(), 12, "CSV row must have 12 columns, got: {row}");
    }

    #[test]
    fn found_entry_has_detection_mechanism() {
        let f = dummy_finding("some_property_violated", 3);
        let entry = ScorecardEntry::found(
            "Vault",
            "echidna_no_drain",
            "PropertyViolation",
            "fast",
            42,
            100,   // first_hit_execs
            0,     // time_ms
            10000, // total_execs
            &f,
            "EchidnaPropertyCaller",
        );
        assert_eq!(entry.first_hit_execs, 100);
        assert_eq!(entry.detection_mechanism, "EchidnaPropertyCaller");
        assert!(entry.detected);
    }

    #[test]
    fn not_found_entry_has_empty_mechanism() {
        let entry = ScorecardEntry::not_found("T", "P", "C", "fast", 0, 500);
        assert_eq!(entry.detection_mechanism, "");
        assert!(!entry.detected);
        assert_eq!(entry.first_hit_execs, 0);
    }

    #[test]
    fn scoreboard_deduplicates_by_hash() {
        let mut board = Scoreboard::new();
        let f = dummy_finding("drain", 3);

        let e1 = ScorecardEntry::found("V", "p", "c", "fast", 1, 100, 0, 1000, &f, "Oracle");
        let e2 = ScorecardEntry::found("V", "p", "c", "fast", 2, 200, 0, 2000, &f, "Oracle");
        assert_eq!(e1.distinct_reproducer_hash, e2.distinct_reproducer_hash);

        board.add(e1);
        board.add(e2); // should be dropped

        assert_eq!(board.len(), 1);
        assert_eq!(board.detected_count(), 1);
    }

    #[test]
    fn scoreboard_keeps_all_not_found() {
        let mut board = Scoreboard::new();
        for seed in 0..5u64 {
            board.add(ScorecardEntry::not_found("T", "P", "C", "fast", seed, 100));
        }
        assert_eq!(board.len(), 5, "all not_found rows must be retained");
        assert_eq!(board.detected_count(), 0);
    }

    #[test]
    fn scoreboard_write_csv_row_count() {
        let mut board = Scoreboard::new();
        let f1 = dummy_finding("overflow", 2);
        let f2 = dummy_finding("drain", 1);

        board.add(ScorecardEntry::found(
            "Token",
            "echidna_ok",
            "arithmetic",
            "fast",
            0,
            10,
            0,
            100,
            &f1,
            "EchidnaPropertyCaller",
        ));
        board.add(ScorecardEntry::found(
            "Vault",
            "balance_ok",
            "economic",
            "fast",
            0,
            20,
            0,
            200,
            &f2,
            "BalanceIncrease",
        ));
        board.add(ScorecardEntry::not_found(
            "Pool", "price_ok", "oracle", "fast", 0, 300,
        ));

        let tmp = tempfile::NamedTempFile::new().unwrap();
        board.write_csv(tmp.path()).unwrap();

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4, "1 header + 3 data rows");
        assert!(lines[0].contains("first_hit_execs"));
        assert!(lines[0].contains("detection_mechanism"));
        assert!(lines[1].contains("Token"));
        assert!(lines[3].contains("false"));
    }

    #[test]
    fn multi_seed_summary_hit_rate_and_median() {
        let f = dummy_finding("violation", 2);

        let entries = vec![
            ScorecardEntry::found("T", "P", "C", "fast", 0, 100, 10, 1000, &f, "Mech"),
            ScorecardEntry::found("T", "P", "C", "fast", 1, 300, 30, 1000, &f, "Mech"),
            ScorecardEntry::not_found("T", "P", "C", "fast", 2, 1000),
            ScorecardEntry::found("T", "P", "C", "fast", 3, 200, 20, 1000, &f, "Mech"),
            ScorecardEntry::not_found("T", "P", "C", "fast", 4, 1000),
        ];

        // Note: all found entries share the same hash, so the Scoreboard
        // would deduplicate — but MultiSeedSummary works on raw slices.
        let summary = MultiSeedSummary::from_entries(&entries);

        assert_eq!(summary.seeds_run, 5);
        assert_eq!(summary.seeds_hit, 3);
        assert!((summary.hit_rate - 0.6).abs() < 1e-9);

        // Sorted first_hit_execs of hits: [100, 200, 300] → median = 200
        assert_eq!(summary.median_first_hit_execs, 200);

        // Sorted times: [10, 20, 30] → median = 20
        assert_eq!(summary.median_time_ms, 20);
    }

    #[test]
    fn median_u64_edge_cases() {
        assert_eq!(median_u64(&[]), 0);
        assert_eq!(median_u64(&[7]), 7);
        assert_eq!(median_u64(&[3, 7]), 5);
        assert_eq!(median_u64(&[1, 2, 3, 4, 5]), 3);
        assert_eq!(median_u64(&[1, 2, 4, 5]), 3);
    }

    #[test]
    fn multi_seed_summary_csv_header_column_count() {
        let cols: Vec<&str> = MultiSeedSummary::csv_header().split(',').collect();
        assert_eq!(cols.len(), 12, "summary header must have 12 columns");
    }
}
