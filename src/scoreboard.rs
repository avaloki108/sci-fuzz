//! Benchmark scoreboard — machine-readable evidence rows and summaries.
//!
//! The scoreboard records one row per `(engine, target, property, seed)` run
//! and emits both raw results and grouped multi-seed summaries.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::types::Finding;

/// Engine that produced a benchmark row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkEngine {
    SciFuzz,
    Echidna,
    Forge,
}

impl std::fmt::Display for BenchmarkEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SciFuzz => write!(f, "sci-fuzz"),
            Self::Echidna => write!(f, "echidna"),
            Self::Forge => write!(f, "forge"),
        }
    }
}

/// Status of a benchmark row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkStatus {
    Measured,
    Unavailable,
    Failed,
    Skipped,
}

impl std::fmt::Display for BenchmarkStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Measured => write!(f, "measured"),
            Self::Unavailable => write!(f, "unavailable"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// One machine-readable benchmark result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorecardEntry {
    pub target: String,
    pub property: String,
    pub category: String,
    pub mode: String,
    pub seed: u64,
    pub found: bool,
    pub first_hit_execs: Option<u64>,
    pub first_hit_time_ms: Option<u64>,
    pub total_execs: u64,
    pub elapsed_ms: u64,
    pub repro_len_raw: Option<usize>,
    pub repro_len_shrunk: Option<usize>,
    pub finding_count: usize,
    pub deduped_finding_count: usize,
    pub engine: BenchmarkEngine,
    pub status: BenchmarkStatus,
    pub detection_mechanism: Option<String>,
    pub error: Option<String>,
}

impl ScorecardEntry {
    /// Stable CSV header for raw benchmark results.
    pub fn csv_header() -> &'static str {
        "target,property,category,mode,seed,found,first_hit_execs,first_hit_time_ms,total_execs,\
elapsed_ms,repro_len_raw,repro_len_shrunk,finding_count,deduped_finding_count,engine,status,\
detection_mechanism,error"
    }

    /// Legacy helper used by existing tests: sci-fuzz measured miss.
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
            found: false,
            first_hit_execs: None,
            first_hit_time_ms: None,
            total_execs,
            elapsed_ms: 0,
            repro_len_raw: None,
            repro_len_shrunk: None,
            finding_count: 0,
            deduped_finding_count: 0,
            engine: BenchmarkEngine::SciFuzz,
            status: BenchmarkStatus::Measured,
            detection_mechanism: None,
            error: None,
        }
    }

    /// Legacy helper used by existing tests: sci-fuzz measured hit.
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
            found: true,
            first_hit_execs: Some(first_hit_execs),
            first_hit_time_ms: Some(time_ms),
            total_execs,
            elapsed_ms: time_ms,
            repro_len_raw: Some(finding.reproducer.len()),
            repro_len_shrunk: Some(finding.reproducer.len()),
            finding_count: 1,
            deduped_finding_count: 1,
            engine: BenchmarkEngine::SciFuzz,
            status: BenchmarkStatus::Measured,
            detection_mechanism: Some(detection_mechanism.into()),
            error: None,
        }
    }

    /// Fully-specified measured row.
    #[allow(clippy::too_many_arguments)]
    pub fn measured(
        target: &str,
        property: &str,
        category: &str,
        mode: &str,
        seed: u64,
        found: bool,
        first_hit_execs: Option<u64>,
        first_hit_time_ms: Option<u64>,
        total_execs: u64,
        elapsed_ms: u64,
        repro_len_raw: Option<usize>,
        repro_len_shrunk: Option<usize>,
        finding_count: usize,
        deduped_finding_count: usize,
        engine: BenchmarkEngine,
        detection_mechanism: Option<String>,
    ) -> Self {
        Self {
            target: target.into(),
            property: property.into(),
            category: category.into(),
            mode: mode.into(),
            seed,
            found,
            first_hit_execs,
            first_hit_time_ms,
            total_execs,
            elapsed_ms,
            repro_len_raw,
            repro_len_shrunk,
            finding_count,
            deduped_finding_count,
            engine,
            status: BenchmarkStatus::Measured,
            detection_mechanism,
            error: None,
        }
    }

    /// Build a non-measured row for unavailable / failed / skipped cases.
    pub fn with_status(
        target: &str,
        property: &str,
        category: &str,
        mode: &str,
        seed: u64,
        engine: BenchmarkEngine,
        status: BenchmarkStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            property: property.into(),
            category: category.into(),
            mode: mode.into(),
            seed,
            found: false,
            first_hit_execs: None,
            first_hit_time_ms: None,
            total_execs: 0,
            elapsed_ms: 0,
            repro_len_raw: None,
            repro_len_shrunk: None,
            finding_count: 0,
            deduped_finding_count: 0,
            engine,
            status,
            detection_mechanism: None,
            error: Some(message.into()),
        }
    }

    /// Serialize as one CSV line (without header).
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.target,
            self.property,
            self.category,
            self.mode,
            self.seed,
            self.found,
            csv_opt(self.first_hit_execs),
            csv_opt(self.first_hit_time_ms),
            self.total_execs,
            self.elapsed_ms,
            csv_opt(self.repro_len_raw),
            csv_opt(self.repro_len_shrunk),
            self.finding_count,
            self.deduped_finding_count,
            self.engine,
            self.status,
            self.detection_mechanism.as_deref().unwrap_or_default(),
            self.error.as_deref().unwrap_or_default(),
        )
    }
}

/// Aggregated statistics across multiple runs for one
/// `(target, property, category, mode, engine)` group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSeedSummary {
    pub target: String,
    pub property: String,
    pub category: String,
    pub mode: String,
    pub engine: BenchmarkEngine,
    pub total_runs: usize,
    pub measured_runs: usize,
    pub found_runs: usize,
    pub hit_rate: f64,
    pub median_first_hit_execs: Option<u64>,
    pub median_first_hit_time_ms: Option<u64>,
    pub median_elapsed_ms: u64,
    pub median_repro_len_shrunk: Option<usize>,
    pub unavailable_runs: usize,
    pub failed_runs: usize,
    pub skipped_runs: usize,
}

impl MultiSeedSummary {
    pub fn csv_header() -> &'static str {
        "target,property,category,mode,engine,total_runs,measured_runs,found_runs,hit_rate,\
median_first_hit_execs,median_first_hit_time_ms,median_elapsed_ms,median_repro_len_shrunk,\
unavailable_runs,failed_runs,skipped_runs"
    }

    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{:.2},{},{},{},{},{},{},{}",
            self.target,
            self.property,
            self.category,
            self.mode,
            self.engine,
            self.total_runs,
            self.measured_runs,
            self.found_runs,
            self.hit_rate,
            csv_opt(self.median_first_hit_execs),
            csv_opt(self.median_first_hit_time_ms),
            self.median_elapsed_ms,
            csv_opt(self.median_repro_len_shrunk),
            self.unavailable_runs,
            self.failed_runs,
            self.skipped_runs,
        )
    }

    pub fn from_entries(entries: &[ScorecardEntry]) -> Self {
        assert!(!entries.is_empty(), "entries must be non-empty");

        let first = &entries[0];
        let total_runs = entries.len();
        let measured_rows: Vec<&ScorecardEntry> = entries
            .iter()
            .filter(|entry| entry.status == BenchmarkStatus::Measured)
            .collect();
        let measured_runs = measured_rows.len();
        let found_rows: Vec<&ScorecardEntry> = measured_rows
            .iter()
            .copied()
            .filter(|entry| entry.found)
            .collect();
        let found_runs = found_rows.len();
        let hit_rate = if measured_runs == 0 {
            0.0
        } else {
            found_runs as f64 / measured_runs as f64
        };

        let mut first_hit_execs: Vec<u64> = found_rows
            .iter()
            .filter_map(|entry| entry.first_hit_execs)
            .collect();
        let mut first_hit_time_ms: Vec<u64> = found_rows
            .iter()
            .filter_map(|entry| entry.first_hit_time_ms)
            .collect();
        let mut elapsed_ms: Vec<u64> = measured_rows.iter().map(|entry| entry.elapsed_ms).collect();
        let mut repro_len_shrunk: Vec<usize> = found_rows
            .iter()
            .filter_map(|entry| entry.repro_len_shrunk)
            .collect();

        first_hit_execs.sort_unstable();
        first_hit_time_ms.sort_unstable();
        elapsed_ms.sort_unstable();
        repro_len_shrunk.sort_unstable();

        Self {
            target: first.target.clone(),
            property: first.property.clone(),
            category: first.category.clone(),
            mode: first.mode.clone(),
            engine: first.engine,
            total_runs,
            measured_runs,
            found_runs,
            hit_rate,
            median_first_hit_execs: median_u64_opt(&first_hit_execs),
            median_first_hit_time_ms: median_u64_opt(&first_hit_time_ms),
            median_elapsed_ms: median_u64(&elapsed_ms),
            median_repro_len_shrunk: median_usize_opt(&repro_len_shrunk),
            unavailable_runs: entries
                .iter()
                .filter(|entry| entry.status == BenchmarkStatus::Unavailable)
                .count(),
            failed_runs: entries
                .iter()
                .filter(|entry| entry.status == BenchmarkStatus::Failed)
                .count(),
            skipped_runs: entries
                .iter()
                .filter(|entry| entry.status == BenchmarkStatus::Skipped)
                .count(),
        }
    }
}

fn csv_opt<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

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

fn median_u64_opt(sorted: &[u64]) -> Option<u64> {
    if sorted.is_empty() {
        None
    } else {
        Some(median_u64(sorted))
    }
}

fn median_usize_opt(sorted: &[usize]) -> Option<usize> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    if n % 2 == 1 {
        Some(sorted[n / 2])
    } else {
        Some((sorted[n / 2 - 1] + sorted[n / 2]) / 2)
    }
}

/// Collects raw benchmark rows and emits both raw and summary artifacts.
#[derive(Debug, Default)]
pub struct Scoreboard {
    entries: Vec<ScorecardEntry>,
}

impl Scoreboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: ScorecardEntry) {
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn detected_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.status == BenchmarkStatus::Measured && entry.found)
            .count()
    }

    pub fn entries(&self) -> &[ScorecardEntry] {
        &self.entries
    }

    pub fn summary_rows(&self) -> Vec<MultiSeedSummary> {
        let mut groups: HashMap<
            (String, String, String, String, BenchmarkEngine),
            Vec<ScorecardEntry>,
        > = HashMap::new();
        for entry in &self.entries {
            groups
                .entry((
                    entry.target.clone(),
                    entry.property.clone(),
                    entry.category.clone(),
                    entry.mode.clone(),
                    entry.engine,
                ))
                .or_default()
                .push(entry.clone());
        }

        let mut summaries: Vec<MultiSeedSummary> = groups
            .into_values()
            .map(|entries| MultiSeedSummary::from_entries(&entries))
            .collect();
        summaries.sort_by(|a, b| {
            (
                a.target.as_str(),
                a.property.as_str(),
                a.category.as_str(),
                a.mode.as_str(),
                a.engine.to_string(),
            )
                .cmp(&(
                    b.target.as_str(),
                    b.property.as_str(),
                    b.category.as_str(),
                    b.mode.as_str(),
                    b.engine.to_string(),
                ))
        });
        summaries
    }

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

    pub fn write_json(&self, path: &Path) -> crate::error::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(&self.entries)?)?;
        Ok(())
    }

    pub fn write_summary_csv(&self, path: &Path) -> crate::error::Result<()> {
        use std::fmt::Write as _;
        let summaries = self.summary_rows();
        let mut out = String::new();
        writeln!(out, "{}", MultiSeedSummary::csv_header()).unwrap();
        for summary in &summaries {
            writeln!(out, "{}", summary.to_csv_row()).unwrap();
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    pub fn write_summary_json(&self, path: &Path) -> crate::error::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(&self.summary_rows())?)?;
        Ok(())
    }

    pub fn print_csv(&self) {
        eprintln!("{}", ScorecardEntry::csv_header());
        for entry in &self.entries {
            eprintln!("{}", entry.to_csv_row());
        }
    }

    pub fn print_summary(&self) {
        eprintln!("{}", MultiSeedSummary::csv_header());
        for summary in self.summary_rows() {
            eprintln!("{}", summary.to_csv_row());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Finding, Severity, Transaction};

    fn dummy_finding(title: &str, reproducer_len: usize) -> Finding {
        Finding {
            severity: Severity::High,
            title: title.into(),
            description: "test".into(),
            contract: Address::ZERO,
            reproducer: vec![Transaction::default(); reproducer_len],
            exploit_profit: None,
        }
    }

    #[test]
    fn scoreboard_csv_header_has_required_columns() {
        let cols: Vec<&str> = ScorecardEntry::csv_header().split(',').collect();
        assert_eq!(cols.len(), 18);
        assert!(cols.contains(&"engine"));
        assert!(cols.contains(&"status"));
        assert!(cols.contains(&"repro_len_shrunk"));
    }

    #[test]
    fn scorecard_entry_csv_row_column_count() {
        let entry = ScorecardEntry::not_found("T", "P", "C", "fast", 7, 42);
        let row = entry.to_csv_row();
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(cols.len(), 18);
    }

    #[test]
    fn scorecard_entry_json_roundtrip_preserves_schema() {
        let finding = dummy_finding("violation", 3);
        let entry = ScorecardEntry::found(
            "Vault",
            "echidna_ok",
            "PropertyViolation",
            "fast",
            42,
            100,
            12,
            1000,
            &finding,
            "EchidnaPropertyCaller",
        );

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"engine\":\"sci-fuzz\""));
        assert!(json.contains("\"status\":\"measured\""));
        let roundtrip: ScorecardEntry = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.found);
        assert_eq!(roundtrip.repro_len_shrunk, Some(3));
    }

    #[test]
    fn scoreboard_keeps_all_rows() {
        let mut board = Scoreboard::new();
        let finding = dummy_finding("drain", 2);
        board.add(ScorecardEntry::found(
            "V", "p", "c", "fast", 1, 100, 1, 1000, &finding, "Oracle",
        ));
        board.add(ScorecardEntry::found(
            "V", "p", "c", "fast", 2, 200, 2, 2000, &finding, "Oracle",
        ));
        assert_eq!(board.len(), 2);
        assert_eq!(board.detected_count(), 2);
    }

    #[test]
    fn write_csv_and_json_emit_stable_artifacts() {
        let mut board = Scoreboard::new();
        board.add(ScorecardEntry::not_found(
            "Pool", "price_ok", "oracle", "fast", 0, 300,
        ));
        board.add(ScorecardEntry::with_status(
            "Pool",
            "price_ok",
            "oracle",
            "fast",
            1,
            BenchmarkEngine::Echidna,
            BenchmarkStatus::Unavailable,
            "echidna not installed",
        ));

        let csv = tempfile::NamedTempFile::new().unwrap();
        let json = tempfile::NamedTempFile::new().unwrap();
        board.write_csv(csv.path()).unwrap();
        board.write_json(json.path()).unwrap();

        let csv_text = std::fs::read_to_string(csv.path()).unwrap();
        assert!(csv_text.contains("engine,status"));
        let json_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(json.path()).unwrap()).unwrap();
        assert_eq!(json_value.as_array().unwrap().len(), 2);
    }

    #[test]
    fn multi_seed_summary_aggregates_hit_rate_and_repro_length() {
        let entries = vec![
            ScorecardEntry::measured(
                "T",
                "P",
                "C",
                "fast",
                0,
                true,
                Some(100),
                Some(10),
                1000,
                25,
                Some(5),
                Some(3),
                2,
                1,
                BenchmarkEngine::SciFuzz,
                Some("oracle".into()),
            ),
            ScorecardEntry::measured(
                "T",
                "P",
                "C",
                "fast",
                1,
                false,
                None,
                None,
                1000,
                30,
                None,
                None,
                0,
                0,
                BenchmarkEngine::SciFuzz,
                None,
            ),
            ScorecardEntry::measured(
                "T",
                "P",
                "C",
                "fast",
                2,
                true,
                Some(300),
                Some(30),
                1000,
                35,
                Some(7),
                Some(5),
                1,
                1,
                BenchmarkEngine::SciFuzz,
                Some("oracle".into()),
            ),
        ];

        let summary = MultiSeedSummary::from_entries(&entries);
        assert_eq!(summary.total_runs, 3);
        assert_eq!(summary.measured_runs, 3);
        assert_eq!(summary.found_runs, 2);
        assert!((summary.hit_rate - (2.0 / 3.0)).abs() < 1e-9);
        assert_eq!(summary.median_first_hit_execs, Some(200));
        assert_eq!(summary.median_first_hit_time_ms, Some(20));
        assert_eq!(summary.median_repro_len_shrunk, Some(4));
    }

    #[test]
    fn summary_rows_group_by_engine_and_target() {
        let mut board = Scoreboard::new();
        board.add(ScorecardEntry::not_found("T", "P", "C", "fast", 0, 10));
        board.add(ScorecardEntry::with_status(
            "T",
            "P",
            "C",
            "fast",
            0,
            BenchmarkEngine::Echidna,
            BenchmarkStatus::Unavailable,
            "missing",
        ));

        let summaries = board.summary_rows();
        assert_eq!(summaries.len(), 2);
        assert!(summaries
            .iter()
            .any(|summary| summary.engine == BenchmarkEngine::SciFuzz));
        assert!(summaries
            .iter()
            .any(|summary| summary.engine == BenchmarkEngine::Echidna));
    }
}
