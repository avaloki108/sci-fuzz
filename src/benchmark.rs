//! Benchmark and comparison pipeline for sci-fuzz.
//!
//! This module provides:
//! - reusable benchmark case definitions for compiled and Foundry targets
//! - a first-class sci-fuzz benchmark runner
//! - comparison scaffolding for Echidna / Forge that degrades gracefully
//! - stable CSV / JSON artifact emission through [`crate::scoreboard`]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::campaign::{Campaign, CampaignFindingRecord};
use crate::project::Project;
use crate::scoreboard::{BenchmarkEngine, BenchmarkStatus, Scoreboard, ScorecardEntry};
use crate::types::{CampaignConfig, ContractInfo, Severity};

/// How a benchmark case decides whether a run "found" the expected issue.
#[derive(Debug, Clone)]
pub enum FindingMatcher {
    AnyFinding,
    TitleContains(String),
    SeverityAtLeast(Severity),
    FailureId(String),
}

impl FindingMatcher {
    fn matches(&self, record: &CampaignFindingRecord) -> bool {
        match self {
            Self::AnyFinding => true,
            Self::TitleContains(needle) => record.finding.title.contains(needle),
            Self::SeverityAtLeast(min) => record.finding.severity >= *min,
            Self::FailureId(expected) => record.finding.failure_id() == *expected,
        }
    }
}

/// One prepared benchmark case.
#[derive(Debug, Clone)]
pub struct BenchmarkCase {
    pub target: String,
    pub property: String,
    pub category: String,
    pub mode: String,
    pub max_depth: u32,
    pub timeout: Duration,
    pub max_execs: Option<u64>,
    pub targets: Vec<ContractInfo>,
    pub matcher: FindingMatcher,
    pub detection_mechanism: Option<String>,
    pub project_root: Option<PathBuf>,
}

impl BenchmarkCase {
    pub fn new(
        target: impl Into<String>,
        property: impl Into<String>,
        category: impl Into<String>,
        targets: Vec<ContractInfo>,
    ) -> Self {
        Self {
            target: target.into(),
            property: property.into(),
            category: category.into(),
            mode: "fast".into(),
            max_depth: 8,
            timeout: Duration::from_secs(10),
            max_execs: None,
            targets,
            matcher: FindingMatcher::AnyFinding,
            detection_mechanism: None,
            project_root: None,
        }
    }

    pub fn with_matcher(mut self, matcher: FindingMatcher) -> Self {
        self.matcher = matcher;
        self
    }

    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    pub fn with_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_execs(mut self, max_execs: Option<u64>) -> Self {
        self.max_execs = max_execs;
        self
    }

    pub fn with_detection_mechanism(mut self, mechanism: impl Into<String>) -> Self {
        self.detection_mechanism = Some(mechanism.into());
        self
    }

    pub fn with_project_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.project_root = Some(root.into());
        self
    }
}

/// A benchmark plan entry that can either run or report why it was skipped.
#[derive(Debug, Clone)]
pub enum BenchmarkPlanEntry {
    Ready(BenchmarkCase),
    Unavailable {
        target: String,
        property: String,
        category: String,
        mode: String,
        reason: String,
    },
}

impl BenchmarkPlanEntry {
    fn unavailable_row(
        &self,
        engine: BenchmarkEngine,
        seed: u64,
        status: BenchmarkStatus,
    ) -> ScorecardEntry {
        match self {
            Self::Ready(case) => ScorecardEntry::with_status(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                engine,
                status,
                "comparison adapter unavailable",
            ),
            Self::Unavailable {
                target,
                property,
                category,
                mode,
                reason,
            } => ScorecardEntry::with_status(
                target,
                property,
                category,
                mode,
                seed,
                engine,
                status,
                reason.clone(),
            ),
        }
    }
}

/// Run a set of benchmark cases across multiple seeds and engines.
pub fn run_benchmark_plan(
    plan: &[BenchmarkPlanEntry],
    seeds: &[u64],
    engines: &[BenchmarkEngine],
) -> Scoreboard {
    let mut board = Scoreboard::new();

    for entry in plan {
        for &seed in seeds {
            for &engine in engines {
                let row = match (entry, engine) {
                    (BenchmarkPlanEntry::Ready(case), BenchmarkEngine::SciFuzz) => {
                        run_sci_fuzz_case(case, seed)
                    }
                    (BenchmarkPlanEntry::Ready(case), BenchmarkEngine::Echidna) => {
                        ExternalComparisonAdapter::echidna().run_case(case, seed)
                    }
                    (BenchmarkPlanEntry::Ready(case), BenchmarkEngine::Forge) => {
                        ExternalComparisonAdapter::forge().run_case(case, seed)
                    }
                    (BenchmarkPlanEntry::Unavailable { .. }, _) => {
                        entry.unavailable_row(engine, seed, BenchmarkStatus::Skipped)
                    }
                };
                board.add(row);
            }
        }
    }

    board
}

/// Write raw and summary artifacts into `output_dir`.
pub fn write_benchmark_artifacts(board: &Scoreboard, output_dir: &Path) -> crate::Result<()> {
    std::fs::create_dir_all(output_dir)?;
    board.write_csv(&output_dir.join("benchmark_results.csv"))?;
    board.write_json(&output_dir.join("benchmark_results.json"))?;
    board.write_summary_csv(&output_dir.join("benchmark_summary.csv"))?;
    board.write_summary_json(&output_dir.join("benchmark_summary.json"))?;
    Ok(())
}

/// Build benchmark cases from a Foundry project's selected targets.
pub fn plan_for_foundry_project(
    root: impl AsRef<Path>,
    target_name: Option<&str>,
    property: &str,
    category: &str,
    timeout: Duration,
    max_depth: u32,
    max_execs: Option<u64>,
) -> crate::Result<Vec<BenchmarkPlanEntry>> {
    let root = root.as_ref().to_path_buf();
    let (_project, bootstrap, _artifact_count) = Project::build_and_select_targets(&root)?;
    let mut cases = Vec::new();

    for target in bootstrap.runtime_targets {
        let target_matches = target_name
            .map(|needle| target.name.as_deref() == Some(needle))
            .unwrap_or(true);
        if !target_matches {
            continue;
        }

        let display_name = target
            .name
            .clone()
            .unwrap_or_else(|| format!("{}", target.address));
        cases.push(BenchmarkPlanEntry::Ready(
            BenchmarkCase::new(display_name, property, category, vec![target])
                .with_timeout(timeout)
                .with_depth(max_depth)
                .with_max_execs(max_execs)
                .with_matcher(FindingMatcher::AnyFinding)
                .with_detection_mechanism("campaign")
                .with_project_root(root.clone()),
        ));
    }

    if cases.is_empty() {
        return Err(crate::Error::Project(
            "No matching Foundry benchmark targets selected".into(),
        ));
    }

    Ok(cases)
}

/// Built-in shared-target benchmark preset over EF/CF compiled fixtures.
pub fn efcf_demo_plan(
    timeout: Duration,
    max_depth: u32,
    max_execs: Option<u64>,
) -> Vec<BenchmarkPlanEntry> {
    [
        (
            "harvey_baz",
            "echidna_all_states",
            "PropertyViolation",
            FindingMatcher::TitleContains("echidna_all_states".into()),
            "EchidnaPropertyCaller",
        ),
        (
            "SimpleDAO",
            "BalanceIncrease",
            "Reentrancy",
            FindingMatcher::SeverityAtLeast(Severity::Critical),
            "BalanceIncrease",
        ),
        (
            "Delegatecall",
            "campaign",
            "AccessControl",
            FindingMatcher::AnyFinding,
            "campaign",
        ),
    ]
    .into_iter()
    .map(|(name, property, category, matcher, mechanism)| {
        match load_compiled_fixture_case(
            name, property, category, matcher, timeout, max_depth, max_execs, mechanism,
        ) {
            Ok(case) => BenchmarkPlanEntry::Ready(case),
            Err(err) => BenchmarkPlanEntry::Unavailable {
                target: name.into(),
                property: property.into(),
                category: category.into(),
                mode: "fast".into(),
                reason: err.to_string(),
            },
        }
    })
    .collect()
}

fn run_sci_fuzz_case(case: &BenchmarkCase, seed: u64) -> ScorecardEntry {
    let config = CampaignConfig {
        timeout: case.timeout,
        max_execs: case.max_execs,
        max_depth: case.max_depth,
        max_snapshots: 256,
        workers: 1,
        seed,
        targets: case.targets.clone(),
        harness: None,
        mode: crate::types::ExecutorMode::Fast,
        rpc_url: None,
        rpc_block_number: None,
        attacker_address: None,
        ..Default::default()
    };

    let mut campaign = Campaign::new(config);
    match campaign.run_with_report() {
        Ok(report) => {
            let matched = report
                .findings
                .iter()
                .find(|record| case.matcher.matches(record));
            let found = matched.is_some();

            ScorecardEntry::measured(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                found,
                matched.map(|record| record.first_observed_execs),
                matched.map(|record| record.first_observed_time_ms),
                report.total_execs,
                report.elapsed_ms,
                matched.map(|record| record.raw_reproducer_len),
                matched.map(|record| record.finding.reproducer.len()),
                report.finding_count,
                report.deduped_finding_count,
                BenchmarkEngine::SciFuzz,
                case.detection_mechanism.clone(),
            )
        }
        Err(err) => ScorecardEntry::with_status(
            &case.target,
            &case.property,
            &case.category,
            &case.mode,
            seed,
            BenchmarkEngine::SciFuzz,
            BenchmarkStatus::Failed,
            err.to_string(),
        ),
    }
}

fn load_compiled_fixture_case(
    name: &str,
    property: &str,
    category: &str,
    matcher: FindingMatcher,
    timeout: Duration,
    max_depth: u32,
    max_execs: Option<u64>,
    mechanism: &str,
) -> crate::Result<BenchmarkCase> {
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("efcf-compiled");
    let bin_path = fixture_root.join(format!("{name}.bin"));
    if !bin_path.exists() {
        return Err(crate::Error::Project(format!(
            "Compiled fixture missing: {}",
            bin_path.display()
        )));
    }

    let bin_hex = std::fs::read_to_string(&bin_path)?;
    let creation_bytecode = hex::decode(bin_hex.trim())?;
    let abi_path = fixture_root.join(format!("{name}.abi"));
    let abi = if abi_path.exists() {
        Some(serde_json::from_str(&std::fs::read_to_string(&abi_path)?)?)
    } else {
        None
    };

    Ok(BenchmarkCase::new(
        name,
        property,
        category,
        vec![ContractInfo {
            address: alloy_primitives::Address::ZERO,
            deployed_bytecode: alloy_primitives::Bytes::from(creation_bytecode.clone()),
            creation_bytecode: Some(alloy_primitives::Bytes::from(creation_bytecode)),
            name: Some(name.into()),
            source_path: None,
            deployed_source_map: None,
            source_file_list: vec![],
            abi,
            link_references: Default::default(),
        }],
    )
    .with_timeout(timeout)
    .with_depth(max_depth)
    .with_max_execs(max_execs)
    .with_matcher(matcher)
    .with_detection_mechanism(mechanism))
}

#[derive(Debug, Clone)]
struct ExternalComparisonAdapter {
    engine: BenchmarkEngine,
    binary: &'static str,
}

impl ExternalComparisonAdapter {
    fn echidna() -> Self {
        Self {
            engine: BenchmarkEngine::Echidna,
            binary: "echidna",
        }
    }

    fn forge() -> Self {
        Self {
            engine: BenchmarkEngine::Forge,
            binary: "forge",
        }
    }

    fn run_case(&self, case: &BenchmarkCase, seed: u64) -> ScorecardEntry {
        if !binary_available(self.binary) {
            return ScorecardEntry::with_status(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                self.engine,
                BenchmarkStatus::Unavailable,
                format!("{} binary not found on PATH", self.binary),
            );
        }

        match self.engine {
            BenchmarkEngine::Forge => run_forge_comparison_case(self.binary, case, seed),
            BenchmarkEngine::Echidna => ScorecardEntry::with_status(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                self.engine,
                BenchmarkStatus::Skipped,
                "echidna adapter currently supports no benchmark case format in this pipeline",
            ),
            BenchmarkEngine::SciFuzz => ScorecardEntry::with_status(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                self.engine,
                BenchmarkStatus::Skipped,
                "invalid external adapter engine",
            ),
        }
    }
}

fn binary_available(binary: impl AsRef<OsStr>) -> bool {
    Command::new(binary).arg("--version").output().is_ok()
}

fn run_forge_comparison_case(binary: &str, case: &BenchmarkCase, seed: u64) -> ScorecardEntry {
    let Some(project_root) = &case.project_root else {
        return ScorecardEntry::with_status(
            &case.target,
            &case.property,
            &case.category,
            &case.mode,
            seed,
            BenchmarkEngine::Forge,
            BenchmarkStatus::Skipped,
            "forge adapter requires a Foundry project case with project_root",
        );
    };

    let run_ctx = match prepare_forge_run_context(case, project_root) {
        Ok(ctx) => ctx,
        Err(err) => {
            return ScorecardEntry::with_status(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                BenchmarkEngine::Forge,
                BenchmarkStatus::Failed,
                err,
            );
        }
    };

    let started = std::time::Instant::now();
    let output = run_forge_command(binary, &run_ctx, seed);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match output {
        Ok(output) => {
            if let Err(err) = std::fs::write(&run_ctx.stdout_path, &output.stdout) {
                tracing::warn!(
                    "[benchmark] failed to write forge stdout {}: {err}",
                    run_ctx.stdout_path.display()
                );
            }
            if let Err(err) = std::fs::write(&run_ctx.stderr_path, &output.stderr) {
                tracing::warn!(
                    "[benchmark] failed to write forge stderr {}: {err}",
                    run_ctx.stderr_path.display()
                );
            }

            let summary =
                parse_forge_result_summary(&output.stdout, &output.stderr, output.success);
            ScorecardEntry::measured(
                &case.target,
                &case.property,
                &case.category,
                &case.mode,
                seed,
                summary.found,
                None,
                None,
                0,
                elapsed_ms,
                None,
                None,
                summary.failed_count.unwrap_or(0),
                summary.failed_count.unwrap_or(0),
                BenchmarkEngine::Forge,
                Some("forge-test-failure-count".into()),
            )
        }
        Err(err) => ScorecardEntry::with_status(
            &case.target,
            &case.property,
            &case.category,
            &case.mode,
            seed,
            BenchmarkEngine::Forge,
            BenchmarkStatus::Failed,
            format!("forge execution failed: {err}"),
        ),
    }
}

#[derive(Debug)]
struct ForgeRunContext {
    project_root: PathBuf,
    match_contract: String,
    _scratch_dir: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

fn prepare_forge_run_context(
    case: &BenchmarkCase,
    project_root: &Path,
) -> Result<ForgeRunContext, String> {
    if !project_root.exists() {
        return Err(format!(
            "project_root does not exist: {}",
            project_root.display()
        ));
    }
    let scratch_dir = std::env::temp_dir().join(format!(
        "sci-fuzz-benchmark-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch_dir).map_err(|err| {
        format!(
            "failed to create temp workdir {}: {err}",
            scratch_dir.display()
        )
    })?;
    let stdout_path = scratch_dir.join("forge.stdout.log");
    let stderr_path = scratch_dir.join("forge.stderr.log");
    Ok(ForgeRunContext {
        project_root: project_root.to_path_buf(),
        match_contract: case.target.clone(),
        _scratch_dir: scratch_dir,
        stdout_path,
        stderr_path,
    })
}

fn run_forge_command(
    binary: &str,
    ctx: &ForgeRunContext,
    seed: u64,
) -> Result<CommandOutput, String> {
    let output = Command::new(binary)
        .arg("test")
        .arg("--root")
        .arg(&ctx.project_root)
        .arg("--match-contract")
        .arg(&ctx.match_contract)
        .arg("--fuzz-seed")
        .arg(seed.to_string())
        .arg("-vv")
        .current_dir(&ctx.project_root)
        .output()
        .map_err(|err| err.to_string())?;
    Ok(CommandOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

#[derive(Debug)]
struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ForgeResultSummary {
    found: bool,
    failed_count: Option<usize>,
}

fn parse_forge_result_summary(stdout: &str, stderr: &str, success: bool) -> ForgeResultSummary {
    let merged = format!("{stdout}\n{stderr}");
    let failed_count = parse_first_usize_before_keyword(&merged, "failed");
    let found = failed_count.unwrap_or(0) > 0 || (!success && failed_count.is_none());
    ForgeResultSummary {
        found,
        failed_count,
    }
}

fn parse_first_usize_before_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    for line in haystack.lines() {
        if !line.contains(keyword) {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for window in parts.windows(2) {
            if window.len() == 2 && window[1].contains(keyword) {
                if let Ok(n) = window[0]
                    .trim_matches(|c: char| !c.is_ascii_digit())
                    .parse::<usize>()
                {
                    return Some(n);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_adapter_reports_unavailable_when_binary_missing() {
        let adapter = ExternalComparisonAdapter {
            engine: BenchmarkEngine::Echidna,
            binary: "definitely-not-a-real-binary",
        };
        let case = BenchmarkCase::new("Target", "campaign", "smoke", Vec::new())
            .with_max_execs(Some(0))
            .with_timeout(Duration::from_millis(1));

        let row = adapter.run_case(&case, 7);
        assert_eq!(row.engine, BenchmarkEngine::Echidna);
        assert_eq!(row.status, BenchmarkStatus::Unavailable);
        assert!(!row.found);
    }

    #[test]
    fn external_adapter_skips_unsupported_case_without_project_root() {
        let adapter = ExternalComparisonAdapter {
            engine: BenchmarkEngine::Forge,
            binary: "sh",
        };
        let case = BenchmarkCase::new("Target", "campaign", "smoke", Vec::new())
            .with_max_execs(Some(0))
            .with_timeout(Duration::from_millis(1));
        let row = adapter.run_case(&case, 9);
        assert_eq!(row.engine, BenchmarkEngine::Forge);
        assert_eq!(row.status, BenchmarkStatus::Skipped);
        assert!(row
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("project_root"));
    }

    #[test]
    fn prepare_forge_context_builds_temp_workdir_and_log_paths() {
        let dir = tempfile::tempdir().unwrap();
        let case = BenchmarkCase::new("Vault", "campaign", "smoke", Vec::new())
            .with_project_root(dir.path());
        let ctx = prepare_forge_run_context(&case, dir.path()).expect("context should build");
        assert_eq!(ctx.project_root, dir.path().to_path_buf());
        assert_eq!(ctx.match_contract, "Vault");
        assert!(ctx.stdout_path.ends_with("forge.stdout.log"));
        assert!(ctx.stderr_path.ends_with("forge.stderr.log"));
    }

    #[test]
    fn parse_forge_summary_maps_failed_count_to_found() {
        let summary =
            parse_forge_result_summary("Suite result: FAILED. 2 failed; 3 passed", "", false);
        assert_eq!(
            summary,
            ForgeResultSummary {
                found: true,
                failed_count: Some(2)
            }
        );
        let summary_ok =
            parse_forge_result_summary("Suite result: ok. 0 failed; 3 passed", "", true);
        assert_eq!(
            summary_ok,
            ForgeResultSummary {
                found: false,
                failed_count: Some(0)
            }
        );
    }

    #[test]
    fn multi_seed_sci_fuzz_benchmark_emits_stable_schema_artifacts() {
        let case = BenchmarkCase::new("Empty", "campaign", "Smoke", Vec::new())
            .with_timeout(Duration::from_millis(1))
            .with_max_execs(Some(0));
        let plan = vec![BenchmarkPlanEntry::Ready(case)];
        let seeds = [11u64, 22u64];
        let engines = [BenchmarkEngine::SciFuzz, BenchmarkEngine::Forge];
        let board = run_benchmark_plan(&plan, &seeds, &engines);

        assert_eq!(board.len(), 4);
        assert_eq!(
            board.entries()[0].status,
            BenchmarkStatus::Measured,
            "first row should be the measured sci-fuzz run"
        );
        assert!(board
            .entries()
            .iter()
            .any(|row| row.engine == BenchmarkEngine::Forge));

        let dir = tempfile::tempdir().unwrap();
        write_benchmark_artifacts(&board, dir.path()).unwrap();

        let results_csv =
            std::fs::read_to_string(dir.path().join("benchmark_results.csv")).unwrap();
        let summary_csv =
            std::fs::read_to_string(dir.path().join("benchmark_summary.csv")).unwrap();
        let results_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("benchmark_results.json")).unwrap(),
        )
        .unwrap();

        assert!(results_csv.contains("engine,status"));
        assert!(summary_csv.contains("median_repro_len_shrunk"));
        assert_eq!(results_json.as_array().unwrap().len(), 4);
    }
}
