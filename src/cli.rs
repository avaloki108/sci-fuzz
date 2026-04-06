//! CLI interface for Sci-Fuzz
//!
//! This module defines the command-line interface using Clap derive macros.
//! It supports multiple subcommands for different fuzzing modes and workflows.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Sci-Fuzz: Next-generation smart contract fuzzer
#[derive(Parser, Debug)]
#[command(
    name = "sci-fuzz",
    version,
    about = "State-first smart contract fuzzer for EVM targets",
    long_about = r#"
Sci-Fuzz is a stateful smart contract fuzzer for EVM targets.

It combines snapshot-based state exploration, coverage-guided feedback,
ABI-aware mutation, and automated invariant checking in one workflow.
"#
)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,

    /// Verbosity level
    #[arg(short, long, global = true, default_value = "info")]
    pub verbosity: Verbosity,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub output_format: OutputFormat,

    /// Disable colors in output
    #[arg(long, global = true)]
    pub no_color: bool,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a repeatable benchmark / comparison pipeline
    #[command(
        name = "benchmark",
        about = "Run structured benchmark cases and emit evidence artifacts",
        long_about = r#"
Run repeatable benchmark cases across one or more engines and seeds.
Outputs machine-readable CSV / JSON artifacts for internal iteration and
comparison scaffolding.
"#
    )]
    Benchmark(BenchmarkArgs),

    /// Fuzz a Foundry project
    #[command(
        name = "forge",
        about = "Fuzz a Foundry project with enhanced exploration",
        long_about = r#"
Fuzz a Foundry project with Sci-Fuzz's enhanced state exploration.
Automatically discovers contracts, generates invariants, and finds
deep-state vulnerabilities.
"#
    )]
    Forge(ForgeArgs),

    /// Audit deployed contract(s) on a JSON-RPC fork
    #[command(
        name = "audit",
        about = "Audit deployed contract(s) on-chain",
        long_about = r#"
Fork at a block (or `latest`) and fuzz one or more predeployed addresses on that chain state.
Requires `--rpc-url` or `ETH_RPC_URL`. Optional Etherscan ABI fetch per address when an API key is set.
This is sci-fuzz’s own revm campaign — not `forge test` and not a cheatcode VM.
"#
    )]
    Audit(AuditArgs),

    /// Run tests with enhanced fuzzing
    #[command(
        name = "test",
        about = "Run Foundry tests with enhanced fuzzing",
        long_about = r#"
Thin project-mode wrapper for in-engine sci-fuzz campaigns.
Builds the Foundry project in the current directory, selects fuzz targets,
optionally filters by `--match-contract` / `--match-test`, and runs a campaign
with test-oriented defaults.
"#
    )]
    Test(TestArgs),

    /// Run CI/CD security scan
    #[command(
        name = "ci",
        about = "Run security scan for CI/CD pipelines",
        long_about = r#"
Run a security scan for CI/CD pipelines.

Runs a real campaign (50k execs, 2 workers, configurable timeout). Emits SARIF 2.1
or JUnit XML output. Optionally writes GitHub Actions annotations (::error/warning/notice)
and Forge .t.sol reproducers to test/repros/. Exits with code 2 when critical or high
findings meet the configured thresholds (distinct from build error exit 1).
"#
    )]
    Ci(CiArgs),

    /// Differential fuzzing between implementations
    #[command(
        name = "diff",
        about = "Compare two local contract implementations via differential execution",
        long_about = r#"
Deploy two contracts from a Foundry project and execute identical generated
call sequences against both, reporting any reproducible divergence in:
  - success vs revert (one succeeds, the other reverts)
  - return data (both succeed but output differs)
  - emitted event signatures (topic[0] set differs)

Unsupported: --reference and --rpc-url. Pass either flag to get a clear error.
On-chain fork comparison is not implemented.
"#
    )]
    Diff(DiffArgs),

    /// Show version information
    #[command(name = "version", about = "Show version information")]
    Version,
}

/// Arguments for the `forge` subcommand
#[derive(Parser, Debug)]
pub struct ForgeArgs {
    /// Path to Foundry project
    #[arg(short, long, default_value = ".")]
    pub project: PathBuf,

    /// Maximum transaction sequence depth
    #[arg(long, default_value = "50")]
    pub depth: u32,

    /// Enable snapshot-based state exploration
    #[arg(long)]
    pub snapshots: bool,

    /// Snapshot strategy to use
    #[arg(long, default_value = "dataflow")]
    pub snapshot_strategy: SnapshotStrategy,

    /// Maximum number of snapshots to keep
    #[arg(long, default_value = "1000")]
    pub max_snapshots: usize,

    /// RPC URL for forked execution
    #[arg(long)]
    pub fork_url: Option<String>,

    /// Block number for forked execution
    #[arg(long)]
    pub fork_block: Option<u64>,

    /// Funder / primary `msg.sender` for fuzz transactions (default: 0x4242…4242)
    #[arg(long)]
    pub attacker: Option<String>,

    /// Templates to use for invariant generation
    #[arg(long, value_delimiter = ',')]
    pub templates: Vec<String>,

    /// Timeout in seconds
    #[arg(long, default_value = "3600")]
    pub timeout: u64,

    /// Number of parallel workers
    #[arg(long, default_value = "4")]
    pub workers: usize,

    /// Random seed for reproducibility
    #[arg(long)]
    pub seed: Option<u64>,

    /// Output directory for results
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Fail on critical findings
    #[arg(long)]
    pub fail_on_critical: bool,

    /// Directory for corpus persistence across runs
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,

    /// Foundry build profile to use (sets FOUNDRY_PROFILE env var during build
    /// and reads the profile's `out` directory for artifacts). Useful when the
    /// echidna harness lives outside `src/` and needs a custom profile to compile.
    #[arg(long)]
    pub forge_profile: Option<String>,
}

/// Arguments for the `benchmark` subcommand
#[derive(Parser, Debug)]
pub struct BenchmarkArgs {
    /// Built-in benchmark preset
    #[arg(long, default_value = "efcf-demo")]
    pub preset: String,

    /// Optional Foundry project root for project benchmarks
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Optional target contract name for project benchmarks
    #[arg(long)]
    pub target: Option<String>,

    /// Property label to record in result rows
    #[arg(long, default_value = "campaign")]
    pub property: String,

    /// Bug class / category label to record in result rows
    #[arg(long, default_value = "Campaign")]
    pub category: String,

    /// Engines to include, comma-separated
    #[arg(long, value_delimiter = ',', default_values_t = vec![BenchmarkEngineArg::SciFuzz, BenchmarkEngineArg::Echidna, BenchmarkEngineArg::Forge])]
    pub engines: Vec<BenchmarkEngineArg>,

    /// Seeds to run, comma-separated
    #[arg(long, value_delimiter = ',', default_values_t = vec![1_u64, 2, 3])]
    pub seeds: Vec<u64>,

    /// Deterministic execution budget per run
    #[arg(long, default_value = "5000")]
    pub max_execs: u64,

    /// Maximum wall-clock timeout per run in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Maximum transaction sequence depth
    #[arg(long, default_value = "8")]
    pub depth: u32,

    /// Output directory for benchmark artifacts
    #[arg(long, default_value = "target/benchmark")]
    pub output_dir: PathBuf,
}

/// Arguments for the `audit` subcommand
#[derive(Parser, Debug)]
pub struct AuditArgs {
    /// On-chain contract address(es) to fuzz against the fork (one or more)
    #[arg(required = true)]
    pub addresses: Vec<String>,

    /// RPC URL for on-chain access
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Block number to fork from
    #[arg(long)]
    pub block_number: Option<u64>,

    /// Funder / primary `msg.sender` for fuzz transactions (default: 0x4242…4242)
    #[arg(long)]
    pub attacker: Option<String>,

    /// Etherscan API key for source verification
    #[arg(long)]
    pub etherscan_key: Option<String>,

    /// Chain name (mainnet, polygon, arbitrum, etc.)
    #[arg(long, default_value = "mainnet")]
    pub chain: String,

    /// Templates to use for vulnerability detection
    #[arg(long, value_delimiter = ',', default_values_t = vec!["erc20".to_string(), "reentrancy".to_string(), "access-control".to_string()])]
    pub templates: Vec<String>,

    /// Generate exploit proof-of-concept
    #[arg(long)]
    pub generate_exploit: bool,

    /// Output file for exploit
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Enable flashloan simulation
    #[arg(long)]
    pub flashloan: bool,

    /// Enable liquidation simulation
    #[arg(long)]
    pub liquidation: bool,
}

/// Arguments for the `test` subcommand
#[derive(Parser, Debug)]
pub struct TestArgs {
    /// Test pattern to match
    #[arg(long)]
    pub match_test: Option<String>,

    /// Contract pattern to match
    #[arg(long)]
    pub match_contract: Option<String>,

    /// Number of fuzzing runs
    #[arg(long, default_value = "10000")]
    pub runs: u32,

    /// Enable snapshot-based exploration
    #[arg(long)]
    pub snapshots: bool,

    /// RPC URL for forked execution
    #[arg(long)]
    pub fork_url: Option<String>,

    /// Block number for forked execution
    #[arg(long)]
    pub fork_block: Option<u64>,

    /// Output format for test results
    #[arg(long, default_value = "pretty")]
    pub test_output: TestOutputFormat,

    /// Fail on first test failure
    #[arg(long)]
    pub fail_fast: bool,

    /// Gas reporting
    #[arg(long)]
    pub gas_report: bool,
}

/// Arguments for the `ci` subcommand
#[derive(Parser, Debug)]
pub struct CiArgs {
    /// Path to Foundry project
    #[arg(short, long, default_value = ".")]
    pub project: PathBuf,

    /// Output format for CI
    #[arg(long, default_value = "junit")]
    pub output_format: CiOutputFormat,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Fail on critical findings
    #[arg(long)]
    pub fail_on_critical: bool,

    /// Fail on high findings
    #[arg(long)]
    pub fail_on_high: bool,

    /// Timeout in seconds
    #[arg(long, default_value = "600")]
    pub timeout: u64,

    /// GitHub Actions mode
    #[arg(long)]
    pub github_actions: bool,

    /// Directory for corpus persistence across runs
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,
}

/// Arguments for the `diff` subcommand
#[derive(Parser, Debug)]
pub struct DiffArgs {
    /// Name of the first contract implementation (as it appears in forge artifacts)
    pub impl_a: String,

    /// Name of the second contract implementation
    pub impl_b: String,

    /// Path to the Foundry project root
    #[arg(short, long, default_value = ".")]
    pub project: PathBuf,

    /// Timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Deterministic seed for the call generator
    #[arg(long, default_value = "0")]
    pub seed: u64,

    /// Maximum number of individual call executions before stopping
    #[arg(long, default_value = "50000")]
    pub max_execs: u64,

    /// Maximum transaction sequence depth per iteration
    #[arg(long, default_value = "16")]
    pub depth: u32,

    /// Filter: only fuzz functions whose name contains this substring (reserved, currently unused)
    #[arg(long)]
    pub match_contract: Option<String>,

    /// Not supported — on-chain reference comparison requires --rpc-url which is not yet implemented
    #[arg(long)]
    pub reference: Option<String>,

    /// Not supported — on-chain fork mode is not yet implemented for diff
    #[arg(long)]
    pub rpc_url: Option<String>,
}

/// Snapshot strategy variants
#[derive(ValueEnum, Clone, Debug)]
pub enum SnapshotStrategy {
    /// Dataflow waypoints prioritize states based on future memory-load behavior
    Dataflow,
    /// Comparison waypoints compress/prune similar states
    Comparison,
    /// Hybrid strategy combining both dataflow and comparison
    Hybrid,
    /// Random selection (baseline)
    Random,
}

/// Benchmark engines supported by the CLI
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BenchmarkEngineArg {
    SciFuzz,
    Echidna,
    Forge,
}

impl std::fmt::Display for BenchmarkEngineArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SciFuzz => write!(f, "sci-fuzz"),
            Self::Echidna => write!(f, "echidna"),
            Self::Forge => write!(f, "forge"),
        }
    }
}

/// Verbosity level
#[derive(ValueEnum, Clone, Debug)]
pub enum Verbosity {
    /// Error level only
    Error,
    /// Warning level and above
    Warn,
    /// Info level and above (default)
    Info,
    /// Debug level and above
    Debug,
    /// Trace level (most verbose)
    Trace,
}

/// Output format for results
#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// Markdown format
    Markdown,
}

/// Test output format
#[derive(ValueEnum, Clone, Debug)]
pub enum TestOutputFormat {
    /// Pretty human-readable output
    Pretty,
    /// Terse output
    Terse,
    /// JSON output
    Json,
}

/// CI output format
#[derive(ValueEnum, Clone, Debug)]
pub enum CiOutputFormat {
    /// JUnit XML format
    Junit,
    /// SARIF format for security tools
    Sarif,
    /// GitHub Code Scanning format
    GitHub,
    /// GitLab SAST format
    GitLab,
}

/// Parse CLI arguments and return configuration
pub fn parse_args() -> Cli {
    Cli::parse()
}

/// Display help information
pub fn display_help() {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    cmd.print_help().unwrap();
}

/// Display version information
pub fn display_version() {
    println!("Sci-Fuzz {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Build: {}",
        option_env!("VERGEN_GIT_SHA").unwrap_or("unknown")
    );
    println!(
        "Commit date: {}",
        option_env!("VERGEN_GIT_COMMIT_TIMESTAMP").unwrap_or("unknown")
    );
    println!();
    println!("License: MIT OR Apache-2.0");
    println!("Repository: https://github.com/your-org/sci-fuzz");
}

/// Convert verbosity level to tracing level
pub fn verbosity_to_level(verbosity: &Verbosity) -> tracing::Level {
    match verbosity {
        Verbosity::Error => tracing::Level::ERROR,
        Verbosity::Warn => tracing::Level::WARN,
        Verbosity::Info => tracing::Level::INFO,
        Verbosity::Debug => tracing::Level::DEBUG,
        Verbosity::Trace => tracing::Level::TRACE,
    }
}

/// Initialize logging with given verbosity level
pub fn init_logging(verbosity: &Verbosity) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let level = verbosity_to_level(verbosity);
    let filter = EnvFilter::from_default_env()
        .add_directive(format!("sci_fuzz={}", level.as_str()).parse().unwrap());

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(false))
        .with(filter)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parsing() {
        // Test that the CLI can be built
        Cli::command().debug_assert();

        // Test basic argument parsing
        let args = vec!["sci-fuzz", "forge", "--depth", "100"];
        let cli = Cli::parse_from(args);
        match cli.command {
            Commands::Forge(ref forge_args) => {
                assert_eq!(forge_args.depth, 100);
            }
            _ => panic!("Expected forge command"),
        }

        let audit = vec![
            "sci-fuzz",
            "audit",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ];
        let cli = Cli::parse_from(audit);
        match cli.command {
            Commands::Audit(ref a) => {
                assert_eq!(a.addresses.len(), 2);
            }
            _ => panic!("Expected audit command"),
        }
    }

    #[test]
    fn test_verbosity_conversion() {
        assert_eq!(verbosity_to_level(&Verbosity::Error), tracing::Level::ERROR);
        assert_eq!(verbosity_to_level(&Verbosity::Warn), tracing::Level::WARN);
        assert_eq!(verbosity_to_level(&Verbosity::Info), tracing::Level::INFO);
        assert_eq!(verbosity_to_level(&Verbosity::Debug), tracing::Level::DEBUG);
        assert_eq!(verbosity_to_level(&Verbosity::Trace), tracing::Level::TRACE);
    }
}
