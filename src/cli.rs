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
    about = "State-first, automated smart contract fuzzer that beats Echidna and Forge",
    long_about = r#"
Sci-Fuzz is a research-backed smart contract fuzzer designed from the ground up
to address the fundamental limitations of existing tools like Echidna and Forge.

By combining snapshot-based state exploration, hybrid guidance mechanisms,
and automated oracle generation, Sci-Fuzz discovers deep-state vulnerabilities
faster and with less manual specification effort.
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

    /// Audit a deployed contract
    #[command(
        name = "audit",
        about = "Audit a deployed contract on-chain",
        long_about = r#"
Audit a deployed contract by forking the chain at a specific block.
Automatically generates exploits and provides detailed vulnerability reports.
"#
    )]
    Audit(AuditArgs),

    /// Run tests with enhanced fuzzing
    #[command(
        name = "test",
        about = "Run Foundry tests with enhanced fuzzing",
        long_about = r#"
Replace `forge test` with Sci-Fuzz's enhanced fuzzing capabilities.
Supports all Foundry test patterns with deeper state exploration.
"#
    )]
    Test(TestArgs),

    /// Run CI/CD security scan
    #[command(
        name = "ci",
        about = "Run security scan for CI/CD pipelines",
        long_about = r#"
Run a security scan suitable for CI/CD pipelines.
Outputs results in machine-readable formats (JUnit, SARIF).
"#
    )]
    Ci(CiArgs),

    /// Differential fuzzing between implementations
    #[command(
        name = "diff",
        about = "Compare two implementations via differential fuzzing",
        long_about = r#"
Compare two contract implementations using differential fuzzing.
Detects behavioral differences that could indicate bugs or optimization issues.
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
}

/// Arguments for the `audit` subcommand
#[derive(Parser, Debug)]
pub struct AuditArgs {
    /// Contract address to audit
    pub address: String,

    /// RPC URL for on-chain access
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Block number to fork from
    #[arg(long)]
    pub block_number: Option<u64>,

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
}

/// Arguments for the `diff` subcommand
#[derive(Parser, Debug)]
pub struct DiffArgs {
    /// First implementation path or address
    pub impl_a: String,

    /// Second implementation path or address
    pub impl_b: String,

    /// Reference specification path or address
    #[arg(long)]
    pub reference: Option<String>,

    /// Tolerance for numerical differences
    #[arg(long, default_value = "0.01")]
    pub tolerance: f64,

    /// RPC URL for on-chain implementations
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Output directory for diff results
    #[arg(short, long)]
    pub output: Option<PathBuf>,
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
