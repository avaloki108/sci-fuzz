//! sci-fuzz — Smart Contract Invariant Fuzzer
//!
//! CLI entry point.

use std::process;

use anyhow::Result;

#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
use sci_fuzz::cli::{Cli, Commands};

fn main() {
    #[cfg(feature = "cli")]
    {
        let cli = Cli::parse();
        init_logging(&cli.verbosity);

        if let Err(err) = run(cli) {
            eprintln!("Error: {err:#}");
            process::exit(1);
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        eprintln!("sci-fuzz was compiled without the `cli` feature.");
        eprintln!("Re-build with: cargo build --features cli");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

#[cfg(feature = "cli")]
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Benchmark(args) => handle_benchmark(args),
        Commands::Forge(args) => handle_forge(args),
        Commands::Audit(args) => handle_audit(args),
        Commands::Test(args) => handle_test(args),
        Commands::Ci(args) => handle_ci(args),
        Commands::Diff(args) => handle_diff(args),
        Commands::Version => handle_version(),
    }
}

// ---------------------------------------------------------------------------
// Sub-command handlers (stubs that will be fleshed out)
// ---------------------------------------------------------------------------

#[cfg(feature = "cli")]
fn handle_benchmark(args: sci_fuzz::cli::BenchmarkArgs) -> Result<()> {
    use sci_fuzz::benchmark::{
        efcf_demo_plan, plan_for_foundry_project, run_benchmark_plan, write_benchmark_artifacts,
    };
    use sci_fuzz::scoreboard::BenchmarkEngine;

    let engines: Vec<BenchmarkEngine> = args
        .engines
        .iter()
        .map(|engine| match engine {
            sci_fuzz::cli::BenchmarkEngineArg::SciFuzz => BenchmarkEngine::SciFuzz,
            sci_fuzz::cli::BenchmarkEngineArg::Echidna => BenchmarkEngine::Echidna,
            sci_fuzz::cli::BenchmarkEngineArg::Forge => BenchmarkEngine::Forge,
        })
        .collect();

    let timeout = std::time::Duration::from_secs(args.timeout);
    let max_execs = Some(args.max_execs);
    let plan = if let Some(project) = &args.project {
        plan_for_foundry_project(
            project,
            args.target.as_deref(),
            &args.property,
            &args.category,
            timeout,
            args.depth,
            max_execs,
        )?
    } else {
        match args.preset.as_str() {
            "efcf-demo" => efcf_demo_plan(timeout, args.depth, max_execs),
            other => {
                anyhow::bail!(
                    "Unknown benchmark preset `{other}`. Use `efcf-demo` or pass --project."
                );
            }
        }
    };

    println!("⚡ sci-fuzz benchmark");
    println!("  seeds      : {:?}", args.seeds);
    println!("  engines    : {:?}", args.engines);
    println!("  timeout    : {}s", args.timeout);
    println!("  max_execs  : {}", args.max_execs);
    println!("  depth      : {}", args.depth);
    println!("  output-dir : {}", args.output_dir.display());
    println!();

    let board = run_benchmark_plan(&plan, &args.seeds, &engines);
    write_benchmark_artifacts(&board, &args.output_dir)?;

    println!("raw results:");
    board.print_csv();
    println!();
    println!("summary:");
    board.print_summary();
    println!();
    println!("wrote:");
    println!(
        "  {}",
        args.output_dir.join("benchmark_results.csv").display()
    );
    println!(
        "  {}",
        args.output_dir.join("benchmark_results.json").display()
    );
    println!(
        "  {}",
        args.output_dir.join("benchmark_summary.csv").display()
    );
    println!(
        "  {}",
        args.output_dir.join("benchmark_summary.json").display()
    );

    Ok(())
}

#[cfg(feature = "cli")]
fn handle_forge(args: sci_fuzz::cli::ForgeArgs) -> Result<()> {
    use sci_fuzz::{campaign::Campaign, project::Project, types::CampaignConfig};

    println!("⚡ sci-fuzz — Smart Contract Invariant Fuzzer");
    println!();
    println!("  project : {}", args.project.display());
    println!("  depth   : {}", args.depth);
    println!("  timeout : {}s", args.timeout);
    println!("  workers : {}", args.workers);
    println!("  seed    : {}", args.seed.unwrap_or(0));
    println!();

    let project_root = args.project.canonicalize().unwrap_or(args.project.clone());
    println!("found project: {}", project_root.display());
    println!("running forge build...");

    let (_project, targets, artifact_count) = Project::build_and_select_targets(&project_root)?;

    println!("discovered {} artifact(s)", artifact_count);
    println!("selected {} fuzz target(s)", targets.len());
    println!("starting campaign...");
    println!();

    // Build a default campaign config from CLI args.
    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(args.timeout),
        max_execs: None,
        max_depth: args.depth,
        max_snapshots: args.max_snapshots,
        workers: args.workers,
        seed: args.seed.unwrap_or_else(|| rand::random()),
        targets,
    };

    let mut campaign = Campaign::new(config);
    let findings = campaign.run()?;

    println!();
    if findings.is_empty() {
        println!("✅ No invariant violations found.");
    } else {
        println!("🐛 Found {} invariant violation(s):", findings.len());
        for (i, finding) in findings.iter().enumerate() {
            println!(
                "  [{i}] [{sev}] {title}",
                sev = finding.severity,
                title = finding.title,
            );
            println!("       {}", finding.description);
        }
    }

    Ok(())
}

#[cfg(feature = "cli")]
fn handle_audit(args: sci_fuzz::cli::AuditArgs) -> Result<()> {
    println!("⚡ sci-fuzz audit");
    println!("  address   : {}", args.address);
    println!("  chain     : {}", args.chain);
    println!("  templates : {:?}", args.templates);
    println!();
    println!("  (on-chain audit not yet implemented — coming soon)");
    Ok(())
}

#[cfg(feature = "cli")]
fn handle_test(args: sci_fuzz::cli::TestArgs) -> Result<()> {
    println!("⚡ sci-fuzz test");
    if let Some(ref pat) = args.match_test {
        println!("  match-test : {pat}");
    }
    println!("  runs       : {}", args.runs);
    println!();
    println!("  (enhanced test runner not yet implemented — coming soon)");
    Ok(())
}

#[cfg(feature = "cli")]
fn handle_ci(args: sci_fuzz::cli::CiArgs) -> Result<()> {
    println!("⚡ sci-fuzz ci");
    println!("  project : {}", args.project.display());
    println!("  format  : {:?}", args.output_format);
    println!("  timeout : {}s", args.timeout);
    println!();
    println!("  (CI mode not yet implemented — coming soon)");
    Ok(())
}

#[cfg(feature = "cli")]
fn handle_diff(args: sci_fuzz::cli::DiffArgs) -> Result<()> {
    println!("⚡ sci-fuzz diff");
    println!("  impl-a    : {}", args.impl_a);
    println!("  impl-b    : {}", args.impl_b);
    println!("  tolerance : {}", args.tolerance);
    println!();
    println!("  (differential fuzzing not yet implemented — coming soon)");
    Ok(())
}

#[cfg(feature = "cli")]
fn handle_version() -> Result<()> {
    println!(
        "sci-fuzz {} — Smart Contract Invariant Fuzzer",
        env!("CARGO_PKG_VERSION")
    );
    println!("License: {}", env!("CARGO_PKG_LICENSE"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[cfg(feature = "cli")]
fn init_logging(verbosity: &sci_fuzz::cli::Verbosity) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let level = match verbosity {
        sci_fuzz::cli::Verbosity::Error => "error",
        sci_fuzz::cli::Verbosity::Warn => "warn",
        sci_fuzz::cli::Verbosity::Info => "info",
        sci_fuzz::cli::Verbosity::Debug => "debug",
        sci_fuzz::cli::Verbosity::Trace => "trace",
    };

    // Respect RUST_LOG if set, otherwise use the CLI flag.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sci_fuzz={level}")));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(false))
        .with(filter)
        .init();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }
}
