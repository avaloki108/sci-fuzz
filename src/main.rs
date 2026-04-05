//! sci-fuzz — Smart Contract Invariant Fuzzer
//!
//! CLI entry point.

use std::process;

use anyhow::{Context, Result};
use sci_fuzz::campaign::Campaign;
use sci_fuzz::types::{Address, Bytes, CampaignConfig, ContractInfo, ExecutorMode};

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

    let (project, bootstrap, artifact_count) = Project::build_and_select_targets(&project_root)?;

    let fork_url = args
        .fork_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| project.eth_rpc_url());

    if let Some(ref url) = fork_url {
        println!("  fork RPC  : {url}");
        if let Some(b) = args.fork_block {
            println!("  fork block: {b}");
        } else {
            println!("  fork block: latest (default)");
        }
    }

    println!("discovered {} artifact(s)", artifact_count);
    println!(
        "selected {} runtime fuzz target(s){}",
        bootstrap.runtime_targets.len(),
        if let Some(ref h) = bootstrap.harness {
            format!(" + harness {}", h.name.as_deref().unwrap_or("(unnamed)"))
        } else {
            String::new()
        }
    );
    println!("starting campaign...");
    println!();

    let attacker_address = args
        .attacker
        .as_ref()
        .map(|s| s.parse::<Address>())
        .transpose()
        .context("invalid --attacker address")?;

    // Build a default campaign config from CLI args.
    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(args.timeout),
        max_execs: None,
        max_depth: args.depth,
        max_snapshots: args.max_snapshots,
        workers: args.workers,
        seed: args.seed.unwrap_or_else(|| rand::random()),
        targets: bootstrap.runtime_targets,
        harness: bootstrap.harness,
        mode: sci_fuzz::types::ExecutorMode::Fast,
        rpc_url: fork_url,
        rpc_block_number: args.fork_block,
        attacker_address,
        ..Default::default()
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
    // Load .env if present (best-effort; ignore errors).
    let _ = dotenvy_load();

    println!("⚡ sci-fuzz audit");
    println!("  addresses : {}", args.addresses.join(", "));
    println!("  chain     : {}", args.chain);
    println!("  timeout   : {}s", args.timeout);
    println!("  flashloan : {}", args.flashloan);
    println!();

    // Resolve RPC URL from CLI flag → env var.
    let rpc_url = args
        .rpc_url
        .clone()
        .or_else(|| std::env::var("ETH_RPC_URL").ok())
        .filter(|s| !s.trim().is_empty());

    let rpc_url = rpc_url.ok_or_else(|| {
        anyhow::anyhow!(
            "fork audit requires an RPC URL: set ETH_RPC_URL or pass --rpc-url <https://...>"
        )
    })?;

    let block = args.block_number.or_else(|| {
        std::env::var("FORK_BLOCK_NUMBER")
            .ok()
            .and_then(|s| s.parse().ok())
    });

    println!("  rpc        : {rpc_url}");
    if let Some(b) = block {
        println!("  fork-block : {b}");
    } else {
        println!("  fork-block : latest (default)");
    }
    println!();
    println!("  ℹ️  RpcCacheDB fork (lazy-load on first access).");
    match sci_fuzz::rpc::rpc_probe_url(&rpc_url) {
        Ok(()) => println!("  ✅ RPC reachable (eth_blockNumber)"),
        Err(e) => eprintln!("  ⚠️  RPC probe failed: {e}"),
    }
    // Resolve Etherscan API key from CLI flag → env var.
    let api_key = args
        .etherscan_key
        .clone()
        .or_else(|| std::env::var("ETHERSCAN_API_KEY").ok())
        .unwrap_or_default();

    let mut targets: Vec<ContractInfo> = Vec::new();
    for addr_str in &args.addresses {
        let target_address: Address = addr_str
            .parse()
            .with_context(|| format!("Invalid address format: {addr_str}"))?;

        let mut abi_val = None;
        if !api_key.is_empty() {
            println!();
            println!(
                "  🔍 Fetching ABI from Etherscan for {} ({})…",
                addr_str, args.chain
            );
            match sci_fuzz::rpc::fetch_etherscan_abi(addr_str, &args.chain, &api_key) {
                Ok(abi) => {
                    println!("  ✅ ABI retrieved successfully!");
                    abi_val = Some(abi);
                }
                Err(e) => {
                    println!("  ⚠️  ABI retrieval failed: {e}");
                }
            }
        } else if targets.is_empty() {
            println!();
            println!("  ℹ️  No ETHERSCAN_API_KEY — ABIs will be missing unless provided elsewhere.");
        }

        let short = addr_str
            .strip_prefix("0x")
            .unwrap_or(addr_str)
            .chars()
            .take(6)
            .collect::<String>();
        targets.push(ContractInfo {
            address: target_address,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: None,
            name: Some(format!("AuditTarget_{short}")),
            source_path: None,
            abi: abi_val,
        });
    }

    let attacker_address = args
        .attacker
        .as_ref()
        .map(|s| s.parse::<Address>())
        .transpose()
        .context("invalid --attacker address")?;

    // --- Build Campaign Configuration --------------------------------------
    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(args.timeout),
        max_execs: None,
        max_depth: 32,
        max_snapshots: 1024,
        workers: 1, // Audit usually runs single-threaded for stability across network
        seed: rand::random(),
        targets,
        harness: None,
        mode: ExecutorMode::Realistic, // Audits should use realistic mode by default
        rpc_url: Some(rpc_url.clone()),
        rpc_block_number: block,
        attacker_address,
        ..Default::default()
    };

    println!();
    println!("🚀 Starting audit campaign...");
    println!("   Mode      : {:?}", config.mode);
    println!("   Timeout   : {}s", args.timeout);
    if args.flashloan {
        println!(
            "   Flashloan : Enabled (Mock Pool 0x{})",
            hex::encode(sci_fuzz::flashloan::MOCK_FLASHLOAN_POOL.as_slice())
        );
    }
    println!();

    let mut campaign = Campaign::new(config);
    let findings = campaign.run()?;

    println!();
    if findings.is_empty() {
        println!("✅ No vulnerabilities discovered.");
    } else {
        println!("🐛 FOUND {} POSSIBLE VULNERABILITIES:", findings.len());
        for (i, f) in findings.iter().enumerate() {
            println!("   [{}] {} -- severity: {}", i + 1, f.title, f.severity);
            println!("        {}", f.description);
            if let Some(profit) = f.exploit_profit {
                println!("        💰 Estimated Profit: {} wei", profit);
            }
            println!();
        }

        if let Some(out_dir) = args.output {
            std::fs::create_dir_all(&out_dir)?;
            for f in findings {
                let path = f.save_to_dir(&out_dir)?;
                println!("   💾 Saved finding to: {}", path.display());
            }
        }
    }

    Ok(())
}

/// Best-effort load of a `.env` file (project root or CWD).
#[cfg(feature = "cli")]
fn dotenvy_load() -> anyhow::Result<()> {
    let candidates = [".env", "../.env"];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            for line in std::fs::read_to_string(path)?.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((key, val)) = line.split_once('=') {
                    // Don't override already-set env vars.
                    if std::env::var(key.trim()).is_err() {
                        std::env::set_var(key.trim(), val.trim());
                    }
                }
            }
            break;
        }
    }
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
