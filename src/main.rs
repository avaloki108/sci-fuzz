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
        Commands::Replay(args) => handle_replay(args),
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
    if args.system_mode {
        println!("  🔗 system-mode: all {} contracts fuzzed as equal targets", bootstrap.runtime_targets.len());
    }
    if !args.extra_senders.is_empty() {
        println!("  👥 extra senders: {}", args.extra_senders.join(", "));
    }
    println!("starting campaign...");
    println!();

    let attacker_address = args
        .attacker
        .as_ref()
        .map(|s| s.parse::<Address>())
        .transpose()
        .context("invalid --attacker address")?;

    // Build a default campaign config from CLI args.
    let extra_senders: Vec<Address> = args
        .extra_senders
        .iter()
        .filter_map(|s| s.parse::<Address>().ok())
        .collect();
    let target_weights: std::collections::HashMap<Address, u32> = args
        .target_weight
        .iter()
        .filter_map(|s| {
            let (addr, w) = s.rsplit_once(':')?;
            Some((addr.parse::<Address>().ok()?, w.parse::<u32>().ok()?))
        })
        .collect();
    let selector_weights: std::collections::HashMap<[u8; 4], u32> = args
        .selector_weight
        .iter()
        .filter_map(|s| {
            let (sel, w) = s.rsplit_once(':')?;
            let sel = sel.trim_start_matches("0x");
            let bytes = hex::decode(sel).ok()?;
            if bytes.len() != 4 { return None; }
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some((arr, w.parse::<u32>().ok()?))
        })
        .collect();

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
        corpus_dir: args.corpus_dir.clone(),
        test_mode: args.mode,
        system_mode: args.system_mode,
        infer_invariants: args.infer_invariants,
        extra_senders,
        target_weights,
        selector_weights,
        auto_rank_targets: args.auto_rank_targets,
        ..Default::default()
    };

    let mut campaign = Campaign::new(config);
    let report = campaign.run_with_report()?;
    let findings: Vec<sci_fuzz::types::Finding> = report
        .findings
        .into_iter()
        .map(|r| r.finding)
        .collect();

    let generate_replay = !args.no_replay;
    sci_fuzz::output::print_campaign_summary(
        &findings,
        report.total_execs,
        report.elapsed_ms,
        report.finding_count,
        report.deduped_finding_count,
        report.first_hit_execs,
        report.first_hit_time_ms,
        generate_replay,
    );

    // Save JSON report if requested.
    if args.save_report {
        let json = sci_fuzz::output::json_report(
            &findings,
            report.total_execs,
            report.elapsed_ms,
            report.finding_count,
            report.deduped_finding_count,
            report.first_hit_execs,
            report.first_hit_time_ms,
            &format!("{:?}", args.mode),
        );
        let out_path = args
            .output
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("."));
        let report_path = std::path::Path::new(out_path).join("sci-fuzz-report.json");
        if let Err(e) = std::fs::write(&report_path, &json) {
            eprintln!("[warn] failed to save report: {e}");
        } else {
            eprintln!("[report] saved to {}", report_path.display());
        }
    }

    // Exit 1 on critical findings if requested.
    if args.fail_on_critical
        && findings
            .iter()
            .any(|f| matches!(f.severity, sci_fuzz::types::Severity::Critical))
    {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(feature = "cli")]
fn handle_audit(args: sci_fuzz::cli::AuditArgs) -> Result<()> {
    // Load .env if present (best-effort; ignore errors).
    let _ = dotenvy_load();

    println!("⚡ sci-fuzz audit");

    use std::path::Path;
    let mut manifest_chain_id: Option<u64> = None;
    let mut named_targets: Vec<(String, Address)> = Vec::new();
    if args.addresses.len() == 1 {
        let p = &args.addresses[0];
        if Path::new(p).is_file() {
            let m = sci_fuzz::bootstrap::AddressManifest::load_path_or_inline(p)
                .with_context(|| format!("failed to load address manifest from {p}"))?;
            manifest_chain_id = m.chain_id;
            if let Some(ref label) = m.rpc_label {
                println!("  manifest  : rpc_label={label}");
            }
            named_targets = m.contracts;
            println!(
                "  manifest  : {} named target(s) from {}",
                named_targets.len(),
                p
            );
        } else {
            let addr: Address = p
                .parse()
                .with_context(|| format!("Invalid address format: {p}"))?;
            let short = p
                .strip_prefix("0x")
                .unwrap_or(p)
                .chars()
                .take(6)
                .collect::<String>();
            named_targets.push((format!("AuditTarget_{short}"), addr));
        }
    } else {
        for p in &args.addresses {
            let addr: Address = p
                .parse()
                .with_context(|| format!("Invalid address format: {p}"))?;
            let short = p
                .strip_prefix("0x")
                .unwrap_or(p)
                .chars()
                .take(6)
                .collect::<String>();
            named_targets.push((format!("AuditTarget_{short}"), addr));
        }
        println!("  addresses : {}", args.addresses.join(", "));
    }
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
    for (label, target_address) in &named_targets {
        let addr_str = format!("{target_address:#x}");

        let mut abi_val = None;
        if !api_key.is_empty() {
            println!();
            println!(
                "  🔍 Fetching ABI from Etherscan for {} ({})…",
                addr_str, args.chain
            );
            match sci_fuzz::rpc::fetch_etherscan_abi(&addr_str, &args.chain, &api_key) {
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
            println!(
                "  ℹ️  No ETHERSCAN_API_KEY — ABIs will be missing unless provided elsewhere."
            );
        }

        targets.push(ContractInfo {
            address: *target_address,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: None,
            name: Some(label.clone()),
            source_path: None,
            deployed_source_map: None,
            source_file_list: vec![],
            abi: abi_val,
            link_references: Default::default(),
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
        fork_expected_chain_id: manifest_chain_id.or_else(|| {
            std::env::var("FORK_CHAIN_ID")
                .ok()
                .and_then(|s| s.parse().ok())
        }),
        // Audit mode: use pre-deployed on-chain addresses directly.
        // Do NOT re-deploy — the contracts already exist on the forked chain.
        // Setting this to false ensures the campaign sees empty deployed_bytecode
        // and falls through to the "use address as-is" path in the deploy loop.
        fork_hydrate_deployed_bytecode: false,
        fork_allow_local_deploy: false,
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
    use sci_fuzz::{project::Project, types::CampaignConfig};

    println!("⚡ sci-fuzz test");
    if let Some(ref pat) = args.match_test {
        println!("  match-test : {pat}");
    }
    if let Some(ref pat) = args.match_contract {
        println!("  match-contract : {pat}");
    }
    println!("  runs       : {}", args.runs);
    println!("  timeout    : 300s");
    println!();

    let project_root = std::path::PathBuf::from(".")
        .canonicalize()
        .unwrap_or(std::path::PathBuf::from("."));
    println!("  project    : {}", project_root.display());
    println!("running forge build...");
    let (_project, bootstrap, artifact_count) = Project::build_and_select_targets(&project_root)?;
    println!("discovered {} artifact(s)", artifact_count);

    let mut targets = bootstrap.runtime_targets;
    if let Some(ref contract_pat) = args.match_contract {
        targets.retain(|target| {
            target
                .name
                .as_deref()
                .map(|name| name.contains(contract_pat))
                .unwrap_or(false)
        });
    }

    if let Some(ref test_pat) = args.match_test {
        targets.retain(|target| {
            target.abi.as_ref().is_some_and(|abi| {
                abi.as_array().into_iter().flatten().any(|entry| {
                    entry.get("type").and_then(|t| t.as_str()) == Some("function")
                        && entry
                            .get("name")
                            .and_then(|n| n.as_str())
                            .is_some_and(|n| n.contains(test_pat))
                })
            })
        });
    }

    if targets.is_empty() {
        anyhow::bail!("no targets matched filters for `sci-fuzz test`");
    }

    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(300),
        max_execs: Some(args.runs as u64),
        max_depth: 16,
        max_snapshots: if args.snapshots { 512 } else { 128 },
        workers: 1,
        seed: 0x51f5_7e57,
        targets,
        harness: bootstrap.harness,
        mode: sci_fuzz::types::ExecutorMode::Fast,
        rpc_url: args.fork_url.clone(),
        rpc_block_number: args.fork_block,
        test_mode: args.mode,
        auto_rank_targets: args.auto_rank_targets,
        ..Default::default()
    };

    let mut campaign = Campaign::new(config);
    let findings = campaign.run()?;
    if findings.is_empty() {
        println!("✅ No invariant violations found.");
        return Ok(());
    }

    println!("🐛 Found {} invariant violation(s):", findings.len());
    for (i, finding) in findings.iter().enumerate() {
        println!("  [{i}] [{}] {}", finding.severity, finding.title);
    }
    if args.fail_fast {
        anyhow::bail!("campaign reported findings and --fail-fast is set");
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn handle_ci(args: sci_fuzz::cli::CiArgs) -> Result<()> {
    use sci_fuzz::cli::CiOutputFormat;
    use sci_fuzz::output::{forge_reproducer, junit_from_findings, sarif_from_findings};
    use sci_fuzz::{campaign::Campaign, project::Project, types::CampaignConfig};
    use std::time::Instant;

    println!("⚡ sci-fuzz ci");
    println!("  project : {}", args.project.display());
    println!("  format  : {:?}", args.output_format);
    println!("  timeout : {}s", args.timeout);
    if args.github_actions {
        println!("  mode    : GitHub Actions");
    }
    println!();

    let project_root = args.project.canonicalize().unwrap_or(args.project.clone());
    println!("running forge build...");

    let (_project, bootstrap, artifact_count) = Project::build_and_select_targets(&project_root)?;
    println!("discovered {} artifact(s)", artifact_count);
    println!("starting security scan...");
    println!();

    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(args.timeout),
        // CI: deterministic budget (enough to be useful, fast enough to not timeout in CI)
        max_execs: Some(50_000),
        max_depth: 30,
        max_snapshots: 512,
        workers: 2,
        seed: 0xcafebabe,
        targets: bootstrap.runtime_targets,
        harness: bootstrap.harness,
        mode: sci_fuzz::types::ExecutorMode::Fast,
        corpus_dir: args.corpus_dir.clone(),
        test_mode: args.mode,
        ..Default::default()
    };

    let start = Instant::now();
    let mut campaign = Campaign::new(config);
    let findings = campaign.run()?;
    let elapsed = start.elapsed().as_secs_f64();

    // Emit GitHub Actions workflow annotations if requested.
    if args.github_actions {
        for f in &findings {
            let level = match f.severity {
                sci_fuzz::types::Severity::Critical | sci_fuzz::types::Severity::High => "error",
                sci_fuzz::types::Severity::Medium => "warning",
                _ => "notice",
            };
            // ::error/warning/notice title=<title>::<message>
            println!(
                "::{level} title={title}::{desc}",
                level = level,
                title = f.title,
                desc = f.description,
            );
        }
    }

    // Build the formatted output string.
    let tool_version = env!("CARGO_PKG_VERSION");
    let output_str = match args.output_format {
        CiOutputFormat::Sarif | CiOutputFormat::GitHub | CiOutputFormat::GitLab => {
            sarif_from_findings(&findings, tool_version)
        }
        CiOutputFormat::Junit => junit_from_findings(&findings, "sci-fuzz", elapsed),
    };

    // Write to file or stdout.
    if let Some(ref out_path) = args.output {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out_path, &output_str)
            .with_context(|| format!("writing output to {}", out_path.display()))?;
        println!("📄 wrote output to: {}", out_path.display());
    } else {
        println!("{output_str}");
    }

    // Optionally save Forge reproducers for each finding.
    if !findings.is_empty() {
        let repro_dir = project_root.join("test").join("repros");
        std::fs::create_dir_all(&repro_dir)?;
        for f in &findings {
            let slug: String = f
                .title
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .take(32)
                .collect::<String>()
                .to_ascii_lowercase();
            let repro_path = repro_dir.join(format!("Repro_{slug}.t.sol"));
            std::fs::write(&repro_path, forge_reproducer(f))?;
            println!("  💾 reproducer: {}", repro_path.display());
        }
    }

    println!();
    if findings.is_empty() {
        println!("✅ No vulnerabilities detected ({elapsed:.1}s).");
        Ok(())
    } else {
        let critical = findings
            .iter()
            .filter(|f| matches!(f.severity, sci_fuzz::types::Severity::Critical))
            .count();
        let high = findings
            .iter()
            .filter(|f| matches!(f.severity, sci_fuzz::types::Severity::High))
            .count();

        println!(
            "🐛 Found {} finding(s): {} critical, {} high ({elapsed:.1}s).",
            findings.len(),
            critical,
            high,
        );

        let should_fail =
            (args.fail_on_critical && critical > 0) || (args.fail_on_high && high > 0);
        if should_fail {
            process::exit(2);
        }
        Ok(())
    }
}

#[cfg(feature = "cli")]
fn handle_diff(args: sci_fuzz::cli::DiffArgs) -> Result<()> {
    use sci_fuzz::diff::{print_diff_result, run_diff};

    if args.reference.is_some() {
        anyhow::bail!("--reference is not implemented in MVP diff mode");
    }
    if args.rpc_url.is_some() {
        anyhow::bail!("--rpc-url is not supported in MVP diff mode");
    }
    if args.depth == 0 {
        anyhow::bail!("--depth must be >= 1");
    }

    // CLI prints introductory info via print_diff_result later or beforehand
    let result = run_diff(&args)?;

    print_diff_result(&result);

    if let Some(out_dir) = args.output {
        std::fs::create_dir_all(&out_dir)?;
        let report_path = out_dir.join("diff_result.json");
        let result_json =
            serde_json::to_string_pretty(&result).context("Failed to serialize diff result")?;
        std::fs::write(&report_path, result_json)?;
        println!("  💾 wrote {}", report_path.display());
    }

    Ok(())
}

#[cfg(feature = "cli")]
fn handle_replay(args: sci_fuzz::cli::ReplayArgs) -> Result<()> {
    use sci_fuzz::campaign::{Campaign, CampaignFindingRecord};
    use sci_fuzz::types::{Address, CampaignConfig, ExecutorMode};

    println!("⚡ sci-fuzz replay");
    println!("  finding  : {}", args.finding.display());
    println!();

    // Load the serialized finding.
    let json = std::fs::read_to_string(&args.finding)
        .with_context(|| format!("failed to read {}", args.finding.display()))?;
    let record: CampaignFindingRecord = serde_json::from_str(&json)
        .with_context(|| "failed to parse finding JSON (expected CampaignFindingRecord)")?;

    println!("  title    : {}", record.finding.title);
    println!("  severity : {}", record.finding.severity);
    println!("  contract : {:#x}", record.finding.contract);
    println!("  repro    : {} tx(s)", record.finding.reproducer.len());
    println!();

    if record.finding.reproducer.is_empty() {
        println!("⚠️  No reproducer sequence in this finding. Nothing to replay.");
        return Ok(());
    }

    // Build project from the --project root.
    let project_root = args.project.canonicalize().unwrap_or(args.project.clone());
    println!("found project: {}", project_root.display());
    println!("running forge build...");
    let (project, bootstrap, artifact_count) =
        sci_fuzz::project::Project::build_and_select_targets(&project_root)?;
    println!("discovered {} artifact(s)", artifact_count);
    println!(
        "selected {} runtime fuzz target(s)",
        bootstrap.runtime_targets.len()
    );
    println!();

    let fork_url = args
        .rpc_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("ETH_RPC_URL").ok())
        .or_else(|| project.eth_rpc_url());

    let attacker_address = args
        .attacker
        .as_ref()
        .map(|s| s.parse::<Address>())
        .transpose()
        .context("invalid --attacker address")?;

    let config = CampaignConfig {
        timeout: std::time::Duration::from_secs(30), // short — replay is deterministic
        max_execs: Some(0), // no fuzzing, just replay
        max_depth: (record.finding.reproducer.len() + 1) as u32,
        max_snapshots: 64,
        workers: 1,
        seed: 0,
        targets: bootstrap.runtime_targets,
        harness: bootstrap.harness,
        mode: ExecutorMode::Fast,
        rpc_url: fork_url,
        rpc_block_number: args.fork_block,
        attacker_address,
        test_mode: sci_fuzz::types::TestMode::default(),
        ..Default::default()
    };

    println!("🔁 Replaying {} tx(s)...", record.finding.reproducer.len());
    let mut campaign = Campaign::new(config);
    let findings = campaign.replay_sequence(&record.finding.reproducer)?;

    println!();
    if findings.is_empty() {
        println!("✅ No violations detected on replay.");
        println!("   (The bug may require specific fork state — try passing --rpc-url)");
    } else {
        println!("🐛 CONFIRMED: {} violation(s) still trigger:", findings.len());
        for (i, f) in findings.iter().enumerate() {
            println!("  [{i}] [{}] {}", f.severity, f.title);
            println!("       {}", f.description);
        }
    }

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
    use sci_fuzz::cli::DiffArgs;

    #[test]
    fn version_is_set() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }

    #[test]
    fn diff_handler_no_longer_stubbed_and_validates_flags() {
        let args = DiffArgs {
            impl_a: "A".into(),
            impl_b: "B".into(),
            project: ".".into(),
            match_contract: None,
            reference: Some("spec".into()),
            rpc_url: None,
            timeout: 1,
            seed: Some(1),
            max_execs: 1,
            depth: 1,
            output: None,
        };
        let err = super::handle_diff(args).unwrap_err();
        assert!(err.to_string().contains("--reference is not implemented"));
    }
}
