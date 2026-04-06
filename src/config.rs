//! sci-fuzz configuration file support.
//!
//! Loads campaign settings from `sci-fuzz.toml` in the project root or from
//! a path specified via `--config <path>`.  CLI flags override file values.
//!
//! ## Example `sci-fuzz.toml`
//!
//! ```toml
//! [campaign]
//! mode = "property"
//! timeout = 3600
//! depth = 50
//! workers = 4
//! seed = 42
//! corpus_dir = "./corpus"
//!
//! [campaign.system]
//! enabled = true
//! extra_senders = ["0xaaaa...bbbb", "0xcccc...dddd"]
//!
//! [campaign.system.target_weights]
//! "0xABCDEF..." = 3
//!
//! [campaign.system.selector_weights]
//! "0xd0e30db0" = 5
//!
//! [campaign.invariants]
//! infer = true
//! prefixes = ["BalanceIncrease", "FlashloanEconomic"]
//!
//! [output]
//! format = "text"    # "text" | "json" | "sarif" | "junit"
//! save_report = true
//! replay = true
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cli::ForgeArgs;
use crate::types::{Address, TestMode};

// ---------------------------------------------------------------------------
// Config file schema
// ---------------------------------------------------------------------------

/// Top-level sci-fuzz config file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SciFuzzConfig {
    #[serde(default)]
    pub campaign: CampaignSection,
    #[serde(default)]
    pub output: OutputSection,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CampaignSection {
    pub mode: Option<String>,
    pub timeout: Option<u64>,
    pub depth: Option<u32>,
    pub max_execs: Option<u64>,
    pub workers: Option<usize>,
    pub seed: Option<u64>,
    pub corpus_dir: Option<String>,
    pub fork_url: Option<String>,
    pub fork_block: Option<u64>,
    pub attacker: Option<String>,
    pub fail_on_critical: Option<bool>,
    pub snapshots: Option<bool>,
    pub max_snapshots: Option<usize>,
    pub snapshot_strategy: Option<String>,
    pub system: SystemSection,
    pub invariants: InvariantsSection,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SystemSection {
    pub enabled: Option<bool>,
    pub extra_senders: Option<Vec<String>>,
    /// Target address → weight (as hex strings).
    pub target_weights: Option<HashMap<String, u32>>,
    /// Selector hex → weight.
    pub selector_weights: Option<HashMap<String, u32>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InvariantsSection {
    pub infer: Option<bool>,
    /// Only run invariants whose names start with one of these prefixes.
    pub prefixes: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputSection {
    pub format: Option<String>,
    pub save_report: Option<bool>,
    /// Generate Forge reproducer scripts for findings.
    pub replay: Option<bool>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

const CONFIG_FILENAME: &str = "sci-fuzz.toml";

/// Try to load config from:
/// 1. `--config <path>` if provided
/// 2. `<project>/sci-fuzz.toml`
/// 3. CWD `sci-fuzz.toml`
pub fn load_config(explicit_path: Option<&str>, project_dir: &Path) -> anyhow::Result<SciFuzzConfig> {
    if let Some(path) = explicit_path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
        let config: SciFuzzConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", path, e))?;
        return Ok(config);
    }

    // Try project dir first, then CWD.
    for dir in &[project_dir, Path::new(".")] {
        let path = dir.join(CONFIG_FILENAME);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let config: SciFuzzConfig = toml::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
            eprintln!("[config] loaded {}", path.display());
            return Ok(config);
        }
    }

    Ok(SciFuzzConfig::default())
}

// ---------------------------------------------------------------------------
// Merge: CLI overrides file values
// ---------------------------------------------------------------------------

/// Merged campaign settings after applying CLI overrides on top of config file.
pub struct ResolvedCampaignSettings {
    pub mode: TestMode,
    pub timeout: u64,
    pub depth: u32,
    pub max_execs: Option<u64>,
    pub workers: usize,
    pub seed: Option<u64>,
    pub corpus_dir: Option<String>,
    pub fork_url: Option<String>,
    pub fork_block: Option<u64>,
    pub attacker: Option<Address>,
    pub system_mode: bool,
    pub extra_senders: Vec<String>,
    pub target_weights: Vec<String>,
    pub selector_weights: Vec<String>,
    pub infer_invariants: bool,
    pub invariant_prefixes: Vec<String>,
    pub output_format: OutputFormat,
    pub save_report: bool,
    pub replay: bool,
    pub fail_on_critical: bool,
    pub snapshots: bool,
    pub max_snapshots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Junit,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "junit" => Ok(OutputFormat::Junit),
            _ => Err(anyhow::anyhow!("unknown output format: '{}'. Use: text, json, sarif, junit", s)),
        }
    }
}

impl ResolvedCampaignSettings {
    /// Resolve settings by layering CLI args over config file.
    pub fn from_cli_and_file(args: &ForgeArgs, config: &SciFuzzConfig) -> Self {
        let mode = args.mode; // CLI always wins for mode
        let timeout = args.timeout;
        let depth = args.depth;
        let max_execs = None; // TODO: add --max-execs CLI flag
        let workers = args.workers;
        let seed = args.seed;
        let corpus_dir = args.corpus_dir.as_ref().map(|p| p.to_string_lossy().to_string())
            .or(config.campaign.corpus_dir.clone());
        let fork_url = args.fork_url.clone()
            .or(config.campaign.fork_url.clone());
        let fork_block = args.fork_block
            .or(config.campaign.fork_block);

        // System mode
        let system_mode = args.system_mode
            || config.campaign.system.enabled.unwrap_or(false);

        // Extra senders: CLI + config file
        let mut extra_senders = args.extra_senders.clone();
        if let Some(ref file_senders) = config.campaign.system.extra_senders {
            for s in file_senders {
                if !extra_senders.contains(s) {
                    extra_senders.push(s.clone());
                }
            }
        }

        // Target weights: CLI + config file
        let mut target_weights = args.target_weight.clone();
        if let Some(ref file_tw) = config.campaign.system.target_weights {
            for (addr, w) in file_tw {
                let entry = format!("{}:{}", addr, w);
                if !target_weights.contains(&entry) {
                    target_weights.push(entry);
                }
            }
        }

        // Selector weights: CLI + config file
        let mut selector_weights = args.selector_weight.clone();
        if let Some(ref file_sw) = config.campaign.system.selector_weights {
            for (sel, w) in file_sw {
                let entry = format!("{}:{}", sel, w);
                if !selector_weights.contains(&entry) {
                    selector_weights.push(entry);
                }
            }
        }

        // Inferred invariants
        let infer_invariants = args.infer_invariants
            && config.campaign.invariants.infer.unwrap_or(true);

        // Invariant prefixes filter
        let invariant_prefixes = config
            .campaign
            .invariants
            .prefixes
            .clone()
            .unwrap_or_default();

        // Output format: CLI wins over config file
        let _output_format = if let Some(ref fmt) = config.output.format {
            fmt.parse::<OutputFormat>().unwrap_or(OutputFormat::Text)
        } else {
            OutputFormat::Text
        };

        // Save report
        let save_report = config.output.save_report.unwrap_or(false);

        // Replay generation
        let replay = config.output.replay.unwrap_or(true);

        let fail_on_critical = args.fail_on_critical
            || config.campaign.fail_on_critical.unwrap_or(false);

        let snapshots = args.snapshots
            || config.campaign.snapshots.unwrap_or(false);
        let max_snapshots = args.max_snapshots;

        Self {
            mode,
            timeout,
            depth,
            max_execs,
            workers,
            seed,
            corpus_dir,
            fork_url,
            fork_block,
            attacker: None, // Parsed separately in main.rs
            system_mode,
            extra_senders,
            target_weights,
            selector_weights,
            infer_invariants,
            invariant_prefixes,
            output_format: OutputFormat::Text,
            save_report,
            replay,
            fail_on_critical,
            snapshots,
            max_snapshots,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_config() {
        let config: SciFuzzConfig = toml::from_str("").unwrap();
        assert!(config.campaign.mode.is_none());
        assert!(config.output.format.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
[campaign]
mode = "assertion"
timeout = 1800
depth = 30
workers = 8
corpus_dir = "./fuzz-corpus"
attacker = "0x4242424242424242424242424242424242424242"

[campaign.system]
enabled = true
extra_senders = ["0xaaaa", "0xbbbb"]

[campaign.system.target_weights]
"0xdead" = 3

[campaign.system.selector_weights]
"0xd0e30db0" = 5

[campaign.invariants]
infer = true
prefixes = ["Flashloan", "Reentrancy"]

[output]
format = "json"
save_report = true
replay = true
"#;
        let config: SciFuzzConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.campaign.mode.as_deref(), Some("assertion"));
        assert_eq!(config.campaign.timeout, Some(1800));
        assert_eq!(config.campaign.workers, Some(8));
        assert!(config.campaign.system.enabled.unwrap());
        assert_eq!(config.campaign.system.extra_senders.as_ref().unwrap().len(), 2);
        assert_eq!(config.campaign.system.target_weights.as_ref().unwrap().get("0xdead"), Some(&3));
        assert!(config.campaign.invariants.infer.unwrap());
        assert_eq!(config.campaign.invariants.prefixes.as_ref().unwrap().len(), 2);
        assert_eq!(config.output.format.as_deref(), Some("json"));
    }

    #[test]
    fn output_format_parse() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("bogus".parse::<OutputFormat>().is_err());
    }
}
