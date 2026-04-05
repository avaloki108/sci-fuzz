//! Foundry project integration for Sci-Fuzz
//!
//! This module provides utilities for parsing Foundry projects,
//! extracting contract information, and interfacing with Foundry's
//! build system and configuration.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

use crate::error::{Error, Result};
use crate::types::{Address, Bytes, ContractInfo};

/// Foundry project configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryConfig {
    /// Profile-specific configurations
    #[serde(default)]
    pub profile: HashMap<String, FoundryProfile>,
    /// Dependencies
    #[serde(default)]
    pub dependencies: HashMap<String, FoundryDependency>,
    /// Fuzz configuration
    pub fuzz: Option<FoundryFuzzConfig>,
    /// Invariant configuration
    pub invariant: Option<FoundryInvariantConfig>,
    /// Etherscan configuration
    #[serde(default)]
    pub etherscan: HashMap<String, FoundryEtherscanConfig>,
}

/// Foundry profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryProfile {
    /// Source directory
    pub src: Option<PathBuf>,
    /// Test directory
    pub test: Option<PathBuf>,
    /// Script directory
    pub script: Option<PathBuf>,
    /// Output directory
    pub out: Option<PathBuf>,
    /// Libraries
    pub libraries: Option<Vec<String>>,
    /// Via IR
    pub via_ir: Option<bool>,
    /// Optimizer runs
    pub optimizer_runs: Option<u32>,
    /// Optimizer enabled
    pub optimizer: Option<bool>,
}

/// Foundry dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryDependency {
    /// Git URL
    pub git: Option<String>,
    /// Branch
    pub branch: Option<String>,
    /// Tag
    pub tag: Option<String>,
    /// Rev (commit hash)
    pub rev: Option<String>,
    /// Local path
    pub path: Option<PathBuf>,
}

/// Foundry fuzz configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryFuzzConfig {
    /// Number of runs
    pub runs: Option<u32>,
    /// Maximum test rejection
    pub max_test_rejections: Option<u32>,
    /// Seed
    pub seed: Option<u64>,
    /// Dictionary weight
    pub dictionary_weight: Option<u32>,
    /// Include storage
    pub include_storage: Option<bool>,
    /// Include push bytes
    pub include_push_bytes: Option<bool>,
}

/// Foundry invariant configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryInvariantConfig {
    /// Number of runs
    pub runs: Option<u32>,
    /// Depth
    pub depth: Option<u32>,
    /// Fail on revert
    pub fail_on_revert: Option<bool>,
    /// Call override
    pub call_override: Option<bool>,
    /// Dictionary weight
    pub dictionary_weight: Option<u32>,
}

/// Foundry Etherscan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryEtherscanConfig {
    /// API key
    pub key: String,
    /// API URL
    pub url: Option<String>,
}

/// Represents a Foundry project
#[derive(Debug, Clone)]
pub struct Project {
    /// Project root directory
    pub root: PathBuf,
    /// Foundry configuration
    pub config: Option<FoundryConfig>,
    /// Discovered contracts
    pub contracts: HashMap<Address, ContractInfo>,
    /// Test contracts (for invariant testing)
    pub test_contracts: HashMap<String, PathBuf>,
    /// Scripts directory
    pub scripts_dir: Option<PathBuf>,
    /// Output directory for artifacts
    pub out_dir: Option<PathBuf>,
}

/// Runtime contracts to deploy first, plus an optional Foundry test harness
/// (`setUp()`) selected from `test/` artifacts.
#[derive(Debug, Clone)]
pub struct FuzzBootstrap {
    /// Non-test contracts (typically `src/`). May be empty when only a harness
    /// is available (test-only repositories).
    pub runtime_targets: Vec<ContractInfo>,
    /// At most one harness: deployed after [`Self::runtime_targets`], then
    /// `setUp()` is run by the campaign.
    pub harness: Option<ContractInfo>,
}

/// Returns true if the JSON ABI declares `function setUp()` with no parameters.
pub fn abi_has_set_up(abi: &serde_json::Value) -> bool {
    let Some(arr) = abi.as_array() else {
        return false;
    };
    arr.iter().any(|entry| {
        entry.get("type").and_then(|t| t.as_str()) == Some("function")
            && entry.get("name").and_then(|n| n.as_str()) == Some("setUp")
            && entry
                .get("inputs")
                .and_then(|i| i.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(false)
    })
}

/// True if any ABI function name starts with `echidna_`.
pub fn abi_has_echidna_property(abi: &serde_json::Value) -> bool {
    let Some(arr) = abi.as_array() else {
        return false;
    };
    arr.iter().any(|entry| {
        entry.get("type").and_then(|t| t.as_str()) == Some("function")
            && entry
                .get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.starts_with("echidna_"))
    })
}

impl Project {
    /// Load a Foundry project from a directory
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.exists() {
            return Err(Error::Project(format!(
                "Project root does not exist: {:?}",
                root
            )));
        }

        // Try to load foundry.toml
        let config_path = root.join("foundry.toml");
        let config = if config_path.exists() {
            let config_str = std::fs::read_to_string(&config_path)
                .map_err(|e| Error::Project(format!("Failed to read foundry.toml: {}", e)))?;
            Some(
                toml::from_str(&config_str)
                    .map_err(|e| Error::Project(format!("Failed to parse foundry.toml: {}", e)))?,
            )
        } else {
            None
        };

        let mut project = Self {
            root,
            config,
            contracts: HashMap::new(),
            test_contracts: HashMap::new(),
            scripts_dir: None,
            out_dir: None,
        };

        // Discover contracts and tests
        project.discover_contracts()?;
        project.discover_tests()?;
        project.discover_scripts()?;
        project.out_dir = Some(project.get_out_dir());

        Ok(project)
    }

    /// Run `forge build` for this project.
    pub fn build(&self) -> Result<()> {
        self.build_with_program("forge")
    }

    fn build_with_program(&self, program: impl AsRef<OsStr>) -> Result<()> {
        run_forge_build_with_program(&self.root, program)
    }

    /// Parse contract artifacts from the project's `out/` directory and
    /// populate [`Project::contracts`] with the results.
    pub fn load_artifacts_from_out(&mut self) -> Result<Vec<ContractInfo>> {
        let out_dir = self.get_out_dir();
        self.out_dir = Some(out_dir.clone());

        let artifact_paths = discover_artifact_paths(&out_dir)?;
        let mut contracts = Vec::with_capacity(artifact_paths.len());
        self.contracts.clear();

        for artifact_path in artifact_paths {
            let contract = parse_artifact_file(&artifact_path, &out_dir)?;
            self.contracts.insert(contract.address, contract.clone());
            contracts.push(contract);
        }

        Ok(contracts)
    }

    /// Select runtime (non-test) fuzz targets — same rules as the historical
    /// [`Self::select_fuzz_targets`].
    pub fn select_runtime_targets(&self) -> Vec<ContractInfo> {
        let mut candidates: Vec<ContractInfo> = self
            .contracts
            .values()
            .filter(|contract| !contract.deployed_bytecode.is_empty())
            .filter(|contract| !is_script_artifact(contract))
            .cloned()
            .collect();

        let has_non_test = candidates
            .iter()
            .any(|contract| !is_test_artifact(contract));
        if has_non_test {
            candidates.retain(|contract| !is_test_artifact(contract));
        }

        candidates.sort_by_key(target_sort_key);
        candidates
    }

    /// Backward-compatible alias for [`Self::select_runtime_targets`].
    pub fn select_fuzz_targets(&self) -> Vec<ContractInfo> {
        self.select_runtime_targets()
    }

    /// Test/harness contracts that declare `setUp()`, have creation bytecode,
    /// and are not scripts.
    pub fn select_harness_candidates(&self) -> Vec<ContractInfo> {
        let mut candidates: Vec<ContractInfo> = self
            .contracts
            .values()
            .filter(|c| !c.deployed_bytecode.is_empty())
            .filter(|c| !is_script_artifact(c))
            .filter(|c| is_test_artifact(c))
            .filter(|c| {
                c.creation_bytecode
                    .as_ref()
                    .map(|b| !b.is_empty())
                    .unwrap_or(false)
            })
            .filter(|c| c.abi.as_ref().is_some_and(abi_has_set_up))
            .cloned()
            .collect();

        candidates.sort_by_key(|c| harness_sort_key(c));
        candidates
    }

    /// Build [`FuzzBootstrap`]: runtime targets plus at most one harness
    /// (prefers an `echidna_*` harness when available).
    pub fn prepare_fuzz_bootstrap(&self) -> Result<FuzzBootstrap> {
        let runtime_targets = self.select_runtime_targets();
        let mut harness_candidates = self.select_harness_candidates();
        harness_candidates.sort_by_key(|c| {
            let prefers_echidna = c
                .abi
                .as_ref()
                .map(|a| abi_has_echidna_property(a))
                .unwrap_or(false);
            (
                !prefers_echidna,
                harness_sort_key(c),
            )
        });

        let harness = harness_candidates.into_iter().next();

        if runtime_targets.is_empty() && harness.is_none() {
            return Err(Error::Project(format!(
                "No fuzzable contracts or harnesses in {} after artifact ingestion",
                self.get_out_dir().display()
            )));
        }

        Ok(FuzzBootstrap {
            runtime_targets,
            harness,
        })
    }

    /// End-to-end Foundry project loading for fuzzing:
    /// load config, run `forge build`, ingest artifacts, and build a bootstrap plan.
    pub fn build_and_select_targets(
        root: impl AsRef<Path>,
    ) -> Result<(Self, FuzzBootstrap, usize)> {
        Self::build_and_select_targets_with_program(root, "forge")
    }

    fn build_and_select_targets_with_program(
        root: impl AsRef<Path>,
        program: impl AsRef<OsStr>,
    ) -> Result<(Self, FuzzBootstrap, usize)> {
        let mut project = Self::load(root)?;
        project.build_with_program(program)?;
        let artifact_count = project.load_artifacts_from_out()?.len();
        let bootstrap = project.prepare_fuzz_bootstrap()?;

        Ok((project, bootstrap, artifact_count))
    }

    /// Discover contracts in the project
    fn discover_contracts(&mut self) -> Result<()> {
        // Determine source directory from config or default
        let src_dir = self
            .config
            .as_ref()
            .and_then(|c| {
                c.profile
                    .get("default")
                    .and_then(|p| p.src.as_ref())
                    .cloned()
            })
            .map(|path| self.resolve_project_path(path))
            .unwrap_or_else(|| self.root.join("src"));

        if !src_dir.exists() {
            return Ok(()); // No source directory
        }

        // Walk the source directory looking for .sol files
        let walker = walkdir::WalkDir::new(&src_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .map(|ext| ext == "sol")
                        .unwrap_or(false)
            });

        for entry in walker {
            let path = entry.path();
            // For now, we just note the path. In a real implementation,
            // we would compile and extract contract information.
            tracing::debug!("Found contract source: {:?}", path);
        }

        Ok(())
    }

    /// Discover test contracts
    fn discover_tests(&mut self) -> Result<()> {
        // Determine test directory from config or default
        let test_dir = self
            .config
            .as_ref()
            .and_then(|c| {
                c.profile
                    .get("default")
                    .and_then(|p| p.test.as_ref())
                    .cloned()
            })
            .map(|path| self.resolve_project_path(path))
            .unwrap_or_else(|| self.root.join("test"));

        if !test_dir.exists() {
            return Ok(()); // No test directory
        }

        // Walk the test directory looking for .sol files
        let walker = walkdir::WalkDir::new(&test_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .map(|ext| ext == "sol")
                        .unwrap_or(false)
            });

        for entry in walker {
            let path = entry.path();
            let file_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();

            // Extract contract name from file (simplified)
            // In reality, would parse Solidity to find contract names
            self.test_contracts.insert(file_stem, path.to_path_buf());
        }

        Ok(())
    }

    /// Discover script files
    fn discover_scripts(&mut self) -> Result<()> {
        // Determine script directory from config or default
        let script_dir = self
            .config
            .as_ref()
            .and_then(|c| {
                c.profile
                    .get("default")
                    .and_then(|p| p.script.as_ref())
                    .cloned()
            })
            .map(|path| self.resolve_project_path(path))
            .unwrap_or_else(|| self.root.join("script"));

        if script_dir.exists() {
            self.scripts_dir = Some(script_dir);
        }

        Ok(())
    }

    /// Get the output directory for artifacts
    pub fn get_out_dir(&self) -> PathBuf {
        self.config
            .as_ref()
            .and_then(|c| {
                c.profile
                    .get("default")
                    .and_then(|p| p.out.as_ref())
                    .cloned()
            })
            .map(|path| self.resolve_project_path(path))
            .unwrap_or_else(|| self.root.join("out"))
    }

    /// Check if this is a valid Foundry project
    pub fn is_valid(&self) -> bool {
        // A project is valid if it has at least some contract sources or tests
        !self.contracts.is_empty() || !self.test_contracts.is_empty()
    }

    /// Get contract by address (for forked mode)
    pub fn get_contract(&self, address: Address) -> Option<&ContractInfo> {
        self.contracts.get(&address)
    }

    /// Get test contract by name
    pub fn get_test_contract(&self, name: &str) -> Option<&PathBuf> {
        self.test_contracts.get(name)
    }

    /// Get all test contract names
    pub fn test_contract_names(&self) -> Vec<&String> {
        self.test_contracts.keys().collect()
    }

    /// Add a contract to the project (e.g., from forked chain)
    pub fn add_contract(&mut self, address: Address, contract: ContractInfo) {
        self.contracts.insert(address, contract);
    }

    /// Get fuzz configuration from foundry.toml
    pub fn get_fuzz_config(&self) -> Option<&FoundryFuzzConfig> {
        self.config.as_ref().and_then(|c| c.fuzz.as_ref())
    }

    /// Get invariant configuration from foundry.toml
    pub fn get_invariant_config(&self) -> Option<&FoundryInvariantConfig> {
        self.config.as_ref().and_then(|c| c.invariant.as_ref())
    }

    /// Get Etherscan API key for a chain
    pub fn get_etherscan_key(&self, chain: &str) -> Option<&str> {
        self.config
            .as_ref()
            .and_then(|c| c.etherscan.get(chain))
            .map(|config| config.key.as_str())
    }

    fn resolve_project_path(&self, path: PathBuf) -> PathBuf {
        if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        }
    }
}

fn run_forge_build_with_program(root: &Path, program: impl AsRef<OsStr>) -> Result<()> {
    let program = program.as_ref();
    let output = Command::new(program)
        .arg("build")
        .current_dir(root)
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => Error::Project(format!(
                "Failed to run `{} build`: binary not found. Install Foundry and ensure `forge` is on PATH.",
                program.to_string_lossy()
            )),
            _ => Error::Project(format!(
                "Failed to run `{} build`: {}",
                program.to_string_lossy(),
                err
            )),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit status {}", output.status)
        };

        return Err(Error::Project(format!(
            "`{} build` failed in {}: {}",
            program.to_string_lossy(),
            root.display(),
            detail
        )));
    }

    Ok(())
}

fn discover_artifact_paths(out_dir: &Path) -> Result<Vec<PathBuf>> {
    if !out_dir.exists() {
        return Err(Error::Project(format!(
            "Foundry output directory does not exist: {}",
            out_dir.display()
        )));
    }

    let mut artifacts = Vec::new();
    for entry in walkdir::WalkDir::new(out_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.ends_with(".dbg.json") || file_name.ends_with(".metadata.json") {
            continue;
        }

        let rel = path.strip_prefix(out_dir).unwrap_or(path);
        if rel
            .components()
            .any(|component| component.as_os_str() == OsStr::new("build-info"))
        {
            continue;
        }

        artifacts.push(path.to_path_buf());
    }

    artifacts.sort();
    Ok(artifacts)
}

fn parse_artifact_file(artifact_path: &Path, out_dir: &Path) -> Result<ContractInfo> {
    let artifact_str = std::fs::read_to_string(artifact_path).map_err(|err| {
        Error::Project(format!(
            "Failed to read Foundry artifact {}: {}",
            artifact_path.display(),
            err
        ))
    })?;
    let artifact: Value = serde_json::from_str(&artifact_str).map_err(|err| {
        Error::Project(format!(
            "Failed to parse Foundry artifact {}: {}",
            artifact_path.display(),
            err
        ))
    })?;

    let source_path = extract_source_path(&artifact, artifact_path, out_dir);
    let contract_name = artifact
        .get("contractName")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            artifact
                .get("compilationTarget")
                .and_then(Value::as_object)
                .and_then(|target| target.values().next())
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            artifact_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            Error::Project(format!(
                "Could not determine contract name for artifact {}",
                artifact_path.display()
            ))
        })?;

    let abi = artifact
        .get("abi")
        .cloned()
        .filter(|value| !value.is_null());
    let creation_bytecode = extract_bytecode(
        &artifact,
        &[
            &["bytecode"],
            &["bytecode", "object"],
            &["evm", "bytecode", "object"],
        ],
        artifact_path,
    )?;
    let deployed_bytecode = extract_bytecode(
        &artifact,
        &[
            &["deployedBytecode"],
            &["deployedBytecode", "object"],
            &["evm", "deployedBytecode", "object"],
        ],
        artifact_path,
    )?
    .unwrap_or_default();

    Ok(ContractInfo {
        address: synthetic_contract_address(&source_path, &contract_name),
        deployed_bytecode,
        creation_bytecode,
        name: Some(contract_name),
        source_path: Some(source_path),
        abi,
    })
}

fn extract_source_path(artifact: &Value, artifact_path: &Path, out_dir: &Path) -> String {
    if let Some(source_path) = artifact
        .get("compilationTarget")
        .and_then(Value::as_object)
        .and_then(|target| target.keys().next())
    {
        return source_path.to_string();
    }

    let rel = artifact_path.strip_prefix(out_dir).unwrap_or(artifact_path);
    rel.parent()
        .map(|parent| parent.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

fn extract_bytecode(
    artifact: &Value,
    candidate_paths: &[&[&str]],
    artifact_path: &Path,
) -> Result<Option<Bytes>> {
    for path in candidate_paths {
        if let Some(value) = get_nested(artifact, path) {
            if let Some(bytes) = decode_bytecode_value(value, artifact_path)? {
                return Ok(Some(bytes));
            }
        }
    }

    Ok(None)
}

fn decode_bytecode_value(value: &Value, artifact_path: &Path) -> Result<Option<Bytes>> {
    match value {
        Value::Null => Ok(None),
        Value::String(raw) => decode_hex_bytes(raw, artifact_path),
        Value::Object(object) => {
            if let Some(raw) = object.get("object").and_then(Value::as_str) {
                decode_hex_bytes(raw, artifact_path)
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn decode_hex_bytes(raw: &str, artifact_path: &Path) -> Result<Option<Bytes>> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Ok(None);
    }

    let bytes = hex::decode(trimmed).map_err(|err| {
        Error::Project(format!(
            "Invalid hex bytecode in artifact {}: {}",
            artifact_path.display(),
            err
        ))
    })?;
    Ok(Some(Bytes::from(bytes)))
}

fn get_nested<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn synthetic_contract_address(source_path: &str, contract_name: &str) -> Address {
    let mut keccak = Keccak::v256();
    keccak.update(source_path.as_bytes());
    keccak.update(&[0xff]);
    keccak.update(contract_name.as_bytes());

    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    Address::from_slice(&hash[12..])
}

fn is_script_artifact(contract: &ContractInfo) -> bool {
    let source_path = contract
        .source_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = contract
        .name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    source_path.starts_with("script/")
        || source_path.contains("/script/")
        || source_path.ends_with(".s.sol")
        || name.ends_with("script")
}

fn is_test_artifact(contract: &ContractInfo) -> bool {
    let source_path = contract
        .source_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = contract
        .name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    source_path.starts_with("test/")
        || source_path.contains("/test/")
        || source_path.ends_with(".t.sol")
        || name.ends_with("test")
}

fn target_sort_key(contract: &ContractInfo) -> (u8, String, String) {
    let source_path = contract
        .source_path
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/");
    let rank = if source_path.starts_with("src/") || source_path == "src" {
        0
    } else {
        1
    };

    (
        rank,
        source_path.to_ascii_lowercase(),
        contract
            .name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
    )
}

fn harness_sort_key(contract: &ContractInfo) -> (u8, String, String) {
    target_sort_key(contract)
}

/// Try to detect the contract type from source code or bytecode
/// Heuristic contract classification based on function selectors in bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Erc20,
    Erc721,
    Erc1155,
}

pub fn detect_contract_type(bytecode: &[u8], source: Option<&str>) -> Option<ContractKind> {
    // Simple heuristic based on function signatures in bytecode
    let hex_bytecode = hex::encode(bytecode);

    // Check for ERC20 signatures
    let erc20_sigs = [
        "18160ddd", // totalSupply()
        "70a08231", // balanceOf(address)
        "a9059cbb", // transfer(address,uint256)
    ];

    let erc20_matches = erc20_sigs
        .iter()
        .filter(|sig| hex_bytecode.contains(*sig))
        .count();

    if erc20_matches >= 2 {
        return Some(ContractKind::Erc20);
    }

    // Check for ERC721 signatures
    let erc721_sigs = [
        "6352211e", // ownerOf(uint256)
        "42842e0e", // safeTransferFrom(address,address,uint256)
    ];

    let erc721_matches = erc721_sigs
        .iter()
        .filter(|sig| hex_bytecode.contains(*sig))
        .count();

    if erc721_matches >= 2 {
        return Some(ContractKind::Erc721);
    }

    // Check source code for contract type hints
    if let Some(source_code) = source {
        if source_code.contains("contract ERC20") || source_code.contains("IERC20") {
            return Some(ContractKind::Erc20);
        }
        if source_code.contains("contract ERC721") || source_code.contains("IERC721") {
            return Some(ContractKind::Erc721);
        }
        if source_code.contains("contract ERC1155") || source_code.contains("IERC1155") {
            return Some(ContractKind::Erc1155);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn write_artifact(
        out_dir: &Path,
        source_path: &str,
        contract_name: &str,
        creation_bytecode: Option<&str>,
        deployed_bytecode: &str,
    ) -> PathBuf {
        let artifact_dir = out_dir.join(source_path);
        fs::create_dir_all(&artifact_dir).unwrap();

        let artifact_path = artifact_dir.join(format!("{contract_name}.json"));
        let artifact = json!({
            "contractName": contract_name,
            "abi": [
                {
                    "type": "function",
                    "name": "echidna_ok",
                    "inputs": [],
                    "outputs": [{"type": "bool"}],
                    "stateMutability": "view"
                }
            ],
            "bytecode": { "object": creation_bytecode.unwrap_or("0x") },
            "deployedBytecode": { "object": deployed_bytecode },
            "compilationTarget": { source_path: contract_name }
        });

        fs::write(
            &artifact_path,
            serde_json::to_vec_pretty(&artifact).unwrap(),
        )
        .unwrap();
        artifact_path
    }

    fn write_foundry_toml(root: &Path) {
        fs::write(
            root.join("foundry.toml"),
            "[profile.default]\nsrc = 'src'\nout = 'out'\n",
        )
        .unwrap();
    }

    fn write_executable_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms).unwrap();
        }
    }

    #[test]
    fn test_project_load_nonexistent() {
        let result = Project::load("/nonexistent/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_project_load_empty_dir() {
        let dir = tempdir().unwrap();
        let project = Project::load(dir.path());
        assert!(project.is_ok());
        let project = project.unwrap();
        assert!(!project.is_valid()); // No contracts or tests
    }

    #[test]
    fn test_detect_contract_type() {
        // Empty bytecode
        assert!(detect_contract_type(&[], None).is_none());

        // Bytecode with ERC20 signatures (simulated)
        let erc20_bytecode = hex::decode("18160ddd70a08231a9059cbb").unwrap(); // Just signatures for test
        assert_eq!(
            detect_contract_type(&erc20_bytecode, None),
            Some(ContractKind::Erc20)
        );
    }

    #[test]
    fn parse_foundry_artifact_into_contract_info() {
        let dir = tempdir().unwrap();
        let out_dir = dir.path().join("out");
        let artifact_path = write_artifact(
            &out_dir,
            "src/Vault.sol",
            "Vault",
            Some("0x600a600c600039600a6000f3602a60005260206000f3"),
            "0x602a60005260206000f3",
        );

        let contract = parse_artifact_file(&artifact_path, &out_dir).unwrap();
        assert_eq!(contract.name.as_deref(), Some("Vault"));
        assert_eq!(contract.source_path.as_deref(), Some("src/Vault.sol"));
        assert_eq!(
            contract.creation_bytecode,
            Some(Bytes::from(
                hex::decode("600a600c600039600a6000f3602a60005260206000f3").unwrap()
            ))
        );
        assert_eq!(
            contract.deployed_bytecode,
            Bytes::from(hex::decode("602a60005260206000f3").unwrap())
        );
        assert!(contract.abi.is_some());
    }

    #[test]
    fn select_fuzzable_contracts_from_mock_out_tree() {
        let dir = tempdir().unwrap();
        write_foundry_toml(dir.path());
        let out_dir = dir.path().join("out");

        write_artifact(
            &out_dir,
            "src/Vault.sol",
            "Vault",
            Some("0x60006000f3"),
            "0x60006000f3",
        );
        write_artifact(
            &out_dir,
            "test/Vault.t.sol",
            "VaultTest",
            Some("0x60006000f3"),
            "0x60006000f3",
        );
        write_artifact(
            &out_dir,
            "script/Deploy.s.sol",
            "DeployScript",
            Some("0x60006000f3"),
            "0x60006000f3",
        );
        write_artifact(&out_dir, "src/IVault.sol", "IVault", Some("0x"), "0x");

        let mut project = Project::load(dir.path()).unwrap();
        let parsed = project.load_artifacts_from_out().unwrap();
        assert_eq!(parsed.len(), 4);

        let targets = project.select_fuzz_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name.as_deref(), Some("Vault"));
        assert_eq!(targets[0].source_path.as_deref(), Some("src/Vault.sol"));
    }

    #[test]
    fn load_minimal_foundry_project_with_out_artifacts() {
        let dir = tempdir().unwrap();
        write_foundry_toml(dir.path());
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/Vault.sol"), "contract Vault {}").unwrap();
        let out_dir = dir.path().join("out");
        write_artifact(
            &out_dir,
            "src/Vault.sol",
            "Vault",
            Some("0x60006000f3"),
            "0x60006000f3",
        );

        let mut project = Project::load(dir.path()).unwrap();
        let parsed = project.load_artifacts_from_out().unwrap();

        assert_eq!(parsed.len(), 1);
        assert!(project.is_valid());
        assert_eq!(project.get_out_dir(), out_dir);

        let contract = project.contracts.values().next().unwrap();
        assert_eq!(contract.name.as_deref(), Some("Vault"));
    }

    #[test]
    fn forge_build_reports_missing_binary_and_failures() {
        let dir = tempdir().unwrap();
        let missing =
            run_forge_build_with_program(dir.path(), "definitely-not-a-real-forge-binary")
                .unwrap_err();
        assert!(missing.to_string().contains("binary not found"));

        let failing_script = dir.path().join("fake-forge-fail");
        write_executable_script(
            &failing_script,
            "#!/bin/sh\nprintf 'boom from fake forge\\n' >&2\nexit 1\n",
        );

        let failed = run_forge_build_with_program(dir.path(), &failing_script).unwrap_err();
        assert!(failed.to_string().contains("boom from fake forge"));
    }

    #[test]
    fn build_and_select_targets_produces_campaign_targets() {
        let dir = tempdir().unwrap();
        write_foundry_toml(dir.path());
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/Vault.sol"), "contract Vault {}").unwrap();

        let forge_script = dir.path().join("fake-forge");
        let out_dir = dir.path().join("out");
        let artifact_dir = out_dir.join("src/Vault.sol");
        let artifact_path = artifact_dir.join("Vault.json");
        write_executable_script(
            &forge_script,
            &format!(
                "#!/bin/sh\nmkdir -p '{}'\ncat > '{}' <<'JSON'\n{}\nJSON\n",
                artifact_dir.display(),
                artifact_path.display(),
                json!({
                    "contractName": "Vault",
                    "abi": [],
                    "bytecode": { "object": "0x60006000f3" },
                    "deployedBytecode": { "object": "0x60006000f3" },
                    "compilationTarget": { "src/Vault.sol": "Vault" }
                })
            ),
        );

        let (_project, bootstrap, artifact_count) =
            Project::build_and_select_targets_with_program(dir.path(), &forge_script).unwrap();

        assert_eq!(artifact_count, 1);
        assert_eq!(bootstrap.runtime_targets.len(), 1);
        assert!(bootstrap.harness.is_none());
        assert_eq!(bootstrap.runtime_targets[0].name.as_deref(), Some("Vault"));

        let config = crate::types::CampaignConfig {
            targets: bootstrap.runtime_targets,
            ..crate::types::CampaignConfig::default()
        };
        assert_eq!(config.targets.len(), 1);
    }
}
