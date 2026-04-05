//! Foundry project integration for Sci-Fuzz
//!
//! This module provides utilities for parsing Foundry projects,
//! extracting contract information, and interfacing with Foundry's
//! build system and configuration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{Address, ContractInfo};

/// Foundry project configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryConfig {
    /// Profile-specific configurations
    pub profile: HashMap<String, FoundryProfile>,
    /// Dependencies
    pub dependencies: HashMap<String, FoundryDependency>,
    /// Fuzz configuration
    pub fuzz: Option<FoundryFuzzConfig>,
    /// Invariant configuration
    pub invariant: Option<FoundryInvariantConfig>,
    /// Etherscan configuration
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

        Ok(project)
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
    use tempfile::tempdir;

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
}
