//! Campaign bootstrap: preflight RPC targets, deploy vs attach, harness `setUp()`.

use crate::evm::EvmExecutor;
use crate::types::{
    BootstrapMode, BootstrapOutcome, Bytes, CampaignConfig, ContractInfo, DeployFailureReport,
    SetupReport, Address,
};

/// One row in `targets` array (preferred manifest format).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ManifestTargetEntry {
    pub name: String,
    pub address: String,
}

/// JSON manifest for fork targets (file path or `--addresses manifest.json`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AddressManifestFile {
    #[serde(default, alias = "chainId")]
    pub chain_id: Option<u64>,
    #[serde(default, alias = "rpcLabel")]
    pub rpc_label: Option<String>,
    /// Legacy: named address → hex string.
    #[serde(default)]
    pub contracts: std::collections::HashMap<String, String>,
    /// Preferred: `[{ "name": "Vault", "address": "0x..." }]`
    #[serde(default)]
    pub targets: Vec<ManifestTargetEntry>,
}

/// Parsed manifest for CLI / config.
#[derive(Debug, Clone)]
pub struct AddressManifest {
    pub chain_id: Option<u64>,
    pub rpc_label: Option<String>,
    pub contracts: Vec<(String, Address)>,
}

impl AddressManifest {
    pub fn from_json_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let raw: AddressManifestFile = serde_json::from_slice(bytes)?;
        let chain_id = raw.chain_id;
        let rpc_label = raw.rpc_label;
        let mut contracts = Vec::new();
        if !raw.targets.is_empty() {
            for t in raw.targets {
                let addr: Address = t
                    .address
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid address for {}: {e}", t.name))?;
                contracts.push((t.name, addr));
            }
        } else {
            for (label, addr_str) in raw.contracts {
                let addr: Address = addr_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid address for {label}: {e}"))?;
                contracts.push((label, addr));
            }
        }
        Ok(AddressManifest {
            chain_id,
            rpc_label,
            contracts,
        })
    }

    /// Load from a path or parse inline JSON (if content looks like `{`).
    pub fn load_path_or_inline(path_or_json: &str) -> anyhow::Result<Self> {
        let p = path_or_json.trim();
        if p.starts_with('{') {
            return Self::from_json_slice(p.as_bytes());
        }
        let bytes = std::fs::read(p)
            .map_err(|e| anyhow::anyhow!("failed to read address manifest {p}: {e}"))?;
        Self::from_json_slice(&bytes)
    }
}

fn deployment_bytecode(target: &ContractInfo) -> Bytes {
    target
        .creation_bytecode
        .clone()
        .filter(|code| !code.is_empty())
        .unwrap_or_else(|| target.deployed_bytecode.clone())
}

/// Preflight-only: clone and enrich targets (RPC code fetch).
pub fn preflight_work_targets(config: &CampaignConfig) -> anyhow::Result<Vec<ContractInfo>> {
    let mut work_targets = config.targets.clone();
    for target in &mut work_targets {
        let deploy_bytecode = deployment_bytecode(target);
        if deploy_bytecode.is_empty() {
            if target.address.is_zero() {
                anyhow::bail!(
                    "target has no deployment bytecode and address is zero — set a deployed contract address"
                );
            }
            if let Some(ref url) = config.rpc_url {
                let u = url.trim();
                if !u.is_empty() {
                    let pre = crate::rpc::preflight_deployed_target_enriched(
                        u,
                        config.rpc_block_number,
                        target.address,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("preflight failed for target {}: {e:#}", target.address)
                    })?;
                    eprintln!(
                        "[bootstrap] preflight: {} code_size={} bytes proxy_hint={:?}",
                        target.address,
                        pre.code.len(),
                        pre.proxy_hint
                    );
                    if config.fork_hydrate_deployed_bytecode {
                        target.deployed_bytecode = Bytes::from(pre.code);
                    }
                }
            }
        }
    }
    Ok(work_targets)
}

/// Deploy or attach targets, optional harness + setUp. Used by the main campaign loop.
pub fn bootstrap_targets(
    executor: &mut EvmExecutor,
    config: &CampaignConfig,
    attacker: Address,
) -> anyhow::Result<BootstrapOutcome> {
    let mode = BootstrapMode::infer(config);
    let work_targets = preflight_work_targets(config)?;

    if config.rpc_url.is_some() {
        let any_local = work_targets.iter().any(|t| !deployment_bytecode(t).is_empty());
        if any_local {
            eprintln!(
                "[bootstrap] fork: deploying local bytecode onto forked state (not Forge script replay); predeploys use code at the pinned block"
            );
        }
        if !config.fork_allow_local_deploy {
            for t in &work_targets {
                if !deployment_bytecode(t).is_empty() {
                    anyhow::bail!(
                        "fork attach-only mode: target {:?} has deployment bytecode — remove bytecode from config or set fork_allow_local_deploy=true (ForkHybrid)",
                        t.name.as_deref().unwrap_or("?")
                    );
                }
            }
        }
    }

    let mut deployed_targets: Vec<ContractInfo> = Vec::new();
    let mut deploy_failures: Vec<DeployFailureReport> = Vec::new();

    // ── Library linking pre-pass ──────────────────────────────────────────────
    // Some contracts (e.g. Echidna harnesses built with internal Solidity
    // libraries) have bytecode with 20-byte placeholder slots that must be
    // filled with the deployed address of each library before the contract can
    // be deployed.  We detect these via the `link_references` map populated at
    // artifact-load time.
    //
    // Strategy:
    //   1. Collect all targets that need linking (non-empty link_references).
    //   2. Build a name→bytecode map from the full target list (libraries
    //      themselves have empty link_references and a name matching what other
    //      contracts want to link against).
    //   3. Deploy each required library once, track its address.
    //   4. Clone and patch the bytecode of every target that references them.
    //
    // Libraries are deployed from `work_targets`; they are NOT added to
    // `deployed_targets` (they're internals, not fuzz targets).

    let mut lib_addresses: std::collections::HashMap<String, Address> =
        std::collections::HashMap::new();

    // Collect names of libraries that are needed.
    let needed_libs: std::collections::HashSet<String> = work_targets
        .iter()
        .flat_map(|t| t.link_references.keys().cloned())
        .collect();

    if !needed_libs.is_empty() {
        eprintln!(
            "[bootstrap] library linking needed for: {:?}",
            needed_libs
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
        );

        // Find library bytecode from targets or harness.
        let all_candidates: Vec<&ContractInfo> = work_targets
            .iter()
            .chain(config.harness.as_ref())
            .collect();

        for lib_name in &needed_libs {
            // Look for a target whose name matches the library name AND has no
            // link_references of its own (i.e. it's a leaf library).
            let lib_candidate = all_candidates.iter().find(|t| {
                t.name.as_deref() == Some(lib_name.as_str()) && t.link_references.is_empty()
            });
            match lib_candidate {
                Some(lib) => {
                    let lib_bc = deployment_bytecode(lib);
                    if lib_bc.is_empty() {
                        eprintln!(
                            "[bootstrap] WARNING: library {} has no bytecode — linking will be incomplete",
                            lib_name
                        );
                        continue;
                    }
                    match executor.deploy(attacker, lib_bc) {
                        Ok(addr) => {
                            eprintln!(
                                "[bootstrap] deployed library {} at {addr:#x}",
                                lib_name
                            );
                            lib_addresses.insert(lib_name.clone(), addr);
                        }
                        Err(e) => {
                            eprintln!(
                                "[bootstrap] WARNING: failed to deploy library {}: {e:#} — linking will be incomplete",
                                lib_name
                            );
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[bootstrap] WARNING: no artifact found for library {} — linking will be incomplete",
                        lib_name
                    );
                }
            }
        }
    }

    /// Patch a contract's creation bytecode in-place with deployed library addresses.
    /// Returns a new `Bytes` if any patching was done, or `None` if nothing needed patching.
    fn apply_link_references(
        creation_bytecode: &Bytes,
        link_references: &std::collections::HashMap<String, Vec<usize>>,
        lib_addresses: &std::collections::HashMap<String, Address>,
    ) -> Option<Bytes> {
        if link_references.is_empty() {
            return None;
        }
        let mut bc = creation_bytecode.to_vec();
        for (lib_name, offsets) in link_references {
            if let Some(addr) = lib_addresses.get(lib_name) {
                for &offset in offsets {
                    if offset + 20 <= bc.len() {
                        bc[offset..offset + 20].copy_from_slice(addr.as_slice());
                    } else {
                        eprintln!(
                            "[bootstrap] WARNING: link offset {} out of bounds for lib {} (bc len {})",
                            offset, lib_name, bc.len()
                        );
                    }
                }
            } else {
                eprintln!(
                    "[bootstrap] WARNING: library {} not deployed — bytecode placeholder NOT patched",
                    lib_name
                );
            }
        }
        Some(Bytes::from(bc))
    }

    // Apply linking to work_targets that need it. We rebuild the vec so we can
    // patch creation_bytecode without mutating the original config.
    let work_targets: Vec<ContractInfo> = work_targets
        .into_iter()
        .map(|mut t| {
            if let Some(ref bc) = t.creation_bytecode.clone() {
                if let Some(patched) =
                    apply_link_references(bc, &t.link_references, &lib_addresses)
                {
                    t.creation_bytecode = Some(patched);
                }
            }
            t
        })
        .collect();

    // Also patch the harness if needed (handled separately below, but we need
    // the patched bytecode there too).  We do this by carrying `lib_addresses`
    // through to the harness section.

    // ── Determine bootstrap strategy ──────────────────────────────────────────
    //
    // When a harness with setUp() is present and runtime targets are likely
    // created *by* the harness (e.g. deployCode, new, or factory calls inside
    // setUp()), deploying them separately will fail because they need constructor
    // args.  We detect this by trying to deploy all targets; if any fail AND
    // we have a harness with setUp(), we snapshot-rollback and retry with
    // harness-first mode:
    //   1. Snapshot current state.
    //   2. Try deploying all runtime targets.
    //   3. If any fail AND harness has setUp() → restore snapshot, deploy
    //      harness first, run setUp(), discover contracts from post-setup state.
    //   4. If all succeed → continue with normal flow.
    //
    // This enables fuzzing complex DeFi protocols where contracts are deployed
    // inside Foundry test setUp() with dependency injection (e.g. Morpho,
    // Aave, Compound).

    let has_harness_with_setup = config.harness.as_ref().is_some_and(|h| {
        h.abi.as_ref().is_some_and(|abi| crate::project::abi_has_set_up(abi))
    });

    // Save a snapshot before attempting runtime target deployment so we can
    // roll back if we need to switch to harness-first mode.
    let pre_deploy_snapshot = if has_harness_with_setup && !work_targets.is_empty() {
        Some(executor.snapshot())
    } else {
        None
    };

    // Try deploying all runtime targets.
    let mut any_deploy_failed = false;
    for target in &work_targets {
        let dbc = deployment_bytecode(target);
        if !dbc.is_empty() {
            match executor.deploy(attacker, dbc.clone()) {
                Ok(deployed_addr) => {
                    deployed_targets.push(ContractInfo {
                        address: deployed_addr,
                        deployed_bytecode: target.deployed_bytecode.clone(),
                        creation_bytecode: target.creation_bytecode.clone(),
                        name: target.name.clone(),
                        source_path: target.source_path.clone(),
                        deployed_source_map: target.deployed_source_map.clone(),
                        source_file_list: target.source_file_list.clone(),
                        abi: target.abi.clone(),
                        link_references: target.link_references.clone(),
                    });
                }
                Err(e) => {
                    any_deploy_failed = true;
                    deploy_failures.push(DeployFailureReport {
                        target_name: target.name.clone(),
                        address: target.address,
                        error: format!("{e:#}"),
                    });
                    tracing::warn!(
                        "[bootstrap] target {} deploy failed: {}",
                        target.name.as_deref().unwrap_or("?"),
                        e
                    );
                }
            }
        } else {
            deployed_targets.push(target.clone());
        }
    }

    // If any runtime target failed to deploy and we have a harness with setUp(),
    // roll back and try harness-first mode instead.
    if any_deploy_failed && has_harness_with_setup {
        if let Some(snapshot) = pre_deploy_snapshot {
            eprintln!(
                "[bootstrap] {}/{} runtime targets failed to deploy — switching to harness-first mode",
                deploy_failures.len(),
                work_targets.len()
            );
            executor.restore(snapshot);
            return bootstrap_harness_first(
                executor,
                config,
                attacker,
                &work_targets,
                mode,
            );
        }
    }

    let mut setup_report = SetupReport {
        deploy_failures,
        ..Default::default()
    };

    if let Some(ref harness) = config.harness {
        let harness_bc = if !harness.link_references.is_empty() {
            let base_bc = deployment_bytecode(harness);
            apply_link_references(&base_bc, &harness.link_references, &lib_addresses)
                .unwrap_or(base_bc)
        } else {
            deployment_bytecode(harness)
        };
        if harness_bc.is_empty() {
            anyhow::bail!("harness contract has no bytecode to deploy");
        }

        let deployed_addr = executor.deploy(attacker, harness_bc)?;
        setup_report.harness_name = harness.name.clone();
        setup_report.harness_address = Some(deployed_addr);
        deployed_targets.push(ContractInfo {
            address: deployed_addr,
            deployed_bytecode: harness.deployed_bytecode.clone(),
            creation_bytecode: harness.creation_bytecode.clone(),
            name: harness.name.clone(),
            source_path: harness.source_path.clone(),
            deployed_source_map: harness.deployed_source_map.clone(),
            source_file_list: harness.source_file_list.clone(),
            abi: harness.abi.clone(),
            link_references: harness.link_references.clone(),
        });

        let has_setup = harness
            .abi
            .as_ref()
            .is_some_and(|abi| crate::project::abi_has_set_up(abi));
        if has_setup {
            setup_report.set_up_called = true;
            match crate::harness::run_setup(executor, attacker, deployed_addr) {
                Ok(()) => {
                    setup_report.set_up_success = true;
                    eprintln!(
                        "[bootstrap] ran setUp() on harness {} ({})",
                        harness.name.as_deref().unwrap_or("?"),
                        deployed_addr
                    );
                }
                Err(e) => {
                    setup_report.set_up_success = false;
                    setup_report.set_up_error = Some(format!("{e:#}"));
                    let msg = format!("{e:#}");
                    if config.require_successful_setup {
                        anyhow::bail!(
                            "setUp() required but failed on harness {}: {}",
                            harness.name.as_deref().unwrap_or("?"),
                            msg
                        );
                    }
                    tracing::warn!(
                        "[bootstrap] setUp() failed on harness {} — continuing without full setup: {}",
                        harness.name.as_deref().unwrap_or("?"),
                        e
                    );
                }
            }
        } else {
            eprintln!(
                "[bootstrap] harness {} ({}) uses constructor-only setup (no setUp())",
                harness.name.as_deref().unwrap_or("?"),
                deployed_addr
            );
        }
    }

    let setup_opt = if config.harness.is_some() || !setup_report.deploy_failures.is_empty() {
        Some(setup_report)
    } else {
        None
    };

    Ok(BootstrapOutcome {
        deployed_targets,
        setup_report: setup_opt,
        mode,
    })
}

/// Harness-first bootstrap: deploy the harness, run setUp(), then discover
/// runtime contracts from post-setup EVM state by matching deployed bytecode
/// against the original runtime target artifacts.
///
/// This path is used when runtime targets cannot be deployed standalone (they
/// need constructor args provided by the harness's setUp() environment).
fn bootstrap_harness_first(
    executor: &mut EvmExecutor,
    config: &CampaignConfig,
    attacker: Address,
    runtime_targets: &[ContractInfo],
    mode: BootstrapMode,
) -> anyhow::Result<BootstrapOutcome> {
    let harness = config
        .harness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("harness-first mode requires a harness"))?;

    // 1. Deploy the harness
    let harness_bc = deployment_bytecode(harness);
    if harness_bc.is_empty() {
        anyhow::bail!("harness contract has no bytecode to deploy");
    }

    let harness_addr = executor.deploy(attacker, harness_bc.clone())
        .map_err(|e| {
            eprintln!(
                "[bootstrap] harness-first: failed to deploy harness {} — {e:#}",
                harness.name.as_deref().unwrap_or("?")
            );
            e
        })?;
    eprintln!(
        "[bootstrap] harness-first: deployed harness {} at {harness_addr:#x}",
        harness.name.as_deref().unwrap_or("?")
    );

    // 2. Run setUp()
    let has_setup = harness
        .abi
        .as_ref()
        .is_some_and(|abi| crate::project::abi_has_set_up(abi));

    let mut setup_report = SetupReport {
        harness_name: harness.name.clone(),
        harness_address: Some(harness_addr),
        set_up_called: has_setup,
        ..Default::default()
    };

    if has_setup {
        match crate::harness::run_setup(executor, attacker, harness_addr) {
            Ok(()) => {
                setup_report.set_up_success = true;
                eprintln!(
                    "[bootstrap] harness-first: setUp() succeeded on {} ({})",
                    harness.name.as_deref().unwrap_or("?"),
                    harness_addr
                );
            }
            Err(e) => {
                setup_report.set_up_success = false;
                setup_report.set_up_error = Some(format!("{e:#}"));
                if config.require_successful_setup {
                    anyhow::bail!(
                        "setUp() required but failed on harness {}: {e:#}",
                        harness.name.as_deref().unwrap_or("?")
                    );
                }
                tracing::warn!(
                    "[bootstrap] harness-first: setUp() failed — continuing: {e:#}"
                );
            }
        }
    }

    // 3. Discover runtime contracts from post-setup EVM state.
    //
    // We scan addresses created by the attacker (sequential CREATE addresses)
    // and match their deployed bytecode against the runtime target artifacts.
    // We also check addresses created during setUp() by scanning a wider range.
    let mut deployed_targets: Vec<ContractInfo> = Vec::new();

    // Collect bytecode fingerprints from runtime targets for matching.
    let target_fingerprints: Vec<(usize, &[u8], &ContractInfo)> = runtime_targets
        .iter()
        .filter_map(|t| {
            let bc = &t.deployed_bytecode;
            if bc.is_empty() || bc.len() < 20 {
                return None;
            }
            // Use the last N bytes as a fingerprint (avoids constructor args in
            // creation bytecode; deployed bytecode is canonical).
            Some((bc.len(), bc.as_ref(), t))
        })
        .collect();

    // Scan CREATE addresses from attacker's nonce range.
    // The harness was deployed at the current nonce, so contracts created
    // during setUp() will be at subsequent nonces.
    let start_nonce = 0u64; // We don't know the exact start, so scan a range.
    let scan_limit = 50u64; // Reasonable upper bound for setUp deployments.

    let mut discovered_count = 0usize;
    for nonce in start_nonce..scan_limit {
        let candidate_addr = {
            // Recreate CREATE address: keccak256(RLP([sender, nonce]))[12:]
            use tiny_keccak::{Hasher, Keccak};
            let mut k = Keccak::v256();
            // RLP encode [address, nonce]
            let mut rlp = Vec::with_capacity(25);
            rlp.push(0xc0 + 2); // list of 2 items
            rlp.push(20); // 20-byte address length
            rlp.extend_from_slice(attacker.as_slice());
            if nonce < 0x80 {
                rlp.push(nonce as u8);
            } else {
                // For nonces >= 128, RLP encodes as short int
                let be = nonce.to_be_bytes();
                let trim = be.iter().position(|&b| b != 0).unwrap_or(7);
                rlp.push(0x80 + (8 - trim) as u8);
                rlp.extend_from_slice(&be[trim..]);
            }
            // Recompute properly using revm's address computation
            // Actually, use the executor's own address computation
            k.update(&rlp);
            let mut hash = [0u8; 32];
            k.finalize(&mut hash);
            // This is NOT correct CREATE address derivation — use the proper formula
            let _ = hash; // suppress unused warning
            // Use proper computation
            let addr = crate::evm::compute_create_address(attacker, nonce);
            addr
        };

        // Check if this address has code
        let code = executor
            .get_code(candidate_addr)
            .unwrap_or_default();

        if code.is_empty() {
            continue;
        }

        // Try to match against runtime target fingerprints
        let mut matched = false;
        for (bc_len, bc_bytes, target) in &target_fingerprints {
            if code.len() == *bc_len && code.as_ref() == *bc_bytes {
                deployed_targets.push(ContractInfo {
                    address: candidate_addr,
                    deployed_bytecode: code.clone(),
                    creation_bytecode: target.creation_bytecode.clone(),
                    name: target.name.clone(),
                    source_path: target.source_path.clone(),
                    deployed_source_map: target.deployed_source_map.clone(),
                    source_file_list: target.source_file_list.clone(),
                    abi: target.abi.clone(),
                    link_references: target.link_references.clone(),
                });
                eprintln!(
                    "[bootstrap] harness-first: discovered {} at {candidate_addr:#x} (bytecode match)",
                    target.name.as_deref().unwrap_or("?")
                );
                discovered_count += 1;
                matched = true;
                break;
            }
        }

        if !matched && !code.is_empty() && code.len() > 64 {
            // Unknown contract deployed during setUp() — add as anonymous target
            // so the fuzzer can still interact with it if system_mode is enabled.
            deployed_targets.push(ContractInfo {
                address: candidate_addr,
                deployed_bytecode: code.clone(),
                creation_bytecode: None,
                name: None,
                source_path: None,
                deployed_source_map: None,
                source_file_list: Vec::new(),
                abi: None,
                link_references: Default::default(),
            });
        }
    }

    // Also add the harness itself to the deployed targets
    deployed_targets.push(ContractInfo {
        address: harness_addr,
        deployed_bytecode: harness.deployed_bytecode.clone(),
        creation_bytecode: harness.creation_bytecode.clone(),
        name: harness.name.clone(),
        source_path: harness.source_path.clone(),
        deployed_source_map: harness.deployed_source_map.clone(),
        source_file_list: harness.source_file_list.clone(),
        abi: harness.abi.clone(),
        link_references: harness.link_references.clone(),
    });

    eprintln!(
        "[bootstrap] harness-first: discovered {discovered_count}/{} runtime targets from setUp() state",
        runtime_targets.len()
    );

    Ok(BootstrapOutcome {
        deployed_targets,
        setup_report: Some(setup_report),
        mode,
    })
}

/// Extra ETH funding on fork overlay after attacker bootstrap.
pub fn fund_fork_addresses(executor: &mut EvmExecutor, config: &CampaignConfig) {
    for (addr, wei) in &config.fork_fund_addresses {
        executor.set_balance(*addr, *wei);
        eprintln!("[bootstrap] fork funded {addr:#x} with {wei} wei");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_targets_array_parses() {
        let j = br#"{
            "chain_id": 1,
            "targets": [
                { "name": "Vault", "address": "0x0000000000000000000000000000000000000001" },
                { "name": "Router", "address": "0x0000000000000000000000000000000000000002" }
            ]
        }"#;
        let m = AddressManifest::from_json_slice(j).unwrap();
        assert_eq!(m.chain_id, Some(1));
        assert_eq!(m.contracts.len(), 2);
        assert_eq!(m.contracts[0].0, "Vault");
    }

    #[test]
    fn manifest_legacy_contracts_map_parses() {
        let j = br#"{
            "chainId": 42161,
            "contracts": { "Pool": "0x0000000000000000000000000000000000000003" }
        }"#;
        let m = AddressManifest::from_json_slice(j).unwrap();
        assert_eq!(m.chain_id, Some(42161));
        assert_eq!(m.contracts[0].0, "Pool");
    }
}
