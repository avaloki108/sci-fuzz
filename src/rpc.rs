//! On-chain state forking via a JSON-RPC endpoint.
//!
//! [`RpcCacheDB`] is a [`revm`] `Database` implementation that fetches account
//! info and storage slots from a live node on first access, then caches them
//! locally so subsequent reads are free.
//!
//! # Usage
//!
//! ```no_run
//! use chimera_fuzz::rpc::RpcCacheDB;
//! let db = RpcCacheDB::new("https://eth-mainnet.g.alchemy.com/v2/KEY", None)
//!     .expect("failed to connect");
//! ```

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use revm::{
    primitives::{
        AccountInfo, Address as RevmAddress, BlockEnv, Bytecode, B256 as RevmB256, U256 as RevmU256,
    },
    Database,
};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Etherscan helpers
// ---------------------------------------------------------------------------

/// Fetch the verified ABI JSON string for a contract from Etherscan.
///
/// Returns the raw JSON string (as returned by `&module=contract&action=getabi`)
/// so the caller can deserialize it with `serde_json`.
///
/// Requires a valid `ETHERSCAN_API_KEY` (or equivalent) in the environment,
/// but also accepts an explicit `api_key` argument.
pub fn fetch_etherscan_abi(address: &str, chain: &str, api_key: &str) -> Result<serde_json::Value> {
    let base = etherscan_api_base(chain);
    let url = format!("{base}&module=contract&action=getabi&address={address}&apikey={api_key}");

    let resp: EtherscanResponse = ureq::get(&url)
        .call()
        .context("Etherscan HTTP request failed")?
        .into_json()
        .context("Etherscan response was not valid JSON")?;

    if resp.status != "1" {
        return Err(anyhow!(
            "Etherscan error for {address}: {}",
            resp.result.as_str().unwrap_or("<unknown>")
        ));
    }

    // The `result` field is a JSON string — parse it into a Value.
    let abi_str = resp
        .result
        .as_str()
        .ok_or_else(|| anyhow!("Etherscan result was not a string"))?;
    serde_json::from_str(abi_str).context("Failed to parse ABI from Etherscan")
}

#[derive(Deserialize)]
struct EtherscanResponse {
    status: String,
    result: serde_json::Value,
}

/// Chain ID used for Etherscan V2 API routing.
fn etherscan_chain_id(chain: &str) -> u64 {
    match chain.to_lowercase().as_str() {
        "mainnet" | "ethereum" => 1,
        "polygon" => 137,
        "arbitrum" | "arb" => 42161,
        "optimism" | "op" => 10,
        "base" => 8453,
        "bsc" | "bnb" => 56,
        "avalanche" | "avax" => 43114,
        "fantom" | "ftm" => 250,
        _ => 1,
    }
}

fn etherscan_api_base(chain: &str) -> String {
    // Etherscan V2 unified endpoint — works for all chains via chainid param.
    let chain_id = etherscan_chain_id(chain);
    format!("https://api.etherscan.io/v2/api?chainid={chain_id}")
}

// ---------------------------------------------------------------------------
// RpcCacheDB
// ---------------------------------------------------------------------------

/// JSON-RPC request body.
#[derive(serde::Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

/// Minimal JSON-RPC response wrapper.
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A `revm` database that forks on-chain state on first access.
///
/// Internally it caches:
/// - [`AccountInfo`] per address (balance, nonce, code hash, bytecode)
/// - Storage slot values per address
#[derive(Debug)]
pub struct RpcCacheDB {
    url: String,
    block: Option<u64>,
    /// Account cache: address → account info.
    accounts: Arc<Mutex<HashMap<RevmAddress, AccountInfo>>>,
    /// Storage cache: (address, slot) → value.
    storage: Arc<Mutex<HashMap<(RevmAddress, RevmU256), RevmU256>>>,
    /// Code hash cache: code_hash -> bytecode (populated from eth_getCode).
    code_hash_cache: Arc<Mutex<HashMap<revm::primitives::B256, Bytecode>>>,
    /// Request counter for unique JSON-RPC IDs.
    req_id: Arc<AtomicU64>,
}

impl RpcCacheDB {
    /// Create a new forking database.
    ///
    /// * `url` — HTTP(S) JSON-RPC endpoint.
    /// * `block` — block number to pin (uses `"latest"` when `None`).
    pub fn new(url: &str, block: Option<u64>) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
            block,
            accounts: Arc::new(Mutex::new(HashMap::new())),
            storage: Arc::new(Mutex::new(HashMap::new())),
            code_hash_cache: Arc::new(Mutex::new(HashMap::new())),
            req_id: Arc::new(AtomicU64::new(1)),
        })
    }

    fn block_param(&self) -> serde_json::Value {
        match self.block {
            Some(n) => serde_json::Value::String(format!("0x{n:x}")),
            None => serde_json::Value::String("latest".to_string()),
        }
    }

    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = self.req_id.fetch_add(1, Ordering::SeqCst);

        let body = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let resp: RpcResponse = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&body)?)
            .context("JSON-RPC request failed")?
            .into_json()
            .context("JSON-RPC response was not valid JSON")?;

        if let Some(err) = resp.error {
            return Err(anyhow!("JSON-RPC error: {}", err.message));
        }

        resp.result
            .ok_or_else(|| anyhow!("JSON-RPC returned null result for {method}"))
    }

    fn fetch_account(&self, addr: RevmAddress) -> Result<AccountInfo> {
        let addr_str = format!("0x{}", hex::encode(addr.as_slice()));
        let block = self.block_param();

        // eth_getBalance
        let bal_hex = self
            .call(
                "eth_getBalance",
                serde_json::json!([&addr_str, block.clone()]),
            )?
            .as_str()
            .ok_or_else(|| anyhow!("bad balance"))?
            .to_string();
        let balance = RevmU256::from_str(&bal_hex).context("parse balance")?;

        // eth_getTransactionCount (nonce)
        let nonce_hex = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([&addr_str, block.clone()]),
            )?
            .as_str()
            .ok_or_else(|| anyhow!("bad nonce"))?
            .to_string();
        let nonce =
            u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).context("parse nonce")?;

        // eth_getCode
        let code_hex = self
            .call("eth_getCode", serde_json::json!([&addr_str, block]))?
            .as_str()
            .ok_or_else(|| anyhow!("bad code"))?
            .to_string();
        let code_bytes = hex::decode(code_hex.trim_start_matches("0x")).context("decode code")?;
        let code = if code_bytes.is_empty() {
            None
        } else {
            Some(Bytecode::new_raw(revm::primitives::Bytes::from(code_bytes)))
        };

        let code_hash = code
            .as_ref()
            .map(|c| c.hash_slow())
            .unwrap_or(revm::primitives::KECCAK_EMPTY);

        // Cache code by hash for code_by_hash_ref lookups.
        if let Some(ref bytecode) = code {
            self.code_hash_cache
                .lock()
                .unwrap()
                .insert(code_hash, bytecode.clone());
        }

        Ok(AccountInfo {
            balance,
            nonce,
            code_hash,
            code,
        })
    }

    /// Test-only: insert a cached account without RPC (clone-isolation tests).
    #[cfg(test)]
    fn test_seed_account(&self, addr: RevmAddress, info: AccountInfo) {
        self.accounts.lock().unwrap().insert(addr, info);
    }

    /// Test-only: number of cached accounts.
    #[cfg(test)]
    fn test_account_cache_len(&self) -> usize {
        self.accounts.lock().unwrap().len()
    }

    fn fetch_storage(&self, addr: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let addr_str = format!("0x{}", hex::encode(addr.as_slice()));
        let slot_bytes = index.to_be_bytes::<32>();
        let slot_str = format!("0x{}", hex::encode(&slot_bytes));
        let block = self.block_param();

        let val = self
            .call(
                "eth_getStorageAt",
                serde_json::json!([addr_str, slot_str, block]),
            )?
            .as_str()
            .ok_or_else(|| anyhow!("bad storage value"))?
            .to_string();

        RevmU256::from_str(&val).context("parse storage value")
    }
}

/// Deep-clone account/storage caches so each [`revm::db::CacheDB`] snapshot gets an
/// independent RPC parent (prefetched entries do not leak across [`crate::evm::EvmExecutor::restore`]).
impl Clone for RpcCacheDB {
    fn clone(&self) -> Self {
        let accounts = self.accounts.lock().unwrap().clone();
        let storage = self.storage.lock().unwrap().clone();
        let code_hash_cache = self.code_hash_cache.lock().unwrap().clone();
        Self {
            url: self.url.clone(),
            block: self.block,
            accounts: Arc::new(Mutex::new(accounts)),
            storage: Arc::new(Mutex::new(storage)),
            code_hash_cache: Arc::new(Mutex::new(code_hash_cache)),
            req_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone JSON-RPC helpers (preflight, block header, code check)
// ---------------------------------------------------------------------------

/// Block tag string matching [`RpcCacheDB`] pin semantics (`latest` vs hex number).
pub fn fork_block_tag_json(block: Option<u64>) -> serde_json::Value {
    match block {
        Some(n) => serde_json::Value::String(format!("0x{n:x}")),
        None => serde_json::Value::String("latest".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Chain ID, fork block header, block env alignment
// ---------------------------------------------------------------------------

/// `eth_chainId` → host chain id (for diagnostics and optional mismatch checks).
pub fn fetch_eth_chain_id(url: &str) -> Result<u64> {
    let v = rpc_post(url, "eth_chainId", serde_json::json!([]))?;
    parse_json_hex_u64(&v).context("eth_chainId: expected hex quantity string")
}

fn parse_json_hex_u64(v: &serde_json::Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected hex string"))?
        .trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).context("parse hex u64")
}

/// Header fields from `eth_getBlockByNumber` used to align [`BlockEnv`] with the fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkBlockHeader {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: Option<u64>,
    pub basefee: Option<RevmU256>,
    pub difficulty: Option<RevmU256>,
    pub prevrandao: Option<RevmB256>,
    pub excess_blob_gas: Option<u64>,
}

/// Fetch full block object for the fork tag (single RPC round-trip).
pub fn fetch_fork_block_object(url: &str, block: Option<u64>) -> Result<serde_json::Value> {
    let tag = fork_block_tag_json(block);
    rpc_post(url, "eth_getBlockByNumber", serde_json::json!([tag, false]))
}

/// Parse [`ForkBlockHeader`] from `eth_getBlockByNumber` result object (testable).
pub fn parse_fork_block_header(v: &serde_json::Value) -> Result<ForkBlockHeader> {
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("eth_getBlockByNumber: not an object"))?;
    let num_hex = obj
        .get("number")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("eth_getBlockByNumber: missing number"))?;
    let ts_hex = obj
        .get("timestamp")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("eth_getBlockByNumber: missing timestamp"))?;
    let number =
        u64::from_str_radix(num_hex.trim_start_matches("0x"), 16).context("parse block number")?;
    let timestamp = u64::from_str_radix(ts_hex.trim_start_matches("0x"), 16)
        .context("parse block timestamp")?;

    let gas_limit = obj.get("gasLimit").and_then(json_hex_u64);
    let basefee = obj.get("baseFeePerGas").and_then(json_hex_u256);
    let difficulty = obj.get("difficulty").and_then(json_hex_u256);
    let prevrandao = obj
        .get("mixHash")
        .and_then(|x| x.as_str())
        .map(parse_hex_b256)
        .transpose()?;
    let excess_blob_gas = obj.get("excessBlobGas").and_then(json_hex_u64);

    Ok(ForkBlockHeader {
        number,
        timestamp,
        gas_limit,
        basefee,
        difficulty,
        prevrandao,
        excess_blob_gas,
    })
}

fn json_hex_u64(v: &serde_json::Value) -> Option<u64> {
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

fn json_hex_u256(v: &serde_json::Value) -> Option<RevmU256> {
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    RevmU256::from_str_radix(s, 16).ok()
}

fn parse_hex_b256(s: &str) -> Result<RevmB256> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("decode mixHash")?;
    if bytes.len() != 32 {
        return Err(anyhow!("mixHash: expected 32 bytes"));
    }
    Ok(RevmB256::from_slice(&bytes))
}

/// Best-effort: align revm [`BlockEnv`] with fork header fields. Missing fields keep prior values.
pub fn merge_fork_header_into_block_env(header: &ForkBlockHeader, be: &mut BlockEnv) {
    be.number = RevmU256::from(header.number);
    be.timestamp = RevmU256::from(header.timestamp);
    if let Some(gl) = header.gas_limit {
        be.gas_limit = RevmU256::from(gl);
    }
    if let Some(bf) = header.basefee {
        be.basefee = bf;
    }
    if let Some(d) = header.difficulty {
        be.difficulty = d;
    }
    if let Some(p) = header.prevrandao {
        be.prevrandao = Some(p);
    }
    if let Some(excess) = header.excess_blob_gas {
        be.set_blob_excess_gas_and_price(excess, false);
    }
}

/// Fetch [`ForkBlockHeader`] from RPC.
pub fn fetch_fork_block_header_full(url: &str, block: Option<u64>) -> Result<ForkBlockHeader> {
    let v = fetch_fork_block_object(url, block)?;
    parse_fork_block_header(&v)
}

// ---------------------------------------------------------------------------
// Deployed-target preflight (enriched)
// ---------------------------------------------------------------------------

/// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
/// = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
pub const EIP1967_IMPL_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/// EIP-1967 beacon slot: keccak256("eip1967.proxy.beacon") - 1
pub const EIP1967_BEACON_SLOT: &str =
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

/// Heuristic classification of proxy-like runtime code (hints only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyBytecodeHint {
    None,
    /// EIP-1167 minimal proxy pattern (45-byte runtime).
    Eip1167MinimalProxy,
    /// EIP-1967 transparent/UUPS proxy (implementation slot non-zero).
    Eip1967Proxy,
}

/// Result of validating `eth_getCode` for a predeployed target.
#[derive(Debug, Clone)]
pub struct DeployedPreflightResult {
    /// Raw runtime bytes from the node.
    pub code: Vec<u8>,
    pub proxy_hint: ProxyBytecodeHint,
}

/// EIP-1167 minimal proxy: fixed prefix + 20-byte implementation + fixed suffix (45 bytes).
pub(crate) const EIP1167_PREFIX: [u8; 10] =
    [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
pub(crate) const EIP1167_SUFFIX: [u8; 15] = [
    0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
];

/// Classify bytecode for logging / triage (not proof of proxy type).
pub fn proxy_bytecode_hint(code: &[u8]) -> ProxyBytecodeHint {
    if code.len() == 45 && code.starts_with(&EIP1167_PREFIX) && code.ends_with(&EIP1167_SUFFIX) {
        return ProxyBytecodeHint::Eip1167MinimalProxy;
    }
    ProxyBytecodeHint::None
}

/// Try to resolve an EIP-1967 proxy to its implementation address.
///
/// Reads the implementation storage slot via `eth_getStorageAt`.
/// Returns `Some(impl_address)` when the slot is non-zero, `None` otherwise.
pub fn resolve_eip1967_impl(
    url: &str,
    block: Option<u64>,
    proxy: crate::types::Address,
) -> Option<crate::types::Address> {
    let proxy_str = format!("0x{}", hex::encode(proxy.as_slice()));
    let slot_val = rpc_post(
        url,
        "eth_getStorageAt",
        serde_json::json!([&proxy_str, EIP1967_IMPL_SLOT, fork_block_tag_json(block)]),
    )
    .ok()?;

    let hex = slot_val.as_str()?;
    let bytes = hex::decode(hex.trim_start_matches("0x")).ok()?;
    if bytes.len() != 32 || bytes == [0u8; 32] {
        return None;
    }
    // Address is in the lower 20 bytes.
    let addr = crate::types::Address::from_slice(&bytes[12..]);
    if addr.is_zero() {
        None
    } else {
        Some(addr)
    }
}

/// Decode `eth_getCode` hex string to bytes; empty is an error for predeploy checks.
pub fn parse_runtime_code_hex(code_hex: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(code_hex.trim_start_matches("0x")).context("decode code hex")?;
    if bytes.is_empty() {
        return Err(anyhow!(
            "no contract code at this address for the configured fork block (eth_getCode empty)"
        ));
    }
    Ok(bytes)
}

/// Fetch and validate runtime code; returns size and optional proxy hint.
///
/// Automatically follows EIP-1967 proxies: when the implementation slot is
/// non-zero, returns the implementation's bytecode instead of the proxy shell.
/// This ensures the mutator sees the real function selectors, not just the
/// fallback dispatcher.
pub fn preflight_deployed_target_enriched(
    url: &str,
    block: Option<u64>,
    address: crate::types::Address,
) -> Result<DeployedPreflightResult> {
    let addr_str = format!("0x{}", hex::encode(address.as_slice()));
    let code_hex = rpc_post(
        url,
        "eth_getCode",
        serde_json::json!([&addr_str, fork_block_tag_json(block)]),
    )?
    .as_str()
    .ok_or_else(|| anyhow!("eth_getCode: expected string"))?
    .to_string();
    let proxy_code = parse_runtime_code_hex(&code_hex)?;
    let mut proxy_hint = proxy_bytecode_hint(&proxy_code);

    // EIP-1967 proxy detection: check implementation slot regardless of bytecode size.
    // Transparent proxies and UUPS proxies both use this slot.
    if let Some(impl_addr) = resolve_eip1967_impl(url, block, address) {
        proxy_hint = ProxyBytecodeHint::Eip1967Proxy;
        let impl_str = format!("0x{}", hex::encode(impl_addr.as_slice()));
        eprintln!("[preflight] EIP-1967 proxy detected at {addr_str} → impl {impl_str}");
        // Fetch implementation bytecode for ABI-aware mutation.
        if let Ok(impl_hex_val) = rpc_post(
            url,
            "eth_getCode",
            serde_json::json!([&impl_str, fork_block_tag_json(block)]),
        ) {
            if let Some(impl_hex) = impl_hex_val.as_str() {
                if let Ok(impl_code) = hex::decode(impl_hex.trim_start_matches("0x")) {
                    if !impl_code.is_empty() {
                        // Return implementation code (for ABI seed) but keep proxy address.
                        // The campaign still calls the proxy — we just use impl bytecode
                        // to extract push constants and get better mutation coverage.
                        return Ok(DeployedPreflightResult {
                            code: impl_code,
                            proxy_hint,
                        });
                    }
                }
            }
        }
    }

    Ok(DeployedPreflightResult {
        code: proxy_code,
        proxy_hint,
    })
}

fn rpc_post(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    if url.trim().is_empty() {
        return Err(anyhow!("RPC URL is empty"));
    }
    let body = RpcRequest {
        jsonrpc: "2.0",
        id: 1u64,
        method,
        params,
    };
    let resp: RpcResponse = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&body)?)
        .context("JSON-RPC request failed")?
        .into_json()
        .context("JSON-RPC response was not valid JSON")?;

    if let Some(err) = resp.error {
        return Err(anyhow!("JSON-RPC error: {}", err.message));
    }

    resp.result
        .ok_or_else(|| anyhow!("JSON-RPC returned null result for {method}"))
}

/// Verify the endpoint responds to `eth_blockNumber` (connectivity / URL validity).
pub fn rpc_probe_url(url: &str) -> Result<()> {
    let _ = rpc_post(url, "eth_blockNumber", serde_json::json!([]))?;
    Ok(())
}

/// Fetch `(block_number, block_timestamp)` for the same fork tag as [`RpcCacheDB`].
pub fn fetch_fork_block_header(url: &str, block: Option<u64>) -> Result<(u64, u64)> {
    let h = fetch_fork_block_header_full(url, block)?;
    Ok((h.number, h.timestamp))
}

/// Ensure `eth_getCode` at `address` is non-empty at the fork block (deployed contract).
pub fn preflight_deployed_code_nonempty(
    url: &str,
    block: Option<u64>,
    address: crate::types::Address,
) -> Result<()> {
    let addr_str = format!("0x{}", hex::encode(address.as_slice()));
    preflight_deployed_target_enriched(url, block, address)
        .map_err(|e| anyhow!("preflight failed for {addr_str}: {e:#}"))?;
    Ok(())
}

use revm::DatabaseRef;

impl DatabaseRef for RpcCacheDB {
    type Error = anyhow::Error;

    fn basic_ref(&self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(info) = self.accounts.lock().unwrap().get(&address) {
            return Ok(Some(info.clone()));
        }
        let info = self.fetch_account(address)?;
        self.accounts.lock().unwrap().insert(address, info.clone());
        Ok(Some(info))
    }

    fn code_by_hash_ref(&self, code_hash: RevmB256) -> Result<Bytecode, Self::Error> {
        if let Some(bytecode) = self.code_hash_cache.lock().unwrap().get(&code_hash) {
            return Ok(bytecode.clone());
        }
        // Fallback: return empty (EXTCODECOPY from unknown hash).
        Ok(Bytecode::new())
    }

    fn storage_ref(&self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        let key = (address, index);
        if let Some(&val) = self.storage.lock().unwrap().get(&key) {
            return Ok(val);
        }
        let val = self.fetch_storage(address, index)?;
        self.storage.lock().unwrap().insert(key, val);
        Ok(val)
    }

    fn block_hash_ref(&self, _number: u64) -> Result<RevmB256, Self::Error> {
        Ok(RevmB256::ZERO)
    }
}

impl Database for RpcCacheDB {
    type Error = anyhow::Error;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: RevmB256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<RevmB256, Self::Error> {
        self.block_hash_ref(number)
    }
}

// ---------------------------------------------------------------------------
// FuzzerDatabase
// ---------------------------------------------------------------------------

use revm::db::EmptyDB;

/// Runtime-selectable database for the fuzzer.
///
/// Wraps either a fresh [`EmptyDB`] for local campaigns or a forking
/// [`RpcCacheDB`] for audits.
#[derive(Debug, Clone)]
pub enum FuzzerDatabase {
    /// Local empty state.
    Empty(EmptyDB),
    /// On-chain state forking.
    Rpc(RpcCacheDB),
}

impl DatabaseRef for FuzzerDatabase {
    type Error = anyhow::Error;

    fn basic_ref(&self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        match self {
            Self::Empty(db) => Ok(db
                .basic_ref(address)
                .map_err(|_| anyhow!("EmptyDB error"))?),
            Self::Rpc(db) => db.basic_ref(address),
        }
    }

    fn code_by_hash_ref(&self, code_hash: RevmB256) -> Result<Bytecode, Self::Error> {
        match self {
            Self::Empty(db) => Ok(db
                .code_by_hash_ref(code_hash)
                .map_err(|_| anyhow!("EmptyDB error"))?),
            Self::Rpc(db) => db.code_by_hash_ref(code_hash),
        }
    }

    fn storage_ref(&self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        match self {
            Self::Empty(db) => Ok(db
                .storage_ref(address, index)
                .map_err(|_| anyhow!("EmptyDB error"))?),
            Self::Rpc(db) => db.storage_ref(address, index),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<RevmB256, Self::Error> {
        match self {
            Self::Empty(db) => Ok(db
                .block_hash_ref(number)
                .map_err(|_| anyhow!("EmptyDB error"))?),
            Self::Rpc(db) => db.block_hash_ref(number),
        }
    }
}

impl Database for FuzzerDatabase {
    type Error = anyhow::Error;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: RevmB256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<RevmB256, Self::Error> {
        self.block_hash_ref(number)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{B256 as RevmB256, U256 as RevmU256};

    #[test]
    fn etherscan_base_url_v2() {
        assert_eq!(
            etherscan_api_base("mainnet"),
            "https://api.etherscan.io/v2/api?chainid=1"
        );
        assert_eq!(
            etherscan_api_base("polygon"),
            "https://api.etherscan.io/v2/api?chainid=137"
        );
        assert_eq!(
            etherscan_api_base("base"),
            "https://api.etherscan.io/v2/api?chainid=8453"
        );
        assert_eq!(
            etherscan_api_base("arbitrum"),
            "https://api.etherscan.io/v2/api?chainid=42161"
        );
    }

    #[test]
    fn rpc_cache_db_new() {
        let db = RpcCacheDB::new("https://example.com/rpc", Some(19_000_000));
        assert!(db.is_ok());
    }

    #[test]
    fn rpc_cache_db_clone_does_not_share_caches() {
        use revm::primitives::Address as A;
        let a = RpcCacheDB::new("https://example.com/rpc", None).unwrap();
        let b = a.clone();
        let addr = A::with_last_byte(0x01);
        a.test_seed_account(addr, AccountInfo::default());
        assert_eq!(a.test_account_cache_len(), 1);
        assert_eq!(b.test_account_cache_len(), 0);
        b.test_seed_account(addr, AccountInfo::default());
        assert_eq!(a.test_account_cache_len(), 1);
        assert_eq!(b.test_account_cache_len(), 1);
    }

    #[test]
    fn parse_fork_block_header_reads_number_timestamp_and_optional_fields() {
        let v = serde_json::json!({
            "number": "0xc",
            "timestamp": "0x3e8",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x3b9aca00",
            "difficulty": "0x0",
            "mixHash": "0x0101010101010101010101010101010101010101010101010101010101010101",
            "excessBlobGas": "0x100"
        });
        let h = parse_fork_block_header(&v).unwrap();
        assert_eq!(h.number, 12);
        assert_eq!(h.timestamp, 1000);
        assert_eq!(h.gas_limit, Some(30_000_000));
        assert_eq!(h.excess_blob_gas, Some(256));
        assert!(h.basefee.is_some());
        assert!(h.prevrandao.is_some());
    }

    #[test]
    fn merge_fork_header_sets_block_env_fields() {
        let h = ForkBlockHeader {
            number: 19_000_000,
            timestamp: 1_700_000_000,
            gas_limit: Some(30_000_000),
            basefee: Some(RevmU256::from(1_000_000_000u64)),
            difficulty: Some(RevmU256::ZERO),
            prevrandao: Some(RevmB256::ZERO),
            excess_blob_gas: Some(0),
        };
        let mut be = revm::primitives::BlockEnv::default();
        merge_fork_header_into_block_env(&h, &mut be);
        assert_eq!(be.number, RevmU256::from(19_000_000u64));
        assert_eq!(be.timestamp, RevmU256::from(1_700_000_000u64));
        assert_eq!(be.gas_limit, RevmU256::from(30_000_000u64));
    }

    #[test]
    fn proxy_bytecode_hint_detects_eip1167() {
        let mut code = Vec::from(EIP1167_PREFIX);
        code.extend(std::iter::repeat(0xab_u8).take(20));
        code.extend_from_slice(&EIP1167_SUFFIX);
        assert_eq!(
            proxy_bytecode_hint(&code),
            ProxyBytecodeHint::Eip1167MinimalProxy
        );
        assert_eq!(
            proxy_bytecode_hint(&[0x60, 0x00, 0x60, 0x00]),
            ProxyBytecodeHint::None
        );
    }

    #[test]
    fn parse_runtime_code_hex_rejects_empty() {
        assert!(parse_runtime_code_hex("0x").is_err());
    }

    #[test]
    fn parse_runtime_code_hex_accepts_nonempty() {
        let b = parse_runtime_code_hex("0x6000").unwrap();
        assert_eq!(b, vec![0x60, 0x00]);
    }
}
