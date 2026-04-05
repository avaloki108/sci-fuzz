//! On-chain state forking via a JSON-RPC endpoint.
//!
//! [`RpcCacheDB`] is a [`revm`] `Database` implementation that fetches account
//! info and storage slots from a live node on first access, then caches them
//! locally so subsequent reads are free.
//!
//! # Usage
//!
//! ```no_run
//! use sci_fuzz::rpc::RpcCacheDB;
//! let db = RpcCacheDB::new("https://eth-mainnet.g.alchemy.com/v2/KEY", None)
//!     .expect("failed to connect");
//! ```

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use revm::{
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, B256 as RevmB256, U256 as RevmU256,
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
    let url = format!("{base}?module=contract&action=getabi&address={address}&apikey={api_key}");

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

fn etherscan_api_base(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "mainnet" | "ethereum" => "https://api.etherscan.io/api",
        "polygon" => "https://api.polygonscan.com/api",
        "arbitrum" | "arb" => "https://api.arbiscan.io/api",
        "optimism" | "op" => "https://api-optimistic.etherscan.io/api",
        "base" => "https://api.basescan.org/api",
        _ => "https://api.etherscan.io/api",
    }
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
#[derive(Debug, Clone)]
pub struct RpcCacheDB {
    url: String,
    block: Option<u64>,
    /// Account cache: address → account info.
    accounts: Arc<Mutex<HashMap<RevmAddress, AccountInfo>>>,
    /// Storage cache: (address, slot) → value.
    storage: Arc<Mutex<HashMap<(RevmAddress, RevmU256), RevmU256>>>,
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

        Ok(AccountInfo {
            balance,
            nonce,
            code_hash: code
                .as_ref()
                .map(|c| c.hash_slow())
                .unwrap_or(revm::primitives::KECCAK_EMPTY),
            code,
        })
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

    fn code_by_hash_ref(&self, _code_hash: RevmB256) -> Result<Bytecode, Self::Error> {
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

    #[test]
    fn etherscan_base_url_mainnet() {
        assert_eq!(
            etherscan_api_base("mainnet"),
            "https://api.etherscan.io/api"
        );
        assert_eq!(
            etherscan_api_base("polygon"),
            "https://api.polygonscan.com/api"
        );
        assert_eq!(etherscan_api_base("base"), "https://api.basescan.org/api");
    }

    #[test]
    fn rpc_cache_db_new() {
        let db = RpcCacheDB::new("https://example.com/rpc", Some(19_000_000));
        assert!(db.is_ok());
    }
}
