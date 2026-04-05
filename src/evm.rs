//! EVM execution wrapper for sci-fuzz.
//!
//! Wraps [`revm`] (v19.x) to provide a simple, snapshot-capable EVM executor
//! for smart-contract fuzzing.  The executor uses an in-memory
//! [`CacheDB<EmptyDB>`] database and exposes helpers for deploying contracts,
//! reading/writing balances & storage, and taking/restoring snapshots.

use std::collections::HashMap;

use anyhow::{anyhow, Context as _, Result};

use revm::{
    db::{CacheDB, EmptyDB},
    inspector_handle_register,
    interpreter::Interpreter,
    primitives::{
        AccountInfo, BlockEnv, ExecutionResult as RevmResult, Output, ResultAndState, SpecId,
        TxKind, U256 as RevmU256,
    },
    Database, DatabaseCommit, DatabaseRef, Evm, EvmContext, Inspector,
};

use crate::types::{Address, Bytes, CoverageMap, ExecutionResult, Log, StateDiff, Transaction, U256};

// ---------------------------------------------------------------------------
// ExecutorMode
// ---------------------------------------------------------------------------

/// Executor mode controlling how strictly EVM rules are enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutorMode {
    /// Minimal checks — best for exploration. Disables balance checks,
    /// gas limits, EIP-3607, base fee. This is the default.
    #[default]
    Fast,
    /// Enforce balance/value plausibility. Still disables gas price but
    /// checks that callers have sufficient balance for `msg.value`.
    /// Best for validation and reducing false positives.
    Realistic,
}

// ---------------------------------------------------------------------------
// CoverageInspector
// ---------------------------------------------------------------------------

/// Collects real per-instruction hitcounts directly from revm.
///
/// We attribute coverage to the currently executing contract address exposed by
/// the interpreter input. This is truthful execution coverage, though
/// `DELEGATECALL` frames are attributed to the storage target rather than the
/// library bytecode address.
#[derive(Debug, Clone, Default)]
struct CoverageInspector {
    coverage: CoverageMap,
}

impl<DB: Database> Inspector<DB> for CoverageInspector {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let address = interp
            .contract
            .bytecode_address
            .unwrap_or(interp.contract.target_address);
        self.coverage
            .record_hit(address, interp.program_counter());
    }
}

// ---------------------------------------------------------------------------
// EvmExecutor
// ---------------------------------------------------------------------------

/// Thin wrapper around a revm [`CacheDB<EmptyDB>`] that provides a
/// fuzzer-friendly interface for EVM execution.
pub struct EvmExecutor {
    /// In-memory account/storage database.
    db: CacheDB<EmptyDB>,
    /// Block-level environment shared across transactions.
    block_env: BlockEnv,
    /// Monotonic nonce used to derive deterministic `CREATE` addresses when
    /// deploying contracts.
    deploy_nonce: u64,
    /// Controls how strictly EVM rules are enforced during execution.
    mode: ExecutorMode,
}

impl EvmExecutor {
    // -- Construction -------------------------------------------------------

    /// Create a fresh executor with an empty state and sensible block defaults.
    pub fn new() -> Self {
        let mut block_env = BlockEnv::default();
        block_env.number = RevmU256::from(1u64);
        block_env.timestamp = RevmU256::from(1u64);
        block_env.gas_limit = RevmU256::from(30_000_000u64);

        Self {
            db: CacheDB::new(EmptyDB::default()),
            block_env,
            deploy_nonce: 0,
            mode: ExecutorMode::Fast,
        }
    }

    // -- Transaction execution ----------------------------------------------

    /// Execute a [`Transaction`] and return our own [`ExecutionResult`].
    ///
    /// State changes are committed to the inner database on success *and*
    /// revert (the revert data is still captured in the result).
    pub fn execute(&mut self, tx: &Transaction) -> Result<ExecutionResult> {
        // Snapshot balances *before* execution so we can compute diffs later.
        let pre_balances = self.snapshot_balances();

        let transact_to = match tx.to {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        };

        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .with_external_context(CoverageInspector::default())
            .with_block_env(self.block_env.clone())
            .with_spec_id(SpecId::CANCUN)
            .append_handler_register(inspector_handle_register)
            .modify_cfg_env(|cfg| match self.mode {
                ExecutorMode::Fast => {
                    cfg.disable_balance_check = true;
                    cfg.disable_block_gas_limit = true;
                    cfg.disable_eip3607 = true;
                    cfg.disable_base_fee = true;
                }
                ExecutorMode::Realistic => {
                    cfg.disable_balance_check = false;
                    cfg.disable_block_gas_limit = true;
                    cfg.disable_eip3607 = true;
                    cfg.disable_base_fee = true;
                }
            })
            .modify_tx_env(|tx_env| {
                tx_env.caller = tx.sender;
                tx_env.transact_to = transact_to;
                tx_env.data = tx.data.clone();
                tx_env.value = tx.value;
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = RevmU256::ZERO;
                tx_env.nonce = None; // skip nonce validation
            })
            .build();

        let ResultAndState { result, state } = evm
            .transact()
            .map_err(|e| anyhow!("EVM transact error: {e:?}"))?;
        let coverage = evm.context.external.coverage.clone();

        // Commit state changes into the CacheDB.
        drop(evm); // release mutable borrow on self.db
        self.db.commit(state.clone());

        // Convert the revm result into our own type.
        let exec_result = self.convert_result(&result, &state, &pre_balances, coverage)?;
        Ok(exec_result)
    }

    // -- Contract deployment ------------------------------------------------

    /// Deploy a contract and return its address.
    ///
    /// `deployer` is used as `msg.sender`, and `bytecode` should contain the
    /// **init-code** (constructor bytecode) of the contract.
    pub fn deploy(&mut self, deployer: Address, bytecode: Bytes) -> Result<Address> {
        let tx = Transaction {
            sender: deployer,
            to: None,
            data: bytecode,
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };

        let result = self.execute(&tx).context("deploy transaction failed")?;
        if !result.success {
            return Err(anyhow!(
                "deploy reverted: 0x{}",
                hex::encode(&result.output)
            ));
        }

        // The created address lives inside the `Output::Create` variant
        // returned by `execute`. We cannot recover it from our flattened
        // `ExecutionResult`, so we re-derive it from the deployer + nonce.
        //
        // However, revm already computed it for us during `transact()`.
        // Since we committed the state, the new account is now in the DB.
        // We find it by replaying the CREATE logic: we ran a create-tx so
        // revm used CREATE (sender, nonce).  We track the nonce ourselves.
        let nonce = self.deploy_nonce;
        self.deploy_nonce += 1;
        let created = compute_create_address(deployer, nonce);
        Ok(created)
    }

    // -- Balance helpers ----------------------------------------------------

    /// Return the balance of `addr` (zero for unknown accounts).
    pub fn get_balance(&self, addr: Address) -> U256 {
        self.db
            .basic_ref(addr)
            .ok()
            .flatten()
            .map_or(U256::ZERO, |info| info.balance)
    }

    /// Overwrite the balance of `addr`.  Creates the account if it does not
    /// already exist.
    pub fn set_balance(&mut self, addr: Address, balance: U256) {
        let existing = self.db.basic_ref(addr).ok().flatten().unwrap_or_default();

        self.db.insert_account_info(
            addr,
            AccountInfo {
                balance,
                ..existing
            },
        );
    }

    // -- Storage helpers ----------------------------------------------------

    /// Read a single storage slot (zero for unknown accounts / slots).
    pub fn get_storage(&self, addr: Address, slot: U256) -> U256 {
        self.db.storage_ref(addr, slot).unwrap_or(U256::ZERO)
    }

    // -- Account helpers ----------------------------------------------------

    /// Insert (or overwrite) account info for `addr`.
    ///
    /// This is useful for pre-loading contracts with specific bytecode and
    /// balance before fuzzing.
    pub fn insert_account_info(&mut self, addr: Address, info: AccountInfo) {
        self.db.insert_account_info(addr, info);
    }

    // -- Snapshots ----------------------------------------------------------

    /// Clone the entire database for later restoration.
    pub fn snapshot(&self) -> CacheDB<EmptyDB> {
        self.db.clone()
    }

    /// Restore the database from a previous snapshot.
    pub fn restore(&mut self, db: CacheDB<EmptyDB>) {
        self.db = db;
    }

    // -- Block environment --------------------------------------------------

    /// Return a shared reference to the current block environment.
    pub fn block_env(&self) -> &BlockEnv {
        &self.block_env
    }

    /// Return a mutable reference so callers can tweak block number,
    /// timestamp, coinbase, etc.
    pub fn block_env_mut(&mut self) -> &mut BlockEnv {
        &mut self.block_env
    }

    /// Set the executor mode.
    pub fn set_mode(&mut self, mode: ExecutorMode) {
        self.mode = mode;
    }

    // -- Static calls -------------------------------------------------------

    /// Call a view function on a contract and return the raw output bytes.
    ///
    /// This is a "static call" — no state changes are committed.
    /// Used by property checkers to call `echidna_*` functions after
    /// each transaction sequence.
    pub fn static_call(
        &self,
        caller: Address,
        to: Address,
        data: Bytes,
    ) -> anyhow::Result<(bool, Bytes)> {
        // Clone the DB so we don't mutate state.
        let mut db_clone = self.db.clone();

        let mut evm = Evm::builder()
            .with_db(&mut db_clone)
            .with_block_env(self.block_env.clone())
            .with_spec_id(SpecId::CANCUN)
            .modify_cfg_env(|cfg| {
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_env(|tx_env| {
                tx_env.caller = caller;
                tx_env.transact_to = TxKind::Call(to);
                tx_env.data = data;
                tx_env.value = RevmU256::ZERO;
                tx_env.gas_limit = 30_000_000;
                tx_env.gas_price = RevmU256::ZERO;
                tx_env.nonce = None;
            })
            .build();

        let ResultAndState { result, .. } = evm
            .transact()
            .map_err(|e| anyhow!("static call error: {e:?}"))?;

        match result {
            RevmResult::Success { output, .. } => {
                let bytes = match output {
                    Output::Call(b) => Bytes::from(b.to_vec()),
                    Output::Create(b, _) => Bytes::from(b.to_vec()),
                };
                Ok((true, bytes))
            }
            RevmResult::Revert { output, .. } => Ok((false, Bytes::from(output.to_vec()))),
            RevmResult::Halt { .. } => Ok((false, Bytes::new())),
        }
    }

    // -- Internal helpers ---------------------------------------------------

    /// Take a snapshot of every known account balance *before* a transaction
    /// so that we can compute balance diffs afterwards.
    fn snapshot_balances(&self) -> HashMap<Address, U256> {
        self.db
            .accounts
            .iter()
            .filter_map(|(addr, acct)| {
                // Skip accounts flagged as not-existing.
                acct.info().map(|info| (*addr, info.balance))
            })
            .collect()
    }

    /// Convert a revm [`RevmResult`] + committed state into our own
    /// [`ExecutionResult`].
    fn convert_result(
        &self,
        result: &RevmResult,
        state: &revm::primitives::EvmState,
        pre_balances: &HashMap<Address, U256>,
        coverage: CoverageMap,
    ) -> Result<ExecutionResult> {
        let (success, gas_used, output, logs) = match result {
            RevmResult::Success {
                gas_used,
                logs,
                output,
                ..
            } => {
                let data = match output {
                    Output::Call(b) => b.clone(),
                    Output::Create(b, _) => b.clone(),
                };
                (true, *gas_used, data, logs.clone())
            }
            RevmResult::Revert { gas_used, output } => {
                (false, *gas_used, output.clone(), Vec::new())
            }
            RevmResult::Halt { gas_used, .. } => (false, *gas_used, Bytes::new(), Vec::new()),
        };

        // Convert revm logs → our Log type.
        let our_logs: Vec<Log> = logs
            .iter()
            .map(|l| Log {
                address: l.address,
                topics: l.data.topics().to_vec(),
                data: l.data.data.clone(),
            })
            .collect();

        // Build state diff from the committed state changes.
        let state_diff = self.build_state_diff(state, pre_balances);

        Ok(ExecutionResult {
            success,
            output,
            gas_used,
            logs: our_logs,
            coverage,
            state_diff,
        })
    }

    /// Derive a [`StateDiff`] from the revm transition state and
    /// pre-execution balances.
    fn build_state_diff(
        &self,
        state: &revm::primitives::EvmState,
        pre_balances: &HashMap<Address, U256>,
    ) -> StateDiff {
        let mut storage_writes: HashMap<Address, HashMap<U256, U256>> = HashMap::new();
        let mut balance_changes: HashMap<Address, (U256, U256)> = HashMap::new();

        for (addr, account) in state {
            // Storage writes.
            if !account.storage.is_empty() {
                let writes: HashMap<U256, U256> = account
                    .storage
                    .iter()
                    .filter(|(_, slot)| slot.is_changed())
                    .map(|(key, slot)| (*key, slot.present_value))
                    .collect();
                if !writes.is_empty() {
                    storage_writes.insert(*addr, writes);
                }
            }

            // Balance changes.
            let old = pre_balances.get(addr).copied().unwrap_or(U256::ZERO);
            let new = account.info.balance;
            if old != new {
                balance_changes.insert(*addr, (old, new));
            }
        }

        StateDiff {
            storage_writes,
            balance_changes,
        }
    }
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CREATE address derivation (RLP(sender, nonce))
// ---------------------------------------------------------------------------

/// Compute the address produced by `CREATE` given `sender` and `nonce`.
///
/// `address = keccak256(rlp([sender, nonce]))[12..]`
fn compute_create_address(sender: Address, nonce: u64) -> Address {
    use tiny_keccak::{Hasher, Keccak};

    let stream = rlp_encode_sender_nonce(&sender, nonce);
    let mut hasher = Keccak::v256();
    hasher.update(&stream);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    Address::from_slice(&hash[12..])
}

/// Minimal RLP encoding of `[sender_address, nonce]`.
fn rlp_encode_sender_nonce(sender: &Address, nonce: u64) -> Vec<u8> {
    let addr_bytes = sender.as_slice(); // 20 bytes

    // RLP-encode the address: 0x80 + 20 = 0x94, then the 20 bytes.
    // RLP-encode the nonce:
    //   0        → 0x80
    //   1..=0x7f → single byte
    //   else     → 0x80+len, then big-endian bytes
    let nonce_rlp = rlp_encode_u64(nonce);

    let addr_rlp_len = 1 + 20; // 0x94 prefix + 20 bytes
    let total_payload = addr_rlp_len + nonce_rlp.len();

    let mut out = Vec::with_capacity(1 + total_payload + 1);

    // List header.
    if total_payload < 56 {
        out.push(0xc0 + total_payload as u8);
    } else {
        let len_bytes = minimal_be_bytes(total_payload);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }

    // Address item.
    out.push(0x80 + 20);
    out.extend_from_slice(addr_bytes);

    // Nonce item.
    out.extend_from_slice(&nonce_rlp);

    out
}

/// RLP-encode a `u64` value.
fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    if value <= 0x7f {
        return vec![value as u8];
    }
    let be = minimal_be_bytes(value as usize);
    let mut out = Vec::with_capacity(1 + be.len());
    out.push(0x80 + be.len() as u8);
    out.extend_from_slice(&be);
    out
}

/// Return the big-endian encoding of `val` without leading zeros.
fn minimal_be_bytes(val: usize) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first_nonzero..].to_vec()
}

// ---------------------------------------------------------------------------
// Trait re-exports for convenience
// ---------------------------------------------------------------------------

// Allow callers to use `revm::primitives::AccountInfo` without adding revm
// directly.
pub use revm::primitives::AccountInfo as RevmAccountInfo;
pub use revm::primitives::Bytecode as RevmBytecode;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::CoverageFeedback;
    use crate::types::B256;
    use revm::primitives::{AccountInfo, Bytecode};

    #[test]
    fn set_and_get_balance() {
        let mut exec = EvmExecutor::new();
        let addr = Address::with_last_byte(0x42);

        assert_eq!(exec.get_balance(addr), U256::ZERO);

        let one_eth = U256::from(1_000_000_000_000_000_000u128);
        exec.set_balance(addr, one_eth);
        assert_eq!(exec.get_balance(addr), one_eth);

        // Overwrite with a different value.
        let two_eth = one_eth + one_eth;
        exec.set_balance(addr, two_eth);
        assert_eq!(exec.get_balance(addr), two_eth);
    }

    #[test]
    fn snapshot_and_restore() {
        let mut exec = EvmExecutor::new();
        let addr = Address::with_last_byte(0x01);
        let bal = U256::from(999u64);

        exec.set_balance(addr, bal);
        let snap = exec.snapshot();

        // Mutate state after snapshot.
        exec.set_balance(addr, U256::ZERO);
        assert_eq!(exec.get_balance(addr), U256::ZERO);

        // Restore and verify original balance is back.
        exec.restore(snap);
        assert_eq!(exec.get_balance(addr), bal);
    }

    #[test]
    fn insert_account_info_with_bytecode() {
        let mut exec = EvmExecutor::new();
        let addr = Address::with_last_byte(0xAA);

        // PUSH1 0x00 PUSH1 0x00 RETURN  (trivial contract)
        let code = Bytecode::new_legacy(Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]));
        let info = AccountInfo {
            balance: U256::from(100u64),
            nonce: 1,
            code: Some(code),
            code_hash: B256::ZERO, // will be computed by insert_contract
        };

        exec.insert_account_info(addr, info);
        assert_eq!(exec.get_balance(addr), U256::from(100u64));
    }

    #[test]
    fn execute_simple_call() {
        let mut exec = EvmExecutor::new();
        let caller = Address::with_last_byte(0x01);
        let target = Address::with_last_byte(0x22);

        // Fund the caller.
        exec.set_balance(caller, U256::from(1_000_000u64));

        // Deploy a trivial contract that just STOPs.
        // STOP = 0x00
        let code = Bytecode::new_legacy(Bytes::from(vec![0x00]));
        exec.insert_account_info(
            target,
            AccountInfo {
                code: Some(code),
                ..Default::default()
            },
        );

        let tx = Transaction {
            sender: caller,
            to: Some(target),
            data: Bytes::new(),
            value: U256::ZERO,
            gas_limit: 1_000_000,
        };

        let result = exec.execute(&tx).expect("execution should succeed");
        assert!(result.success);
    }

    #[test]
    fn get_storage_default_is_zero() {
        let exec = EvmExecutor::new();
        let addr = Address::with_last_byte(0x10);
        assert_eq!(exec.get_storage(addr, U256::from(0u64)), U256::ZERO);
    }

    #[test]
    fn create_address_derivation() {
        // Known test vector: sender = 0x0000...01, nonce = 0
        // We just verify it returns a non-zero, deterministic address.
        let sender = Address::with_last_byte(0x01);
        let a = compute_create_address(sender, 0);
        let b = compute_create_address(sender, 0);
        assert_eq!(a, b);
        assert_ne!(a, Address::ZERO);

        // Different nonce → different address.
        let c = compute_create_address(sender, 1);
        assert_ne!(a, c);
    }

    #[test]
    fn default_block_env_is_sensible() {
        let exec = EvmExecutor::new();
        assert!(exec.block_env().number > RevmU256::ZERO);
        assert!(exec.block_env().timestamp > RevmU256::ZERO);
        assert!(exec.block_env().gas_limit > RevmU256::ZERO);
    }

    #[test]
    fn static_call_returns_output() {
        let mut exec = EvmExecutor::new();
        let caller = Address::with_last_byte(0x01);
        let target = Address::with_last_byte(0xCC);

        // Contract: store 1 at mem[0], return 32 bytes.
        // PUSH1 1, PUSH1 0, MSTORE8, PUSH1 0x20, PUSH1 0, RETURN
        let code = Bytecode::new_legacy(Bytes::from(vec![
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x53, // MSTORE8
            0x60, 0x20, // PUSH1 32  (return length)
            0x60, 0x00, // PUSH1 0   (return offset)
            0xf3, // RETURN
        ]));
        exec.insert_account_info(
            target,
            AccountInfo {
                code: Some(code),
                ..Default::default()
            },
        );

        let (success, output) = exec
            .static_call(caller, target, Bytes::new())
            .expect("static call should succeed");
        assert!(success);
        assert_eq!(output.len(), 32);
        assert_eq!(output[0], 1);
    }

    #[test]
    fn static_call_does_not_mutate_state() {
        let mut exec = EvmExecutor::new();
        let caller = Address::with_last_byte(0x01);
        let target = Address::with_last_byte(0xCC);

        // Contract: SSTORE(slot=0, value=0x42), then STOP.
        // PUSH1 0x42, PUSH1 0x00, SSTORE, STOP
        let code = Bytecode::new_legacy(Bytes::from(vec![
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0x00
            0x55, // SSTORE
            0x00, // STOP
        ]));
        exec.insert_account_info(
            target,
            AccountInfo {
                code: Some(code),
                ..Default::default()
            },
        );

        // static_call should succeed but NOT persist the SSTORE.
        let (success, _) = exec
            .static_call(caller, target, Bytes::new())
            .expect("static call should succeed");
        assert!(success);

        // Storage must still be zero — the write was on a cloned DB.
        assert_eq!(exec.get_storage(target, U256::from(0u64)), U256::ZERO);
    }

    #[test]
    fn executor_mode_defaults_to_fast() {
        let exec = EvmExecutor::new();
        assert_eq!(exec.mode, ExecutorMode::Fast);
    }

    #[test]
    fn set_mode_switches_to_realistic() {
        let mut exec = EvmExecutor::new();
        exec.set_mode(ExecutorMode::Realistic);
        assert_eq!(exec.mode, ExecutorMode::Realistic);
    }

    #[test]
    fn realistic_mode_rejects_unfunded_transfer() {
        let mut exec = EvmExecutor::new();
        exec.set_mode(ExecutorMode::Realistic);

        let sender = Address::with_last_byte(0x01);
        let recipient = Address::with_last_byte(0x02);

        // Sender has zero balance — do NOT fund them.
        // Deploy a trivial STOP contract at recipient so the call has a target.
        exec.insert_account_info(
            recipient,
            AccountInfo {
                code: Some(Bytecode::new_legacy(Bytes::from(vec![0x00]))),
                ..Default::default()
            },
        );

        let tx = Transaction {
            sender,
            to: Some(recipient),
            data: Bytes::new(),
            value: U256::from(1_000_000u64), // send value with no balance
            gas_limit: 1_000_000,
        };

        let result = exec.execute(&tx);
        // In Realistic mode the balance check is enforced, so this must
        // either error or produce a non-success result.
        match result {
            Err(_) => {} // transact-level rejection — acceptable
            Ok(r) => assert!(!r.success, "unfunded transfer must not succeed"),
        }
    }

    #[test]
    fn fast_mode_allows_unfunded_transfer() {
        let mut exec = EvmExecutor::new();
        // Fast is the default, but be explicit.
        exec.set_mode(ExecutorMode::Fast);

        let sender = Address::with_last_byte(0x01);
        let recipient = Address::with_last_byte(0x02);

        exec.insert_account_info(
            recipient,
            AccountInfo {
                code: Some(Bytecode::new_legacy(Bytes::from(vec![0x00]))),
                ..Default::default()
            },
        );

        let tx = Transaction {
            sender,
            to: Some(recipient),
            data: Bytes::new(),
            value: U256::from(1_000_000u64),
            gas_limit: 1_000_000,
        };

        let result = exec.execute(&tx).expect("fast mode should not error");
        assert!(result.success, "fast mode should allow unfunded transfer");
    }

    #[test]
    fn execute_collects_branch_sensitive_instruction_coverage() {
        let mut exec = EvmExecutor::new();
        let caller = Address::with_last_byte(0x21);
        let target = Address::with_last_byte(0x12);
        exec.set_balance(caller, U256::from(10u64));

        // A tiny loop whose first branch depends on CALLVALUE:
        // value=0 exits immediately, value>0 executes the loop body.
        let code = Bytecode::new_legacy(Bytes::from(vec![
            0x34, // CALLVALUE
            0x5b, // loop: JUMPDEST
            0x80, // DUP1
            0x15, // ISZERO
            0x60, 0x0e, // PUSH1 end
            0x57, // JUMPI
            0x60, 0x01, // PUSH1 1
            0x90, // SWAP1
            0x03, // SUB
            0x60, 0x01, // PUSH1 loop
            0x56, // JUMP
            0x5b, // end: JUMPDEST
            0x00, // STOP
        ]));
        exec.insert_account_info(
            target,
            AccountInfo {
                code: Some(code),
                ..Default::default()
            },
        );

        let zero_value = exec
            .execute(&Transaction {
                sender: caller,
                to: Some(target),
                data: Bytes::new(),
                value: U256::ZERO,
                gas_limit: 1_000_000,
            })
            .expect("zero-value call should execute");
        let nonzero_value = exec
            .execute(&Transaction {
                sender: caller,
                to: Some(target),
                data: Bytes::new(),
                value: U256::from(1u64),
                gas_limit: 1_000_000,
            })
            .expect("non-zero-value call should execute");

        assert_eq!(zero_value.coverage.hitcount(target, 7), 0);
        assert!(zero_value.coverage.hitcount(target, 14) > 0);

        assert!(nonzero_value.coverage.hitcount(target, 7) > 0);
        assert!(nonzero_value.coverage.hitcount(target, 9) > 0);
    }

    #[test]
    fn execute_collects_real_hitcounts_for_feedback_buckets() {
        let mut exec = EvmExecutor::new();
        let caller = Address::with_last_byte(0x11);
        let target = Address::with_last_byte(0x12);
        exec.set_balance(caller, U256::from(100u64));

        // Loop `CALLVALUE` times:
        // CALLVALUE; JUMPDEST; DUP1; ISZERO; PUSH1 end; JUMPI;
        // PUSH1 1; SWAP1; SUB; PUSH1 loop; JUMP; JUMPDEST; STOP
        let code = Bytecode::new_legacy(Bytes::from(vec![
            0x34, // CALLVALUE
            0x5b, // loop: JUMPDEST
            0x80, // DUP1
            0x15, // ISZERO
            0x60, 0x0e, // PUSH1 end
            0x57, // JUMPI
            0x60, 0x01, // PUSH1 1
            0x90, // SWAP1
            0x03, // SUB
            0x60, 0x01, // PUSH1 loop
            0x56, // JUMP
            0x5b, // end: JUMPDEST
            0x00, // STOP
        ]));
        exec.insert_account_info(
            target,
            AccountInfo {
                code: Some(code),
                ..Default::default()
            },
        );

        let one_iteration = exec
            .execute(&Transaction {
                sender: caller,
                to: Some(target),
                data: Bytes::new(),
                value: U256::from(1u64),
                gas_limit: 1_000_000,
            })
            .expect("1-iteration loop should execute");
        let four_iterations = exec
            .execute(&Transaction {
                sender: caller,
                to: Some(target),
                data: Bytes::new(),
                value: U256::from(4u64),
                gas_limit: 1_000_000,
            })
            .expect("4-iteration loop should execute");

        assert_eq!(one_iteration.coverage.hitcount(target, 1), 2);
        assert_eq!(four_iterations.coverage.hitcount(target, 1), 5);

        let mut feedback = CoverageFeedback::new();
        assert!(feedback.record_from_coverage_map(&one_iteration.coverage));
        assert!(
            feedback.record_from_coverage_map(&four_iterations.coverage),
            "higher loop hitcounts should move existing PCs into new AFL buckets"
        );
    }
}
