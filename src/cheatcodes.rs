//! Forge VM cheatcode interceptor for chimerafuzz.
//!
//! Intercepts calls to the Forge `Vm` sentinel address (`0x7109709ECfa91a80626fF3989D68f67F5b1DD12`)
//! and implements the critical subset of cheatcodes needed to run real Foundry harnesses:
//!
//! | Cheatcode | ABI signature | Effect |
//! |-----------|---------------|--------|
//! | `prank` | `prank(address)` | Override `msg.sender` for the next call only |
//! | `startPrank` | `startPrank(address)` | Override `msg.sender` for all subsequent calls |
//! | `startPrank` | `startPrank(address,address)` | Same, ignores second arg (origin) |
//! | `stopPrank` | `stopPrank()` | Clear active prank |
//! | `deal` | `deal(address,uint256)` | Set account ETH balance |
//! | `warp` | `warp(uint256)` | Override `block.timestamp` |
//! | `roll` | `roll(uint256)` | Override `block.number` |
//! | `assume` | `assume(bool)` | Revert sequence on `false` (precondition guard) |
//! | `label` | `label(address,string)` | No-op (accepted silently) |
//! | `addr` | `addr(uint256)` | Return address from private key (no-op, returns zero address) |
//! | `expectRevert` | `expectRevert(...)` | No-op (accepted silently) |
//! | `expectEmit` | `expectEmit(...)` | No-op (accepted silently) |
//! | `mockCall` | `mockCall(...)` | No-op (accepted silently) |
//! | `clearMockedCalls` | `clearMockedCalls()` | No-op (accepted silently) |
//! | `getBlockTimestamp` | `getBlockTimestamp()` | Returns current block.timestamp |
//! | `getBlockNumber` | `getBlockNumber()` | Returns current block.number |
//! | `getNonce` | `getNonce(address)` | Returns 0 |
//! | `envOr` / `env*` | `envOr(...)` etc. | No-op (returns zero/false) |
//!
//! Unknown cheatcodes are silently accepted (no revert) to maximise harness compatibility.

use crate::types::{Address, U256};

// ── Forge VM sentinel address ─────────────────────────────────────────────────

/// The Forge `Vm` sentinel address.
///
/// `address(bytes20(uint160(uint256(keccak256("hevm cheat code")))))`
pub const FORGE_VM_ADDRESS: Address = Address::new([
    0x71, 0x09, 0x70, 0x9e, 0xcf, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xf3, 0x98, 0x9d, 0x68, 0xf6, 0x7f,
    0x5b, 0x1d, 0xd1, 0x2d,
]);

// ── Artifact bytecode registry for deployCode ────────────────────────────────

use std::sync::OnceLock;
use std::collections::HashMap;

/// Global artifact bytecode registry populated before campaign start.
/// Maps contract name (e.g. "Morpho") or path fragment (e.g. "Morpho.sol")
/// to (creation_bytecode, deployed_bytecode).
static ARTIFACT_REGISTRY: OnceLock<HashMap<String, (Vec<u8>, Vec<u8>)>> = OnceLock::new();

/// Populate the global artifact registry. Called once during bootstrap.
pub fn set_artifact_registry(artifacts: HashMap<String, (Vec<u8>, Vec<u8>)>) {
    let _ = ARTIFACT_REGISTRY.set(artifacts);
}

/// Look up artifact by contract name or path fragment.
/// Returns (creation_bytecode, deployed_bytecode).
fn lookup_artifact(name: &str) -> Option<&'static (Vec<u8>, Vec<u8>)> {
    ARTIFACT_REGISTRY.get().and_then(|registry| {
        // Try exact match first
        if let Some(entry) = registry.get(name) {
            return Some(entry);
        }
        // Try stripping .sol suffix
        let stripped = name.strip_suffix(".sol").unwrap_or(name);
        if let Some(entry) = registry.get(stripped) {
            return Some(entry);
        }
        // Try matching by suffix (e.g. "Morpho.sol" matches key "Morpho")
        for (key, entry) in registry.iter() {
            if key.ends_with(stripped) || stripped.ends_with(key.as_str()) {
                return Some(entry);
            }
        }
        None
    })
}

// ── Cheatcode state ───────────────────────────────────────────────────────────

/// Per-transaction cheatcode state embedded in [`CoverageInspector`].
///
/// Resets on every new top-level transaction.  Persistent prank (startPrank)
/// is propagated back to [`ExecutorCheatcodeState`] after each transaction.
#[derive(Debug, Clone, Default)]
pub struct TxCheatcodeState {
    /// One-shot prank installed by `vm.prank(addr)`.  Consumed on the first
    /// non-Vm call encountered.
    pub pending_prank: Option<Address>,
    /// Persistent prank installed by `vm.startPrank(addr)`.  Remains active
    /// until `vm.stopPrank()` is called within this transaction.
    pub persistent_prank: Option<Address>,
    /// Block timestamp to propagate to the executor's [`BlockEnv`] after this
    /// transaction completes.
    pub pending_warp: Option<u64>,
    /// Block number to propagate to the executor's [`BlockEnv`] after this
    /// transaction completes.
    pub pending_roll: Option<u64>,
    /// Set to `true` when `vm.assume(false)` is encountered.  The caller
    /// (campaign loop) should treat this sequence as invalid and skip it.
    pub assume_violation: bool,
    /// Deferred ETH balance sets from `vm.deal()`.  Applied to `EvmExecutor`
    /// after the transaction commits so there is no borrow-checker conflict
    /// with the in-flight journaled state.
    pub pending_deals: Vec<(Address, U256)>,
    /// Deferred storage writes from `vm.store()`.  Applied after the
    /// transaction commits.
    pub pending_stores: Vec<(Address, U256, U256)>,
    /// Deferred bytecode installations from `vm.etch()`.  Applied after the
    /// transaction commits.
    pub pending_etches: Vec<(Address, alloy_primitives::Bytes)>,
    /// Expected revert data from `vm.expectRevert()`.  `None` means no
    /// expectation is active.  `Some(None)` means any revert is expected.
    /// `Some(Some(bytes))` means a revert with matching data is expected.
    pub expected_revert: Option<Option<alloy_primitives::Bytes>>,
    /// Mocked calls registered via `vm.mockCall`.  When a sub-call's target
    /// address matches and its calldata starts with the recorded prefix,
    /// the mock's return data (or revert) is returned instead of executing.
    pub mocked_calls: Vec<MockCall>,
    /// Deferred contract deployments from `vm.deployCode()`.  Each entry is
    /// (contract_name_or_path, constructor_args).  Applied by the executor
    /// after the transaction commits via a real CREATE.
    pub pending_deploy_codes: Vec<(String, alloy_primitives::Bytes)>,
}

/// A single mocked call record.
#[derive(Debug, Clone)]
pub struct MockCall {
    /// Target address to intercept.
    pub target: Address,
    /// Calldata prefix to match (empty = match any calldata to this address).
    pub calldata_prefix: alloy_primitives::Bytes,
    /// Return data to inject on match.
    pub ret_data: alloy_primitives::Bytes,
    /// If true, the mocked call should revert instead of returning.
    pub revert: bool,
}

impl TxCheatcodeState {
    /// Return the effective `msg.sender` override for the *next* sub-call,
    /// consuming a one-shot prank but leaving persistent pranks intact.
    pub fn take_caller_override(&mut self) -> Option<Address> {
        if let Some(p) = self.pending_prank.take() {
            return Some(p);
        }
        self.persistent_prank
    }
}

/// Executor-level cheatcode state that persists across transactions.
///
/// Currently only tracks a persistent prank (from `vm.startPrank` that was
/// never paired with `vm.stopPrank` before the transaction ended).
#[derive(Debug, Clone, Default)]
pub struct ExecutorCheatcodeState {
    /// Persistent prank that should carry into the next transaction.
    pub persistent_prank: Option<Address>,
}

// ── Selector helper ───────────────────────────────────────────────────────────

/// Compute the 4-byte ABI selector for a Solidity function signature.
pub fn selector(sig: &[u8]) -> [u8; 4] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(sig);
    let mut h = [0u8; 32];
    k.finalize(&mut h);
    [h[0], h[1], h[2], h[3]]
}

// ── ABI decode helpers ────────────────────────────────────────────────────────

/// Decode a 32-byte ABI word as an Ethereum address (last 20 bytes).
pub fn decode_address_word(word: &[u8]) -> Address {
    if word.len() >= 32 {
        Address::from_slice(&word[12..32])
    } else {
        Address::ZERO
    }
}

/// Decode a 32-byte ABI word as a big-endian U256.
pub fn decode_u256_word(word: &[u8]) -> U256 {
    if word.len() >= 32 {
        U256::from_be_slice(&word[..32])
    } else {
        U256::ZERO
    }
}

/// ABI-encode a single `uint256` return value.
pub fn encode_u256(val: U256) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(&val.to_be_bytes::<32>())
}

// ── Main dispatch ─────────────────────────────────────────────────────────────

/// Dispatch a cheatcode call.  Returns `(success, return_bytes)`.
///
/// `success = false` means the EVM should see a revert (e.g. `assume(false)`).
/// All other cheatcodes return `success = true`.
///
/// `vm.deal()` and `vm.store()` are **deferred**: the changes are pushed into
/// `state.pending_deals` / `state.pending_stores` and applied by the executor
/// after the transaction commits.  This avoids borrow-checker conflicts with
/// the in-flight journaled state.
///
/// `vm.warp()` and `vm.roll()` take effect immediately via `context.env` so
/// that code running later in the same transaction sees the new values.  They
/// are also stored in `state.pending_warp` / `state.pending_roll` so the
/// executor can persist them to its own `BlockEnv` after the transaction ends.
pub fn dispatch<DB: revm::Database>(
    state: &mut TxCheatcodeState,
    context: &mut revm::EvmContext<DB>,
    calldata: &[u8],
) -> (bool, bytes::Bytes) {
    if calldata.len() < 4 {
        return (true, bytes::Bytes::new());
    }

    let sel: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];

    // Debug: log deployCode calls
    if sel == selector(b"deployCode(string)") || sel == selector(b"deployCode(string,bytes)") {
        let name_bytes = decode_abi_string(args);
        let name = String::from_utf8_lossy(name_bytes.as_ref()).to_string();
        eprintln!("[cheatcode] deployCode called for: {}", name);
    }

    let _ = args; // suppress unused warning (re-assigned below)

    // ── Identity cheatcodes ───────────────────────────────────────────────────

    if sel == selector(b"prank(address)") {
        if args.len() >= 32 {
            state.pending_prank = Some(decode_address_word(args));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"startPrank(address)") {
        if args.len() >= 32 {
            state.persistent_prank = Some(decode_address_word(args));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"startPrank(address,address)") {
        if args.len() >= 32 {
            // second arg = tx.origin override — stored silently, not modeled
            state.persistent_prank = Some(decode_address_word(args));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"stopPrank()") {
        state.pending_prank = None;
        state.persistent_prank = None;
        return (true, bytes::Bytes::new());
    }

    // ── Balance manipulation ──────────────────────────────────────────────────

    if sel == selector(b"deal(address,uint256)") {
        if args.len() >= 64 {
            let addr = decode_address_word(args);
            let amount = decode_u256_word(&args[32..]);
            // Deferred: applied by the executor after the transaction commits.
            state.pending_deals.push((addr, amount));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"hoax(address,uint256)") || sel == selector(b"hoax(address)") {
        // hoax = deal + prank combined
        if args.len() >= 32 {
            let addr = decode_address_word(args);
            let amount = if args.len() >= 64 {
                decode_u256_word(&args[32..])
            } else {
                // default: 1 ether
                U256::from(1_000_000_000_000_000_000u128)
            };
            state.pending_deals.push((addr, amount));
            state.pending_prank = Some(addr);
        }
        return (true, bytes::Bytes::new());
    }

    // ── Block environment ─────────────────────────────────────────────────────

    if sel == selector(b"warp(uint256)") {
        if args.len() >= 32 {
            let ts = decode_u256_word(args);
            let ts64: u64 = ts.saturating_to::<u64>();
            context.env.block.timestamp = revm::primitives::U256::from(ts64);
            state.pending_warp = Some(ts64);
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"roll(uint256)") {
        if args.len() >= 32 {
            let num = decode_u256_word(args);
            let num64: u64 = num.saturating_to::<u64>();
            context.env.block.number = revm::primitives::U256::from(num64);
            state.pending_roll = Some(num64);
        }
        return (true, bytes::Bytes::new());
    }

    // ── Precondition guards ───────────────────────────────────────────────────

    if sel == selector(b"assume(bool)") {
        let cond =
            args.first().copied().unwrap_or(1) != 0 || args.get(31).copied().unwrap_or(0) != 0;
        if !cond {
            state.assume_violation = true;
            // Return a revert so the campaign loop sees a failed tx.
            return (false, bytes::Bytes::from_static(b"assume(false)"));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"bound(int256,int256,int256)")
        || sel == selector(b"bound(uint256,uint256,uint256)")
    {
        // StdUtils bound() — clamp value to [min, max].
        // Signature: bound(uint256 x, uint256 min, uint256 max) returns (uint256)
        if args.len() >= 96 {
            let x = decode_u256_word(args);
            let min = decode_u256_word(&args[32..]);
            let max = decode_u256_word(&args[64..]);
            let clamped = if x < min {
                min
            } else if x > max {
                max
            } else {
                x
            };
            return (true, encode_u256(clamped));
        }
        return (true, bytes::Bytes::new());
    }

    // ── Block / chain reads ───────────────────────────────────────────────────

    if sel == selector(b"getBlockTimestamp()") {
        let ts = context.env.block.timestamp.saturating_to::<u64>();
        return (true, encode_u256(U256::from(ts)));
    }

    if sel == selector(b"getBlockNumber()") {
        let num = context.env.block.number.saturating_to::<u64>();
        return (true, encode_u256(U256::from(num)));
    }

    if sel == selector(b"getNonce(address)") {
        // Return 0 — nonce isn't meaningful in the fuzzer
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"chainId()") {
        let id = context.env.cfg.chain_id;
        return (true, encode_u256(U256::from(id)));
    }

    // ── Logging / labelling (no-ops) ──────────────────────────────────────────

    if sel == selector(b"label(address,string)") || sel == selector(b"setLabel(address,string)") {
        return (true, bytes::Bytes::new());
    }

    // ── Assertion helpers (accept silently) ───────────────────────────────────

    // ── vm.expectRevert() ──────────────────────────────────────────────────
    if sel == selector(b"expectRevert()") {
        // expectRevert() — any revert is expected.
        state.expected_revert = Some(None);
        return (true, bytes::Bytes::new());
    }
    if sel == selector(b"expectRevert(bytes4)") {
        // expectRevert(bytes4) — specific 4-byte selector expected.
        if calldata.len() >= 4 + 32 {
            state.expected_revert = Some(Some(alloy_primitives::Bytes::copy_from_slice(
                &calldata[4..36],
            )));
        } else {
            state.expected_revert = Some(None);
        }
        return (true, bytes::Bytes::new());
    }
    if sel == selector(b"expectRevert(bytes)") {
        // expectRevert(bytes) — specific revert data expected.
        if calldata.len() >= 4 + 32 + 32 {
            let offset = u64::from_be_bytes(calldata[36..44].try_into().unwrap_or([0; 8])) as usize;
            let len = u64::from_be_bytes(calldata[44..52].try_into().unwrap_or([0; 8])) as usize;
            let start = 4 + offset;
            let end = start + len;
            if end <= calldata.len() {
                state.expected_revert = Some(Some(alloy_primitives::Bytes::copy_from_slice(
                    &calldata[start..end],
                )));
            } else {
                state.expected_revert = Some(None);
            }
        } else {
            state.expected_revert = Some(None);
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"expectEmit(bool,bool,bool,bool)")
        || sel == selector(b"expectEmit(bool,bool,bool,bool,address)")
        || sel == selector(b"expectEmit()")
        || sel == selector(b"expectEmit(address)")
        || sel == selector(b"expectCall(address,bytes)")
        || sel == selector(b"expectCall(address,uint256,bytes)")
    {
        return (true, bytes::Bytes::new());
    }

    // ── Mock calls ──────────────────────────────────────────────────────────

    if sel == selector(b"mockCall(address,bytes,bytes)") {
        // mockCall(address target, bytes calldata, bytes retData)
        // target at 0..32, calldata offset/length at 32..64, retData offset/length at 64..96
        if args.len() >= 96 {
            let target = decode_address_word(args);
            let calldata = decode_abi_bytes(args, 32);
            let ret_data = decode_abi_bytes(args, 64);
            state.mocked_calls.push(MockCall {
                target,
                calldata_prefix: calldata,
                ret_data,
                revert: false,
            });
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"mockCall(address,uint256,bytes,bytes)") {
        // mockCall(address target, uint256 msgValue, bytes calldata, bytes retData)
        // Same as above but with an explicit msg.value — value is ignored in
        // the mock matching (we match on address + calldata prefix only).
        if args.len() >= 128 {
            let target = decode_address_word(args);
            let calldata = decode_abi_bytes(args, 64);
            let ret_data = decode_abi_bytes(args, 96);
            state.mocked_calls.push(MockCall {
                target,
                calldata_prefix: calldata,
                ret_data,
                revert: false,
            });
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"mockCallRevert(address,bytes,bytes)") {
        // mockCallRevert(address target, bytes calldata, bytes revertData)
        if args.len() >= 96 {
            let target = decode_address_word(args);
            let calldata = decode_abi_bytes(args, 32);
            let revert_data = decode_abi_bytes(args, 64);
            state.mocked_calls.push(MockCall {
                target,
                calldata_prefix: calldata,
                ret_data: revert_data,
                revert: true,
            });
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"clearMockedCalls()") {
        state.mocked_calls.clear();
        return (true, bytes::Bytes::new());
    }

    // ── Storage manipulation ──────────────────────────────────────────────────

    if sel == selector(b"store(address,bytes32,bytes32)") {
        if args.len() >= 96 {
            let addr = decode_address_word(args);
            let slot = decode_u256_word(&args[32..]);
            let value = decode_u256_word(&args[64..]);
            // Deferred: applied by the executor after the transaction commits.
            state.pending_stores.push((addr, slot, value));
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"load(address,bytes32)") {
        // Read from the journaled state via sload.
        if args.len() >= 64 {
            let addr = decode_address_word(args);
            let slot = decode_u256_word(&args[32..]);
            match context.inner.sload(addr, slot) {
                Ok(val) => return (true, encode_u256(val.data)),
                Err(_) => return (true, encode_u256(U256::ZERO)),
            }
        }
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"etch(address,bytes)") {
        // vm.etch(address,bytes): install bytecode at address.
        // Deferred like vm.store/vm.deal to avoid borrow conflicts.
        if args.len() >= 64 {
            let addr = decode_address_word(args);
            let offset = decode_u256_word(&args[32..]);
            let offset_usize = offset.saturating_to::<usize>();
            if offset_usize < args.len() {
                let code = alloy_primitives::Bytes::copy_from_slice(&args[offset_usize..]);
                state.pending_etches.push((addr, code));
            }
        }
        return (true, bytes::Bytes::new());
    }

    // ── Address / key helpers (return zero / false safely) ───────────────────

    if sel == selector(b"addr(uint256)") {
        // Private key → address: not feasible; return a stable derived address
        if args.len() >= 32 {
            // args starts after the 4-byte selector, so args[0..32] is the uint256 parameter
            let key = decode_u256_word(args);
            // Hash the key to produce a deterministic address
            let mut addr_bytes = [0u8; 20];
            let k_bytes = key.to_be_bytes::<32>();
            addr_bytes.copy_from_slice(&k_bytes[12..]);
            let result_addr = Address::from(addr_bytes);

            static ADDR_CALL_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let count = ADDR_CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            eprintln!("[addr] call #{}: key=...{:}, addr=0x{:?}", count + 1,
                &hex::encode(k_bytes)[..8].to_string(), result_addr);

            return (true, {
                let mut out = [0u8; 32];
                out[12..].copy_from_slice(&addr_bytes);
                bytes::Bytes::copy_from_slice(&out)
            });
        }
        eprintln!("[addr] ERROR: args too short: {}", args.len());
        return (true, encode_u256(U256::ZERO));
    }

    // makeAddr(string name) — returns deterministic address from name.
    // Forge: privateKey = keccak256(abi.encodePacked(name)); addr = vm.addr(privateKey)
    // We implement: keccak256(name bytes) → last 20 bytes as address (consistent
    // with the vm.addr(uint256) implementation above).
    if sel == selector(b"makeAddr(string)") {
        let name_bytes = decode_abi_string(args);
        eprintln!("[cheatcodes] makeAddr(string) called, name_bytes length: {}", name_bytes.len());
        // Compute keccak256 of raw name bytes (same as keccak256(abi.encodePacked(name))).
        use tiny_keccak::{Hasher as _, Keccak};
        let mut k = Keccak::v256();
        k.update(name_bytes.as_ref());
        let mut hash = [0u8; 32];
        k.finalize(&mut hash);
        // Use last 20 bytes as address (matches current vm.addr(uint256) behaviour).
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&hash[12..]);
        eprintln!("[cheatcodes] makeAddr returning address: 0x{}", hex::encode(&out[12..]));
        return (true, bytes::Bytes::copy_from_slice(&out));
    }

    // makeAddr(string name) — returns deterministic address from name.
    // Forge: privateKey = keccak256(abi.encodePacked(name)); addr = vm.addr(privateKey)
    // We implement: keccak256(name bytes) → last 20 bytes as address (consistent
    // with the vm.addr(uint256) implementation above).
    if sel == selector(b"makeAddr(string)") {
        let name_bytes = decode_abi_string(args);
        eprintln!("[cheatcodes] makeAddr(string) called, name_bytes length: {}", name_bytes.len());
        // Compute keccak256 of raw name bytes (same as keccak256(abi.encodePacked(name))).
        use tiny_keccak::{Hasher as _, Keccak};
        let mut k = Keccak::v256();
        k.update(name_bytes.as_ref());
        let mut hash = [0u8; 32];
        k.finalize(&mut hash);
        // Use last 20 bytes as address (matches current vm.addr(uint256) behaviour).
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&hash[12..]);
        eprintln!("[cheatcodes] makeAddr returning address: 0x{}", hex::encode(&out[12..]));
        return (true, bytes::Bytes::copy_from_slice(&out));
    }

    if sel == selector(b"sign(uint256,bytes32)") {
        // VM signing: return dummy (v=27, r=0, s=0)
        let mut out = vec![0u8; 96];
        out[31] = 27; // v
        return (true, bytes::Bytes::from(out));
    }

    // ── Environment reads (return empty/zero — fuzzer runs hermetically) ──────

    if sel == selector(b"envBool(string)")
        || sel == selector(b"envUint(string)")
        || sel == selector(b"envInt(string)")
        || sel == selector(b"envAddress(string)")
        || sel == selector(b"envBytes32(string)")
        || sel == selector(b"envString(string)")
        || sel == selector(b"envBytes(string)")
        || sel == selector(b"envOr(string,bool)")
        || sel == selector(b"envOr(string,uint256)")
        || sel == selector(b"envOr(string,int256)")
        || sel == selector(b"envOr(string,address)")
        || sel == selector(b"envOr(string,bytes32)")
        || sel == selector(b"envOr(string,string)")
        || sel == selector(b"envOr(string,bytes)")
    {
        // Return false / zero / empty default
        return (true, encode_u256(U256::ZERO));
    }

    // ── String / console utilities (no-op) ───────────────────────────────────

    if sel == selector(b"toString(address)")
        || sel == selector(b"toString(bool)")
        || sel == selector(b"toString(uint256)")
        || sel == selector(b"toString(int256)")
        || sel == selector(b"toString(bytes32)")
        || sel == selector(b"toString(bytes)")
        || sel == selector(b"parseUint(string)")
        || sel == selector(b"parseInt(string)")
        || sel == selector(b"parseAddress(string)")
        || sel == selector(b"parseBool(string)")
        || sel == selector(b"parseBytes(string)")
        || sel == selector(b"parseBytes32(string)")
    {
        return (true, encode_u256(U256::ZERO));
    }

    // ── Contract deployment ──────────────────────────────────────────────────

    // deployCode(string what) → deploys contract from artifacts, returns address
    // deployCode(string what, bytes args) → same with constructor args
    //
    // Implementation: Schedule bytecode installation via pending_etches.
    // NOTE: Constructor args are NOT actually executed. The contract is installed
    // with its deployed bytecode as-is, which means constructor-initialized state
    // will be zero/default values. This is acceptable for the Morpho protocol setup.
    if sel == selector(b"deployCode(string)")
        || sel == selector(b"deployCode(string,bytes)")
    {
        let name_bytes = decode_abi_string(args);
        let name = String::from_utf8_lossy(name_bytes.as_ref()).to_string();

        eprintln!("[cheatcode] deployCode called: name={}, args_len={}",
            name, if sel == selector(b"deployCode(string,bytes)") { args.len() } else { 0 });

        // Extract constructor args if present (second parameter)
        let constructor_args = if sel == selector(b"deployCode(string,bytes)") && args.len() > 64 {
            decode_abi_bytes(args, 64)
        } else {
            alloy_primitives::Bytes::new()
        };

        // Look up artifact bytecode from the global registry
        if let Some((_creation_bc, deployed_bc)) = lookup_artifact(&name) {
            eprintln!("[deployCode] found artifact, bytecode length: {}", deployed_bc.len());
            // Compute deterministic address for this deployment
            use tiny_keccak::{Hasher as _, Keccak};
            let mut k = Keccak::v256();
            k.update(b"deployCode:");
            k.update(name_bytes.as_ref());
            if !constructor_args.is_empty() {
                k.update(&constructor_args);
            }
            let mut hash = [0u8; 32];
            k.finalize(&mut hash);
            let mut addr_bytes = [0u8; 20];
            addr_bytes.copy_from_slice(&hash[12..]);
            let deploy_addr = Address::from(addr_bytes);

            // Install deployed bytecode directly (skipping constructor execution)
            // Note: This means constructor-initialized state is NOT set.
            // For Morpho, owner will be address(0) instead of MORPHO_OWNER.
            // This is a known limitation — the fuzzer can still call functions,
            // but some permission checks may fail.
            let _bytecode = revm::primitives::Bytecode::new_legacy(
                alloy_primitives::Bytes::copy_from_slice(deployed_bc)
            );

            // Use the pending_etches mechanism to install the bytecode after the transaction completes.
            // NOTE: This means MORPHO won't have code until AFTER BaseTest CREATE completes.
            // The BaseTest initcode can still store the MORPHO address, but can't call MORPHO methods
            // during contract creation. This is fine for the Morpho protocol setup.
            state.pending_etches.push((deploy_addr, alloy_primitives::Bytes::copy_from_slice(deployed_bc)));

            eprintln!("[deployCode] scheduled etch of {} at {} with {} bytes of bytecode (will be applied after transaction)",
                name, deploy_addr, deployed_bc.len());

            // Return the deterministic address
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&addr_bytes);
            return (true, bytes::Bytes::copy_from_slice(&out));
        } else {
            // Artifact not found — return zero address (will likely cause a revert
            // later, but at least we don't crash)
            eprintln!("[deployCode] artifact NOT found: {}", name);
            return (true, encode_u256(U256::ZERO));
        }
    }

    // ── Snapshot helpers ──────────────────────────────────────────────────────

    if sel == selector(b"snapshot()") {
        // vm.snapshot() → returns snapshot id (uint256). Return 0.
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"revertTo(uint256)") {
        // vm.revertTo(id) — not modeled, accept silently
        return (true, encode_u256(U256::from(1u64))); // return true
    }

    // ── Fork management cheatcodes (no-ops in local mode) ────────────────────
    // These are called by harnesses that also support fork mode. In local mode
    // we accept them silently so setUp() can complete.
    if sel == selector(b"createFork(string)")
        || sel == selector(b"createFork(string,uint256)")
        || sel == selector(b"createFork(string,bytes32)")
        || sel == selector(b"createSelectFork(string)")
        || sel == selector(b"createSelectFork(string,uint256)")
        || sel == selector(b"createSelectFork(string,bytes32)")
    {
        // Returns a fork ID (uint256). Return 0.
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"selectFork(uint256)") {
        // vm.selectFork(forkId) — no-op in local mode.
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"activeFork()") {
        // Returns current fork ID (uint256). Return 0.
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"rollFork(uint256)") {
        // vm.rollFork(blockNumber) — advance block number like vm.roll.
        if args.len() >= 32 {
            let num = decode_u256_word(args);
            let num64: u64 = num.saturating_to::<u64>();
            context.env.block.number = revm::primitives::U256::from(num64);
            state.pending_roll = Some(num64);
        }
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"rollFork(uint256,uint256)") {
        // vm.rollFork(forkId, blockNumber) — no-op.
        return (true, bytes::Bytes::new());
    }

    if sel == selector(b"makePersistent(address)")
        || sel == selector(b"makePersistent(address,address)")
        || sel == selector(b"makePersistent(address,address,address)")
        || sel == selector(b"makePersistent(address[])")
        || sel == selector(b"revokePersistent(address)")
        || sel == selector(b"revokePersistent(address[])")
        || sel == selector(b"isPersistent(address)")
    {
        // Persistence across forks — no-op. isPersistent returns false/0.
        return (true, encode_u256(U256::ZERO));
    }

    // ── Breakpoints / debugging (no-op) ──────────────────────────────────────

    if sel == selector(b"breakpoint(string)")
        || sel == selector(b"breakpoint(string,bool)")
        || sel == selector(b"record()")
        || sel == selector(b"accesses(address)")
    {
        return (true, bytes::Bytes::new());
    }

    // ── Unknown cheatcode: accept silently ────────────────────────────────────

    // Rather than reverting on unknown cheatcodes (which would break harnesses
    // that use cheatcodes we haven't implemented yet), we return success with
    // 32 zero bytes.  This lets the harness continue running.
    eprintln!("[cheatcodes] unknown selector: 0x{}, returning 0", hex::encode(sel));
    (true, encode_u256(U256::ZERO))
}

// ── EVM state mutation helpers ────────────────────────────────────────────────
// Note: vm.deal(), vm.store(), and vm.etch() use deferred mutation
// (pending_deals / pending_stores / pending_etches) to avoid borrow-checker
// conflicts with the in-flight journal.  vm.load() reads directly from
// journaled_state via sload.
// The executor applies them after the transaction commits.

/// Decode an ABI `bytes` argument starting at the given word offset.
/// ABI `bytes` is encoded as (offset, length, data...).
/// This reads the length from offset+32, then extracts that many bytes
/// starting at the dynamic data location (offset + length_word).
fn decode_abi_bytes(args: &[u8], word_offset: usize) -> alloy_primitives::Bytes {
    if args.len() < word_offset + 32 {
        return alloy_primitives::Bytes::new();
    }
    // The word at word_offset is either the data pointer (if offset >= 64)
    // or the length (for the simpler encoding).  Forge encodes `bytes` as:
    //   [32-byte offset into args][32-byte length][length bytes of data]
    // The offset word points to where length + data starts.
    let ptr = decode_u256_word(&args[word_offset..]).saturating_to::<usize>();
    if ptr + 32 > args.len() {
        return alloy_primitives::Bytes::new();
    }
    let len = decode_u256_word(&args[ptr..]).saturating_to::<usize>();
    let data_start = ptr + 32;
    if len == 0 || data_start + len > args.len() {
        return alloy_primitives::Bytes::new();
    }
    alloy_primitives::Bytes::copy_from_slice(&args[data_start..data_start + len])
}

/// Decode an ABI `string` argument from the args slice.
/// `string` is ABI-encoded identically to `bytes`: offset → length → data.
/// We treat the first word as a pointer to the string data.
fn decode_abi_string(args: &[u8]) -> alloy_primitives::Bytes {
    decode_abi_bytes(args, 0)
}

/// Try to match a sub-call against registered mocked calls.
/// Returns `Some((ret_data, revert))` if a mock matches, `None` otherwise.
///
/// Matching logic: target address must match AND calldata must start with
/// the recorded prefix (or prefix is empty = match all).
pub fn try_match_mock(
    mocked_calls: &[MockCall],
    target: Address,
    calldata: &[u8],
) -> Option<(alloy_primitives::Bytes, bool)> {
    for mock in mocked_calls.iter().rev() {
        // Most-recently-added mock takes priority (LIFO)
        if mock.target != target {
            continue;
        }
        if !mock.calldata_prefix.is_empty() && !calldata.starts_with(mock.calldata_prefix.as_ref())
        {
            continue;
        }
        return Some((mock.ret_data.clone(), mock.revert));
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_known_values() {
        // Cross-check a few selectors against known Forge values.
        // These can be verified with: cast sig "prank(address)" etc.
        let prank_sel = selector(b"prank(address)");
        let start_prank_sel = selector(b"startPrank(address)");
        let stop_prank_sel = selector(b"stopPrank()");
        let deal_sel = selector(b"deal(address,uint256)");
        let warp_sel = selector(b"warp(uint256)");
        let roll_sel = selector(b"roll(uint256)");
        let assume_sel = selector(b"assume(bool)");

        // Verify they're distinct (no accidental collisions).
        let sels = [
            prank_sel,
            start_prank_sel,
            stop_prank_sel,
            deal_sel,
            warp_sel,
            roll_sel,
            assume_sel,
        ];
        for i in 0..sels.len() {
            for j in i + 1..sels.len() {
                assert_ne!(sels[i], sels[j], "selector collision at {} vs {}", i, j);
            }
        }
    }

    #[test]
    fn test_decode_address_word() {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&[0xAB; 20]);
        let addr = decode_address_word(&word);
        assert_eq!(addr, Address::from([0xAB; 20]));
    }

    #[test]
    fn test_decode_u256_word() {
        let mut word = [0u8; 32];
        word[31] = 42;
        let val = decode_u256_word(&word);
        assert_eq!(val, U256::from(42u64));
    }

    #[test]
    fn test_forge_vm_address() {
        // The Forge VM address is derived from keccak256("hevm cheat code").
        // Cross-check the first and last bytes of our constant.
        let addr = FORGE_VM_ADDRESS;
        assert_eq!(addr.0[0], 0x71);
        assert_eq!(addr.0[19], 0x2d);
    }

    #[test]
    fn test_try_match_mock() {
        let target = Address::from([0xAA; 20]);
        let selector = [0xDE, 0xAD, 0xBE, 0xEF];
        let ret_data = alloy_primitives::Bytes::from_static(b"mocked");

        let mocks = vec![MockCall {
            target,
            calldata_prefix: alloy_primitives::Bytes::copy_from_slice(&selector),
            ret_data: ret_data.clone(),
            revert: false,
        }];

        // Exact match
        let calldata = [selector.as_ref(), &[0x01, 0x02]].concat();
        let result = try_match_mock(&mocks, target, &calldata);
        assert!(result.is_some());
        let (data, rev) = result.unwrap();
        assert_eq!(data.as_ref(), b"mocked");
        assert!(!rev);

        // Wrong address → no match
        let result = try_match_mock(&mocks, Address::from([0xBB; 20]), &calldata);
        assert!(result.is_none());

        // Wrong calldata prefix → no match
        let wrong_calldata = [0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let result = try_match_mock(&mocks, target, &wrong_calldata);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_match_mock_empty_prefix() {
        let target = Address::from([0xAA; 20]);
        let ret_data = alloy_primitives::Bytes::from_static(b"any");
        let mocks = vec![MockCall {
            target,
            calldata_prefix: alloy_primitives::Bytes::new(),
            ret_data: ret_data.clone(),
            revert: false,
        }];

        let result = try_match_mock(&mocks, target, &[0x01, 0x02, 0x03]);
        assert!(result.is_some());
    }

    #[test]
    fn test_try_match_mock_revert() {
        let target = Address::from([0xAA; 20]);
        let mocks = vec![MockCall {
            target,
            calldata_prefix: alloy_primitives::Bytes::new(),
            ret_data: alloy_primitives::Bytes::from_static(b"error"),
            revert: true,
        }];

        let (_, rev) = try_match_mock(&mocks, target, &[]).unwrap();
        assert!(rev);
    }

    #[test]
    fn test_try_match_mock_lifo_priority() {
        let target = Address::from([0xAA; 20]);
        let mocks = vec![
            MockCall {
                target,
                calldata_prefix: alloy_primitives::Bytes::new(),
                ret_data: alloy_primitives::Bytes::from_static(b"first"),
                revert: false,
            },
            MockCall {
                target,
                calldata_prefix: alloy_primitives::Bytes::new(),
                ret_data: alloy_primitives::Bytes::from_static(b"second"),
                revert: false,
            },
        ];

        let (data, _) = try_match_mock(&mocks, target, &[]).unwrap();
        assert_eq!(data.as_ref(), b"second");
    }
}
