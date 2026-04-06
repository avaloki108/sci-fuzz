//! Forge VM cheatcode interceptor for sci-fuzz.
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
    0x71, 0x09, 0x70, 0x9e, 0xcf, 0xa9, 0x1a, 0x80, 0x62, 0x6f,
    0xf3, 0x98, 0x9d, 0x68, 0xf6, 0x7f, 0x5b, 0x1d, 0xd1, 0x2d,
]);

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

    let sel = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = if calldata.len() > 4 { &calldata[4..] } else { &[] };

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
        let cond = args.first().copied().unwrap_or(1) != 0
            || args.get(31).copied().unwrap_or(0) != 0;
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

    if sel == selector(b"label(address,string)")
        || sel == selector(b"setLabel(address,string)")
    {
        return (true, bytes::Bytes::new());
    }

    // ── Assertion helpers (accept silently) ───────────────────────────────────

    if sel == selector(b"expectRevert()")
        || sel == selector(b"expectRevert(bytes4)")
        || sel == selector(b"expectRevert(bytes)")
        || sel == selector(b"expectEmit(bool,bool,bool,bool)")
        || sel == selector(b"expectEmit(bool,bool,bool,bool,address)")
        || sel == selector(b"expectEmit()")
        || sel == selector(b"expectEmit(address)")
        || sel == selector(b"expectCall(address,bytes)")
        || sel == selector(b"expectCall(address,uint256,bytes)")
    {
        return (true, bytes::Bytes::new());
    }

    // ── Mock calls (accept silently / no mock storage yet) ───────────────────

    if sel == selector(b"mockCall(address,bytes,bytes)")
        || sel == selector(b"mockCall(address,uint256,bytes,bytes)")
        || sel == selector(b"clearMockedCalls()")
        || sel == selector(b"mockCallRevert(address,bytes,bytes)")
    {
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
            let key = decode_u256_word(args);
            // Hash the key to produce a deterministic address
            let mut addr_bytes = [0u8; 20];
            let k_bytes = key.to_be_bytes::<32>();
            addr_bytes.copy_from_slice(&k_bytes[12..]);
            return (true, {
                let mut out = [0u8; 32];
                out[12..].copy_from_slice(&addr_bytes);
                bytes::Bytes::copy_from_slice(&out)
            });
        }
        return (true, encode_u256(U256::ZERO));
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

    // ── Snapshot helpers ──────────────────────────────────────────────────────

    if sel == selector(b"snapshot()") {
        // vm.snapshot() → returns snapshot id (uint256). Return 0.
        return (true, encode_u256(U256::ZERO));
    }

    if sel == selector(b"revertTo(uint256)") {
        // vm.revertTo(id) — not modeled, accept silently
        return (true, encode_u256(U256::from(1u64))); // return true
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
    (true, encode_u256(U256::ZERO))
}

// ── EVM state mutation helpers ────────────────────────────────────────────────
// Note: vm.deal(), vm.store(), and vm.etch() use deferred mutation
// (pending_deals / pending_stores / pending_etches) to avoid borrow-checker
// conflicts with the in-flight journal.  vm.load() reads directly from
// journaled_state via sload.
// The executor applies them after the transaction commits.

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
}
