//! Transaction mutators for coverage-guided fuzzing.
//!
//! Generates and mutates EVM transactions targeting smart contracts.  The
//! mutator is ABI-aware: when contract ABIs are available it extracts
//! four-byte function selectors and builds well-formed calldata.  When no
//! ABI is present it falls back to raw random bytes.

use std::collections::{HashMap, HashSet};

use rand::Rng;

use crate::types::{Address, Bytes, ContractInfo, ExecutionResult, Transaction, B256, U256};

// ---------------------------------------------------------------------------
// Common ETH values for payable function fuzzing
// ---------------------------------------------------------------------------

/// Commonly meaningful ETH amounts used when fuzzing payable functions.
const COMMON_ETH_VALUES: &[u128] = &[
    1,                          // 1 wei
    1_000_000_000,              // 1 gwei
    10_000_000_000_000_000,     // 0.01 ether
    100_000_000_000_000_000,    // 0.1 ether
    1_000_000_000_000_000_000,  // 1 ether
    10_000_000_000_000_000_000, // 10 ether
];

// ---------------------------------------------------------------------------
// Selector helpers
// ---------------------------------------------------------------------------

/// Keccak-256 the input and return the first four bytes (the EVM function
/// selector).
fn keccak_selector(data: &[u8]) -> [u8; 4] {
    use tiny_keccak::{Hasher, Keccak};
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Try to reconstruct a Solidity canonical signature from a JSON ABI entry
/// and return its four-byte selector.
///
/// The expected shape is the standard `solc --abi` output:
///
/// ```json
/// { "type": "function", "name": "transfer",
///   "inputs": [{"type": "address"}, {"type": "uint256"}] }
/// ```
fn selector_from_abi_entry(entry: &serde_json::Value) -> Option<[u8; 4]> {
    let name = entry.get("name")?.as_str()?;
    let inputs = entry.get("inputs")?.as_array()?;

    let param_types: Vec<&str> = inputs
        .iter()
        .filter_map(|p| p.get("type").and_then(|t| t.as_str()))
        .collect();

    let sig = format!("{}({})", name, param_types.join(","));
    Some(keccak_selector(sig.as_bytes()))
}

// ---------------------------------------------------------------------------
// ValueDictionary
// ---------------------------------------------------------------------------

/// Dictionary of "interesting" values observed during fuzzing.
///
/// Modeled after Medusa's Slither integration and EF/CF's bytecode constant
/// extraction.  Values are seeded from:
/// - Constants in contract bytecode (PUSH1..PUSH32 operands)
/// - Return values and log data from executions
/// - Common boundary values (0, 1, MAX_UINT, etc.)
#[derive(Debug, Clone, Default)]
pub struct ValueDictionary {
    /// Interesting uint256 values.
    pub uint_values: Vec<U256>,
    /// Interesting addresses.
    pub address_values: Vec<Address>,
    /// Interesting bytes32 values.
    pub bytes32_values: Vec<B256>,
}

impl ValueDictionary {
    /// Create a new dictionary seeded with common boundary values.
    pub fn new() -> Self {
        let uint_values = vec![
            U256::ZERO,
            U256::from(1u64),
            U256::from(2u64),
            U256::MAX,
            // type(uint128).max
            U256::from(u128::MAX),
            // type(uint64).max
            U256::from(u64::MAX),
            // Common block numbers
            U256::from(15_000_000u64),
            U256::from(18_000_000u64),
            // Common timestamps (Unix epoch relative)
            U256::from(1_000_000u64),
            U256::from(1_700_000_000u64),
            // Powers of 2 and common boundaries
            U256::from(1u64) << 255, // sign bit for int256
            U256::from(0xdeadu64),   // common magic value
        ];

        let address_values = vec![Address::ZERO];

        let bytes32_values = vec![B256::ZERO];

        Self {
            uint_values,
            address_values,
            bytes32_values,
        }
    }

    /// Extract PUSH1..PUSH32 operands from EVM bytecode and add them to the
    /// dictionary.
    ///
    /// EVM PUSH opcodes range from 0x60 (PUSH1) to 0x7f (PUSH32).
    /// Each pushes N bytes (where N = opcode − 0x5f) as an immediate operand.
    pub fn seed_from_bytecode(&mut self, bytecode: &[u8]) {
        let mut i = 0;
        while i < bytecode.len() {
            let op = bytecode[i];
            if (0x60..=0x7f).contains(&op) {
                let n = (op - 0x60 + 1) as usize;
                if i + 1 + n <= bytecode.len() {
                    let operand = &bytecode[i + 1..i + 1 + n];

                    // Store as U256 (left-pad with zeros to 32 bytes).
                    let mut padded = [0u8; 32];
                    padded[32 - n..].copy_from_slice(operand);
                    let val = U256::from_be_bytes(padded);
                    if !self.uint_values.contains(&val) {
                        self.uint_values.push(val);
                    }

                    // If exactly 20 bytes, also store as address.
                    if n == 20 {
                        let addr = Address::from_slice(operand);
                        if !self.address_values.contains(&addr) {
                            self.address_values.push(addr);
                        }
                    }

                    // If exactly 32 bytes, also store as bytes32.
                    if n == 32 {
                        let b32 = B256::from(padded);
                        if !self.bytes32_values.contains(&b32) {
                            self.bytes32_values.push(b32);
                        }
                    }

                    i += 1 + n;
                } else {
                    break; // truncated bytecode
                }
            } else {
                i += 1;
            }
        }
    }

    /// Extract interesting values from an execution result.
    ///
    /// Harvests values from return data, log topics/data, and storage writes.
    pub fn seed_from_execution(&mut self, result: &ExecutionResult) {
        // Extract 32-byte words from return data.
        self.extract_words_from_bytes(&result.output);

        // Extract from logs.
        for log in &result.logs {
            for topic in &log.topics {
                if !self.bytes32_values.contains(topic) {
                    self.bytes32_values.push(*topic);
                }
                let val = U256::from_be_bytes(topic.0);
                if !self.uint_values.contains(&val) {
                    self.uint_values.push(val);
                }
                // Extract address from topic (last 20 bytes).
                let addr = Address::from_slice(&topic.0[12..]);
                if !self.address_values.contains(&addr) {
                    self.address_values.push(addr);
                }
            }
            self.extract_words_from_bytes(&log.data);
        }

        // Extract from storage writes.
        for (addr, writes) in &result.state_diff.storage_writes {
            if !self.address_values.contains(addr) {
                self.address_values.push(*addr);
            }
            for (slot, value) in writes {
                if !self.uint_values.contains(slot) {
                    self.uint_values.push(*slot);
                }
                if !self.uint_values.contains(value) {
                    self.uint_values.push(*value);
                }
            }
        }
    }

    /// Seed the dictionary from on-chain storage reads (e.g. pool reserves).
    ///
    /// This is the bridge between the dataflow waypoint tracker and the
    /// flashloan mutator: whenever the fuzzer observes an `SLOAD` from a
    /// storage slot that looks like a large reserve value, we add that value
    /// to the uint dictionary so the flashloan mutator can propose borrow
    /// amounts that match real reserve sizes.
    pub fn seed_from_storage_reserves(&mut self, values: &[U256]) {
        // Heuristic: only add values that are >= 1e6 wei (ignores boolean/enum slots).
        let min_reserve = U256::from(1_000_000u64);
        for &v in values {
            if v >= min_reserve && !self.uint_values.contains(&v) {
                self.uint_values.push(v);
            }
        }
    }

    /// Pick a random uint256 — biased toward dictionary values.
    pub fn random_uint(&self, rng: &mut impl Rng) -> U256 {
        if !self.uint_values.is_empty() && rng.gen_bool(0.8) {
            self.uint_values[rng.gen_range(0..self.uint_values.len())]
        } else {
            U256::from_be_bytes(rng.gen::<[u8; 32]>())
        }
    }

    /// Pick a random address — biased toward dictionary values.
    pub fn random_address(&self, rng: &mut impl Rng) -> Address {
        if !self.address_values.is_empty() && rng.gen_bool(0.8) {
            self.address_values[rng.gen_range(0..self.address_values.len())]
        } else {
            Address::from(rng.gen::<[u8; 20]>())
        }
    }

    /// Pick a random bytes32 — biased toward dictionary values.
    pub fn random_word(&self, rng: &mut impl Rng) -> B256 {
        if !self.bytes32_values.is_empty() && rng.gen_bool(0.8) {
            self.bytes32_values[rng.gen_range(0..self.bytes32_values.len())]
        } else {
            B256::from(rng.gen::<[u8; 32]>())
        }
    }

    // -- internal helpers ---------------------------------------------------

    /// Chop `data` into 32-byte words and add each as a uint/bytes32 value.
    fn extract_words_from_bytes(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset + 32 <= data.len() {
            let mut word = [0u8; 32];
            word.copy_from_slice(&data[offset..offset + 32]);

            let val = U256::from_be_bytes(word);
            if !self.uint_values.contains(&val) {
                self.uint_values.push(val);
            }

            let b32 = B256::from(word);
            if !self.bytes32_values.contains(&b32) {
                self.bytes32_values.push(b32);
            }

            offset += 32;
        }
    }
}

// ---------------------------------------------------------------------------
// ABI-type-aware argument generation
// ---------------------------------------------------------------------------

/// Generate a random ABI-encoded argument for the given Solidity type.
///
/// Returns a 32-byte big-endian encoded value suitable for direct
/// concatenation into EVM calldata.
fn generate_typed_arg(typ: &str, dict: &ValueDictionary, rng: &mut impl Rng) -> Vec<u8> {
    match typ {
        // --- unsigned integers -------------------------------------------
        "uint256" => dict.random_uint(rng).to_be_bytes::<32>().to_vec(),
        "uint128" => {
            let v = dict.random_uint(rng) & U256::from(u128::MAX);
            v.to_be_bytes::<32>().to_vec()
        }
        "uint64" => {
            let v = dict.random_uint(rng) & U256::from(u64::MAX);
            v.to_be_bytes::<32>().to_vec()
        }
        "uint32" => {
            let v = dict.random_uint(rng) & U256::from(u32::MAX);
            v.to_be_bytes::<32>().to_vec()
        }
        "uint8" => {
            let v = dict.random_uint(rng) & U256::from(0xFFu64);
            v.to_be_bytes::<32>().to_vec()
        }

        // --- signed integers ---------------------------------------------
        // ABI encoding uses two's complement in a 256-bit word.  We mask
        // a random dictionary value to the type width, then sign-extend
        // when the high bit of that width is set.
        "int256" | "int128" | "int64" | "int32" | "int8" => {
            let bits: usize = match typ {
                "int8" => 8,
                "int32" => 32,
                "int64" => 64,
                "int128" => 128,
                _ => 256,
            };
            let v = dict.random_uint(rng);
            if bits < 256 {
                let type_mask = (U256::from(1u64) << bits) - U256::from(1u64);
                let masked = v & type_mask;
                let sign_bit = U256::from(1u64) << (bits - 1);
                if masked & sign_bit != U256::ZERO {
                    // Sign-extend: fill upper bits with 1.
                    (masked | !type_mask).to_be_bytes::<32>().to_vec()
                } else {
                    masked.to_be_bytes::<32>().to_vec()
                }
            } else {
                v.to_be_bytes::<32>().to_vec()
            }
        }

        // --- address -----------------------------------------------------
        "address" => {
            let addr = dict.random_address(rng);
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(addr.as_slice());
            buf.to_vec()
        }

        // --- bool --------------------------------------------------------
        "bool" => {
            let mut buf = [0u8; 32];
            buf[31] = if rng.gen_bool(0.5) { 1 } else { 0 };
            buf.to_vec()
        }

        // --- bytes32 -----------------------------------------------------
        "bytes32" => dict.random_word(rng).0.to_vec(),

        // --- unknown / dynamic types — random 32 bytes -------------------
        _ => rng.gen::<[u8; 32]>().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// TxMutator
// ---------------------------------------------------------------------------

/// Generates and mutates transactions targeting smart contracts.
pub struct TxMutator {
    /// Known contract targets.
    targets: Vec<ContractInfo>,
    /// Known four-byte function selectors extracted from ABIs.
    selectors: Vec<[u8; 4]>,
    /// Parameter types for each known selector (from ABI).
    selector_params: HashMap<[u8; 4], Vec<String>>,
    /// Selectors whose ABI entry has `stateMutability: "payable"`.
    payable_selectors: HashSet<[u8; 4]>,
    /// Pool of known addresses (senders, contracts, constants).
    address_pool: Vec<Address>,
    /// Dictionary of interesting values seeded from operations.
    pub dict: ValueDictionary,
}

impl TxMutator {
    /// Build a mutator from a set of target contracts.
    ///
    /// Selectors are extracted from any available ABIs.  The address pool is
    /// seeded with all target addresses plus a small set of "interesting"
    /// defaults (zero address, max address, etc.).
    pub fn new(targets: Vec<ContractInfo>) -> Self {
        let mut selectors = Vec::new();
        let mut selector_params: HashMap<[u8; 4], Vec<String>> = HashMap::new();
        let mut payable_selectors: HashSet<[u8; 4]> = HashSet::new();
        let mut address_pool = Vec::new();
        let mut dict = ValueDictionary::new();

        for target in &targets {
            address_pool.push(target.address);

            // Seed dictionary from deployed bytecode.
            dict.seed_from_bytecode(&target.deployed_bytecode);

            if let Some(abi) = &target.abi {
                if let Some(entries) = abi.as_array() {
                    for entry in entries {
                        if entry.get("type").and_then(|t| t.as_str()) == Some("function") {
                            if let Some(sel) = selector_from_abi_entry(entry) {
                                selectors.push(sel);

                                // Track payable functions.
                                if entry.get("stateMutability").and_then(|s| s.as_str())
                                    == Some("payable")
                                {
                                    payable_selectors.insert(sel);
                                }

                                // Record parameter types for ABI-aware generation.
                                if let Some(inputs) = entry.get("inputs").and_then(|i| i.as_array())
                                {
                                    let types: Vec<String> = inputs
                                        .iter()
                                        .filter_map(|p| {
                                            p.get("type").and_then(|t| t.as_str()).map(String::from)
                                        })
                                        .collect();
                                    selector_params.insert(sel, types);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Always have at least one sender available.
        if address_pool.is_empty() {
            address_pool.push(Address::ZERO);
        }

        Self {
            targets,
            selectors,
            selector_params,
            payable_selectors,
            address_pool,
            dict,
        }
    }

    /// Generate a completely random transaction targeting one of the known
    /// contracts.
    pub fn generate(&self, rng: &mut impl Rng) -> Transaction {
        let to = self.random_target(rng);
        let sender = self.random_sender(rng);
        let data = self.random_calldata(rng);

        let value = self.random_value(&data, rng);

        Transaction {
            sender,
            to: Some(to),
            data,
            value,
            gas_limit: 30_000_000,
        }
    }

    /// Generate a transaction for use inside a multi-step sequence.
    ///
    /// Unlike [`generate`], this method biases toward reusing the same
    /// sender across calls so that stateful interactions (e.g.
    /// deposit → withdraw) come from a single actor.
    pub fn generate_in_sequence(
        &self,
        prev_sender: Option<Address>,
        rng: &mut impl Rng,
    ) -> Transaction {
        let to = self.random_target(rng);
        let sender = self.pick_sender(prev_sender, rng);
        let data = self.random_calldata(rng);

        let value = self.random_value(&data, rng);

        Transaction {
            sender,
            to: Some(to),
            data,
            value,
            gas_limit: 30_000_000,
        }
    }

    /// Pick a sender for a sequence, biasing toward reusing `prev_sender`.
    pub fn pick_sender(&self, prev_sender: Option<Address>, rng: &mut impl Rng) -> Address {
        if let Some(prev) = prev_sender {
            if rng.gen_bool(0.7) {
                return prev; // 70% chance: reuse the same sender
            }
        }
        self.random_sender(rng)
    }

    /// Mutate an existing transaction.
    ///
    /// One of the following mutations is chosen uniformly at random:
    /// - **bit flip**: flip a random bit in the calldata
    /// - **byte replace**: overwrite a random byte in the calldata
    /// - **value change**: pick a new `msg.value`
    /// - **sender change**: pick a different sender from the address pool
    pub fn mutate(&self, tx: &Transaction, rng: &mut impl Rng) -> Transaction {
        let mut out = tx.clone();

        match rng.gen_range(0u8..5) {
            0 => {
                // Bit flip in calldata.
                let mut raw = out.data.to_vec();
                if !raw.is_empty() {
                    let idx = rng.gen_range(0..raw.len());
                    let bit: u8 = 1 << rng.gen_range(0u32..8);
                    raw[idx] ^= bit;
                    out.data = Bytes::from(raw);
                }
            }
            1 => {
                // Replace a random byte.
                let mut raw = out.data.to_vec();
                if !raw.is_empty() {
                    let idx = rng.gen_range(0..raw.len());
                    raw[idx] = rng.gen();
                    out.data = Bytes::from(raw);
                }
            }
            2 => {
                // Change msg.value.
                out.value = U256::from(rng.gen_range(0u64..=1_000_000_000_000_000_000));
            }
            3 => {
                // Change sender.
                out.sender = self.random_sender(rng);
            }
            _ => {
                // Swap selector (keep arguments).
                if !self.selectors.is_empty() {
                    let mut raw = out.data.to_vec();
                    let sel = self.selectors[rng.gen_range(0..self.selectors.len())];
                    if raw.len() >= 4 {
                        raw[..4].copy_from_slice(&sel);
                    } else {
                        raw = sel.to_vec();
                    }
                    out.data = Bytes::from(raw);
                }
            }
        }

        out
    }

    /// Mutate a transaction *sequence*.
    ///
    /// Possible mutations:
    /// - mutate a single element
    /// - insert a new random transaction
    /// - remove a transaction (if length > 1)
    /// - swap two transactions
    pub fn mutate_sequence(&self, seq: &[Transaction], rng: &mut impl Rng) -> Vec<Transaction> {
        let mut out: Vec<Transaction> = seq.to_vec();

        if out.is_empty() {
            out.push(self.generate(rng));
            return out;
        }

        match rng.gen_range(0u8..4) {
            0 => {
                // Mutate one transaction in place.
                let idx = rng.gen_range(0..out.len());
                out[idx] = self.mutate(&out[idx], rng);
            }
            1 => {
                // Insert a new transaction at a random position.
                let pos = rng.gen_range(0..=out.len());
                out.insert(pos, self.generate(rng));
            }
            2 if out.len() > 1 => {
                // Remove a random transaction.
                let idx = rng.gen_range(0..out.len());
                out.remove(idx);
            }
            _ => {
                if out.len() >= 2 {
                    // Swap two random positions.
                    let a = rng.gen_range(0..out.len());
                    let mut b = rng.gen_range(0..out.len());
                    while b == a {
                        b = rng.gen_range(0..out.len());
                    }
                    out.swap(a, b);
                } else {
                    // Fallback: mutate the single element.
                    out[0] = self.mutate(&out[0], rng);
                }
            }
        }

        out
    }

    // -- internal helpers ---------------------------------------------------

    /// Pick a random target address from the known contracts.
    fn random_target(&self, rng: &mut impl Rng) -> Address {
        if self.targets.is_empty() {
            return Address::ZERO;
        }
        self.targets[rng.gen_range(0..self.targets.len())].address
    }

    /// Pick a random sender — biased toward the address pool but
    /// occasionally fully random.
    fn random_sender(&self, rng: &mut impl Rng) -> Address {
        if !self.address_pool.is_empty() && rng.gen_bool(0.7) {
            self.address_pool[rng.gen_range(0..self.address_pool.len())]
        } else {
            Address::from(rng.gen::<[u8; 20]>())
        }
    }

    /// Choose a `msg.value` for a transaction, using the calldata selector
    /// to decide whether the target function is payable.
    fn random_value(&self, data: &Bytes, rng: &mut impl Rng) -> U256 {
        let is_payable = data.len() >= 4 && {
            let mut sel = [0u8; 4];
            sel.copy_from_slice(&data[..4]);
            self.payable_selectors.contains(&sel)
        };

        if is_payable {
            // Payable function: send a meaningful value 80% of the time.
            if rng.gen_bool(0.8) {
                let v = COMMON_ETH_VALUES[rng.gen_range(0..COMMON_ETH_VALUES.len())];
                U256::from(v)
            } else {
                U256::ZERO
            }
        } else if rng.gen_bool(0.1) {
            // Non-payable: occasionally attach some ETH (10%).
            U256::from(rng.gen_range(0u64..=1_000_000_000_000_000_000))
        } else {
            U256::ZERO
        }
    }

    /// Build random calldata, preferring a known selector when available.
    ///
    /// When ABI parameter info is available for the chosen selector,
    /// [`generate_typed_arg`] is used to produce type-aware arguments
    /// instead of pure random bytes.  Payable selectors are chosen with
    /// higher probability when available.
    fn random_calldata(&self, rng: &mut impl Rng) -> Bytes {
        if !self.selectors.is_empty() && rng.gen_bool(0.8) {
            // Bias toward payable selectors 40% of the time.
            let sel = if !self.payable_selectors.is_empty() && rng.gen_bool(0.4) {
                let payable: Vec<[u8; 4]> = self.payable_selectors.iter().copied().collect();
                payable[rng.gen_range(0..payable.len())]
            } else {
                self.selectors[rng.gen_range(0..self.selectors.len())]
            };
            let mut buf = sel.to_vec();

            if let Some(params) = self.selector_params.get(&sel) {
                // ABI-aware: generate correctly typed arguments.
                for param_type in params {
                    buf.extend_from_slice(&generate_typed_arg(param_type, &self.dict, rng));
                }
            } else {
                // Fallback: append 0‒4 random 32-byte ABI words.
                let n_words: usize = rng.gen_range(0..=4);
                for _ in 0..n_words {
                    let word: [u8; 32] = rng.gen();
                    buf.extend_from_slice(&word);
                }
            }
            Bytes::from(buf)
        } else {
            let len: usize = rng.gen_range(0..=128);
            let raw: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            Bytes::from(raw)
        }
    }

    /// Feed an execution result into the value dictionary so future
    /// mutations can reuse observed constants.
    pub fn feed_execution(&mut self, result: &ExecutionResult) {
        self.dict.seed_from_execution(result);
    }

    /// Number of known function selectors extracted from ABIs.
    pub fn selector_count(&self) -> usize {
        self.selectors.len()
    }

    /// Add an address to the sender/address pool.
    ///
    /// Use this to ensure the fuzzer generates transactions from funded
    /// accounts (e.g. the attacker address) rather than only from contract
    /// addresses discovered via ABI parsing.
    pub fn add_to_address_pool(&mut self, addr: Address) {
        if !self.address_pool.contains(&addr) {
            self.address_pool.push(addr);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: build a mutator with no targets (pure random mode).
    fn empty_mutator() -> TxMutator {
        TxMutator::new(vec![])
    }

    /// Build a mutator with a payable `deposit()` and non-payable
    /// `withdraw(uint256)` function for stateful testing.
    fn deposit_withdraw_mutator() -> TxMutator {
        let abi: serde_json::Value = serde_json::json!([
            {
                "type": "function",
                "name": "deposit",
                "stateMutability": "payable",
                "inputs": []
            },
            {
                "type": "function",
                "name": "withdraw",
                "stateMutability": "nonpayable",
                "inputs": [
                    { "type": "uint256", "name": "amount" }
                ]
            }
        ]);

        let targets = vec![ContractInfo {
            address: Address::ZERO,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: None,
            name: Some("Vault".into()),
            source_path: None,
            abi: Some(abi),
        }];

        TxMutator::new(targets)
    }

    #[test]
    fn generate_produces_valid_tx() {
        let m = empty_mutator();
        let mut rng = rand::thread_rng();
        let tx = m.generate(&mut rng);

        assert!(tx.to.is_some());
        assert!(tx.gas_limit > 0);
    }

    #[test]
    fn mutate_preserves_gas_limit() {
        let m = empty_mutator();
        let mut rng = rand::thread_rng();
        let base = Transaction {
            sender: Address::ZERO,
            to: Some(Address::ZERO),
            data: Bytes::from(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };

        for _ in 0..20 {
            let mutated = m.mutate(&base, &mut rng);
            assert_eq!(mutated.gas_limit, 30_000_000);
        }
    }

    #[test]
    fn mutate_sequence_never_returns_empty_for_nonempty_input() {
        let m = empty_mutator();
        let mut rng = rand::thread_rng();
        let seq = vec![m.generate(&mut rng), m.generate(&mut rng)];

        for _ in 0..50 {
            let out = m.mutate_sequence(&seq, &mut rng);
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn mutate_sequence_bootstraps_from_empty() {
        let m = empty_mutator();
        let mut rng = rand::thread_rng();
        let out = m.mutate_sequence(&[], &mut rng);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn keccak_selector_known_value() {
        // transfer(address,uint256) → 0xa9059cbb
        let sel = keccak_selector(b"transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn selector_extraction_from_abi() {
        let abi: serde_json::Value = serde_json::json!([
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    { "type": "address", "name": "to" },
                    { "type": "uint256", "name": "amount" }
                ]
            }
        ]);

        let targets = vec![ContractInfo {
            address: Address::ZERO,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: None,
            name: Some("Token".into()),
            source_path: None,
            abi: Some(abi),
        }];

        let m = TxMutator::new(targets);
        assert!(!m.selectors.is_empty());
        assert_eq!(m.selectors[0], [0xa9, 0x05, 0x9c, 0xbb]);
    }

    // -- ValueDictionary tests ---------------------------------------------

    #[test]
    fn seed_from_bytecode_extracts_push_values() {
        let mut dict = ValueDictionary::new();
        // PUSH1 0x42,  PUSH2 0x00 0xff,  STOP
        let bytecode: Vec<u8> = vec![0x60, 0x42, 0x61, 0x00, 0xff, 0x00];
        dict.seed_from_bytecode(&bytecode);

        assert!(dict.uint_values.contains(&U256::from(0x42u64)));
        assert!(dict.uint_values.contains(&U256::from(0x00ffu64)));
    }

    #[test]
    fn dictionary_returns_seeded_values() {
        let mut dict = ValueDictionary::new();
        let sentinel = U256::from(0xCAFEu64);
        dict.uint_values.push(sentinel);

        // With an RNG that always picks from the dictionary (seeded so
        // gen_bool(0.8) is true), we should eventually see our sentinel.
        let mut rng = rand::thread_rng();
        let mut found = false;
        for _ in 0..200 {
            if dict.random_uint(&mut rng) == sentinel {
                found = true;
                break;
            }
        }
        assert!(found, "sentinel value never returned from dictionary");
    }

    #[test]
    fn generate_typed_arg_uint256_returns_32_bytes() {
        let dict = ValueDictionary::new();
        let mut rng = rand::thread_rng();
        let arg = generate_typed_arg("uint256", &dict, &mut rng);
        assert_eq!(arg.len(), 32);
    }

    #[test]
    fn generate_typed_arg_address_returns_32_bytes_left_padded() {
        let dict = ValueDictionary::new();
        let mut rng = rand::thread_rng();

        for _ in 0..20 {
            let arg = generate_typed_arg("address", &dict, &mut rng);
            assert_eq!(arg.len(), 32);
            // First 12 bytes must be zero (left-padded).
            assert_eq!(&arg[..12], &[0u8; 12]);
        }
    }

    #[test]
    fn generate_typed_arg_bool_returns_zero_or_one() {
        let dict = ValueDictionary::new();
        let mut rng = rand::thread_rng();

        for _ in 0..50 {
            let arg = generate_typed_arg("bool", &dict, &mut rng);
            assert_eq!(arg.len(), 32);
            // All bytes except the last must be zero.
            assert_eq!(&arg[..31], &[0u8; 31]);
            assert!(arg[31] == 0 || arg[31] == 1);
        }
    }

    // -- Payable awareness tests -------------------------------------------

    #[test]
    fn payable_selectors_tracked_from_abi() {
        let m = deposit_withdraw_mutator();
        // deposit() selector
        let deposit_sel = keccak_selector(b"deposit()");
        // withdraw(uint256) selector
        let withdraw_sel = keccak_selector(b"withdraw(uint256)");

        assert!(m.payable_selectors.contains(&deposit_sel));
        assert!(!m.payable_selectors.contains(&withdraw_sel));
    }

    #[test]
    fn payable_function_usually_gets_nonzero_value() {
        let m = deposit_withdraw_mutator();
        let deposit_sel = keccak_selector(b"deposit()");
        let mut rng = rand::thread_rng();

        // Build calldata that starts with the deposit selector.
        let data = Bytes::from(deposit_sel.to_vec());
        let mut nonzero_count = 0;
        let trials = 200;
        for _ in 0..trials {
            let v = m.random_value(&data, &mut rng);
            if v != U256::ZERO {
                nonzero_count += 1;
            }
        }
        // With 80% probability, expect at least 60% nonzero over 200 trials.
        assert!(
            nonzero_count > trials * 60 / 100,
            "expected mostly nonzero values for payable, got {nonzero_count}/{trials}"
        );
    }

    #[test]
    fn nonpayable_function_usually_gets_zero_value() {
        let m = deposit_withdraw_mutator();
        let withdraw_sel = keccak_selector(b"withdraw(uint256)");
        let mut rng = rand::thread_rng();

        let data = Bytes::from(withdraw_sel.to_vec());
        let mut zero_count = 0;
        let trials = 200;
        for _ in 0..trials {
            let v = m.random_value(&data, &mut rng);
            if v == U256::ZERO {
                zero_count += 1;
            }
        }
        // With 90% zero probability, expect at least 70% zero over 200 trials.
        assert!(
            zero_count > trials * 70 / 100,
            "expected mostly zero values for non-payable, got {zero_count}/{trials} zeros"
        );
    }

    // -- Sender stickiness tests -------------------------------------------

    #[test]
    fn pick_sender_reuses_previous_most_of_the_time() {
        let m = empty_mutator();
        let mut rng = rand::thread_rng();
        let prev = Address::from([0xAA; 20]);

        let mut reuse_count = 0;
        let trials = 200;
        for _ in 0..trials {
            if m.pick_sender(Some(prev), &mut rng) == prev {
                reuse_count += 1;
            }
        }
        // 70% probability → expect at least 50% reuse over 200 trials.
        assert!(
            reuse_count > trials * 50 / 100,
            "expected sender reuse, got {reuse_count}/{trials}"
        );
    }

    #[test]
    fn generate_in_sequence_preserves_sender() {
        let m = deposit_withdraw_mutator();
        let mut rng = rand::thread_rng();

        // Generate an initial tx, then a follow-up in the same sequence.
        let first = m.generate(&mut rng);
        let mut same_sender = 0;
        let trials = 100;
        for _ in 0..trials {
            let next = m.generate_in_sequence(Some(first.sender), &mut rng);
            if next.sender == first.sender {
                same_sender += 1;
            }
        }
        // Should reuse sender frequently.
        assert!(
            same_sender > trials * 40 / 100,
            "expected sender stickiness, got {same_sender}/{trials}"
        );
    }
}
