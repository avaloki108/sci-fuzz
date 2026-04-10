//! Foundry-style harness setup (`setUp`) executed inside chimerafuzz's revm executor.

use anyhow::{Context, Result};

use crate::evm::EvmExecutor;
use crate::types::{Address, Bytes, Transaction, U256};

/// Selector for `setUp()` — `bytes4(keccak256("setUp()"))`.
pub fn setup_selector() -> [u8; 4] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(b"setUp()");
    let mut h = [0u8; 32];
    k.finalize(&mut h);
    [h[0], h[1], h[2], h[3]]
}

/// Call `setUp()` on `harness` with `sender` as `msg.sender`. State commits on success.
pub fn run_setup(executor: &mut EvmExecutor, sender: Address, harness: Address) -> Result<()> {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&setup_selector());
    let tx = Transaction {
        sender,
        to: Some(harness),
        data: Bytes::from(data),
        value: U256::ZERO,
        gas_limit: 30_000_000,
    };
    let result = executor.execute(&tx).context("setUp() execution failed")?;
    if !result.success {
        return Err(anyhow::anyhow!(
            "setUp() reverted: 0x{}\n\
             Hint: vm.prank/vm.deal/vm.warp/vm.roll cheatcodes are supported. \
             Unimplemented cheatcodes are accepted silently. \
             Check the revert data above for the actual failure reason.",
            hex::encode(&result.output)
        ));
    }
    Ok(())
}
