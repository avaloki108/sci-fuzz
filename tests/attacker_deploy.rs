//! Different attacker EOAs must yield different CREATE addresses (campaign uses
//! [`sci_fuzz::types::CampaignConfig::resolved_attacker`] as deployer).

use sci_fuzz::types::{Address, Bytes, U256};
use sci_fuzz::EvmExecutor;

#[test]
fn different_attacker_eoa_yields_different_first_deploy_address() {
    let init = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]);
    let fund = U256::from(10u64).pow(U256::from(18));

    let default_att = Address::repeat_byte(0x42);
    let mut ex1 = EvmExecutor::new();
    ex1.set_balance(default_att, fund);
    let d1 = ex1.deploy(default_att, init.clone()).expect("deploy");

    let custom_att = Address::with_last_byte(0x77);
    let mut ex2 = EvmExecutor::new();
    ex2.set_balance(custom_att, fund);
    let d2 = ex2.deploy(custom_att, init).expect("deploy");

    assert_ne!(
        d1, d2,
        "CREATE address must depend on sender; attacker override must change deploy address"
    );
}
