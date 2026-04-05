// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Control contract: property only fails after a multi-transaction sequence.
///
/// The property `echidna_not_drained` holds until:
///   1. Someone calls `deposit()` with value > 0
///   2. Then someone calls `withdraw()`
///
/// After withdraw, the contract balance drops to 0 and the property fails.
/// A correct stateful fuzzer MUST discover this two-step sequence.
contract PropStateful {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;

    function deposit() public payable {
        require(msg.value > 0, "must send ether");
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /// Property: contract should never be drained to zero after having funds.
    /// Returns true as long as the contract has ether OR has never received any.
    function echidna_not_drained() public view returns (bool) {
        // If no one ever deposited, the property trivially holds.
        if (totalDeposited == 0) {
            return true;
        }
        // Once someone has deposited, balance should stay > 0.
        return address(this).balance > 0;
    }
}
