// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test harness: `setUp` writes state read by an `echidna_*` property.
contract HarnessWithSetup {
    uint256 public initialized;

    function setUp() external {
        initialized = 42;
    }

    function echidna_initialized() external view returns (bool) {
        return initialized == 42;
    }
}
