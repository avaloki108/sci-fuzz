// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Control contract: echidna_always_false() always returns false.
/// Any correct property-checking fuzzer MUST report this as a violation.
contract PropFalse {
    function echidna_always_false() public pure returns (bool) {
        return false;
    }
}
