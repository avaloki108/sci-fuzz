// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Control contract: two properties, one holds and one fails.
/// A correct property-checking fuzzer MUST report echidna_bad as violated
/// and MUST NOT report echidna_good as violated.
contract PropMulti {
    function echidna_good() public pure returns (bool) {
        return true;
    }

    function echidna_bad() public pure returns (bool) {
        return false;
    }
}
