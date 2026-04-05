// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Control contract: echidna_always_reverts() always reverts.
/// In Echidna semantics, a reverting property is treated as "property holds"
/// (conservative: if we can't evaluate it, we don't flag it).
/// A correct property-checking fuzzer MUST NOT report this as a violation.
contract PropReverts {
    function echidna_always_reverts() public pure returns (bool) {
        revert("this property always reverts");
    }
}
