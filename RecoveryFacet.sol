// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/**
 * Executed _inside_ the lost EOA via EIP-7702 delegation.
 * Merely updates two storage words that represent the new public-key.
 */
contract RecoveryFacet {
    bytes32 private constant PK_X_SLOT = keccak256("ppar.pk.x");
    bytes32 private constant PK_Y_SLOT = keccak256("ppar.pk.y");

    event KeyRotated(address indexed newEOA);

    function rotateKey(address newEOA) external {
        assembly {
            sstore(PK_X_SLOT, newEOA)
            sstore(PK_Y_SLOT, 0)
        }
        emit KeyRotated(newEOA);
    }
}
