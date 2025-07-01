// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "../src/RecoveryFacet.sol";

/**
 * @title MockGuardian
 * @notice Mock Guardian contract for testing without ZK proof verification
 * @dev Bypasses proof verification to test core recovery logic
 */
contract MockGuardian {
    /*------------------- user registry -------------------*/
    struct Record {
        address oldEOA;
        bytes32 pwHash;   // 0 if mode 0x01
        bytes32 salt;     // 0 if mode 0x01
        uint8   mode;     // 0x01 Google, 0x02 Google+Pw
    }
    mapping(bytes32 => Record) public records;     // emailHash ⇒ record
    mapping(bytes32 => bool)   public usedNonce;   // replay protection

    /*------------------- mock settings -------------------*/
    bool public shouldProofPass = true;  // Control proof verification outcome
    bool public shouldCallFail = false;  // Control EIP-7702 call outcome

    /*------------------- events --------------------------*/
    event Registered(bytes32 indexed emailHash, uint8 mode);
    event Nonce(bytes32 indexed emailHash, bytes32 nonce);
    event Recovered(address indexed oldEOA,
                    address indexed newEOA,
                    address guardian, uint8 mode);

    /*------------------- mock controls -------------------*/
    function setProofVerification(bool _shouldPass) external {
        shouldProofPass = _shouldPass;
    }

    function setCallBehavior(bool _shouldFail) external {
        shouldCallFail = _shouldFail;
    }

    /*------------------- admin / onboarding --------------*/
    function register(
        address oldEOA,
        uint8   mode,           // 0x01 or 0x02
        bytes32 emailHash,
        bytes32 pwHash,
        bytes32 salt
    ) external {
        require(records[emailHash].oldEOA == address(0), "exists");
        if (mode == 0x02) {
            require(pwHash != 0 && salt != 0, "pw missing");
        } else {
            pwHash = 0;  
            salt = 0;
        }
        records[emailHash] = Record(oldEOA, pwHash, salt, mode);
        emit Registered(emailHash, mode);
    }

    /*------------------- recovery ------------------------*/
    function requestNonce(bytes32 emailHash) external returns (bytes32 n) {
        n = keccak256(abi.encodePacked(emailHash, blockhash(block.number - 1)));
        require(!usedNonce[n], "in-flight");
        emit Nonce(emailHash, n);
    }

    function recover(
        bytes32   emailHash,
        address   newEOA,
        bytes32   n,
        bytes     calldata proof
    ) external {
        Record memory r = records[emailHash];
        require(r.oldEOA != address(0), "unregistered");
        require(!usedNonce[n],          "nonce used");

        // Mock proof verification - controllable for testing
        require(shouldProofPass, "bad proof");
        require(proof.length >= 32, "proof too short"); // Basic length check
        
        usedNonce[n] = true;

        /* -- delegate call via EIP-7702 (mocked) -- */
        if (shouldCallFail) {
            revert("set authorized address failed");
        }

        // Instead of actual EIP-7702 call, we'll directly call the RecoveryFacet
        // This simulates the successful execution inside the EOA
        RecoveryFacet(payable(r.oldEOA)).setAuthorizedAddress(newEOA);

        emit Recovered(r.oldEOA, newEOA, msg.sender, r.mode);
    }

    /*------------------- direct recovery for testing -------------------*/
    function recoverDirect(
        address recoveryFacet,
        address newEOA
    ) external {
        // Direct call to RecoveryFacet for testing
        RecoveryFacet(payable(recoveryFacet)).setAuthorizedAddress(newEOA);
    }

    /*------------------- helper functions for testing -------------------*/
    function markNonceAsUsed(bytes32 nonce) external {
        usedNonce[nonce] = true;
    }

    function getRecord(bytes32 emailHash) external view returns (Record memory) {
        return records[emailHash];
    }

    function isNonceUsed(bytes32 nonce) external view returns (bool) {
        return usedNonce[nonce];
    }
} 