// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import "./VerifierGooglePw.sol";
import "./VerifierGoogle.sol"; // single-factor verifier
import "./RecoveryFacet.sol";

interface IEIP7702 {
    function sendWithCode(address target, bytes calldata data, bytes calldata initCode)
        external
        returns (bool success);
}

contract Guardian {
    /*------------------- custom errors -------------------*/
    error EmailAlreadyRegistered();
    error PasswordMissing();
    error NonceInFlight();
    error UserNotRegistered();
    error NonceAlreadyUsed();
    error InvalidProof();
    error SetAuthorizedAddressFailed();
    /*------------------- user registry -------------------*/

    struct Record {
        address oldEOA;
        bytes32 pwHash; // 0 if mode 0x01
        bytes32 salt; // 0 if mode 0x01
        uint8 mode; // 0x01 Google, 0x02 Google+Pw
    }

    mapping(bytes32 => Record) public records; // emailHash ⇒ record
    mapping(bytes32 => bool) public usedNonce; // replay protection

    /*------------------- verifiers -----------------------*/
    VerifierGoogle immutable vGoogle;
    VerifierGooglePw immutable vGooglePw;

    constructor(address _vg, address _vpg) {
        vGoogle = VerifierGoogle(_vg);
        vGooglePw = VerifierGooglePw(_vpg);
    }

    /*------------------- events --------------------------*/
    event Registered(bytes32 indexed emailHash, uint8 mode);
    event Nonce(bytes32 indexed emailHash, bytes32 nonce);
    event Recovered(address indexed oldEOA, address indexed newEOA, address guardian, uint8 mode);

    /*------------------- admin / onboarding --------------*/
    function register(
        address oldEOA,
        uint8 mode, // 0x01 or 0x02
        bytes32 emailHash,
        bytes32 pwHash,
        bytes32 salt
    ) external {
        if (records[emailHash].oldEOA != address(0)) revert EmailAlreadyRegistered();
        if (mode == 0x02) {
            if (pwHash == 0 || salt == 0) revert PasswordMissing();
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
        if (usedNonce[n]) revert NonceInFlight();
        emit Nonce(emailHash, n);
    }

    function recover(bytes32 emailHash, address newEOA, bytes32 n, bytes calldata proof) external {
        Record memory r = records[emailHash];
        if (r.oldEOA == address(0)) revert UserNotRegistered();
        if (usedNonce[n]) revert NonceAlreadyUsed();

        bool ok = (r.mode == 0x01)
            ? vGoogle.verifyProof(proof, [uint256(emailHash), uint256(uint160(newEOA)), uint256(n)])
            : vGooglePw.verifyProof(
                proof, [uint256(emailHash), uint256(uint160(newEOA)), uint256(n), uint256(r.pwHash), uint256(r.salt)]
            );
        if (!ok) revert InvalidProof();
        usedNonce[n] = true;

        /* -- delegate call via EIP-7702 (simplified helper) -- */
        bytes memory cd = abi.encodeWithSelector(RecoveryFacet.setAuthorizedAddress.selector, newEOA);
        // oldEOA already contains 0xef0100 || address(RecoveryFacet)
        (bool succ,) = r.oldEOA.call(cd);
        if (!succ) revert SetAuthorizedAddressFailed();

        emit Recovered(r.oldEOA, newEOA, msg.sender, r.mode);
    }
}
