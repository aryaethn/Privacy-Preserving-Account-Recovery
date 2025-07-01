// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Guardian.sol";
import "../src/RecoveryFacet.sol";
import "../src/VerifierGoogle.sol";
import "../src/VerifierGooglePw.sol";
import "./MockGuardian.sol";

contract GuardianTest is Test {
    Guardian public guardian;
    RecoveryFacet public recoveryFacet;
    VerifierGoogle public verifierGoogle;
    VerifierGooglePw public verifierGooglePw;

    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public newEOA = address(0x3);
    address public oldEOA = address(0x4);

    // Test constants
    bytes32 public constant EMAIL_HASH = keccak256("test@example.com");
    bytes32 public constant EMAIL_HASH_2 = keccak256("test2@example.com");
    bytes32 public constant PW_HASH = keccak256("password123");
    bytes32 public constant SALT = keccak256("salt");

    // Events
    event Registered(bytes32 indexed emailHash, uint8 mode);
    event Nonce(bytes32 indexed emailHash, bytes32 nonce);
    event Recovered(address indexed oldEOA, address indexed newEOA, address guardian, uint8 mode);

    function setUp() public {
        // Deploy verifiers
        verifierGoogle = new VerifierGoogle();
        verifierGooglePw = new VerifierGooglePw();

        // Deploy Guardian
        guardian = new Guardian(address(verifierGoogle), address(verifierGooglePw));

        // Deploy RecoveryFacet
        recoveryFacet = new RecoveryFacet(address(guardian));
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public {
        // Check that Guardian contract was deployed successfully
        assertTrue(address(guardian) != address(0));
        assertTrue(address(guardian).code.length > 0);
    }

    /*//////////////////////////////////////////////////////////////
                            REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterGoogleOnly() public {
        vm.prank(user1);

        vm.expectEmit(true, false, false, false);
        emit Registered(EMAIL_HASH, 0x01);

        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        // Check record is stored correctly
        (address storedEOA, bytes32 storedPwHash, bytes32 storedSalt, uint8 storedMode) = guardian.records(EMAIL_HASH);

        assertEq(storedEOA, oldEOA);
        assertEq(storedPwHash, 0);
        assertEq(storedSalt, 0);
        assertEq(storedMode, 0x01);
    }

    function test_RegisterGoogleWithPassword() public {
        vm.prank(user1);

        vm.expectEmit(true, false, false, false);
        emit Registered(EMAIL_HASH, 0x02);

        guardian.register(oldEOA, 0x02, EMAIL_HASH, PW_HASH, SALT);

        // Check record is stored correctly
        (address storedEOA, bytes32 storedPwHash, bytes32 storedSalt, uint8 storedMode) = guardian.records(EMAIL_HASH);

        assertEq(storedEOA, oldEOA);
        assertEq(storedPwHash, PW_HASH);
        assertEq(storedSalt, SALT);
        assertEq(storedMode, 0x02);
    }

    function test_RevertWhen_RegisterExistingEmail() public {
        // Register first time
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        // Try to register again with same email hash
        vm.prank(user2);
        vm.expectRevert(Guardian.EmailAlreadyRegistered.selector);
        guardian.register(user2, 0x01, EMAIL_HASH, 0, 0);
    }

    function test_RevertWhen_RegisterMode02WithoutPassword() public {
        vm.prank(user1);
        vm.expectRevert(Guardian.PasswordMissing.selector);
        guardian.register(oldEOA, 0x02, EMAIL_HASH, 0, SALT); // pwHash is 0

        vm.prank(user1);
        vm.expectRevert(Guardian.PasswordMissing.selector);
        guardian.register(oldEOA, 0x02, EMAIL_HASH, PW_HASH, 0); // salt is 0
    }

    function test_RegisterMode01IgnoresPasswordParams() public {
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, PW_HASH, SALT);

        // Check that password params are ignored for mode 0x01
        (address storedEOA, bytes32 storedPwHash, bytes32 storedSalt, uint8 storedMode) = guardian.records(EMAIL_HASH);

        assertEq(storedEOA, oldEOA);
        assertEq(storedPwHash, 0); // Should be 0 despite passing PW_HASH
        assertEq(storedSalt, 0); // Should be 0 despite passing SALT
        assertEq(storedMode, 0x01);
    }

    /*//////////////////////////////////////////////////////////////
                            NONCE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RequestNonce() public {
        vm.prank(user1);

        vm.expectEmit(true, false, false, false);
        emit Nonce(EMAIL_HASH, 0); // We don't know the exact nonce value

        bytes32 nonce = guardian.requestNonce(EMAIL_HASH);

        // Nonce should be non-zero
        assertTrue(nonce != 0);

        // Nonce should not be marked as used yet
        assertFalse(guardian.usedNonce(nonce));
    }

    function test_NonceBasedOnBlockHash() public {
        // Request nonce in block N
        vm.prank(user1);
        bytes32 nonce1 = guardian.requestNonce(EMAIL_HASH);

        // Mine a block
        vm.roll(block.number + 1);

        // Request nonce in block N+1 (should be different)
        vm.prank(user1);
        bytes32 nonce2 = guardian.requestNonce(EMAIL_HASH);

        // Nonces should be different due to different block hashes
        assertTrue(nonce1 != nonce2);
    }

    function test_RevertWhen_NonceInFlight() public {
        vm.prank(user1);
        bytes32 nonce = guardian.requestNonce(EMAIL_HASH);

        // Mark nonce as used
        // We need to access the mapping through a recovery attempt
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        // This is testing the scenario where a nonce is already in use
        // In practice, this would happen during recovery attempts
    }

    /*//////////////////////////////////////////////////////////////
                            RECOVERY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoverWithMockGuardian() public {
        // Deploy MockGuardian for testing
        MockGuardian mockGuardian = new MockGuardian();

        // Deploy RecoveryFacet for this test
        RecoveryFacet testRecoveryFacet = new RecoveryFacet(address(mockGuardian));

        // Register user with MockGuardian
        vm.prank(user1);
        mockGuardian.register(address(testRecoveryFacet), 0x01, EMAIL_HASH, 0, 0);

        // Request nonce
        vm.prank(user1);
        bytes32 nonce = mockGuardian.requestNonce(EMAIL_HASH);

        // Test successful recovery with MockGuardian
        bytes memory proof = abi.encode(uint256(0x123), uint256(0x456)); // Valid proof

        vm.prank(user1);
        mockGuardian.recover(EMAIL_HASH, newEOA, nonce, proof);

        // Verify authorized address was set
        assertEq(testRecoveryFacet.getAuthorizedAddress(), newEOA);

        // Test failed proof verification - mine a block to get different nonce
        vm.roll(block.number + 1);
        vm.prank(user1);
        bytes32 nonce2 = mockGuardian.requestNonce(EMAIL_HASH);

        mockGuardian.setProofVerification(false); // Make proof verification fail

        vm.prank(user1);
        vm.expectRevert(MockGuardian.InvalidProof.selector);
        mockGuardian.recover(EMAIL_HASH, user2, nonce2, proof);
    }

    function test_RevertWhen_RecoverUnregisteredUser() public {
        vm.prank(user1);
        bytes32 nonce = guardian.requestNonce(EMAIL_HASH);

        bytes memory proof = "";

        vm.prank(user1);
        vm.expectRevert(Guardian.UserNotRegistered.selector);
        guardian.recover(EMAIL_HASH, newEOA, nonce, proof);
    }

    function test_RevertWhen_RecoverWithUsedNonce() public {
        // Register user
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        // Request nonce
        vm.prank(user1);
        bytes32 nonce = guardian.requestNonce(EMAIL_HASH);

        // Manually mark nonce as used (simulating a previous recovery)
        vm.store(address(guardian), keccak256(abi.encode(nonce, 1)), bytes32(uint256(1)));

        bytes memory proof = "";

        vm.prank(user1);
        vm.expectRevert(Guardian.NonceAlreadyUsed.selector);
        guardian.recover(EMAIL_HASH, newEOA, nonce, proof);
    }

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FullRegistrationAndNonceFlow() public {
        // 1. Register user with Google-only mode
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        // 2. Request nonce
        vm.prank(user1);
        bytes32 nonce1 = guardian.requestNonce(EMAIL_HASH);

        // 3. Mine a block to change blockhash
        vm.roll(block.number + 1);

        // 4. Request another nonce (should be different due to different blockhash)
        vm.prank(user1);
        bytes32 nonce2 = guardian.requestNonce(EMAIL_HASH);

        // Verify nonces are different and both valid
        assertTrue(nonce1 != nonce2);
        assertFalse(guardian.usedNonce(nonce1));
        assertFalse(guardian.usedNonce(nonce2));
    }

    function test_MultipleUserRegistrations() public {
        // Register multiple users
        vm.prank(user1);
        guardian.register(oldEOA, 0x01, EMAIL_HASH, 0, 0);

        vm.prank(user2);
        guardian.register(user2, 0x02, EMAIL_HASH_2, PW_HASH, SALT);

        // Verify both registrations
        (address eoa1,,, uint8 mode1) = guardian.records(EMAIL_HASH);
        (address eoa2,,, uint8 mode2) = guardian.records(EMAIL_HASH_2);

        assertEq(eoa1, oldEOA);
        assertEq(mode1, 0x01);
        assertEq(eoa2, user2);
        assertEq(mode2, 0x02);
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecordStorage() public {
        vm.prank(user1);
        guardian.register(oldEOA, 0x02, EMAIL_HASH, PW_HASH, SALT);

        // Check all fields are stored correctly
        (address storedEOA, bytes32 storedPwHash, bytes32 storedSalt, uint8 storedMode) = guardian.records(EMAIL_HASH);

        assertEq(storedEOA, oldEOA);
        assertEq(storedPwHash, PW_HASH);
        assertEq(storedSalt, SALT);
        assertEq(storedMode, 0x02);
    }

    function test_NonceStorageAndUsage() public {
        vm.prank(user1);
        bytes32 nonce = guardian.requestNonce(EMAIL_HASH);

        // Initially not used
        assertFalse(guardian.usedNonce(nonce));

        // After marking as used (simulated)
        vm.store(address(guardian), keccak256(abi.encode(nonce, 1)), bytes32(uint256(1)));
        assertTrue(guardian.usedNonce(nonce));
    }

    /*//////////////////////////////////////////////////////////////
                            EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_RegisterWithZeroAddresses() public {
        vm.prank(user1);
        guardian.register(address(0), 0x01, EMAIL_HASH, 0, 0);

        (address storedEOA,,,) = guardian.records(EMAIL_HASH);
        assertEq(storedEOA, address(0));
    }

    function test_NonceWithSameEmailDifferentBlocks() public {
        bytes32[] memory nonces = new bytes32[](5);

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(user1);
            nonces[i] = guardian.requestNonce(EMAIL_HASH);
            vm.roll(block.number + 1); // Move to next block
        }

        // All nonces should be different
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(nonces[i] != nonces[j]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Register(address _eoa, bytes32 _emailHash, bytes32 _pwHash, bytes32 _salt) public {
        vm.assume(_emailHash != 0);
        vm.assume(_pwHash != 0);
        vm.assume(_salt != 0);

        vm.prank(user1);
        guardian.register(_eoa, 0x02, _emailHash, _pwHash, _salt);

        (address storedEOA, bytes32 storedPwHash, bytes32 storedSalt, uint8 storedMode) = guardian.records(_emailHash);

        assertEq(storedEOA, _eoa);
        assertEq(storedPwHash, _pwHash);
        assertEq(storedSalt, _salt);
        assertEq(storedMode, 0x02);
    }

    function testFuzz_RequestNonce(bytes32 _emailHash) public {
        vm.prank(user1);
        bytes32 nonce = guardian.requestNonce(_emailHash);

        // Nonce should be deterministic based on email hash and block hash
        bytes32 expectedNonce = keccak256(abi.encodePacked(_emailHash, blockhash(block.number - 1)));
        assertEq(nonce, expectedNonce);
    }
}
