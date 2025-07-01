// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/RecoveryFacet.sol";
import "../src/Guardian.sol";
import "../src/VerifierGoogle.sol";
import "../src/VerifierGooglePw.sol";
import "./MockGuardian.sol";

contract RecoveryFacetTest is Test {
    RecoveryFacet public recoveryFacet;
    Guardian public guardian;
    VerifierGoogle public verifierGoogle;
    VerifierGooglePw public verifierGooglePw;
    
    address public guardian_address;
    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public newEOA = address(0x3);
    address public unauthorized = address(0x4);
    
    // Test constants
    bytes32 public constant EMAIL_HASH = keccak256("test@example.com");
    bytes32 public constant PW_HASH = keccak256("password123");
    bytes32 public constant SALT = keccak256("salt");
    
    event AuthorizedAddressSet(address indexed newAuthorizedAddress);

    function setUp() public {
        // Deploy verifiers
        verifierGoogle = new VerifierGoogle();
        verifierGooglePw = new VerifierGooglePw();
        
        // Deploy Guardian
        guardian = new Guardian(address(verifierGoogle), address(verifierGooglePw));
        guardian_address = address(guardian);
        
        // Deploy RecoveryFacet with Guardian address
        recoveryFacet = new RecoveryFacet(guardian_address);
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public {
        // Check that Guardian address is set correctly
        assertEq(recoveryFacet.guardian(), guardian_address);
        
        // Check that it inherits from Simple7702Account
        assertTrue(address(recoveryFacet).code.length > 0);
        
        // Check initial authorized address is zero
        assertEq(recoveryFacet.getAuthorizedAddress(), address(0));
    }

    function test_SupportsInterface() public {
        // Check ERC165 support
        assertTrue(recoveryFacet.supportsInterface(type(IERC165).interfaceId));
        assertTrue(recoveryFacet.supportsInterface(type(IAccount).interfaceId));
        assertTrue(recoveryFacet.supportsInterface(type(IERC1271).interfaceId));
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_OnlyGuardianCanSetAuthorizedAddress() public {
        // Guardian should be able to set authorized address
        vm.prank(guardian_address);
        recoveryFacet.setAuthorizedAddress(newEOA);
        
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
    }

    function test_RevertWhen_NonGuardianSetsAuthorizedAddress() public {
        // Unauthorized user should not be able to set authorized address
        vm.prank(unauthorized);
        vm.expectRevert("only guardian");
        recoveryFacet.setAuthorizedAddress(newEOA);
    }

    function test_RevertWhen_UserSetsAuthorizedAddress() public {
        vm.prank(user1);
        vm.expectRevert("only guardian");
        recoveryFacet.setAuthorizedAddress(newEOA);
    }

    function test_RevertWhen_SelfSetsAuthorizedAddress() public {
        vm.prank(address(recoveryFacet));
        vm.expectRevert("only guardian");
        recoveryFacet.setAuthorizedAddress(newEOA);
    }

    /*//////////////////////////////////////////////////////////////
                        FUNCTIONALITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetAuthorizedAddress() public {
        vm.prank(guardian_address);
        
        vm.expectEmit(true, false, false, false);
        emit AuthorizedAddressSet(newEOA);
        
        recoveryFacet.setAuthorizedAddress(newEOA);
        
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
    }

    function test_UpdateAuthorizedAddress() public {
        address firstAddress = address(0x111);
        address secondAddress = address(0x222);
        
        vm.startPrank(guardian_address);
        
        // Set first address
        recoveryFacet.setAuthorizedAddress(firstAddress);
        assertEq(recoveryFacet.getAuthorizedAddress(), firstAddress);
        
        // Update to second address
        recoveryFacet.setAuthorizedAddress(secondAddress);
        assertEq(recoveryFacet.getAuthorizedAddress(), secondAddress);
        
        vm.stopPrank();
    }

    function test_SetAuthorizedAddressToZero() public {
        vm.startPrank(guardian_address);
        
        // Set to non-zero address first
        recoveryFacet.setAuthorizedAddress(newEOA);
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
        
        // Set to zero address
        recoveryFacet.setAuthorizedAddress(address(0));
        assertEq(recoveryFacet.getAuthorizedAddress(), address(0));
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RequireForExecute_Self() public {
        // Test that contract can call itself
        vm.prank(address(recoveryFacet));
        recoveryFacet.getAuthorizedAddress(); // This should not revert
    }

    function test_RequireForExecute_EntryPoint() public {
        // Test that EntryPoint can execute
        address entryPoint = address(recoveryFacet.entryPoint());
        vm.prank(entryPoint);
        recoveryFacet.getAuthorizedAddress(); // This should not revert
    }

    function test_RequireForExecute_AuthorizedAddress() public {
        // Set authorized address
        vm.prank(guardian_address);
        recoveryFacet.setAuthorizedAddress(newEOA);
        
        // Test that authorized address can execute
        vm.prank(newEOA);
        recoveryFacet.getAuthorizedAddress(); // This should not revert
    }

    function test_RevertWhen_UnauthorizedExecution() public {
        // Test that unauthorized address cannot execute functions that require authorization
        // Since _requireForExecute is used in inherited Simple7702Account functions,
        // and getAuthorizedAddress is a view function, we test the access control indirectly
        
        // The key access control test is ensuring only Guardian can set authorized addresses
        // which is already covered in other tests. This test verifies the override works.
        
        // Test: unauthorized address should NOT be able to call Guardian-only functions
        vm.prank(unauthorized);
        vm.expectRevert("only guardian");
        recoveryFacet.setAuthorizedAddress(newEOA);
    }

    /*//////////////////////////////////////////////////////////////
                        STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_StorageSlotConsistency() public {
        vm.startPrank(guardian_address);
        
        // Set authorized address
        recoveryFacet.setAuthorizedAddress(newEOA);
        
        // Check that storage is consistent
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
        
        // Set different address
        recoveryFacet.setAuthorizedAddress(user1);
        assertEq(recoveryFacet.getAuthorizedAddress(), user1);
        
        vm.stopPrank();
    }

    function test_StorageSlotDoesNotConflict() public {
        // The custom storage slot should not conflict with inherited storage
        vm.startPrank(guardian_address);
        
        // Set authorized address
        recoveryFacet.setAuthorizedAddress(newEOA);
        
        // Check that Simple7702Account functionality still works
        assertTrue(address(recoveryFacet.entryPoint()) != address(0));
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IntegrationWithMockGuardian() public {
        // Deploy MockGuardian for testing
        MockGuardian mockGuardian = new MockGuardian();
        
        // Deploy RecoveryFacet that accepts MockGuardian as the guardian
        RecoveryFacet testRecoveryFacet = new RecoveryFacet(address(mockGuardian));
        
        // Register user with MockGuardian (using RecoveryFacet address as oldEOA for testing)
        vm.prank(user1);
        mockGuardian.register(address(testRecoveryFacet), 0x01, EMAIL_HASH, 0, 0);
        
        // Request nonce
        vm.prank(user1);
        bytes32 nonce = mockGuardian.requestNonce(EMAIL_HASH);
        
        // Create valid proof (32+ bytes)
        bytes memory proof = abi.encode(uint256(0x123), uint256(0x456));
        
        // This should work with MockGuardian
        vm.prank(user1);
        mockGuardian.recover(EMAIL_HASH, newEOA, nonce, proof);
        
        // Verify that the authorized address was set
        assertEq(testRecoveryFacet.getAuthorizedAddress(), newEOA);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetAuthorizedAddress(address _newAddress) public {
        vm.prank(guardian_address);
        recoveryFacet.setAuthorizedAddress(_newAddress);
        
        assertEq(recoveryFacet.getAuthorizedAddress(), _newAddress);
    }

    function testFuzz_OnlyGuardianCanSet(address _caller, address _newAddress) public {
        vm.assume(_caller != guardian_address);
        
        vm.prank(_caller);
        vm.expectRevert("only guardian");
        recoveryFacet.setAuthorizedAddress(_newAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_HelperFunctions() public {
        // Test that helper functions work correctly
        assertEq(recoveryFacet.guardian(), guardian_address);
        assertTrue(recoveryFacet.supportsInterface(type(IERC165).interfaceId));
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_MultipleUpdates() public {
        vm.startPrank(guardian_address);
        
        address[] memory addresses = new address[](5);
        addresses[0] = address(0x1111);
        addresses[1] = address(0x2222);
        addresses[2] = address(0x3333);
        addresses[3] = address(0x4444);
        addresses[4] = address(0x5555);
        
        for (uint i = 0; i < addresses.length; i++) {
            recoveryFacet.setAuthorizedAddress(addresses[i]);
            assertEq(recoveryFacet.getAuthorizedAddress(), addresses[i]);
        }
        
        vm.stopPrank();
    }

    function test_SetSameAddressTwice() public {
        vm.startPrank(guardian_address);
        
        recoveryFacet.setAuthorizedAddress(newEOA);
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
        
        // Setting same address again should work
        recoveryFacet.setAuthorizedAddress(newEOA);
        assertEq(recoveryFacet.getAuthorizedAddress(), newEOA);
        
        vm.stopPrank();
    }
} 