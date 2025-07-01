// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "../lib/account-abstraction/contracts/accounts/Simple7702Account.sol";

/**
 * Executed _inside_ the lost EOA via EIP-7702 delegation.
 * Allows Guardian to set an additional authorized address for execution.
 * Inherits from Simple7702Account for ERC-4337 compatibility.
 */
contract RecoveryFacet is Simple7702Account {
    // Guardian contract address that can call setAuthorizedAddress
    address public immutable guardian;

    event AuthorizedAddressSet(address indexed newAuthorizedAddress);

    modifier onlyGuardian() {
        require(msg.sender == guardian, "only guardian");
        _;
    }

    constructor(address _guardian) {
        guardian = _guardian;
    }

    /**
     * @notice Sets the authorized address that can execute functions
     * @param newAuthorizedAddress The new address to authorize for execution
     * @dev Only callable by the Guardian contract
     */
    function setAuthorizedAddress(address newAuthorizedAddress) external onlyGuardian {
        bytes32 slot = keccak256("ppar.authorized.address");
        assembly {
            sstore(slot, newAuthorizedAddress)
        }
        emit AuthorizedAddressSet(newAuthorizedAddress);
    }

    /**
     * @notice Gets the current authorized address
     * @return authorizedAddress The currently authorized address
     */
    function getAuthorizedAddress() external view returns (address authorizedAddress) {
        bytes32 slot = keccak256("ppar.authorized.address");
        assembly {
            authorizedAddress := sload(slot)
        }
    }

    /**
     * @notice Override _requireForExecute to allow Guardian-set authorized address in addition to self and EntryPoint
     */
    function _requireForExecute() internal view override {
        bytes32 slot = keccak256("ppar.authorized.address");
        address authorizedAddress;
        assembly {
            authorizedAddress := sload(slot)
        }
        
        require(
            msg.sender == address(this) ||
            msg.sender == address(entryPoint()) ||
            msg.sender == authorizedAddress,
            "not from self, EntryPoint, or authorized address"
        );
    }
}
