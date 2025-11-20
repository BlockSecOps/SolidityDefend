// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableUUPS
 * @notice Test contract for UUPS (EIP-1822) proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. missing-upgrade-authorization - Upgrade function lacks proper access control
 * 2. uninitialized-proxy-state - Proxy state not properly initialized
 * 3. delegatecall-to-untrusted - Unsafe delegatecall in proxy
 * 4. storage-collision - Implementation storage collision
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical
 * REFERENCE: EIP-1822, EIP-1967
 */

contract VulnerableUUPS {
    // EIP-1967 storage slot for implementation
    // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _implementation) {
        _setImplementation(_implementation);
    }

    function _setImplementation(address newImplementation) private {
        assembly {
            sstore(IMPLEMENTATION_SLOT, newImplementation)
        }
    }

    function implementation() public view returns (address impl) {
        assembly {
            impl := sload(IMPLEMENTATION_SLOT)
        }
    }

    // VULNERABILITY 1: Anyone can upgrade
    // Expected: missing-upgrade-authorization (CRITICAL)
    function upgradeTo(address newImplementation) public {
        // No access control!
        _setImplementation(newImplementation);
    }

    fallback() external payable {
        address impl = implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @title UUPSImplementation
 * @notice UUPS implementation with vulnerabilities
 */
contract UUPSImplementation {
    address public owner;
    mapping(address => uint256) public balances;

    // VULNERABILITY 2: Unprotected upgrade in implementation
    // Expected: missing-access-control (CRITICAL)
    function upgradeToAndCall(address newImplementation, bytes memory data) public {
        // VULNERABILITY: No owner check!
        // In UUPS, the upgrade logic is in implementation, not proxy

        // Upgrade
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, newImplementation)
        }

        // Call initialization on new implementation
        if (data.length > 0) {
            (bool success,) = address(this).delegatecall(data);
            require(success, "Initialization failed");
        }
    }

    // VULNERABILITY 3: Re-initializable
    // Expected: unprotected-initializer (HIGH)
    function initialize(address _owner) public {
        // Can be called multiple times to reset owner!
        owner = _owner;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
