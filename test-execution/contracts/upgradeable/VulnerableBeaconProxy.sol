// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableBeaconProxy
 * @notice Test contract for Beacon Proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. unprotected-beacon-upgrade - Beacon can be upgraded by anyone
 * 2. beacon-implementation-mismatch - No validation of beacon implementation
 * 3. delegatecall-to-untrusted - Unsafe delegatecall to beacon implementation
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical
 * REFERENCE: EIP-1967 Beacon Proxy
 */

contract VulnerableBeacon {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABILITY 1: Anyone can upgrade the beacon
    // Expected: missing-access-control (CRITICAL)
    function upgradeTo(address newImplementation) public {
        // No access control - affects ALL proxies using this beacon!
        implementation = newImplementation;
    }
}

contract VulnerableBeaconProxy {
    // Beacon address stored in specific slot
    bytes32 internal constant BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    constructor(address beacon) {
        _setBeacon(beacon);
    }

    function _setBeacon(address beacon) private {
        assembly {
            sstore(BEACON_SLOT, beacon)
        }
    }

    function _beacon() internal view returns (address beacon) {
        assembly {
            beacon := sload(BEACON_SLOT)
        }
    }

    function _implementation() internal view returns (address) {
        // VULNERABILITY 2: No validation that beacon is a contract
        // Expected: missing-contract-existence-check (HIGH)
        return VulnerableBeacon(_beacon()).implementation();
    }

    // VULNERABILITY 3: Beacon can be changed by anyone
    // Expected: missing-access-control (CRITICAL)
    function changeBeacon(address newBeacon) public {
        // No access control!
        _setBeacon(newBeacon);
    }

    fallback() external payable {
        address impl = _implementation();
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

contract BeaconImplementation {
    address public owner;
    mapping(address => uint256) public balances;
    bool public initialized;

    // VULNERABILITY 4: Multiple initialization possible
    // Expected: unprotected-initializer (HIGH)
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
        // VULNERABILITY: initialized flag can be reset through upgrade!
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
