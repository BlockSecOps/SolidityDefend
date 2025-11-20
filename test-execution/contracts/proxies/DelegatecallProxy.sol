// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DelegatecallProxy
 * @notice Test contract for delegatecall proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. delegatecall-to-untrusted - Delegatecall to untrusted address
 * 2. proxy-selector-collision - Function selector collision between proxy and logic
 * 3. storage-collision - Storage layout mismatch
 *
 * TEST CATEGORY: proxy
 * SEVERITY: critical
 */

contract DelegatecallProxy {
    address public owner;           // Slot 0
    address public logic;           // Slot 1
    uint256 public value;           // Slot 2

    constructor(address _logic) {
        owner = msg.sender;
        logic = _logic;
    }

    // VULNERABILITY 1: Anyone can change logic contract
    // Expected: missing-access-control (CRITICAL)
    function setLogic(address _logic) public {
        logic = _logic;
    }

    // VULNERABILITY 2: Delegatecall without validation
    // Expected: delegatecall-to-untrusted (CRITICAL)
    function execute(bytes memory data) public returns (bytes memory) {
        (bool success, bytes memory result) = logic.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    fallback() external payable {
        address _logic = logic;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _logic, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract LogicContract {
    // VULNERABILITY 3: Storage collision - same slots as proxy!
    address public admin;           // Slot 0 - COLLIDES with owner
    address public implementation;  // Slot 1 - COLLIDES with logic
    uint256 public data;           // Slot 2 - COLLIDES with value

    function setValue(uint256 _value) public {
        data = _value;
    }

    function changeAdmin(address _admin) public {
        admin = _admin;
    }
}
