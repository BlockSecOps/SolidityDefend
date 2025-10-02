// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Test contract with validation and logic vulnerabilities
contract ValidationIssues {
    address public token;
    uint256[] public values;

    // Vulnerability: Missing zero address check
    function setToken(address _token) public {
        token = _token; // Should check for address(0)
    }

    // Vulnerability: Array bounds issue
    function updateValue(uint256 _index, uint256 _value) public {
        values[_index] = _value; // No bounds checking
    }

    // Vulnerability: Division before multiplication (precision loss)
    function calculateReward(uint256 _amount, uint256 _rate) public pure returns (uint256) {
        return (_amount / 100) * _rate; // Should be (_amount * _rate) / 100
    }

    // Vulnerability: Parameter consistency issue
    function transfer(address _to, uint256 _amount, bytes calldata _data) public {
        // Parameters not validated for consistency
        require(_to != address(0), "Invalid recipient");
        // Missing: validate _amount > 0, _data length checks
    }

    // Vulnerability: Unchecked external call
    function callExternalContract(address _contract, bytes calldata _data) public {
        (bool success, ) = _contract.call(_data);
        // Should check success and handle failure
    }
}