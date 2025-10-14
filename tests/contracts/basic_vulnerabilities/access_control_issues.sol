// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Test contract with multiple access control vulnerabilities
contract AccessControlIssues {
    address public owner;
    uint256 public balance;
    bool public initialized;

    // Vulnerability: Unprotected initializer
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    // Vulnerability: Missing access control on critical function
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    // Vulnerability: Missing access control on withdrawal
    function withdraw(uint256 _amount) public {
        require(_amount <= balance, "Insufficient balance");
        balance -= _amount;
        payable(msg.sender).transfer(_amount);
    }

    // Vulnerability: Default visibility (should be explicit)
    function updateBalance(uint256 _newBalance) {
        balance = _newBalance;
    }

    // Proper function with access control
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function emergencyStop() public onlyOwner {
        // Emergency functionality
    }
}