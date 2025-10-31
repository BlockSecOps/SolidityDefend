// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlIssue {
    address public owner;
    uint256 public sensitiveValue;

    constructor() {
        owner = msg.sender;
    }

    // Missing access control
    function setSensitiveValue(uint256 _value) external {
        sensitiveValue = _value;
    }

    function emergencyWithdraw() external {
        // Should have onlyOwner modifier
        payable(msg.sender).transfer(address(this).balance);
    }
}
