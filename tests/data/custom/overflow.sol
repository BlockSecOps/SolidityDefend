// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OverflowVulnerable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        // Potential overflow in older Solidity versions
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount; // Potential overflow
    }
}
