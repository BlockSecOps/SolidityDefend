// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableRestaking {
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public rewards;

    // Should trigger restaking-withdrawal-delays
    function unstake(uint256 amount) external {
        // No withdrawal delay - instant unstaking
        stakes[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Should trigger restaking-delegation-manipulation
    function delegate(address operator, uint256 amount) external {
        // No allocation delay - instant delegation
        stakes[operator] += amount;
    }

    // Should trigger restaking-slashing-conditions
    function slash(address user, uint256 amount) external {
        // No slashing accounting - can double slash
        stakes[user] -= amount;
    }

    // Should trigger restaking-rewards-manipulation
    function distributeRewards(address[] calldata users, uint256 totalRewards) external {
        // Not proportional - first user gets all rewards
        rewards[users[0]] += totalRewards;
    }
}
