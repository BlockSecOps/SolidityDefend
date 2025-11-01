// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableSocialRecovery {
    mapping(address => address[]) public guardians;

    // This should trigger aa-social-recovery detector
    function initiateRecovery(address account, address newOwner) external {
        // No timelock delay
        // No minimum guardian threshold
        // No approval tracking
        // Should trigger multiple findings
    }

    function approveRecovery(address account) external {
        // Missing guardian validation
    }

    function completeRecovery(address account) external {
        // No replay protection
        // Anyone can execute
    }
}
