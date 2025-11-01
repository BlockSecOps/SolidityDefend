// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableSessionKey {
    // This should trigger aa-session-key-vulnerabilities detector
    function validateSessionKey(address sessionKey, bytes calldata data) external {
        // No expiration check
        // No target restrictions
        // No function selector restrictions
        // No value limits
        // Should trigger multiple findings
    }

    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        require(success);
    }
}
