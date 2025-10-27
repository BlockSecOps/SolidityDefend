// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerablePaymaster
 * @notice Test contract with ERC-4337 Paymaster vulnerabilities
 * @dev Should trigger: erc4337-paymaster-abuse detector
 */
contract VulnerablePaymaster {
    mapping(address => uint256) public deposits;

    // VULNERABLE: No nonce tracking - replay attack possible
    function validatePaymasterUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // VULNERABLE: No nonce validation
        // VULNERABLE: No spending limit check
        // VULNERABLE: No target whitelist
        // VULNERABLE: No gas limit validation
        // VULNERABLE: No chain ID binding

        return ("", 0);
    }

    // VULNERABLE: No spending limits
    function sponsorTransaction(address user, uint256 cost) external {
        require(deposits[msg.sender] >= cost, "Insufficient deposit");
        deposits[msg.sender] -= cost;
        // Missing validation allows unlimited sponsorship
    }

    // VULNERABLE: Missing chain ID validation
    function executeUserOp(bytes calldata userOp) external {
        // Can be replayed across chains
    }
}

/**
 * @title VulnerableNonceManager
 * @notice Test contract with nonce management vulnerabilities
 * @dev Should trigger: aa-nonce-management detector
 */
contract VulnerableNonceManager {
    mapping(address => uint256) public nonces;

    // VULNERABLE: Sequential nonce only, no key support
    function incrementNonce(address user) external {
        nonces[user]++;
    }

    // VULNERABLE: No getNonce function with key parameter
    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }

    // VULNERABLE: No invalidateNonce function
    // Missing emergency nonce invalidation
}

/**
 * @title VulnerableSessionKey
 * @notice Test contract with session key vulnerabilities
 * @dev Should trigger: aa-session-key-security detector
 */
contract VulnerableSessionKey {
    mapping(address => mapping(address => bool)) public sessionKeys;

    // VULNERABLE: No expiration time
    // VULNERABLE: No spending limits
    // VULNERABLE: No target restrictions
    // VULNERABLE: No operation limits
    function addSessionKey(address account, address sessionKey) external {
        sessionKeys[account][sessionKey] = true;
    }

    // VULNERABLE: No validation of session key constraints
    function executeWithSessionKey(
        address account,
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        require(sessionKeys[account][msg.sender], "Invalid session key");
        // Execute without checking expiration, limits, or restrictions
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }
}

/**
 * @title VulnerableSignatureAggregator
 * @notice Test contract with signature aggregation vulnerabilities
 * @dev Should trigger: aa-signature-aggregation detector
 */
contract VulnerableSignatureAggregator {
    // VULNERABLE: No signature validation
    // VULNERABLE: No duplicate prevention
    function aggregateSignatures(
        bytes[] calldata signatures
    ) external pure returns (bytes memory) {
        // VULNERABLE: Simply concatenates without validation
        bytes memory aggregated;
        for (uint i = 0; i < signatures.length; i++) {
            aggregated = abi.encodePacked(aggregated, signatures[i]);
        }
        return aggregated;
    }

    // VULNERABLE: No malleability protection
    function validateAggregatedSignature(
        bytes32 hash,
        bytes calldata signature
    ) external pure returns (bool) {
        // No actual validation
        return true;
    }
}

/**
 * @title VulnerableSocialRecovery
 * @notice Test contract with social recovery vulnerabilities
 * @dev Should trigger: aa-social-recovery detector
 */
contract VulnerableSocialRecovery {
    mapping(address => address[]) public guardians;
    mapping(address => uint256) public threshold;

    // VULNERABLE: No timelock for recovery
    // VULNERABLE: No guardian verification
    function initiateRecovery(
        address account,
        address newOwner
    ) external {
        // VULNERABLE: Immediate execution without timelock
        // Missing guardian signature validation
        // No minimum guardian count check
    }

    // VULNERABLE: Guardians can be added instantly
    function addGuardian(address account, address guardian) external {
        guardians[account].push(guardian);
        // No delay, no existing guardian approval needed
    }

    // VULNERABLE: Single guardian can change ownership
    function completeRecovery(address account, address newOwner) external {
        // No multi-sig validation
        // No timelock check
    }
}

/**
 * @title VulnerableHardwareWalletDelegation
 * @notice Test contract with hardware wallet delegation vulnerabilities
 * @dev Should trigger: hardware-wallet-delegation detector
 */
contract VulnerableHardwareWalletDelegation {
    mapping(address => address) public delegates;

    // VULNERABLE: No expiration for delegation
    // VULNERABLE: No scope restrictions
    // VULNERABLE: No value limits
    function setDelegate(address delegate) external {
        delegates[msg.sender] = delegate;
    }

    // VULNERABLE: Unlimited delegation power
    function executeAsDelegate(
        address account,
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        require(delegates[account] == msg.sender, "Not delegate");
        // VULNERABLE: No checks on target, value, or operation type
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }
}
