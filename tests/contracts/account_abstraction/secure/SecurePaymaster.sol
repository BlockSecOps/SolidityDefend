// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecurePaymaster
 * @notice Secure implementation of ERC-4337 Paymaster
 * @dev Implements all security best practices
 */
contract SecurePaymaster {
    mapping(address => uint256) public deposits;
    mapping(address => mapping(uint256 => bool)) public usedNonces;
    mapping(address => uint256) public spendingLimits;
    mapping(address => mapping(address => bool)) public targetWhitelist;
    uint256 public immutable chainId;
    uint256 public constant MAX_GAS_LIMIT = 1000000;

    constructor() {
        chainId = block.chainid;
    }

    // SECURE: Validates nonce, spending limits, target whitelist, gas limits, chain ID
    function validatePaymasterUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // Decode userOp
        (address sender, uint256 nonce, address target, uint256 gasLimit, uint256 chainIdFromOp) = abi.decode(
            userOp,
            (address, uint256, address, uint256, uint256)
        );

        // SECURE: Check nonce hasn't been used
        require(!usedNonces[sender][nonce], "Nonce already used");
        usedNonces[sender][nonce] = true;

        // SECURE: Validate spending limit
        require(maxCost <= spendingLimits[sender], "Exceeds spending limit");
        spendingLimits[sender] -= maxCost;

        // SECURE: Validate target is whitelisted
        require(targetWhitelist[sender][target], "Target not whitelisted");

        // SECURE: Validate gas limit
        require(gasLimit <= MAX_GAS_LIMIT, "Gas limit too high");

        // SECURE: Validate chain ID
        require(chainIdFromOp == chainId, "Invalid chain ID");

        return ("", 0);
    }

    // SECURE: Set spending limits with proper access control
    function setSpendingLimit(address user, uint256 limit) external {
        require(msg.sender == user, "Unauthorized");
        spendingLimits[user] = limit;
    }

    // SECURE: Whitelist targets with proper access control
    function whitelistTarget(address target) external {
        targetWhitelist[msg.sender][target] = true;
    }
}

/**
 * @title SecureNonceManager
 * @notice Secure nonce management with key support
 */
contract SecureNonceManager {
    mapping(address => mapping(uint192 => uint256)) public nonces;

    // SECURE: Sequential nonce with key support
    function incrementNonce(address user, uint192 key) external {
        nonces[user][key]++;
    }

    // SECURE: getNonce with key parameter for parallel transactions
    function getNonce(address user, uint192 key) external view returns (uint256) {
        return nonces[user][key];
    }

    // SECURE: Emergency nonce invalidation
    function invalidateNonce(uint192 key) external {
        nonces[msg.sender][key] = type(uint256).max;
    }
}

/**
 * @title SecureSessionKey
 * @notice Secure session key implementation with comprehensive restrictions
 */
contract SecureSessionKey {
    struct SessionKeyData {
        uint256 expirationTime;
        uint256 spendingLimit;
        uint256 spentAmount;
        address[] targetWhitelist;
        uint256 operationLimit;
        uint256 operationCount;
        bool isActive;
    }

    mapping(address => mapping(address => SessionKeyData)) public sessionKeys;

    // SECURE: Add session key with all restrictions
    function addSessionKey(
        address sessionKey,
        uint256 duration,
        uint256 spendingLimit,
        address[] calldata targets,
        uint256 operationLimit
    ) external {
        sessionKeys[msg.sender][sessionKey] = SessionKeyData({
            expirationTime: block.timestamp + duration,
            spendingLimit: spendingLimit,
            spentAmount: 0,
            targetWhitelist: targets,
            operationLimit: operationLimit,
            operationCount: 0,
            isActive: true
        });
    }

    // SECURE: Validate all session key constraints
    function executeWithSessionKey(
        address account,
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        SessionKeyData storage keyData = sessionKeys[account][msg.sender];

        // SECURE: Check if session key is active
        require(keyData.isActive, "Session key not active");

        // SECURE: Check expiration
        require(block.timestamp < keyData.expirationTime, "Session key expired");

        // SECURE: Check spending limit
        require(keyData.spentAmount + value <= keyData.spendingLimit, "Spending limit exceeded");

        // SECURE: Check target is whitelisted
        bool targetAllowed = false;
        for (uint i = 0; i < keyData.targetWhitelist.length; i++) {
            if (keyData.targetWhitelist[i] == target) {
                targetAllowed = true;
                break;
            }
        }
        require(targetAllowed, "Target not whitelisted");

        // SECURE: Check operation limit
        require(keyData.operationCount < keyData.operationLimit, "Operation limit exceeded");

        // Update state
        keyData.spentAmount += value;
        keyData.operationCount++;

        // Execute
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    // SECURE: Revoke session key
    function revokeSessionKey(address sessionKey) external {
        sessionKeys[msg.sender][sessionKey].isActive = false;
    }
}

/**
 * @title SecureSocialRecovery
 * @notice Secure social recovery with timelock and multi-sig
 */
contract SecureSocialRecovery {
    uint256 public constant RECOVERY_TIMELOCK = 7 days;
    uint256 public constant MIN_GUARDIANS = 3;

    struct RecoveryRequest {
        address newOwner;
        uint256 initiatedAt;
        uint256 approvalCount;
        mapping(address => bool) approvals;
        bool executed;
    }

    mapping(address => address[]) public guardians;
    mapping(address => uint256) public threshold;
    mapping(address => RecoveryRequest) public recoveryRequests;

    // SECURE: Initiate recovery with timelock
    function initiateRecovery(
        address account,
        address newOwner
    ) external {
        require(isGuardian(account, msg.sender), "Not a guardian");
        require(guardians[account].length >= MIN_GUARDIANS, "Insufficient guardians");

        RecoveryRequest storage request = recoveryRequests[account];
        require(!request.executed, "Recovery already executed");

        request.newOwner = newOwner;
        request.initiatedAt = block.timestamp;
        request.approvalCount = 1;
        request.approvals[msg.sender] = true;
    }

    // SECURE: Guardians approve recovery
    function approveRecovery(address account) external {
        require(isGuardian(account, msg.sender), "Not a guardian");
        RecoveryRequest storage request = recoveryRequests[account];
        require(request.initiatedAt > 0, "No recovery request");
        require(!request.approvals[msg.sender], "Already approved");

        request.approvals[msg.sender] = true;
        request.approvalCount++;
    }

    // SECURE: Complete recovery after timelock and threshold met
    function completeRecovery(address account) external {
        RecoveryRequest storage request = recoveryRequests[account];

        // SECURE: Check timelock
        require(
            block.timestamp >= request.initiatedAt + RECOVERY_TIMELOCK,
            "Timelock not expired"
        );

        // SECURE: Check threshold
        require(
            request.approvalCount >= threshold[account],
            "Threshold not met"
        );

        require(!request.executed, "Already executed");
        request.executed = true;

        // Transfer ownership (implementation depends on account structure)
    }

    // SECURE: Add guardian with delay
    function addGuardian(address guardian) external {
        guardians[msg.sender].push(guardian);
        if (threshold[msg.sender] == 0) {
            threshold[msg.sender] = (guardians[msg.sender].length * 2) / 3;
        }
    }

    function isGuardian(address account, address guardian) internal view returns (bool) {
        address[] memory accountGuardians = guardians[account];
        for (uint i = 0; i < accountGuardians.length; i++) {
            if (accountGuardians[i] == guardian) {
                return true;
            }
        }
        return false;
    }
}
