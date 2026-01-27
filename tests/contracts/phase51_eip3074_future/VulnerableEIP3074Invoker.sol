// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title VulnerableEIP3074Invoker
 * @notice VULNERABLE: Upgradeable invoker violates EIP-3074 security model
 * @dev Should trigger: eip3074-upgradeable-invoker (Critical)
 *
 * EIP-3074 explicitly forbids upgradeable invokers because users sign
 * AUTH messages trusting specific code. Upgradeable invokers break this trust.
 */
contract VulnerableEIP3074Invoker is Initializable, UUPSUpgradeable {
    address public owner;

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == owner, "Not owner");
    }

    // VULNERABLE: AUTH opcode in upgradeable contract
    function executeAuth(
        address target,
        bytes calldata data,
        bytes calldata signature
    ) external returns (bool success, bytes memory result) {
        bytes32 commit = keccak256(abi.encode(target, data));

        assembly {
            // AUTH opcode - sets authorized account
            let authorized := auth(target, commit)

            // AUTHCALL - call as authorized account
            success := authcall(gas(), target, 0, add(data, 32), mload(data), 0, 0)
        }

        return (success, result);
    }
}

/**
 * @title VulnerableCommitValidation
 * @notice VULNERABLE: Incomplete commit hash validation
 * @dev Should trigger: eip3074-commit-validation (High)
 */
contract VulnerableCommitValidation {
    // VULNERABLE: Commit doesn't include all required parameters
    function execute(
        bytes calldata sig,
        address to,
        uint256 value,
        bytes calldata data
    ) external {
        // Missing: nonce, deadline, chainId, invoker address
        bytes32 commit = keccak256(abi.encode(to));

        assembly {
            let authorized := auth(to, commit)
            let success := authcall(gas(), to, value, add(data, 32), mload(data), 0, 0)
        }
    }
}

/**
 * @title VulnerableReplayAttack
 * @notice VULNERABLE: Missing replay protection
 * @dev Should trigger: eip3074-replay-attack (High)
 */
contract VulnerableReplayAttack {
    // No nonce tracking
    // No chainId validation
    // No deadline enforcement

    function invoke(
        address to,
        bytes calldata data,
        bytes calldata signature
    ) external {
        // VULNERABLE: Can be replayed indefinitely
        bytes32 commit = keccak256(abi.encode(to, data));

        assembly {
            let authorized := auth(to, commit)
            let success := authcall(gas(), to, 0, add(data, 32), mload(data), 0, 0)
        }
    }
}

/**
 * @title VulnerableCallDepthGriefing
 * @notice VULNERABLE: No call depth validation before AUTHCALL
 * @dev Should trigger: eip3074-call-depth-griefing (Medium)
 */
contract VulnerableCallDepthGriefing {
    function execute(address to, bytes calldata data) external {
        // VULNERABLE: No depth check - can fail if called at high depth
        assembly {
            let success := authcall(gas(), to, 0, add(data, 32), mload(data), 0, 0)
            if iszero(success) {
                revert(0, 0)
            }
        }
    }

    // Recursive function that increases call depth
    function nestedExecute(address to, bytes calldata data, uint256 depth) external {
        if (depth > 0) {
            this.nestedExecute(to, data, depth - 1);
        }
        assembly {
            let success := authcall(gas(), to, 0, add(data, 32), mload(data), 0, 0)
        }
    }
}

/**
 * @title VulnerableInvokerAuthorization
 * @notice VULNERABLE: Missing authorization checks
 * @dev Should trigger: eip3074-invoker-authorization (High)
 */
contract VulnerableInvokerAuthorization {
    // VULNERABLE: No caller check, no target validation, no selector validation
    function execute(
        address to,
        uint256 value,
        bytes calldata data
    ) external {
        // Anyone can call, any target, any function
        assembly {
            let success := authcall(gas(), to, value, add(data, 32), mload(data), 0, 0)
        }
    }
}
