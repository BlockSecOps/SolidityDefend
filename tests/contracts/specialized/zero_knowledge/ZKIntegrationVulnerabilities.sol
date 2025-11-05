// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ZKIntegrationVulnerabilities
 * @notice ZK System Integration and Composability Vulnerabilities
 *
 * VULNERABILITY: Integration with DeFi, bridges, and other systems
 * CATEGORY: Zero-Knowledge Proof Security
 *
 * BACKGROUND:
 * ZK proofs are often integrated with complex DeFi protocols, bridges, rollups,
 * and other smart contract systems. These integrations introduce new attack
 * vectors beyond the ZK proofs themselves.
 *
 * INTEGRATION RISKS:
 * 1. Oracle integration (price manipulation via proofs)
 * 2. Cross-protocol proof reuse
 * 3. Flash loan + ZK proof combinations
 * 4. MEV attacks on ZK transactions
 * 5. Proof verification gas griefing
 * 6. State consistency between ZK and non-ZK components
 * 7. Callback vulnerabilities during proof verification
 *
 * TESTED DETECTORS:
 * - zk-integration-oracle
 * - zk-integration-flashloan
 * - zk-integration-callback
 * - zk-integration-gas-griefing
 * - zk-integration-state-consistency
 */

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

/**
 * @title ZKOracleIntegration
 * @notice ZK proof integration with price oracles
 */
contract ZKOracleIntegration {
    IPriceOracle public priceOracle;

    /**
     * @notice VULNERABILITY 1: Oracle price used in ZK proof validation
     * @dev Oracle can be manipulated before/during proof verification
     */
    function verifyWithOraclePrice(
        uint256[8] calldata proof,
        address token,
        uint256 amount
    ) external view returns (bool) {
        // Get current price from oracle
        uint256 price = priceOracle.getPrice(token);

        // VULNERABLE: Oracle price can be manipulated
        // Attacker can:
        // 1. Manipulate oracle price
        // 2. Submit proof that's valid for manipulated price
        // 3. Price returns to normal after verification

        // Public inputs should include price at specific block/timestamp
        // Not current price which can be manipulated

        return _verify(proof, amount, price);
    }

    /**
     * @notice VULNERABILITY 2: Timestamp not validated in proof
     */
    function verifyWithTimestamp(
        uint256[8] calldata proof,
        uint256 timestamp,
        uint256 amount
    ) external view returns (bool) {
        // VULNERABLE: No check that timestamp is recent
        // Attacker can use old proof with outdated oracle data

        // MISSING: require(timestamp >= block.timestamp - MAX_AGE, "Proof too old");

        return _verify(proof, amount, timestamp);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256 amount,
        uint256 price
    ) internal pure returns (bool) {
        return proof[0] != 0 && amount > 0 && price > 0;
    }

    function setPriceOracle(address _oracle) external {
        priceOracle = IPriceOracle(_oracle);
    }
}

/**
 * @title ZKFlashLoanIntegration
 * @notice ZK proof with flash loan vulnerability
 */
contract ZKFlashLoanIntegration {
    mapping(address => uint256) public balances;

    /**
     * @notice VULNERABILITY 3: Flash loan + ZK proof combination
     * @dev Attacker borrows funds, generates proof, then repays
     */
    function depositWithProof(
        uint256[8] calldata proof,
        uint256 amount
    ) external {
        // Get user's balance
        uint256 userBalance = address(msg.sender).balance;

        // VULNERABLE: User can flash loan ETH, pass balance check,
        // generate proof showing they have funds, then repay loan

        // Proof should verify:
        // 1. User has funds at specific block
        // 2. Funds are not borrowed
        // 3. Funds will remain after transaction

        require(_verify(proof, userBalance), "Invalid proof");

        balances[msg.sender] += amount;

        // ATTACK FLOW:
        // 1. Flash loan 100 ETH
        // 2. Generate proof showing balance >= 100 ETH
        // 3. Call depositWithProof (proof passes)
        // 4. Repay flash loan
        // 5. Get deposit credit without actually having funds
    }

    /**
     * @notice VULNERABILITY 4: Same-block proof validation
     */
    mapping(address => uint256) public lastProofBlock;

    function verifyWithBlockCheck(
        uint256[8] calldata proof,
        uint256 amount
    ) external {
        // VULNERABLE: Only checks that proofs aren't reused in same block
        // Doesn't prevent flash loan attack across blocks

        require(lastProofBlock[msg.sender] != block.number, "Already used");

        lastProofBlock[msg.sender] = block.number;

        require(_verify(proof, amount), "Invalid proof");

        balances[msg.sender] += amount;
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0 && amount > 0;
    }
}

/**
 * @title ZKCallbackVulnerability
 * @notice Callback vulnerabilities during proof verification
 */
contract ZKCallbackVulnerability {
    mapping(address => uint256) public deposits;

    /**
     * @notice VULNERABILITY 5: Callback to user during verification
     * @dev User can re-enter during verification process
     */
    function depositWithCallback(
        uint256[8] calldata proof,
        uint256 amount,
        bytes calldata data
    ) external {
        // Verify proof first
        require(_verify(proof, amount), "Invalid proof");

        // VULNERABLE: Callback to msg.sender before state update
        (bool success, ) = msg.sender.call(data);
        require(success, "Callback failed");

        // State update after callback
        deposits[msg.sender] += amount;

        // ATTACK: During callback, attacker can:
        // 1. Re-enter with same proof
        // 2. Call other functions that depend on deposit state
        // 3. Manipulate external state before this tx completes
    }

    /**
     * @notice VULNERABILITY 6: Verification status callback
     */
    event VerificationStarted(address indexed user, uint256 amount);
    event VerificationCompleted(address indexed user, bool success);

    function depositWithEvents(
        uint256[8] calldata proof,
        uint256 amount
    ) external {
        emit VerificationStarted(msg.sender, amount);

        // VULNERABLE: External contracts can observe verification
        // via events and front-run or back-run

        bool valid = _verify(proof, amount);

        emit VerificationCompleted(msg.sender, valid);

        if (valid) {
            deposits[msg.sender] += amount;
        }

        // ATTACK: MEV bots can observe VerificationCompleted event
        // and sandwich attack or front-run subsequent transactions
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0 && amount > 0;
    }
}

/**
 * @title ZKGasGriefing
 * @notice Gas-related vulnerabilities
 */
contract ZKGasGriefing {
    /**
     * @notice VULNERABILITY 7: Unbounded verification gas
     * @dev No gas limit on proof verification
     */
    function verifyWithoutGasLimit(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: No gas limit
        // Attacker can provide proof that requires excessive gas

        // Public inputs length not limited
        if (publicInputs.length > 1000) {
            // Might consume all block gas
        }

        return _verify(proof, publicInputs);
    }

    /**
     * @notice VULNERABILITY 8: Gas griefing via invalid proofs
     */
    function batchVerify(
        uint256[][8] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view returns (bool[] memory) {
        bool[] memory results = new bool[](proofs.length);

        // VULNERABLE: No limit on batch size
        // Attacker can submit huge batch to grief gas

        for (uint256 i = 0; i < proofs.length; i++) {
            // Each verification might be expensive
            results[i] = _verify(proofs[i], publicInputs[i]);

            // ATTACK: Submit batch of 1000 invalid proofs
            // Each consumes verification gas
            // Transaction consumes entire block gas
        }

        return results;
    }

    /**
     * @notice VULNERABILITY 9: Verification gas not compensated
     */
    function verifyWithFee(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external payable returns (bool) {
        // VULNERABLE: Fixed fee doesn't cover verification cost
        require(msg.value >= 0.01 ether, "Insufficient fee");

        // Verification might cost more gas than fee covers
        // Especially for complex proofs or many public inputs

        bool valid = _verify(proof, publicInputs);

        // Refund if valid
        if (valid) {
            payable(msg.sender).transfer(msg.value);
        }

        // ATTACK: Submit invalid proof, pay small fee,
        // cause contract to consume expensive verification gas
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        // Simplified - real verification is expensive
        uint256 gasUsed = 0;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            gasUsed += publicInputs[i];
        }
        return proof[0] != 0;
    }
}

/**
 * @title ZKStateConsistency
 * @notice State consistency between ZK and non-ZK components
 */
contract ZKStateConsistency {
    // On-chain state
    uint256 public onChainBalance;

    // ZK state root
    bytes32 public zkStateRoot;

    /**
     * @notice VULNERABILITY 10: On-chain and ZK state can diverge
     * @dev No mechanism to ensure consistency
     */
    function updateOnChain(uint256 amount) external {
        onChainBalance += amount;

        // VULNERABLE: On-chain state updated but ZK state not updated
        // States diverge and become inconsistent

        // MISSING: Synchronization mechanism
        // MISSING: Proof that update maintains consistency
    }

    function updateZKState(
        uint256[8] calldata proof,
        bytes32 newStateRoot
    ) external {
        require(_verify(proof, uint256(newStateRoot)), "Invalid proof");

        zkStateRoot = newStateRoot;

        // VULNERABLE: ZK state updated but on-chain state not updated
        // Inconsistency between two views of state
    }

    /**
     * @notice VULNERABILITY 11: Race condition between updates
     */
    function syncStates(
        uint256 onChainDelta,
        bytes32 newZkRoot,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: No atomic update of both states
        // Race condition possible if another tx executes between updates

        onChainBalance += onChainDelta; // Update 1

        // Another transaction could execute here!

        require(_verify(proof, uint256(newZkRoot)), "Invalid proof");
        zkStateRoot = newZkRoot; // Update 2

        // If race occurs, states become inconsistent
    }

    function _verify(uint256[8] calldata proof, uint256 value) internal pure returns (bool) {
        return proof[0] != 0 && value != 0;
    }
}

/**
 * @title ZKBridgeIntegration
 * @notice ZK bridge integration vulnerabilities
 */
contract ZKBridgeIntegration {
    mapping(bytes32 => bool) public processedProofs;

    /**
     * @notice VULNERABILITY 12: Bridge proof not bound to destination chain
     * @dev Proof from L1→L2 can be replayed L1→L3
     */
    function bridgeWithProof(
        uint256[8] calldata proof,
        uint256 amount,
        address recipient,
        uint256 chainId
    ) external {
        bytes32 proofHash = keccak256(abi.encode(proof));
        require(!processedProofs[proofHash], "Proof used");

        // VULNERABLE: chainId not validated in proof
        // Same proof can be used on multiple destination chains

        // MISSING: Proof must include destination chainId as public input

        require(_verify(proof, amount), "Invalid proof");

        processedProofs[proofHash] = true;

        // Process bridge transfer
        payable(recipient).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 13: Bridge state not synchronized
     */
    uint256 public l1Balance;
    uint256 public l2Balance;

    function syncBalances(
        uint256[8] calldata l1Proof,
        uint256[8] calldata l2Proof,
        uint256 l1Amount,
        uint256 l2Amount
    ) external {
        // VULNERABLE: Separate proofs for each side
        // Can be inconsistent

        require(_verify(l1Proof, l1Amount), "Invalid L1 proof");
        require(_verify(l2Proof, l2Amount), "Invalid L2 proof");

        l1Balance = l1Amount;
        l2Balance = l2Amount;

        // MISSING: Constraint that l1Balance + l2Balance = constant
        // Conservation of value not enforced
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0 && amount > 0;
    }

    receive() external payable {}
}

/**
 * @title ZKRollupIntegration
 * @notice ZK rollup integration vulnerabilities
 */
contract ZKRollupIntegration {
    bytes32 public stateRoot;
    uint256 public batchNumber;

    /**
     * @notice VULNERABILITY 14: State root update without proper ordering
     * @dev Batch N+1 can be submitted before batch N
     */
    function submitBatch(
        uint256 batchId,
        bytes32 newStateRoot,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: No check that batchId = batchNumber + 1
        // Batches can be submitted out of order

        require(_verify(proof, uint256(newStateRoot)), "Invalid proof");

        stateRoot = newStateRoot;
        batchNumber = batchId;

        // ATTACK: Skip batch N, submit batch N+1
        // Or submit batch N+2 before N+1
        // State becomes inconsistent
    }

    /**
     * @notice VULNERABILITY 15: No forced inclusion mechanism
     */
    mapping(bytes32 => bool) public pendingWithdrawals;

    function requestWithdrawal(bytes32 withdrawalHash) external {
        pendingWithdrawals[withdrawalHash] = true;

        // VULNERABLE: Operator can ignore withdrawal requests
        // No forced inclusion after timeout

        // MISSING: Mechanism to force withdrawals if operator censors
        // MISSING: Timeout after which users can withdraw directly
    }

    function _verify(uint256[8] calldata proof, uint256 value) internal pure returns (bool) {
        return proof[0] != 0 && value != 0;
    }
}

/**
 * @title ZKComposability
 * @notice ZK proof composability issues
 */
contract ZKComposability {
    /**
     * @notice VULNERABILITY 16: Proof composition without validation
     * @dev Combining multiple proofs without proper checks
     */
    function verifyComposite(
        uint256[8] calldata proof1,
        uint256[8] calldata proof2,
        uint256 amount1,
        uint256 amount2
    ) external pure returns (bool) {
        // VULNERABLE: Verifies proofs independently
        // Doesn't verify they're composable

        bool valid1 = _verify(proof1, amount1);
        bool valid2 = _verify(proof2, amount2);

        // MISSING: Verification that proof2's inputs match proof1's outputs
        // MISSING: Consistency check between proofs
        // MISSING: Proof that proofs can be safely composed

        return valid1 && valid2;
    }

    /**
     * @notice VULNERABILITY 17: Recursive proof without depth limit
     */
    function verifyRecursive(
        uint256[8] calldata outerProof,
        uint256[8][] calldata innerProofs,
        uint256 depth
    ) external pure returns (bool) {
        // VULNERABLE: No limit on recursion depth
        // Can cause gas exhaustion

        if (depth == 0) {
            return _verify(outerProof, 0);
        }

        // MISSING: require(depth <= MAX_DEPTH, "Too deep");

        for (uint256 i = 0; i < innerProofs.length; i++) {
            // Recursive verification - unbounded
            if (!_verify(innerProofs[i], depth)) {
                return false;
            }
        }

        return _verify(outerProof, depth);
    }

    function _verify(uint256[8] calldata proof, uint256 value) internal pure returns (bool) {
        return proof[0] != 0 && value >= 0;
    }
}

/**
 * @title ZKMEVVulnerability
 * @notice MEV attacks on ZK transactions
 */
contract ZKMEVVulnerability {
    mapping(bytes32 => bool) public usedNullifiers;

    /**
     * @notice VULNERABILITY 18: ZK transaction visible in mempool
     * @dev MEV bots can see and exploit ZK transactions
     */
    function withdraw(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier used");
        require(_verify(proof, amount), "Invalid proof");

        // VULNERABLE: Transaction visible in mempool before mining
        // MEV bots can:
        // 1. Front-run with higher gas to steal withdrawal
        // 2. Back-run to exploit price impact
        // 3. Sandwich attack

        usedNullifiers[nullifier] = true;

        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 19: No MEV protection mechanism
     */
    function withdrawWithRecipient(
        uint256[8] calldata proof,
        bytes32 nullifier,
        address recipient,
        uint256 amount
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier used");
        require(_verify(proof, amount), "Invalid proof");

        // VULNERABLE: recipient not committed in proof
        // Front-runner can change recipient to themselves

        usedNullifiers[nullifier] = true;

        // ATTACK: See withdraw in mempool, front-run with own address
        payable(recipient).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0 && amount > 0;
    }

    receive() external payable {}
}
