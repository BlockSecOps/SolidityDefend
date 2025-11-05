// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProofReplayAttacks
 * @notice Zero-Knowledge Proof Replay and Malleability Attacks
 *
 * VULNERABILITY: Proof replay and malleability
 * CATEGORY: Zero-Knowledge Proof Security
 *
 * BACKGROUND:
 * ZK proofs can be vulnerable to replay attacks where the same valid proof
 * is reused in different contexts. Proof malleability allows attackers to
 * create new valid proofs from existing ones without knowing the witness.
 *
 * ATTACK VECTORS:
 * 1. Cross-contract replay (proof valid in contract A reused in contract B)
 * 2. Cross-chain replay (same proof used on different chains)
 * 3. Temporal replay (reusing proof after state change)
 * 4. Proof malleability (modifying proof while maintaining validity)
 * 5. Nullifier bypass (circumventing nullifier checks)
 * 6. Commitment replay (reusing commitment in different contexts)
 *
 * REAL-WORLD IMPACT:
 * - Double-spending in privacy pools
 * - Duplicate withdrawals
 * - Voting multiple times
 * - Bypassing one-time-use constraints
 *
 * TESTED DETECTORS:
 * - zk-proof-replay
 * - zk-proof-malleability
 * - zk-nullifier-bypass
 * - zk-commitment-replay
 * - zk-cross-contract-replay
 */

/**
 * @title BasicReplayVulnerability
 * @notice Missing nullifier/nonce tracking
 */
contract BasicReplayVulnerability {
    event ProofVerified(address indexed user, uint256 amount);

    /**
     * @notice VULNERABILITY 1: No replay protection
     * @dev Same proof can be submitted multiple times
     */
    function verifyAndWithdraw(
        uint256[8] calldata proof,
        uint256 amount
    ) external {
        // VULNERABLE: No tracking of used proofs
        // Same proof can be replayed infinitely
        require(_verify(proof, amount), "Invalid proof");

        // Missing: Nullifier or nonce tracking
        // Missing: mapping(bytes32 => bool) public usedProofs

        payable(msg.sender).transfer(amount);
        emit ProofVerified(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 2: Weak nullifier tracking
     */
    mapping(bytes32 => bool) public weakNullifiers;

    function verifyWithWeakNullifier(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        // VULNERABLE: Nullifier is user-provided, not derived from proof
        // Attacker can provide different nullifier for same proof
        require(!weakNullifiers[nullifier], "Nullifier used");

        require(_verify(proof, amount), "Invalid proof");

        weakNullifiers[nullifier] = true; // Weak protection!

        payable(msg.sender).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0; // Simplified
    }

    receive() external payable {}
}

/**
 * @title CrossContractReplay
 * @notice Cross-contract proof replay vulnerabilities
 */
contract VaultA {
    mapping(bytes32 => bool) public nullifiers;

    function withdraw(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        require(!nullifiers[nullifier], "Nullifier used");
        require(_verify(proof, amount), "Invalid proof");

        nullifiers[nullifier] = true;
        payable(msg.sender).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

contract VaultB {
    mapping(bytes32 => bool) public nullifiers;

    /**
     * @notice VULNERABILITY 3: Cross-contract replay
     * @dev Proof used in VaultA can be replayed in VaultB
     */
    function withdraw(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        // VULNERABLE: Each contract has separate nullifier tracking
        // Proof that was used in VaultA can be reused in VaultB
        // Missing: Global nullifier registry or contract-specific binding

        require(!nullifiers[nullifier], "Nullifier used");
        require(_verify(proof, amount), "Invalid proof");

        nullifiers[nullifier] = true;
        payable(msg.sender).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title CrossChainReplay
 * @notice Cross-chain proof replay
 */
contract CrossChainBridge {
    mapping(bytes32 => bool) public processedProofs;

    /**
     * @notice VULNERABILITY 4: Cross-chain replay
     * @dev Proof for Ethereum mainnet can be replayed on other EVM chains
     */
    function bridgeWithProof(
        uint256[8] calldata proof,
        uint256 amount,
        address recipient
    ) external {
        bytes32 proofHash = keccak256(abi.encode(proof, amount, recipient));

        require(!processedProofs[proofHash], "Proof already processed");

        // VULNERABLE: No chain ID binding in proof
        // Same proof valid on Ethereum can be replayed on:
        // - Polygon
        // - Arbitrum
        // - Optimism
        // - BSC
        // - Any EVM chain
        //
        // Missing: Chain ID must be part of public inputs in ZK circuit

        require(_verify(proof, amount), "Invalid proof");

        processedProofs[proofHash] = true;
        payable(recipient).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title TemporalReplay
 * @notice Time-based replay vulnerabilities
 */
contract TemporalReplayVault {
    mapping(bytes32 => uint256) public proofLastUsed;
    uint256 public constant COOLDOWN = 1 days;

    /**
     * @notice VULNERABILITY 5: Time-based replay allowed
     * @dev Proof can be reused after cooldown period
     */
    function withdrawWithCooldown(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        bytes32 proofHash = keccak256(abi.encode(proof));

        // VULNERABLE: Allows proof reuse after cooldown
        // Should be one-time-use only
        require(
            block.timestamp >= proofLastUsed[proofHash] + COOLDOWN,
            "Cooldown active"
        );

        require(_verify(proof, amount), "Invalid proof");

        // REPLAY ALLOWED: After cooldown, same proof can be reused!
        proofLastUsed[proofHash] = block.timestamp;

        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 6: Proof valid across epoch boundaries
     */
    uint256 public currentEpoch;
    mapping(uint256 => mapping(bytes32 => bool)) public epochNullifiers;

    function withdrawWithEpoch(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        // VULNERABLE: Only checks nullifier within current epoch
        // Proof can be replayed in next epoch
        require(!epochNullifiers[currentEpoch][nullifier], "Nullifier used");

        require(_verify(proof, amount), "Invalid proof");

        epochNullifiers[currentEpoch][nullifier] = true;

        // REPLAY POSSIBLE: Same proof valid in next epoch!

        payable(msg.sender).transfer(amount);
    }

    function advanceEpoch() external {
        currentEpoch++;
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title ProofMalleabilityVault
 * @notice Proof malleability attacks
 */
contract ProofMalleabilityVault {
    mapping(bytes32 => bool) public usedProofs;

    /**
     * @notice VULNERABILITY 7: ECDSA-style malleability
     * @dev Proof components can be modified while remaining valid
     */
    function withdrawMalleable(
        uint256[8] calldata proof,
        uint256 amount
    ) external {
        bytes32 proofHash = keccak256(abi.encode(proof));
        require(!usedProofs[proofHash], "Proof used");

        // VULNERABLE: Proof might be malleable
        // In ECDSA: (r,s) and (r, -s mod n) are both valid
        // In ZK: Similar malleability might exist in proof components

        // Example malleability:
        // If proof = [a, b, c, d, e, f, g, h]
        // Malleable version = [a, b, c, d, -e, -f, -g, -h] might also be valid

        require(_verify(proof, amount), "Invalid proof");

        usedProofs[proofHash] = true;

        // ATTACK: Attacker can create proof' from proof
        // proof' has different hash but is equally valid
        // Bypasses usedProofs check

        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 8: Commitment malleability
     */
    mapping(bytes32 => bool) public usedCommitments;

    function withdrawWithCommitment(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount
    ) external {
        require(!usedCommitments[commitment], "Commitment used");

        // VULNERABLE: Commitment might have multiple valid forms
        // Example: commitment and keccak256(commitment) might both be "valid"
        // or commitment * G and commitment * 2G might both work

        require(_verify(proof, amount), "Invalid proof");

        usedCommitments[commitment] = true;

        payable(msg.sender).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title NullifierBypass
 * @notice Nullifier bypass attacks
 */
contract NullifierBypassVault {
    mapping(bytes32 => bool) public usedNullifiers;

    /**
     * @notice VULNERABILITY 9: Nullifier collision
     * @dev Weak nullifier derivation allows collisions
     */
    function withdrawWithCollision(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier used");

        // VULNERABLE: Nullifier derivation might allow collisions
        // If nullifier = hash(secret), attacker might find secret' where
        // hash(secret') == hash(secret) due to weak hash or truncation

        require(_verify(proof, amount), "Invalid proof");

        usedNullifiers[nullifier] = true;

        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 10: Nullifier frontrunning
     */
    function withdrawWithFrontrun(
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint256 amount,
        address recipient
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier used");

        require(_verify(proof, amount), "Invalid proof");

        // VULNERABLE: Nullifier marked as used BEFORE transfer
        // But transfer hasn't completed yet
        usedNullifiers[nullifier] = true;

        // ATTACK: If this transaction fails/reverts, nullifier is still marked used
        // Legitimate user's funds are locked

        // Also vulnerable to frontrunning:
        // Attacker sees proof in mempool, extracts nullifier,
        // frontruns with same nullifier but different recipient

        payable(recipient).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title CommitmentReplay
 * @notice Commitment replay attacks
 */
contract CommitmentReplayVault {
    mapping(bytes32 => uint256) public commitmentDeposits;
    mapping(bytes32 => bool) public spentCommitments;

    /**
     * @notice VULNERABILITY 11: Commitment reuse across contracts
     */
    function deposit(bytes32 commitment) external payable {
        require(msg.value > 0, "No value");

        // VULNERABLE: Same commitment can be used in multiple contracts
        // No binding to specific contract address

        commitmentDeposits[commitment] += msg.value;
    }

    function withdraw(
        uint256[8] calldata proof,
        bytes32 commitment
    ) external {
        require(commitmentDeposits[commitment] > 0, "No deposit");
        require(!spentCommitments[commitment], "Already spent");

        // VULNERABLE: Proof for commitment in Contract A
        // can be replayed for same commitment in Contract B

        require(_verify(proof, commitment), "Invalid proof");

        uint256 amount = commitmentDeposits[commitment];
        spentCommitments[commitment] = true;

        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 12: Partial commitment spend
     */
    function withdrawPartial(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount
    ) external {
        require(commitmentDeposits[commitment] >= amount, "Insufficient");

        // VULNERABLE: Partial withdrawals without nullifier per withdrawal
        // Same proof can be used multiple times for different amounts

        require(_verify(proof, commitment), "Invalid proof");

        commitmentDeposits[commitment] -= amount;

        // MISSING: Unique nullifier for each withdrawal

        payable(msg.sender).transfer(amount);
    }

    function _verify(
        uint256[8] calldata proof,
        bytes32 commitment
    ) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title BatchReplayAttack
 * @notice Batch proof replay
 */
contract BatchReplayVault {
    mapping(bytes32 => bool) public batchProcessed;

    /**
     * @notice VULNERABILITY 13: Batch replay attack
     * @dev Entire batch can be replayed
     */
    function processBatch(
        uint256[][8] calldata proofs,
        bytes32[] calldata nullifiers,
        uint256[] calldata amounts
    ) external {
        require(
            proofs.length == nullifiers.length &&
            nullifiers.length == amounts.length,
            "Length mismatch"
        );

        bytes32 batchHash = keccak256(abi.encode(proofs, nullifiers, amounts));

        require(!batchProcessed[batchHash], "Batch already processed");

        // VULNERABLE: Individual nullifiers not checked
        // Only batch hash is tracked
        // If one nullifier in batch is already used, entire batch should fail

        for (uint256 i = 0; i < proofs.length; i++) {
            require(_verify(proofs[i], amounts[i]), "Invalid proof");
            // MISSING: Check individual nullifiers
        }

        batchProcessed[batchHash] = true;

        // Process withdrawals
        for (uint256 i = 0; i < amounts.length; i++) {
            payable(msg.sender).transfer(amounts[i]);
        }
    }

    /**
     * @notice VULNERABILITY 14: Batch reordering attack
     */
    mapping(bytes32 => bool) public nullifierUsed;

    function processBatchUnordered(
        uint256[][8] calldata proofs,
        bytes32[] calldata nullifiers,
        uint256[] calldata amounts
    ) external {
        // VULNERABLE: No check that nullifiers are in canonical order
        // Attacker can reorder proofs in batch to create new batch hash
        // Same nullifiers in different order = different batch hash

        bytes32 batchHash = keccak256(abi.encode(proofs, nullifiers, amounts));
        require(!batchProcessed[batchHash], "Batch processed");

        for (uint256 i = 0; i < nullifiers.length; i++) {
            // Check individual nullifiers
            require(!nullifierUsed[nullifiers[i]], "Nullifier used");
            nullifierUsed[nullifiers[i]] = true;
        }

        batchProcessed[batchHash] = true;

        // ATTACK: Same set of nullifiers reordered creates new batch
        // Can process same nullifiers multiple times in different batches
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}

/**
 * @title RecursiveProofReplay
 * @notice Recursive proof vulnerabilities
 */
contract RecursiveProofVault {
    mapping(bytes32 => bool) public proofUsed;

    /**
     * @notice VULNERABILITY 15: Recursive proof replay
     * @dev Inner proofs in recursive verification can be replayed
     */
    function verifyRecursive(
        uint256[8] calldata outerProof,
        uint256[8] calldata innerProof,
        uint256 amount
    ) external {
        bytes32 outerHash = keccak256(abi.encode(outerProof));
        require(!proofUsed[outerHash], "Outer proof used");

        // Verify outer proof (proves inner proof is valid)
        require(_verify(outerProof, amount), "Invalid outer proof");

        // VULNERABLE: Inner proof not tracked
        // Same inner proof can be used in multiple outer proofs

        proofUsed[outerHash] = true;

        // MISSING: Track inner proof hash
        // bytes32 innerHash = keccak256(abi.encode(innerProof));
        // require(!proofUsed[innerHash], "Inner proof used");

        payable(msg.sender).transfer(amount);
    }

    function _verify(uint256[8] calldata proof, uint256 amount) internal pure returns (bool) {
        return proof[0] != 0;
    }

    receive() external payable {}
}
