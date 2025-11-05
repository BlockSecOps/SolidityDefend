// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UnderconstrainedCircuits
 * @notice Zero-Knowledge Proof Under-Constrained Circuit Vulnerabilities
 *
 * VULNERABILITY: Under-constrained circuits in ZK systems
 * CATEGORY: Zero-Knowledge Proof Security
 *
 * BACKGROUND:
 * Under-constrained circuits are one of the most common and dangerous vulnerabilities
 * in zero-knowledge proof systems. They occur when the circuit constraints don't
 * fully enforce the intended logic, allowing invalid proofs to be accepted.
 *
 * COMMON UNDER-CONSTRAINED PATTERNS:
 * 1. Missing range checks (allows out-of-range values)
 * 2. Unconstrained intermediate values
 * 3. Missing uniqueness constraints
 * 4. Weak equality checks
 * 5. Unconstrained public inputs
 * 6. Missing non-zero constraints
 *
 * REAL-WORLD EXAMPLES:
 * - Zcash Counterfeiting Bug (under-constrained value commitment)
 * - Multiple zkSNARK bridge exploits
 * - Various DeFi ZK protocol vulnerabilities
 *
 * TESTED DETECTORS:
 * - zk-underconstrained-circuit
 * - zk-missing-range-check
 * - zk-unconstrained-input
 * - zk-weak-constraint
 */

/**
 * @title SimpleZKVerifier
 * @notice Simplified ZK verifier demonstrating under-constrained vulnerabilities
 */
contract SimpleZKVerifier {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic;
    }

    VerifyingKey public vk;

    /**
     * @notice VULNERABILITY 1: Missing range check on public inputs
     * @dev Public inputs should be validated to be in field range
     */
    function verifyProof(
        Proof memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        // VULNERABLE: No validation that publicInputs are in field range
        // Attacker can provide inputs >= field_modulus
        // This can lead to proof forgery

        // Example: If field modulus is p, input should be < p
        // Missing: require(publicInputs[i] < FIELD_MODULUS, "Input out of range");

        return _verify(proof, publicInputs);
    }

    /**
     * @notice VULNERABILITY 2: Unconstrained intermediate computation
     * @dev Intermediate values not validated
     */
    function verifyWithIntermediate(
        Proof memory proof,
        uint256[] memory publicInputs,
        uint256 intermediate
    ) public view returns (bool) {
        // VULNERABLE: 'intermediate' value is not constrained
        // In a real ZK circuit, this would be computed inside the circuit
        // but not properly constrained, allowing arbitrary values

        // Missing: Constraint that intermediate = f(publicInputs)
        return _verify(proof, publicInputs);
    }

    /**
     * @notice Simplified verification (placeholder)
     */
    function _verify(
        Proof memory proof,
        uint256[] memory inputs
    ) internal view returns (bool) {
        // Simplified verification logic
        // In real implementation, would do pairing checks
        return true; // Placeholder
    }
}

/**
 * @title ZKBridge
 * @notice ZK bridge with under-constrained deposit/withdraw
 */
contract ZKBridge {
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(uint256 => bool) public processedDeposits;

    uint256 public totalDeposits;
    uint256 public constant MAX_AMOUNT = 1000 ether;

    event Deposit(address indexed depositor, uint256 amount, uint256 depositId);
    event Withdrawal(address indexed recipient, uint256 amount, bytes32 nullifier);

    /**
     * @notice VULNERABILITY 3: Missing uniqueness constraint on deposits
     * @dev depositId not properly constrained to be unique
     */
    function deposit(uint256 amount, uint256 depositId) external payable {
        require(msg.value == amount, "Incorrect amount");
        require(amount <= MAX_AMOUNT, "Amount too large");

        // VULNERABLE: No proof that depositId is unique or properly derived
        // In ZK circuit, depositId should be constrained to hash(depositor, amount, nonce)
        // Missing constraint allows same depositId to be reused

        require(!processedDeposits[depositId], "Deposit already processed");
        processedDeposits[depositId] = true;

        totalDeposits += amount;
        emit Deposit(msg.sender, amount, depositId);
    }

    /**
     * @notice VULNERABILITY 4: Unconstrained nullifier derivation
     * @dev Nullifier should be derived from deposit commitment, but isn't constrained
     */
    function withdraw(
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        uint256[8] calldata proof
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(amount <= MAX_AMOUNT, "Amount too large");

        // VULNERABLE: No constraint that nullifier = hash(secret, depositId)
        // Attacker can provide arbitrary nullifier
        // Missing: ZK proof that nullifier is correctly derived

        // In proper implementation, would verify ZK proof that:
        // 1. nullifier = hash(secret, depositId)
        // 2. commitment = hash(secret, amount)
        // 3. commitment was included in deposits
        // 4. secret is known

        usedNullifiers[nullifier] = true;

        require(address(this).balance >= amount, "Insufficient balance");
        payable(recipient).transfer(amount);

        emit Withdrawal(recipient, amount, nullifier);
    }

    /**
     * @notice VULNERABILITY 5: Missing amount validation in circuit
     * @dev Amount should be constrained to match deposit
     */
    function withdrawWithAmount(
        bytes32 nullifier,
        uint256 depositAmount,
        uint256 withdrawAmount,
        uint256[8] calldata proof
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier already used");

        // VULNERABLE: No constraint that withdrawAmount <= depositAmount
        // In ZK circuit, should constrain withdrawAmount to match original deposit
        // Missing: require(withdrawAmount <= depositAmount) in circuit

        usedNullifiers[nullifier] = true;
        payable(msg.sender).transfer(withdrawAmount);
    }

    receive() external payable {}
}

/**
 * @title ZKRollup
 * @notice ZK Rollup with state transition vulnerabilities
 */
contract ZKRollup {
    uint256 public stateRoot;
    uint256 public batchNumber;

    struct BatchHeader {
        uint256 batchId;
        uint256 prevStateRoot;
        uint256 newStateRoot;
        uint256 numTransactions;
    }

    event BatchSubmitted(uint256 indexed batchId, uint256 newStateRoot);

    /**
     * @notice VULNERABILITY 6: Unconstrained state root transition
     * @dev New state root not properly constrained to old state root
     */
    function submitBatch(
        BatchHeader calldata header,
        uint256[8] calldata proof
    ) external {
        require(header.batchId == batchNumber + 1, "Invalid batch ID");

        // VULNERABLE: No constraint that newStateRoot is correctly computed from prevStateRoot
        // In ZK circuit, should constrain:
        // newStateRoot = applyTransactions(prevStateRoot, transactions)
        // Missing: Proper state transition constraint

        // Current implementation just accepts any state root with valid proof format
        require(header.prevStateRoot == stateRoot, "Invalid previous state root");

        // Missing: Verify that proof constrains state transition properly
        stateRoot = header.newStateRoot;
        batchNumber = header.batchId;

        emit BatchSubmitted(header.batchId, header.newStateRoot);
    }

    /**
     * @notice VULNERABILITY 7: Missing balance constraint
     * @dev Total balance not constrained in state transition
     */
    function submitBatchWithBalance(
        uint256 prevBalance,
        uint256 newBalance,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: No constraint that sum(newBalances) == sum(prevBalances)
        // Can inflate total balance without constraint
        // Missing: Conservation of balance constraint in circuit

        // Should have circuit constraint:
        // sum(state[i].balance for i in old_state) == sum(state[j].balance for j in new_state)
    }

    /**
     * @notice VULNERABILITY 8: Unconstrained transaction validity
     * @dev Individual transactions not fully validated
     */
    function verifyTransaction(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256[8] calldata proof
    ) external pure returns (bool) {
        // VULNERABLE: Missing constraints:
        // 1. from has sufficient balance
        // 2. nonce is correct
        // 3. signature is valid
        // 4. amount is non-negative

        // Circuit should constrain all of these, but might miss some
        return true; // Placeholder
    }
}

/**
 * @title ZKPrivacyPool
 * @notice Privacy pool with membership proof vulnerabilities
 */
contract ZKPrivacyPool {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedNullifiers;

    uint256 public constant DENOMINATION = 1 ether;

    event Deposit(bytes32 indexed commitment, uint256 leafIndex);
    event Withdrawal(bytes32 nullifier, address recipient);

    /**
     * @notice VULNERABILITY 9: Weak merkle proof constraint
     * @dev Merkle proof not fully constrained
     */
    function withdraw(
        bytes32 nullifier,
        bytes32 commitment,
        uint256[8] calldata proof,
        bytes32[] calldata merklePath
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier used");

        // VULNERABLE: Merkle proof verification under-constrained
        // Circuit should constrain:
        // 1. commitment is in merkle tree at specified index
        // 2. merkleRoot matches contract's merkleRoot
        // 3. Path is correctly computed

        // Missing constraints might allow:
        // - Using commitment not in tree
        // - Proof against wrong root
        // - Invalid path computation

        usedNullifiers[nullifier] = true;
        payable(msg.sender).transfer(DENOMINATION);

        emit Withdrawal(nullifier, msg.sender);
    }

    /**
     * @notice VULNERABILITY 10: Missing non-membership constraint
     * @dev Should prove nullifier not in used set, but doesn't
     */
    function withdrawWithNonMembership(
        bytes32 nullifier,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: Circuit should prove nullifier NOT in usedNullifiers
        // but constraint might be missing or weak
        // This is hard to implement correctly in ZK

        require(!usedNullifiers[nullifier], "Nullifier used");
        usedNullifiers[nullifier] = true;

        payable(msg.sender).transfer(DENOMINATION);
    }

    /**
     * @notice VULNERABILITY 11: Unconstrained nullifier uniqueness
     */
    function multiWithdraw(
        bytes32[] calldata nullifiers,
        uint256[][8] calldata proofs
    ) external {
        // VULNERABLE: No constraint that all nullifiers are distinct
        // Attacker could provide same nullifier twice in array
        // Circuit should constrain nullifiers[i] != nullifiers[j] for all i != j

        for (uint256 i = 0; i < nullifiers.length; i++) {
            require(!usedNullifiers[nullifiers[i]], "Nullifier used");
            usedNullifiers[nullifiers[i]] = true;
        }

        payable(msg.sender).transfer(DENOMINATION * nullifiers.length);
    }

    function deposit(bytes32 commitment) external payable {
        require(msg.value == DENOMINATION, "Incorrect denomination");
        emit Deposit(commitment, 0); // Simplified
    }

    receive() external payable {}
}

/**
 * @title ZKVoting
 * @notice ZK voting with constraint vulnerabilities
 */
contract ZKVoting {
    uint256 public yesVotes;
    uint256 public noVotes;

    mapping(bytes32 => bool) public hasVoted;

    /**
     * @notice VULNERABILITY 12: Missing vote validity constraint
     * @dev Vote value not constrained to 0 or 1
     */
    function vote(
        bytes32 voterId,
        bool voteValue,
        uint256[8] calldata proof
    ) external {
        require(!hasVoted[voterId], "Already voted");

        // VULNERABLE: In ZK circuit, voteValue should be constrained to {0, 1}
        // Missing: constraint that voteValue * (1 - voteValue) == 0
        // This allows fractional votes or values > 1

        hasVoted[voterId] = true;

        if (voteValue) {
            yesVotes += 1;
        } else {
            noVotes += 1;
        }
    }

    /**
     * @notice VULNERABILITY 13: Unconstrained voter eligibility
     */
    function voteWithEligibility(
        bytes32 voterId,
        uint256 eligibilityScore,
        bool voteValue,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: eligibilityScore not constrained to valid range
        // Circuit should prove eligibilityScore >= THRESHOLD
        // but might not constrain eligibilityScore to be non-negative
        // or in valid range

        require(eligibilityScore >= 100, "Not eligible");
        require(!hasVoted[voterId], "Already voted");

        hasVoted[voterId] = true;

        if (voteValue) {
            yesVotes += 1;
        } else {
            noVotes += 1;
        }
    }

    /**
     * @notice VULNERABILITY 14: Missing weight constraint
     */
    function weightedVote(
        bytes32 voterId,
        uint256 weight,
        bool voteValue,
        uint256[8] calldata proof
    ) external {
        require(!hasVoted[voterId], "Already voted");

        // VULNERABLE: weight not constrained
        // Circuit should constrain weight to match voter's actual voting power
        // Missing: weight == getVotingPower(voterId) constraint

        hasVoted[voterId] = true;

        if (voteValue) {
            yesVotes += weight;
        } else {
            noVotes += weight;
        }
    }
}

/**
 * @title ZKIdentity
 * @notice ZK identity verification with under-constrained proofs
 */
contract ZKIdentity {
    mapping(bytes32 => bool) public verifiedIdentities;

    /**
     * @notice VULNERABILITY 15: Missing attribute constraints
     * @dev Identity attributes not fully constrained
     */
    function verifyIdentity(
        bytes32 identityCommitment,
        uint256 age,
        uint256 country,
        uint256[8] calldata proof
    ) external {
        // VULNERABLE: Circuit should constrain:
        // 1. age is in valid range (0-150)
        // 2. country is in valid set
        // 3. attributes match commitment
        //
        // Missing constraints allow:
        // - Negative age
        // - Invalid country code
        // - Attributes not matching commitment

        require(age >= 18, "Underage");

        verifiedIdentities[identityCommitment] = true;
    }

    /**
     * @notice VULNERABILITY 16: Weak uniqueness constraint
     */
    function proveUniqueness(
        bytes32 commitment1,
        bytes32 commitment2,
        uint256[8] calldata proof
    ) external pure returns (bool) {
        // VULNERABLE: Circuit should prove commitment1 != commitment2
        // but might have weak constraint that allows collision
        // or doesn't fully constrain both commitments

        return commitment1 != commitment2; // Should be proven in circuit
    }
}
