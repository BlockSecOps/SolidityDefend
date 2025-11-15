// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Week2VulnerableSignatures
 * @notice Additional vulnerable signature patterns for Phase 3 Week 2 testing
 * @dev Tests for: nonce-reuse, weak-commit-reveal, permit-signature-exploit, weak-signature-validation
 */

// ============================================================================
// 1. WEAK MULTI-SIGNATURE VALIDATION
// ============================================================================

/**
 * @notice VULNERABLE: Multi-signature without duplicate signer check
 * @dev Attacker can submit same signature multiple times to meet threshold
 */
contract VulnerableMultiSigDuplicateSigners {
    address[] public owners;
    uint256 public requiredSignatures;

    constructor(address[] memory _owners, uint256 _requiredSignatures) {
        owners = _owners;
        requiredSignatures = _requiredSignatures;
    }

    /**
     * @notice VULNERABILITY: No duplicate signer detection
     * @dev Same signature can be counted multiple times towards threshold
     */
    function executeWithMultiSig(
        address to,
        uint256 amount,
        bytes32 txHash,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external {
        require(v.length >= requiredSignatures, "Not enough signatures");

        uint256 validSignatures = 0;

        // VULNERABLE: No tracking of seen signers
        for (uint256 i = 0; i < v.length && validSignatures < requiredSignatures; i++) {
            address signer = ecrecover(txHash, v[i], r[i], s[i]);

            // Check if signer is an owner
            for (uint256 j = 0; j < owners.length; j++) {
                if (signer == owners[j]) {
                    validSignatures++;
                    break;  // VULNERABLE: Doesn't prevent using same signer again
                }
            }
        }

        require(validSignatures >= requiredSignatures, "Insufficient valid signatures");
        payable(to).transfer(amount);
    }
}

/**
 * @notice VULNERABLE: M-of-N multisig allowing signature reuse
 * @dev Classic vulnerability where 1 valid signature can be submitted M times
 */
contract VulnerableThresholdSignature {
    mapping(address => bool) public isSigner;
    uint256 public threshold;  // M of N

    constructor(address[] memory signers, uint256 _threshold) {
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = true;
        }
        threshold = _threshold;
    }

    /**
     * @notice VULNERABILITY: Counts signatures without uniqueness check
     * @dev Attacker can provide same (v,r,s) multiple times
     */
    function execute(
        bytes memory data,
        bytes memory signatures
    ) external {
        bytes32 dataHash = keccak256(data);
        uint256 signatureCount = signatures.length / 65;
        require(signatureCount >= threshold, "Not enough signatures");

        uint256 validCount = 0;

        // VULNERABLE: No duplicate detection
        for (uint256 i = 0; i < signatureCount; i++) {
            (uint8 v, bytes32 r, bytes32 s) = splitSignature(signatures, i);
            address recovered = ecrecover(dataHash, v, r, s);

            if (isSigner[recovered]) {
                validCount++;
            }
        }

        require(validCount >= threshold, "Invalid signatures");
        // Execute transaction...
    }

    function splitSignature(bytes memory sig, uint256 index)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        uint256 offset = index * 65;
        assembly {
            r := mload(add(sig, add(offset, 32)))
            s := mload(add(sig, add(offset, 64)))
            v := byte(0, mload(add(sig, add(offset, 65))))
        }
    }
}

// ============================================================================
// 2. WEAK COMMIT-REVEAL SCHEMES
// ============================================================================

/**
 * @notice VULNERABLE: Commit-reveal with too short delay
 * @dev 1 block delay allows MEV bots to front-run reveals
 */
contract VulnerableShortDelayCommitReveal {
    struct Commitment {
        bytes32 commitHash;
        uint256 commitBlock;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;

    /**
     * @notice Commit to a value
     */
    function commit(bytes32 commitHash) external {
        commitments[msg.sender] = Commitment({
            commitHash: commitHash,
            commitBlock: block.number,
            revealed: false
        });
    }

    /**
     * @notice VULNERABILITY: Delay is too short and predictable
     * @dev Only 1 block delay - MEV bots can time reveals
     */
    function reveal(uint256 value, bytes32 salt) external {
        Commitment storage c = commitments[msg.sender];
        require(c.commitHash != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // VULNERABILITY: Commit-reveal delay is too short and predictable (only 1 block)
        require(block.number > c.commitBlock, "Too early");

        bytes32 hash = keccak256(abi.encode(value, salt));
        require(hash == c.commitHash, "Invalid reveal");

        c.revealed = true;
        // Process value...
    }
}

/**
 * @notice VULNERABLE: Commit-reveal with predictable timing
 * @dev Fixed delay allows MEV extraction
 */
contract VulnerablePredictableCommitReveal {
    struct Order {
        bytes32 commitment;
        uint256 commitTimestamp;
        bool executed;
    }

    mapping(address => Order) public orders;

    function commitOrder(bytes32 commitment) external {
        orders[msg.sender] = Order({
            commitment: commitment,
            commitTimestamp: block.timestamp,
            executed: false
        });
    }

    /**
     * @notice VULNERABILITY: Commit-reveal delay too short (5 seconds) and predictable
     * @dev Miners can manipulate block.timestamp within ~15 second range
     */
    function revealOrder(uint256 price, bytes32 salt) external {
        Order storage order = orders[msg.sender];
        require(order.commitment != bytes32(0), "No order");

        // VULNERABILITY: Commit-reveal delay is too short (5 seconds) and predictable timing
        require(block.timestamp >= order.commitTimestamp + 5, "Too early");

        bytes32 hash = keccak256(abi.encode(price, salt));
        require(hash == order.commitment, "Invalid reveal");

        order.executed = true;
        // Execute order at price...
    }
}

/**
 * @notice VULNERABLE: No randomization in reveal window
 * @dev Predictable reveal window enables MEV attacks
 */
contract VulnerableNoRandomizationCommitReveal {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitTimes;

    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        commitTimes[msg.sender] = block.timestamp;
    }

    /**
     * @notice VULNERABILITY: Fixed reveal window (no randomization)
     * @dev MEV bots can monitor commitments and time their reveals
     */
    function reveal(uint256 bid, bytes32 nonce) external {
        require(commitments[msg.sender] != bytes32(0), "No commitment");

        // VULNERABILITY: Commit-reveal delay is too short (60 seconds) and predictable
        uint256 revealTime = commitTimes[msg.sender] + 60; // Always 60 seconds
        require(block.timestamp >= revealTime, "Too early");
        require(block.timestamp < revealTime + 300, "Too late");

        bytes32 hash = keccak256(abi.encode(bid, nonce));
        require(hash == commitments[msg.sender], "Invalid");

        // Process bid...
        delete commitments[msg.sender];
    }
}

// ============================================================================
// 3. ADVANCED NONCE-REUSE VULNERABILITIES
// ============================================================================

/**
 * @notice VULNERABLE: Nonce incremented before all validations
 * @dev Nonce consumed even when transaction fails
 */
contract VulnerableEarlyNonceIncrement {
    mapping(address => uint256) public nonces;

    function executeWithSignature(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABILITY: Nonce incremented before validation
        uint256 nonce = nonces[msg.sender]++;

        bytes32 hash = keccak256(abi.encode(to, amount, nonce));
        address signer = ecrecover(hash, v, r, s);

        // If this fails, nonce is already consumed
        require(signer == msg.sender, "Invalid signature");
        require(amount <= address(this).balance, "Insufficient balance");

        payable(to).transfer(amount);
    }
}

/**
 * @notice VULNERABLE: Nonce used for randomness
 * @dev Predictable nonces make poor randomness source
 */
contract VulnerableNonceRandomness {
    mapping(address => uint256) public nonces;

    function playGame(uint256 userGuess, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[msg.sender]++;

        bytes32 hash = keccak256(abi.encode(userGuess, nonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        // VULNERABILITY: Nonce used for randomness (predictable!)
        uint256 randomNumber = uint256(keccak256(abi.encode(nonce, block.timestamp))) % 100;

        if (randomNumber == userGuess) {
            // User wins...
        }
    }
}

/**
 * @notice VULNERABLE: Nonce parameter without validation
 * @dev Accepts arbitrary nonce values
 */
contract VulnerableArbitraryNonce {
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    /**
     * @notice VULNERABILITY: Accepts any nonce, no sequential requirement
     * @dev Users can cherry-pick nonces, enabling complex replay scenarios
     */
    function execute(uint256 nonce, bytes memory data, uint8 v, bytes32 r, bytes32 s) external {
        // VULNERABILITY: No validation that nonce follows any sequence
        require(!usedNonces[msg.sender][nonce], "Nonce used");

        bytes32 hash = keccak256(abi.encode(nonce, data));
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        usedNonces[msg.sender][nonce] = true;
        // Execute data...
    }
}

// ============================================================================
// 4. ADVANCED PERMIT VULNERABILITIES
// ============================================================================

/**
 * @notice VULNERABLE: Permit with no deadline validation
 * @dev Expired signatures are still accepted
 */
contract VulnerablePermitNoDeadlineValidation {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    /**
     * @notice VULNERABILITY: Deadline parameter exists but never validated
     * @dev Old signatures can be used indefinitely
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,  // ← Deadline parameter present
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABILITY: deadline exists but is never checked!
        // require(block.timestamp <= deadline, "Expired"); // ← Missing!

        bytes32 digest = keccak256(abi.encode(owner, spender, value, nonces[owner]++, deadline));
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == owner, "Invalid signature");

        allowance[owner][spender] = value;
    }
}

/**
 * @notice VULNERABLE: Permit without zero address check
 * @dev Invalid ecrecover returns address(0), which passes require
 */
contract VulnerablePermitNoZeroCheck {
    mapping(address => mapping(address => uint256)) public allowance;

    /**
     * @notice VULNERABILITY: No zero address validation on ecrecover
     * @dev Invalid signature returns address(0), which might pass checks
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(owner, spender, value));
        address recoveredAddress = ecrecover(digest, v, r, s);

        // VULNERABILITY: No check for address(0)
        // require(recoveredAddress != address(0), "Invalid signature"); // ← Missing!
        require(recoveredAddress == owner, "Invalid signature");

        allowance[owner][spender] = value;
    }
}
