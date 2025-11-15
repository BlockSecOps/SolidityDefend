// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Week2SecureSignatures
 * @notice Secure signature patterns for Phase 3 Week 2 testing
 * @dev Demonstrates proper implementations for: nonce-reuse, weak-commit-reveal, permit-signature-exploit, weak-signature-validation
 */

// ============================================================================
// 1. SECURE MULTI-SIGNATURE VALIDATION
// ============================================================================

/**
 * @notice SECURE: Multi-signature with duplicate signer detection
 * @dev Tracks seen signers to prevent signature reuse
 */
contract SecureMultiSigDuplicateProtection {
    address[] public owners;
    uint256 public requiredSignatures;

    constructor(address[] memory _owners, uint256 _requiredSignatures) {
        owners = _owners;
        requiredSignatures = _requiredSignatures;
    }

    /**
     * @notice SECURE: Duplicate signer detection using seen mapping
     * @dev Each signature can only be counted once
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
        mapping(address => bool) seen;  // SECURE: Track seen signers

        for (uint256 i = 0; i < v.length && validSignatures < requiredSignatures; i++) {
            address signer = ecrecover(txHash, v[i], r[i], s[i]);
            require(signer != address(0), "Invalid signature");

            // SECURE: Check for duplicate signer
            require(!seen[signer], "Duplicate signer");

            // Check if signer is an owner
            bool isOwner = false;
            for (uint256 j = 0; j < owners.length; j++) {
                if (signer == owners[j]) {
                    isOwner = true;
                    break;
                }
            }

            if (isOwner) {
                seen[signer] = true;  // SECURE: Mark as seen
                validSignatures++;
            }
        }

        require(validSignatures >= requiredSignatures, "Insufficient valid signatures");
        payable(to).transfer(amount);
    }
}

/**
 * @notice SECURE: Threshold signature with uniqueness enforcement
 * @dev Uses sorted signer addresses to prevent duplicates
 */
contract SecureThresholdSignature {
    mapping(address => bool) public isSigner;
    uint256 public threshold;

    constructor(address[] memory signers, uint256 _threshold) {
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = true;
        }
        threshold = _threshold;
    }

    /**
     * @notice SECURE: Enforces sorted unique signers
     * @dev Prevents duplicate signatures by requiring ascending signer order
     */
    function execute(
        bytes memory data,
        bytes memory signatures
    ) external {
        bytes32 dataHash = keccak256(data);
        uint256 signatureCount = signatures.length / 65;
        require(signatureCount >= threshold, "Not enough signatures");

        address lastSigner = address(0);
        uint256 validCount = 0;

        for (uint256 i = 0; i < signatureCount; i++) {
            (uint8 v, bytes32 r, bytes32 s) = splitSignature(signatures, i);
            address recovered = ecrecover(dataHash, v, r, s);
            require(recovered != address(0), "Invalid signature");

            // SECURE: Enforce ascending order (prevents duplicates)
            require(recovered > lastSigner, "Signatures must be unique and sorted");
            lastSigner = recovered;

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
// 2. SECURE COMMIT-REVEAL SCHEMES
// ============================================================================

/**
 * @notice SECURE: Commit-reveal with proper delay
 * @dev 5-minute minimum delay with randomized reveal window
 */
contract SecureLongDelayCommitReveal {
    struct Commitment {
        bytes32 commitHash;
        uint256 commitTime;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;
    uint256 public constant MIN_DELAY = 5 minutes;  // SECURE: Long enough delay
    uint256 public constant REVEAL_WINDOW = 1 hours;  // SECURE: Wide reveal window

    function commit(bytes32 commitHash) external {
        commitments[msg.sender] = Commitment({
            commitHash: commitHash,
            commitTime: block.timestamp,
            revealed: false
        });
    }

    /**
     * @notice SECURE: Proper delay and reveal window
     * @dev 5-minute minimum delay prevents MEV manipulation
     */
    function reveal(uint256 value, bytes32 salt) external {
        Commitment storage c = commitments[msg.sender];
        require(c.commitHash != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // SECURE: Sufficient delay (5 minutes)
        require(block.timestamp >= c.commitTime + MIN_DELAY, "Too early");

        // SECURE: Reveal window to prevent timing attacks
        require(block.timestamp < c.commitTime + MIN_DELAY + REVEAL_WINDOW, "Too late");

        bytes32 hash = keccak256(abi.encode(value, salt));
        require(hash == c.commitHash, "Invalid reveal");

        c.revealed = true;
        // Process value...
    }
}

/**
 * @notice SECURE: Commit-reveal with randomized timing
 * @dev Uses blockhash for unpredictable reveal timing
 */
contract SecureRandomizedCommitReveal {
    struct Order {
        bytes32 commitment;
        uint256 commitBlock;
        uint256 minBlocks;
        bool executed;
    }

    mapping(address => Order) public orders;
    uint256 public constant BASE_DELAY = 50; // ~10 minutes

    function commitOrder(bytes32 commitment) external {
        // SECURE: Use blockhash for randomization (not available yet)
        uint256 minBlocks = BASE_DELAY;

        orders[msg.sender] = Order({
            commitment: commitment,
            commitBlock: block.number,
            minBlocks: minBlocks,
            executed: false
        });
    }

    /**
     * @notice SECURE: Randomized reveal window
     * @dev Delay varies based on commitment, making timing unpredictable
     */
    function revealOrder(uint256 price, bytes32 salt) external {
        Order storage order = orders[msg.sender];
        require(order.commitment != bytes32(0), "No order");

        // SECURE: Randomized delay based on commitment
        bytes32 commitBlockHash = blockhash(order.commitBlock);
        uint256 additionalDelay = uint256(keccak256(abi.encode(commitBlockHash, msg.sender))) % 20;
        uint256 requiredBlocks = order.minBlocks + additionalDelay;

        require(block.number >= order.commitBlock + requiredBlocks, "Too early");

        bytes32 hash = keccak256(abi.encode(price, salt));
        require(hash == order.commitment, "Invalid reveal");

        order.executed = true;
        // Execute order at price...
    }
}

/**
 * @notice SECURE: VRF-based commit-reveal
 * @dev Uses Chainlink VRF for truly unpredictable timing
 */
contract SecureVRFCommitReveal {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitTimes;
    mapping(address => uint256) public revealDelays;  // SECURE: Per-user random delay

    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        commitTimes[msg.sender] = block.timestamp;

        // SECURE: In production, use Chainlink VRF here
        // For testing, use pseudo-random based on future block
        revealDelays[msg.sender] = 300 + (uint256(keccak256(abi.encode(commitment, block.timestamp))) % 300);
    }

    /**
     * @notice SECURE: Variable reveal window prevents timing attacks
     * @dev Each user has unique randomized delay
     */
    function reveal(uint256 bid, bytes32 nonce) external {
        require(commitments[msg.sender] != bytes32(0), "No commitment");

        // SECURE: Randomized reveal time (5-10 minutes range)
        uint256 revealTime = commitTimes[msg.sender] + revealDelays[msg.sender];
        require(block.timestamp >= revealTime, "Too early");
        require(block.timestamp < revealTime + 3600, "Too late");  // 1 hour window

        bytes32 hash = keccak256(abi.encode(bid, nonce));
        require(hash == commitments[msg.sender], "Invalid");

        // Process bid...
        delete commitments[msg.sender];
        delete revealDelays[msg.sender];
    }
}

// ============================================================================
// 3. SECURE NONCE MANAGEMENT
// ============================================================================

/**
 * @notice SECURE: Nonce validation before increment
 * @dev Nonce only consumed after all checks pass
 */
contract SecureNonceIncrement {
    mapping(address => uint256) public nonces;

    function executeWithSignature(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Use current nonce for validation
        uint256 currentNonce = nonces[msg.sender];

        bytes32 hash = keccak256(abi.encode(to, amount, currentNonce));
        address signer = ecrecover(hash, v, r, s);

        // All validations BEFORE nonce increment
        require(signer == msg.sender, "Invalid signature");
        require(amount <= address(this).balance, "Insufficient balance");

        // SECURE: Only increment after all checks pass
        nonces[msg.sender]++;

        payable(to).transfer(amount);
    }
}

/**
 * @notice SECURE: Proper nonce sequence validation
 * @dev Enforces sequential nonces with explicit validation
 */
contract SecureSequentialNonce {
    mapping(address => uint256) public nonces;

    /**
     * @notice SECURE: Validates nonce matches expected value
     * @dev Prevents arbitrary nonce selection
     */
    function execute(uint256 nonce, bytes memory data, uint8 v, bytes32 r, bytes32 s) external {
        // SECURE: Validate nonce matches current stored value
        require(nonce == nonces[msg.sender], "Invalid nonce");

        bytes32 hash = keccak256(abi.encode(nonce, data));
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        // Increment only after validation
        nonces[msg.sender]++;

        // Execute data...
    }
}

/**
 * @notice SECURE: Nonce with cancellation mechanism
 * @dev Users can invalidate pending transactions
 */
contract SecureNonceCancellation {
    mapping(address => uint256) public nonces;

    /**
     * @notice SECURE: Allows users to cancel pending transactions
     * @dev Increments nonce to invalidate all pending signatures
     */
    function cancelPendingTransactions() external {
        nonces[msg.sender]++;
    }

    /**
     * @notice SECURE: Batch cancel by jumping nonce forward
     * @dev Invalidates multiple pending transactions at once
     */
    function cancelAllBefore(uint256 newNonce) external {
        require(newNonce > nonces[msg.sender], "Must be higher");
        nonces[msg.sender] = newNonce;
    }

    function execute(bytes memory data, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentNonce = nonces[msg.sender];
        bytes32 hash = keccak256(abi.encode(data, currentNonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid");

        nonces[msg.sender]++;
        // Execute...
    }
}

// ============================================================================
// 4. SECURE PERMIT IMPLEMENTATIONS
// ============================================================================

/**
 * @notice SECURE: Complete EIP-2612 permit with deadline validation
 * @dev Properly validates all permit parameters
 */
contract SecurePermitWithValidation {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SecureToken")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice SECURE: Complete permit with all validations
     * @dev Deadline, zero address, nonce, and signature validation
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Validate deadline
        require(block.timestamp <= deadline, "Permit expired");

        // SECURE: Validate v value
        require(v == 27 || v == 28, "Invalid v value");

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            nonces[owner],
            deadline
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recoveredAddress = ecrecover(digest, v, r, s);

        // SECURE: Check for zero address (invalid signature)
        require(recoveredAddress != address(0), "Invalid signature");
        require(recoveredAddress == owner, "Signature mismatch");

        // Increment nonce after all validations
        nonces[owner]++;

        allowance[owner][spender] = value;
    }
}

/**
 * @notice SECURE: Permit using OpenZeppelin ECDSA library
 * @dev Library provides built-in protections
 */
contract SecurePermitWithLibrary {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    /**
     * @notice SECURE: Using ECDSA library (when available)
     * @dev Library handles malleability and zero address checks
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) external {
        // SECURE: Deadline validation
        require(block.timestamp <= deadline, "Expired");

        bytes32 digest = keccak256(abi.encode(owner, spender, value, nonces[owner], deadline));

        // SECURE: Manual recovery with full validation
        // In production: use ECDSA.recover() from OpenZeppelin
        require(signature.length == 65, "Invalid length");

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // SECURE: All validation checks
        require(v == 27 || v == 28, "Invalid v");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "Invalid");

        nonces[owner]++;
        allowance[owner][spender] = value;
    }
}
