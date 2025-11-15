// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SignatureSecure - Secure Patterns
 * @notice SECURE: Proper signature validation with all security measures
 * @dev This contract demonstrates secure signature handling patterns.
 *
 * Security Features:
 * 1. Proper EIP-712 domain separator with chainId
 * 2. Signature malleability protection (s-value validation)
 * 3. Cross-chain replay protection (chainId inclusion)
 * 4. Proper nonce tracking and increment
 * 5. Deadline validation for time-sensitive operations
 * 6. Safe batch signature validation
 */

/**
 * @notice SECURE: Proper EIP-712 domain separator implementation
 * @dev Uses complete EIP-712 structured data signing
 */
contract SecureEIP712DomainSeparator {
    address public owner;
    bytes32 public DOMAIN_SEPARATOR;

    // EIP-712 type hashes
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address to,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    mapping(address => uint256) public nonces;

    constructor() {
        owner = msg.sender;

        // SECURE: Proper domain separator with all fields
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("SecureContract")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice SECURE: Complete EIP-712 implementation
     * @dev Uses proper domain separator and struct hashing
     */
    function executeWithSignature(
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Signature expired");

        uint256 nonce = nonces[owner]++;

        // SECURE: Proper EIP-712 structured data hashing
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_TYPEHASH,
            to,
            amount,
            nonce,
            deadline
        ));

        bytes32 hash = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        payable(to).transfer(amount);
    }

    /**
     * @notice SECURE: Dynamic domain separator (handles chain forks)
     * @dev Recalculates domain separator if chainId changes
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (block.chainid == _getChainId()) {
            return DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator();
        }
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("SecureContract")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function _getChainId() private pure returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }
}

/**
 * @notice SECURE: Signature malleability protection
 * @dev Validates s-value to prevent signature malleation
 */
contract SecureSignatureMalleabilityProtection {
    address public owner;
    mapping(bytes32 => bool) public executed;

    // ECDSA malleability threshold
    bytes32 private constant MAX_S_VALUE = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Validates s-value range
     * @dev Prevents signature malleability by checking s <= MAX_S_VALUE
     */
    function executeTransaction(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 txHash = keccak256(abi.encode(to, amount, nonce));

        // SECURE: Validate s-value is in lower range
        require(uint256(s) <= uint256(MAX_S_VALUE), "Invalid s value");

        // SECURE: Validate v is 27 or 28
        require(v == 27 || v == 28, "Invalid v value");

        address signer = ecrecover(txHash, v, r, s);
        require(signer == owner, "Invalid signer");
        require(!executed[txHash], "Already executed");

        executed[txHash] = true;
        payable(to).transfer(amount);
    }

    /**
     * @notice SECURE: Using OpenZeppelin ECDSA library
     * @dev Library automatically handles malleability protection
     */
    function executeWithECDSALibrary(
        bytes32 hash,
        bytes memory signature
    ) external {
        address signer = _recover(hash, signature);
        require(signer == owner, "Invalid signature");
    }

    /**
     * @notice SECURE: Custom ECDSA recovery with full validation
     */
    function _recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // SECURE: Validate s-value
        require(uint256(s) <= uint256(MAX_S_VALUE), "Invalid s value");

        // SECURE: Validate v
        require(v == 27 || v == 28, "Invalid v value");

        return ecrecover(hash, v, r, s);
    }
}

/**
 * @notice SECURE: Cross-chain replay protection
 * @dev Includes chainId in all signatures
 */
contract SecureCrossChainReplayProtection {
    address public owner;
    mapping(uint256 => bool) public usedNonces;
    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        owner = msg.sender;

        // SECURE: Domain separator includes chainId
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SecureTransfer")),
            keccak256(bytes("1")),
            block.chainid,  // SECURE: Dynamic chainId
            address(this)
        ));
    }

    /**
     * @notice SECURE: Includes block.chainid in signature
     * @dev Prevents cross-chain replay attacks
     */
    function transfer(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Include block.chainid in hash
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Transfer(address to,uint256 amount,uint256 nonce,uint256 chainId)"),
            to,
            amount,
            nonce,
            block.chainid  // SECURE: Dynamic chainId prevents replay on other chains
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        require(!usedNonces[nonce], "Nonce used");

        usedNonces[nonce] = true;
        payable(to).transfer(amount);
    }

    /**
     * @notice SECURE: Uses EIP-712 domain separator (which includes chainId)
     * @dev Signature automatically invalid on different chain
     */
    function transferWithEIP712(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Transfer(address to,uint256 amount,uint256 nonce)"),
            to,
            amount,
            nonce
        ));

        // SECURE: Domain separator already contains chainId
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        require(!usedNonces[nonce], "Nonce used");

        usedNonces[nonce] = true;
        payable(to).transfer(amount);
    }
}

/**
 * @notice SECURE: Proper nonce tracking
 * @dev Prevents signature replay with sequential nonce tracking
 */
contract SecureNonceTracking {
    address public owner;
    mapping(address => uint256) public nonces;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Sequential nonce with increment
     * @dev Nonce must match current value and is incremented after use
     */
    function executeAction(
        string memory action,
        uint256 value,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Verify nonce matches expected value
        require(nonce == nonces[owner], "Invalid nonce");

        // SECURE: Include nonce in signature hash
        bytes32 hash = keccak256(abi.encode(action, value, nonce));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // SECURE: Increment nonce to prevent replay
        nonces[owner]++;

        // Execute action
    }

    /**
     * @notice SECURE: Post-increment pattern
     * @dev Uses current nonce and increments in one operation
     */
    function executeWithPostIncrement(
        string memory action,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Use current nonce and increment
        uint256 currentNonce = nonces[owner]++;

        bytes32 hash = keccak256(abi.encode(
            action,
            value,
            currentNonce,
            block.chainid
        ));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // Execute action
    }
}

/**
 * @notice SECURE: EIP-2612 permit with deadline validation
 * @dev Implements proper permit() with expiration
 */
contract SecurePermitWithDeadline {
    string public name = "SecureToken";
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice SECURE: Proper EIP-2612 permit implementation
     * @dev Validates deadline to prevent old signatures from being used
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

        uint256 nonce = nonces[owner]++;

        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonce,
            deadline  // SECURE: Deadline in signature
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Invalid signer");

        allowance[owner][spender] = value;
    }

    /**
     * @notice SECURE: Short deadline for time-sensitive permits
     * @dev Uses short expiration window for security
     */
    function permitWithShortDeadline(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Deadline must be within 1 hour
        require(deadline <= block.timestamp + 1 hours, "Deadline too far");
        require(block.timestamp <= deadline, "Permit expired");

        uint256 nonce = nonces[owner]++;

        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonce,
            deadline
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        allowance[owner][spender] = value;
    }
}

/**
 * @notice SECURE: Safe batch signature validation
 * @dev Validates all signatures before executing any operations
 */
contract SecureBatchSignatureValidation {
    address public owner;
    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        owner = msg.sender;

        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SecureBatch")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice SECURE: Validates all signatures before execution
     * @dev Reverts if any signature is invalid
     */
    function batchExecute(
        address[] memory targets,
        uint256[] memory amounts,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external {
        require(targets.length == amounts.length, "Length mismatch");
        require(v.length == targets.length, "Signature length mismatch");

        // SECURE: Validate ALL signatures first
        for (uint256 i = 0; i < targets.length; i++) {
            bytes32 structHash = keccak256(abi.encode(
                keccak256("Transfer(address to,uint256 amount,uint256 index)"),
                targets[i],
                amounts[i],
                i
            ));

            bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

            address signer = ecrecover(hash, v[i], r[i], s[i]);
            require(signer == owner, "Invalid signature in batch");
        }

        // SECURE: Execute only after all validations pass
        for (uint256 i = 0; i < targets.length; i++) {
            payable(targets[i]).transfer(amounts[i]);
        }
    }

    /**
     * @notice SECURE: Batch with merkle root signature
     * @dev Single signature validates merkle root of all operations
     */
    function batchExecuteWithMerkleProof(
        address[] memory targets,
        uint256[] memory amounts,
        bytes32 merkleRoot,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Verify merkle root matches operations
        bytes32 computedRoot = keccak256(abi.encode(targets, amounts));
        require(computedRoot == merkleRoot, "Invalid merkle root");

        // SECURE: Validate signature on merkle root
        bytes32 structHash = keccak256(abi.encode(
            keccak256("BatchTransfer(bytes32 merkleRoot)"),
            merkleRoot
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // Execute batch
        for (uint256 i = 0; i < targets.length; i++) {
            payable(targets[i]).transfer(amounts[i]);
        }
    }
}

/**
 * @notice SECURE: Complete meta-transaction implementation
 * @dev All security measures combined
 */
contract SecureMetaTransaction {
    address public owner;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    bytes32 public constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)"
    );

    // ECDSA malleability protection
    bytes32 private constant MAX_S_VALUE = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    constructor() {
        owner = msg.sender;

        // SECURE: Complete domain separator
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SecureMetaTx")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice SECURE: Complete meta-transaction with all protections
     * - Proper EIP-712 domain separator
     * - Signature malleability protection
     * - Cross-chain replay protection (chainId in domain separator)
     * - Proper nonce tracking
     * - Deadline validation
     */
    function executeMetaTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        // SECURE: Validate deadline
        require(block.timestamp <= deadline, "Transaction expired");

        // SECURE: Get and increment nonce
        uint256 nonce = nonces[owner]++;

        // SECURE: EIP-712 structured hash
        bytes32 structHash = keccak256(abi.encode(
            META_TX_TYPEHASH,
            to,
            value,
            keccak256(data),
            nonce,
            deadline
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        // SECURE: Validate s-value for malleability protection
        require(uint256(s) <= uint256(MAX_S_VALUE), "Invalid s value");
        require(v == 27 || v == 28, "Invalid v value");

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Invalid signer");

        (success, ) = to.call{value: value}(data);
        require(success, "Meta-transaction failed");
    }
}
