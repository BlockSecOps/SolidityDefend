// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SignatureVulnerabilities - Vulnerable Patterns
 * @notice VULNERABLE: Multiple signature validation vulnerabilities
 * @dev This contract demonstrates insecure signature handling patterns.
 *
 * Vulnerabilities Demonstrated:
 * 1. Missing EIP-712 domain separator
 * 2. Signature malleability (no s-value validation)
 * 3. Cross-chain replay attacks (missing chainId)
 * 4. Missing nonce in signatures
 * 5. Nonce reuse possibilities
 * 6. Missing deadline validation
 * 7. Unsafe batch signature validation
 */

/**
 * @notice VULNERABLE: Missing EIP-712 domain separator
 * @dev Uses raw keccak256 without proper EIP-712 structuring
 */
contract VulnerableMissingEIP712Domain {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: No EIP-712 domain separator
     * @dev Signature can be replayed across contracts and chains
     */
    function executeWithSignature(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Missing EIP-712 domain separator
        bytes32 hash = keccak256(abi.encode(to, amount));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        payable(to).transfer(amount);
    }

    /**
     * @notice VULNERABLE: Incomplete EIP-712 (missing chainId)
     */
    function executeWithIncompleteEIP712(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Has domain separator but missing chainId
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
            keccak256(bytes("MyContract")),
            keccak256(bytes("1")),
            address(this)
            // Missing: block.chainid
        ));

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Transfer(address to,uint256 amount)"),
            to,
            amount
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        payable(to).transfer(amount);
    }
}

/**
 * @notice VULNERABLE: Signature malleability
 * @dev Does not validate s-value range, allowing signature malleation
 */
contract VulnerableSignatureMalleability {
    address public owner;
    mapping(bytes32 => bool) public executed;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: No s-value validation
     * @dev Attacker can flip s to create valid alternate signature
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

        // VULNERABLE: No s-value range check
        // s can be flipped: s' = secp256k1n - s
        address signer = ecrecover(txHash, v, r, s);
        require(signer == owner, "Invalid signer");
        require(!executed[txHash], "Already executed");

        executed[txHash] = true;
        payable(to).transfer(amount);
    }

    /**
     * @notice VULNERABLE: Custom ECDSA without malleability protection
     */
    function executeWithCustomECDSA(
        bytes32 hash,
        bytes memory signature
    ) external {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // VULNERABLE: No s-value validation
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
    }
}

/**
 * @notice VULNERABLE: Cross-chain replay attacks
 * @dev Signatures work on all chains (Ethereum, BSC, Polygon, etc.)
 */
contract VulnerableCrossChainReplay {
    address public owner;
    mapping(uint256 => bool) public usedNonces;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: No chainId in signature
     * @dev Same signature works on all EVM chains
     */
    function transfer(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Missing block.chainid
        bytes32 hash = keccak256(abi.encode(to, amount, nonce));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        require(!usedNonces[nonce], "Nonce used");

        usedNonces[nonce] = true;
        payable(to).transfer(amount);
    }

    /**
     * @notice VULNERABLE: Hardcoded chainId
     * @dev Won't work after chain fork, but that's a different issue
     */
    function transferWithHardcodedChainId(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Hardcoded chainId instead of block.chainid
        bytes32 hash = keccak256(abi.encode(to, amount, nonce, uint256(1)));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        require(!usedNonces[nonce], "Nonce used");

        usedNonces[nonce] = true;
        payable(to).transfer(amount);
    }
}

/**
 * @notice VULNERABLE: Missing nonce in signature
 * @dev Signature can be replayed multiple times
 */
contract VulnerableMissingNonce {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: No nonce tracking
     * @dev Signature can be replayed infinitely
     */
    function executeAction(
        string memory action,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: No nonce in hash or tracking
        bytes32 hash = keccak256(abi.encode(action, value));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // Action executed - but can be replayed!
    }

    /**
     * @notice VULNERABLE: Nonce in hash but not validated
     */
    function executeWithUnvalidatedNonce(
        string memory action,
        uint256 value,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Nonce in hash but never checked/stored
        bytes32 hash = keccak256(abi.encode(action, value, nonce));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // Nonce not tracked - signature can be replayed!
    }
}

/**
 * @notice VULNERABLE: Nonce reuse patterns
 * @dev Improper nonce management allows replay attacks
 */
contract VulnerableNonceReuse {
    address public owner;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public executed;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Nonce not incremented
     */
    function executeWithNonIncrementedNonce(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Checks nonce but doesn't increment
        require(nonce == nonces[msg.sender], "Invalid nonce");

        bytes32 hash = keccak256(abi.encode(to, amount, nonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // VULNERABLE: Nonce not incremented - can reuse same nonce
        payable(to).transfer(amount);
    }

    /**
     * @notice VULNERABLE: Nonce can be reset
     */
    function resetNonce() external {
        // VULNERABLE: Allows nonce reset, enabling replay
        nonces[msg.sender] = 0;
    }

    /**
     * @notice VULNERABLE: Arbitrary nonce acceptance
     */
    function executeWithArbitraryNonce(
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encode(to, amount, nonce));

        // VULNERABLE: Accepts any nonce, no sequential requirement
        require(!executed[hash], "Already executed");

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        executed[hash] = true;
        payable(to).transfer(amount);
    }
}

/**
 * @notice VULNERABLE: EIP-2612 permit without deadline validation
 * @dev Permit signatures can be used indefinitely
 */
contract VulnerablePermitNoDeadline {
    string public name = "MyToken";
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    /**
     * @notice VULNERABLE: No deadline parameter or validation
     * @dev Old permit signatures never expire
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        uint256 nonce = nonces[owner]++;

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce)"),
            owner,
            spender,
            value,
            nonce
            // Missing: deadline
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // VULNERABLE: No deadline check
        allowance[owner][spender] = value;
    }

    /**
     * @notice VULNERABLE: Deadline in signature but not validated
     */
    function permitWithUnvalidatedDeadline(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        uint256 nonce = nonces[owner]++;

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            nonce,
            deadline
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // VULNERABLE: Deadline in hash but never checked!
        allowance[owner][spender] = value;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }
}

/**
 * @notice VULNERABLE: Unsafe batch signature validation
 * @dev Single invalid signature doesn't halt batch processing
 */
contract VulnerableBatchSignatureValidation {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Batch validation without proper checks
     * @dev Continues processing even if some signatures are invalid
     */
    function batchExecute(
        address[] memory targets,
        uint256[] memory amounts,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external {
        require(targets.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            bytes32 hash = keccak256(abi.encode(targets[i], amounts[i]));
            address signer = ecrecover(hash, v[i], r[i], s[i]);

            // VULNERABLE: Doesn't revert on invalid signature
            if (signer == owner) {
                payable(targets[i]).transfer(amounts[i]);
            }
            // Continues to next iteration even if signature invalid
        }
    }

    /**
     * @notice VULNERABLE: Batch with single signature for all
     * @dev One signature validates entire batch
     */
    function batchExecuteWithSingleSignature(
        address[] memory targets,
        uint256[] memory amounts,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABLE: Single signature for entire batch
        bytes32 hash = keccak256(abi.encode(targets, amounts));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        // All transfers approved by single signature
        for (uint256 i = 0; i < targets.length; i++) {
            payable(targets[i]).transfer(amounts[i]);
        }
    }
}

/**
 * @notice VULNERABLE: Multiple signature issues combined
 * @dev Real-world example with multiple vulnerabilities
 */
contract VulnerableMetaTransaction {
    address public owner;
    mapping(uint256 => bool) public executedNonces;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Multiple issues in one function
     * - Missing EIP-712 domain separator
     * - No signature malleability protection
     * - Missing chainId (cross-chain replay)
     * - Weak nonce validation
     */
    function executeMetaTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        // VULNERABLE: Multiple issues
        bytes32 hash = keccak256(abi.encode(to, value, data, nonce));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signer");
        require(!executedNonces[nonce], "Nonce used");

        executedNonces[nonce] = true;

        (success, ) = to.call{value: value}(data);
    }
}
