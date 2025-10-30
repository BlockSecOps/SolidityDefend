// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title LegitimateMultisigWallet
 * @notice Properly implemented multisig wallet with security best practices
 * @dev This contract should NOT trigger false positives from multisig-bypass detector
 *
 * Security Measures:
 * 1. Strict signature count validation (prevents bypass via insufficient signatures)
 * 2. Duplicate signer detection
 * 3. Nonce management to prevent replay
 * 4. Signature ordering enforcement
 * 5. Owner validation for all signers
 */

contract LegitimateMultisigWallet {
    // Constants
    uint256 public constant MAX_OWNERS = 10;
    uint256 public immutable requiredSignatures;

    // State
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public nonce;

    // Events
    event Executed(bytes32 indexed txHash, uint256 nonce);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    constructor(address[] memory _owners, uint256 _requiredSignatures) {
        require(_owners.length > 0, "At least one owner required");
        require(_owners.length <= MAX_OWNERS, "Too many owners");
        require(_requiredSignatures > 0, "Required signatures must be > 0");
        require(_requiredSignatures <= _owners.length, "Required signatures exceeds owner count");

        // Strict validation: exactly _requiredSignatures required
        requiredSignatures = _requiredSignatures;

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "Invalid owner");
            require(!isOwner[owner], "Duplicate owner");

            isOwner[owner] = true;
            owners.push(owner);
            emit OwnerAdded(owner);
        }
    }

    /**
     * @notice Execute transaction with proper signature validation
     * @param to Destination address
     * @param value ETH value to send
     * @param data Transaction data
     * @param signatures Concatenated signatures (r,s,v format)
     */
    function executeTransaction(
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signatures
    ) external returns (bool success) {
        // Generate transaction hash
        bytes32 txHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(address(this), to, value, data, nonce))
            )
        );

        // Strict signature count validation
        require(signatures.length == requiredSignatures * 65, "Invalid signature count");

        // Prevent duplicate signers and validate all signatures
        address[] memory signers = new address[](requiredSignatures);
        address lastSigner = address(0);

        for (uint256 i = 0; i < requiredSignatures; i++) {
            bytes memory signature = slice(signatures, i * 65, 65);
            address signer = recoverSigner(txHash, signature);

            // Validate signer is an owner
            require(isOwner[signer], "Invalid signer");

            // Prevent duplicate signers (signatures must be sorted by address)
            require(signer > lastSigner, "Duplicate or unsorted signer");

            signers[i] = signer;
            lastSigner = signer;
        }

        // All validations passed, increment nonce
        nonce++;

        // Execute transaction
        (success, ) = to.call{value: value}(data);
        require(success, "Transaction failed");

        emit Executed(txHash, nonce - 1);
    }

    /**
     * @notice Recover signer from signature
     * @param hash Message hash
     * @param signature Signature bytes (r, s, v)
     * @return Recovered address
     */
    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        return ecrecover(hash, v, r, s);
    }

    /**
     * @notice Slice bytes
     * @param data Source bytes
     * @param start Start index
     * @param length Length to slice
     * @return result Sliced bytes
     */
    function slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory result) {
        result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
    }

    receive() external payable {}
}

/**
 * EXPECTED RESULTS:
 * ================
 * This multisig wallet implements all security best practices and should NOT trigger:
 *
 * ✅ multisig-bypass: Strict signature count validation (exactly requiredSignatures)
 * ✅ multisig-bypass: Duplicate signer detection with address ordering
 * ✅ multisig-bypass: Nonce management prevents replay
 * ✅ multisig-bypass: All signers validated as owners
 *
 * Expected Findings: 0 (Zero false positives)
 */
