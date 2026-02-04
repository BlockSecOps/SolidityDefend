# EIP-4844 Blob Transaction Detector

**Detector ID:** `eip4844-blob-validation`
**Total Detectors:** 1
**Added in:** v1.9.1 (2026-01-15)
**Categories:** EIP Security, Data Availability

---

## Overview

EIP-4844 (Proto-Danksharding) introduces blob-carrying transactions to Ethereum, providing a cost-effective data availability layer for Layer 2 rollups. Blobs are large data chunks (up to 128 KB each, max 6 per transaction) that are temporarily available on the consensus layer.

Key concepts:
- **Versioned Hashes**: 32-byte commitments to blob data using KZG polynomial commitments
- **BLOBHASH Opcode**: New opcode to access blob versioned hashes within smart contracts
- **KZG Point Evaluation Precompile**: Verifies that a blob commitment opens to a specific value at a given point

Improper validation of blob data can lead to:
- Accepting invalid or malicious blob commitments
- Processing stale or uncommitted blob data
- Vulnerability to data availability attacks

---

## Detector Summary

| Detector ID | Severity | Description | CWE |
|-------------|----------|-------------|-----|
| `eip4844-blob-validation` | High | Blob transaction validation issues | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |

---

## Detailed Detector Documentation

### eip4844-blob-validation

**Severity:** High
**CWE:** [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

#### Description

This detector identifies improper validation of EIP-4844 blob transactions, including:

1. **Missing Version Prefix Validation**: Blob versioned hashes must have the correct version prefix (0x01 for KZG commitments)
2. **Unverified BLOBHASH Usage**: Using BLOBHASH opcode output without proper verification
3. **Missing KZG Proof Verification**: Not using the point evaluation precompile to verify blob data
4. **Index Bounds Issues**: Not validating blob index before BLOBHASH call

#### Detection Criteria

- `blobhash()` opcode usage without version validation
- Processing versioned hashes without checking the 0x01 prefix
- Missing calls to the KZG point evaluation precompile (0x0a)
- Blob index used without bounds checking
- Versioned hash used in critical logic without cryptographic verification

#### Vulnerable Code Patterns

**Pattern 1: Missing Version Prefix Validation**

```solidity
// VULNERABLE: No version prefix check
contract VulnerableBlobProcessor {
    function processBlobData(bytes32 versionedHash) external {
        // Missing: require(uint8(versionedHash[0]) == 0x01)
        // Attacker could pass invalid commitment format
        emit BlobProcessed(versionedHash);
        _processData(versionedHash);
    }
}
```

**Pattern 2: Unverified BLOBHASH Usage**

```solidity
// VULNERABLE: BLOBHASH without validation
contract VulnerableBlobReader {
    function getBlobHash(uint256 index) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            hash := blobhash(index)
        }
        // Returns potentially invalid or zero hash without checking
        return hash;
    }

    function processBlob(uint256 blobIndex) external {
        bytes32 hash;
        assembly {
            hash := blobhash(blobIndex)
        }
        // No validation that hash is non-zero or properly formatted
        criticalOperation(hash);
    }
}
```

**Pattern 3: Missing KZG Proof Verification**

```solidity
// VULNERABLE: Trusting blob data without cryptographic proof
contract VulnerableL2Bridge {
    function submitBatchRoot(
        bytes32 versionedHash,
        bytes32 batchRoot
    ) external {
        // Accepts claimed batch root without verifying
        // it corresponds to the blob commitment
        batchRoots[versionedHash] = batchRoot;
    }
}
```

**Pattern 4: Unbounded Blob Index**

```solidity
// VULNERABLE: No index bounds validation
contract VulnerableBlobIndexer {
    function readBlob(uint256 index) external view returns (bytes32) {
        assembly {
            // EIP-4844 allows max 6 blobs per transaction
            // No check that index < 6
            let hash := blobhash(index)
            mstore(0, hash)
            return(0, 32)
        }
    }
}
```

#### Secure Code Patterns

**Pattern 1: Complete Blob Validation**

```solidity
// SECURE: Full validation of blob versioned hashes
contract SecureBlobProcessor {
    // KZG point evaluation precompile address
    address constant KZG_PRECOMPILE = address(0x0a);

    // EIP-4844 version prefix for KZG commitments
    uint8 constant VERSIONED_HASH_VERSION_KZG = 0x01;

    // Maximum blobs per transaction
    uint256 constant MAX_BLOBS_PER_TX = 6;

    error InvalidVersionPrefix(bytes32 hash);
    error InvalidBlobIndex(uint256 index);
    error KZGVerificationFailed();
    error NoBlobAtIndex(uint256 index);

    function processBlobData(
        bytes32 versionedHash,
        bytes32 z,      // Evaluation point
        bytes32 y,      // Expected value
        bytes48 commitment,
        bytes48 proof
    ) external {
        // 1. Validate version prefix
        if (uint8(versionedHash[0]) != VERSIONED_HASH_VERSION_KZG) {
            revert InvalidVersionPrefix(versionedHash);
        }

        // 2. Verify via KZG point evaluation precompile
        bytes memory input = abi.encodePacked(
            versionedHash,
            z,
            y,
            commitment,
            proof
        );

        (bool success, bytes memory result) = KZG_PRECOMPILE.staticcall(input);

        if (!success || result.length == 0) {
            revert KZGVerificationFailed();
        }

        // 3. Process verified data
        _processVerifiedBlob(versionedHash, y);
    }

    function getBlobHash(uint256 index) external view returns (bytes32 hash) {
        // Validate index bounds
        if (index >= MAX_BLOBS_PER_TX) {
            revert InvalidBlobIndex(index);
        }

        assembly {
            hash := blobhash(index)
        }

        // Validate non-zero result
        if (hash == bytes32(0)) {
            revert NoBlobAtIndex(index);
        }

        // Validate version prefix
        if (uint8(hash[0]) != VERSIONED_HASH_VERSION_KZG) {
            revert InvalidVersionPrefix(hash);
        }
    }

    function _processVerifiedBlob(bytes32 hash, bytes32 data) internal {
        // Safe to use verified data
    }
}
```

**Pattern 2: Secure L2 Batch Submission**

```solidity
// SECURE: Rollup batch submission with proper blob verification
contract SecureRollupBridge {
    address constant KZG_PRECOMPILE = address(0x0a);
    uint8 constant VERSION_KZG = 0x01;

    struct BatchSubmission {
        bytes32 versionedHash;
        bytes32 stateRoot;
        uint256 timestamp;
        bool verified;
    }

    mapping(uint256 => BatchSubmission) public batches;
    uint256 public batchCount;

    event BatchSubmitted(uint256 indexed batchId, bytes32 versionedHash, bytes32 stateRoot);

    function submitBatch(
        uint256 blobIndex,
        bytes32 expectedStateRoot,
        bytes32 z,
        bytes32 y,
        bytes48 commitment,
        bytes48 proof
    ) external {
        // 1. Get blob hash from current transaction
        bytes32 versionedHash;
        assembly {
            versionedHash := blobhash(blobIndex)
        }

        require(versionedHash != bytes32(0), "No blob at index");
        require(uint8(versionedHash[0]) == VERSION_KZG, "Invalid version");

        // 2. Verify KZG proof
        (bool success, ) = KZG_PRECOMPILE.staticcall(
            abi.encodePacked(versionedHash, z, y, commitment, proof)
        );
        require(success, "KZG verification failed");

        // 3. Store verified batch
        batches[batchCount] = BatchSubmission({
            versionedHash: versionedHash,
            stateRoot: expectedStateRoot,
            timestamp: block.timestamp,
            verified: true
        });

        emit BatchSubmitted(batchCount, versionedHash, expectedStateRoot);
        batchCount++;
    }
}
```

**Pattern 3: Safe Multi-Blob Processing**

```solidity
// SECURE: Processing multiple blobs with validation
contract SecureMultiBlobProcessor {
    uint256 constant MAX_BLOBS = 6;
    uint8 constant VERSION_KZG = 0x01;

    struct BlobInfo {
        bytes32 versionedHash;
        bool isValid;
    }

    function getAllBlobHashes() external view returns (BlobInfo[] memory blobs) {
        blobs = new BlobInfo[](MAX_BLOBS);

        for (uint256 i = 0; i < MAX_BLOBS; i++) {
            bytes32 hash;
            assembly {
                hash := blobhash(i)
            }

            if (hash != bytes32(0)) {
                blobs[i] = BlobInfo({
                    versionedHash: hash,
                    isValid: uint8(hash[0]) == VERSION_KZG
                });
            }
        }
    }

    function processAllBlobs(
        bytes32[] calldata expectedHashes
    ) external view returns (bool) {
        require(expectedHashes.length <= MAX_BLOBS, "Too many blobs");

        for (uint256 i = 0; i < expectedHashes.length; i++) {
            bytes32 actualHash;
            assembly {
                actualHash := blobhash(i)
            }

            // Verify hash matches expected
            require(actualHash == expectedHashes[i], "Hash mismatch");

            // Verify version
            require(uint8(actualHash[0]) == VERSION_KZG, "Invalid version");
        }

        return true;
    }
}
```

---

## Remediation Guidelines

### 1. Always Validate Version Prefix

```solidity
// First byte must be 0x01 for KZG commitments
require(uint8(versionedHash[0]) == 0x01, "Invalid version prefix");
```

### 2. Use KZG Precompile for Verification

```solidity
address constant KZG_PRECOMPILE = address(0x0a);

// Precompile input: versionedHash || z || y || commitment || proof
(bool success, ) = KZG_PRECOMPILE.staticcall(proofData);
require(success, "KZG verification failed");
```

### 3. Validate Blob Index Bounds

```solidity
// Maximum 6 blobs per transaction
require(blobIndex < 6, "Invalid blob index");
```

### 4. Check for Zero Hash

```solidity
bytes32 hash;
assembly {
    hash := blobhash(index)
}
require(hash != bytes32(0), "No blob at index");
```

### 5. Handle Missing Blobs Gracefully

```solidity
function safeGetBlobHash(uint256 index) internal view returns (bytes32 hash, bool exists) {
    assembly {
        hash := blobhash(index)
    }
    exists = hash != bytes32(0);
}
```

---

## Testing

The detector has been validated with comprehensive test cases:

| Test Scenario | Findings | Contracts |
|---------------|----------|-----------|
| Missing version validation | 2 | 1 |
| Unverified BLOBHASH | 2 | 1 |
| Missing KZG verification | 1 | 1 |

**Total:** 5 findings across 3 test contracts

---

## Best Practices

### For Rollup Developers

1. **Always verify blob commitments** using the KZG precompile before trusting data
2. **Validate version prefixes** to ensure compatibility with future blob versions
3. **Include blob hashes in state commitments** for verifiable data availability
4. **Handle blob expiration** - blobs are only available for ~18 days

### For DApp Developers

1. **Check blob availability** before relying on blob data
2. **Use events** to log blob versioned hashes for off-chain indexing
3. **Implement fallback mechanisms** for when blob data is unavailable
4. **Test with blob-carrying transactions** on testnets

### Security Considerations

1. **Blob data is not permanently available** - design systems accordingly
2. **Versioned hashes are commitments, not data** - actual blob data is off-chain
3. **KZG proofs are required** for trustless verification of blob contents
4. **Future versions may use different commitment schemes** - validate version prefix

---

## References

### EIP Specification
- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)

### Technical Resources
- [KZG Polynomial Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)
- [Proto-Danksharding FAQ](https://notes.ethereum.org/@vbuterin/proto_danksharding_faq)
- [EIP-4844 Precompile Specification](https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile)

### Related Detectors
- `l2-rollup-*` - Layer 2 rollup security detectors
- `cross-chain-*` - Cross-chain validation detectors

---

**Last Updated:** 2026-01-26
**Detector Version:** 1.0.0
**Source:** `crates/detectors/src/eip4844/blob_validation.rs`
