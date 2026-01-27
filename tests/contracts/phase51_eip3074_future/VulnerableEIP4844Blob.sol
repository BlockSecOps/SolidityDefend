// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableEIP4844Blob
 * @notice VULNERABLE: Improper blob transaction validation
 * @dev Should trigger: eip4844-blob-validation (High)
 */
contract VulnerableBlobProcessor {
    event BlobProcessed(bytes32 indexed versionedHash);

    // VULNERABLE: No validation of versioned hash
    function processBlobData(bytes32 versionedHash) external {
        // Missing: version prefix check (0x01)
        // Missing: KZG proof verification
        emit BlobProcessed(versionedHash);
    }

    // VULNERABLE: Using BLOBHASH without version validation
    function getBlobHash(uint256 index) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            hash := blobhash(index)
        }
        // Missing: require(hash >> 248 == 0x01, "Invalid version")
        return hash;
    }

    // VULNERABLE: Processing blob data without KZG verification
    function processBlob(
        bytes32 versionedHash,
        bytes calldata blobData,
        bytes calldata proof
    ) external {
        // Should use point_evaluation_precompile (0x0a) for verification
        // Missing KZG proof validation
        _processBlobData(blobData);
    }

    function _processBlobData(bytes calldata data) internal {
        // Process without verification
    }
}

/**
 * @title VulnerableRollupBlobSubmitter
 * @notice VULNERABLE: L2 batch submission without blob verification
 * @dev Should trigger: eip4844-blob-validation (High)
 */
contract VulnerableRollupBlobSubmitter {
    address public sequencer;

    constructor() {
        sequencer = msg.sender;
    }

    // VULNERABLE: Batch submission without blobhash verification
    function submitBatch(
        bytes calldata batchData,
        bytes32 stateRoot
    ) external {
        require(msg.sender == sequencer, "Not sequencer");
        // Missing: blobhash verification
        // Missing: KZG proof validation
        _updateState(stateRoot);
    }

    // VULNERABLE: DA check without KZG verification
    function checkDataAvailability(bytes32 commitment) external view returns (bool) {
        // Should verify using point_evaluation_precompile
        return true; // Always returns true - dangerous
    }

    function _updateState(bytes32 newRoot) internal {
        // Update state without proper verification
    }
}

/**
 * @title VulnerableBlobGasCalculation
 * @notice VULNERABLE: Improper blob gas price handling
 * @dev Should trigger: eip4844-blob-validation (High)
 */
contract VulnerableBlobGasCalculation {
    function estimateBlobGas(uint256 numBlobs) external view returns (uint256) {
        uint256 blobBaseFee;
        assembly {
            blobBaseFee := blobbasefee()
        }
        // VULNERABLE: May not properly calculate blob gas cost
        return blobBaseFee; // Should multiply by blob count and gas per blob
    }
}
