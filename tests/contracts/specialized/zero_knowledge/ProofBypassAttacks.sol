// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProofBypassAttacks
 * @notice Zero-Knowledge Proof Verification Bypass Vulnerabilities
 *
 * VULNERABILITY: Bypassing ZK proof verification
 * CATEGORY: Zero-Knowledge Proof Security
 *
 * BACKGROUND:
 * ZK proof verification can be bypassed through various attack vectors:
 * - Weak or missing proof validation
 * - Accepting invalid proof formats
 * - Skipping verification under certain conditions
 * - Time-based verification bypass
 * - Proof caching vulnerabilities
 * - Public input manipulation
 *
 * REAL-WORLD IMPACT:
 * Proof bypass allows attackers to:
 * - Forge transactions without valid credentials
 * - Bypass authentication/authorization
 * - Mint tokens without valid proof
 * - Drain funds from privacy pools
 * - Manipulate rollup state
 *
 * TESTED DETECTORS:
 * - zk-proof-bypass
 * - zk-weak-verification
 * - zk-missing-verification
 * - zk-cached-proof
 */

/**
 * @title WeakProofVerifier
 * @notice Verifier with weak proof validation
 */
contract WeakProofVerifier {
    mapping(bytes32 => bool) public verifiedProofs;

    /**
     * @notice VULNERABILITY 1: Always returns true for certain inputs
     * @dev Verification logic has bypass conditions
     */
    function verifyProof(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external pure returns (bool) {
        // VULNERABLE: If proof[0] == 0, verification is skipped
        if (proof[0] == 0) {
            return true; // BYPASS!
        }

        // VULNERABLE: Empty public inputs bypass verification
        if (publicInputs.length == 0) {
            return true; // BYPASS!
        }

        // Real verification would happen here
        return _pairing(proof);
    }

    /**
     * @notice VULNERABILITY 2: Weak pairing check
     */
    function _pairing(uint256[8] calldata proof) internal pure returns (bool) {
        // VULNERABLE: Weak check that can be bypassed
        // Real pairing check is expensive, so might be simplified incorrectly
        if (proof[0] == proof[1]) {
            return true; // WEAK CHECK!
        }

        // Placeholder for real pairing check
        return true;
    }

    /**
     * @notice VULNERABILITY 3: Admin bypass
     */
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function verifyProofWithAdmin(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: Admin can bypass verification
        if (msg.sender == admin) {
            return true; // ADMIN BYPASS!
        }

        return _pairing(proof);
    }
}

/**
 * @title CachedProofVerifier
 * @notice Verifier with proof caching vulnerabilities
 */
contract CachedProofVerifier {
    // Cache verified proofs for gas optimization
    mapping(bytes32 => bool) public verifiedProofCache;
    mapping(bytes32 => uint256) public proofTimestamp;

    uint256 public constant CACHE_DURATION = 1 hours;

    /**
     * @notice VULNERABILITY 4: Proof caching allows replay
     * @dev Once proof is verified, same proof hash can be reused
     */
    function verifyProofWithCache(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external returns (bool) {
        bytes32 proofHash = keccak256(abi.encode(proof, publicInputs));

        // VULNERABLE: Check cache first
        if (verifiedProofCache[proofHash]) {
            // Proof was verified before, skip verification
            // BYPASS: Attacker can replay cached proof with different context
            return true;
        }

        // Verify proof
        bool valid = _verify(proof, publicInputs);

        if (valid) {
            // Cache the result
            verifiedProofCache[proofHash] = true;
            proofTimestamp[proofHash] = block.timestamp;
        }

        return valid;
    }

    /**
     * @notice VULNERABILITY 5: Time-based cache allows expired proof reuse
     */
    function verifyProofWithExpiry(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        bytes32 proofHash = keccak256(abi.encode(proof, publicInputs));

        // VULNERABLE: Accepts cached proofs within expiry window
        if (
            verifiedProofCache[proofHash] &&
            block.timestamp < proofTimestamp[proofHash] + CACHE_DURATION
        ) {
            return true; // CACHED BYPASS!
        }

        // Would need to verify fresh proof
        return false;
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        // Placeholder verification
        return true;
    }
}

/**
 * @title PublicInputBypass
 * @notice Vulnerabilities in public input handling
 */
contract PublicInputBypass {
    /**
     * @notice VULNERABILITY 6: Public inputs not validated before verification
     * @dev Malformed public inputs can bypass verification
     */
    function verifyWithPublicInputs(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external pure returns (bool) {
        // VULNERABLE: No validation of public inputs
        // Missing checks:
        // - Length validation
        // - Range validation
        // - Format validation

        // If publicInputs is empty or malformed, verification might be skipped
        if (publicInputs.length > 10) {
            return true; // BYPASS: Arbitrary length limit bypass
        }

        return _verify(proof, publicInputs);
    }

    /**
     * @notice VULNERABILITY 7: Public input substitution
     */
    function verifyWithSubstitution(
        uint256[8] calldata proof,
        uint256[] calldata providedInputs,
        uint256[] calldata verifyInputs
    ) external pure returns (bool) {
        // VULNERABLE: Uses different inputs for verification than provided
        // Attacker provides one set of inputs to application logic
        // But verification uses different inputs

        // Application uses providedInputs
        // But verification uses verifyInputs
        // BYPASS: Can prove one thing, claim another

        return _verify(proof, verifyInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        return true; // Placeholder
    }
}

/**
 * @title ConditionalVerification
 * @notice Conditional verification bypass
 */
contract ConditionalVerification {
    bool public emergencyMode;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY 8: Emergency mode bypasses verification
     */
    function verifyProofWithEmergency(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: Emergency mode skips verification
        if (emergencyMode) {
            return true; // EMERGENCY BYPASS!
        }

        return _verify(proof, publicInputs);
    }

    /**
     * @notice VULNERABILITY 9: Amount-based bypass
     */
    function verifyProofWithAmountBypass(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        uint256 amount
    ) external pure returns (bool) {
        // VULNERABLE: Small amounts skip verification for "gas optimization"
        if (amount < 0.1 ether) {
            return true; // SMALL AMOUNT BYPASS!
        }

        return _verify(proof, publicInputs);
    }

    function setEmergencyMode(bool _emergencyMode) external {
        require(msg.sender == owner, "Not owner");
        emergencyMode = _emergencyMode;
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        return true; // Placeholder
    }
}

/**
 * @title BatchVerificationBypass
 * @notice Batch proof verification vulnerabilities
 */
contract BatchVerificationBypass {
    /**
     * @notice VULNERABILITY 10: Batch verification accepts if ANY proof is valid
     * @dev Should require ALL proofs valid, but only checks if at least one is valid
     */
    function verifyBatch(
        uint256[][8] calldata proofs,
        uint256[][] calldata publicInputs
    ) external pure returns (bool) {
        require(proofs.length == publicInputs.length, "Length mismatch");

        // VULNERABLE: Returns true if ANY proof is valid
        // Should require ALL proofs to be valid
        for (uint256 i = 0; i < proofs.length; i++) {
            if (_verify(proofs[i], publicInputs[i])) {
                return true; // BYPASS: Only needs one valid proof!
            }
        }

        return false;
    }

    /**
     * @notice VULNERABILITY 11: Batch size bypass
     */
    function verifyBatchWithLimit(
        uint256[][8] calldata proofs,
        uint256[][] calldata publicInputs
    ) external pure returns (bool) {
        // VULNERABLE: If batch is too large, verification is skipped
        if (proofs.length > 100) {
            return true; // BATCH SIZE BYPASS!
        }

        // Verify all proofs
        for (uint256 i = 0; i < proofs.length; i++) {
            if (!_verify(proofs[i], publicInputs[i])) {
                return false;
            }
        }

        return true;
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        return true; // Placeholder
    }
}

/**
 * @title ProofMalleability
 * @notice Proof malleability bypass attacks
 */
contract ProofMalleability {
    mapping(bytes32 => bool) public usedProofs;

    /**
     * @notice VULNERABILITY 12: Proof can be modified to create new valid proof
     * @dev No check for proof malleability
     */
    function verifyMalleableProof(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external returns (bool) {
        bytes32 proofHash = keccak256(abi.encode(proof));

        require(!usedProofs[proofHash], "Proof already used");

        // VULNERABLE: Proof might be malleable
        // Attacker can:
        // 1. Modify proof components while keeping it valid
        // 2. Generate new proofHash
        // 3. Bypass usedProofs check

        // Example malleability:
        // If proof uses ECDSA, signature (r,s) and (r, -s mod n) are both valid
        // If proof uses pairing, certain transformations preserve validity

        bool valid = _verify(proof, publicInputs);

        if (valid) {
            usedProofs[proofHash] = true;
        }

        return valid;
    }

    /**
     * @notice VULNERABILITY 13: Public input malleability
     */
    function verifyWithMalleableInput(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: Public inputs might have multiple representations
        // Example: 0x00...01 and 0x01 might be treated as same
        // or modular arithmetic might make multiple inputs equivalent

        bytes32 inputHash = keccak256(abi.encode(publicInputs));

        // Should check for input normalization
        // Missing: Ensure inputs are in canonical form

        return _verify(proof, publicInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        return true; // Placeholder
    }
}

/**
 * @title IncompleteVerification
 * @notice Incomplete proof verification
 */
contract IncompleteVerification {
    /**
     * @notice VULNERABILITY 14: Partial proof verification
     * @dev Only verifies subset of proof components
     */
    function verifyPartialProof(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external pure returns (bool) {
        // VULNERABLE: Only checks first half of proof
        // Full proof has 8 components, but only validates 4
        if (proof[0] == 0 || proof[1] == 0 || proof[2] == 0 || proof[3] == 0) {
            return false;
        }

        // Missing: Verification of proof[4], proof[5], proof[6], proof[7]
        // BYPASS: Can provide arbitrary values for second half

        return true;
    }

    /**
     * @notice VULNERABILITY 15: Missing pairing equations
     */
    function verifyWithMissingPairing(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external pure returns (bool) {
        // VULNERABLE: zkSNARK verification requires 2 pairing checks
        // This implementation only does 1 (or simplified version)

        // Should verify:
        // e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
        // where L = sum of public inputs

        // Missing: Second pairing check
        // BYPASS: Proof doesn't need to satisfy all equations

        return true; // Simplified/incomplete verification
    }
}

/**
 * @title FallbackVerification
 * @notice Fallback verification bypass
 */
contract FallbackVerification {
    address public primaryVerifier;
    address public fallbackVerifier;

    constructor(address _primary, address _fallback) {
        primaryVerifier = _primary;
        fallbackVerifier = _fallback;
    }

    /**
     * @notice VULNERABILITY 16: Falls back to weaker verifier on failure
     */
    function verifyWithFallback(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // Try primary verifier
        (bool success, bytes memory result) = primaryVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[8],uint256[])",
                proof,
                publicInputs
            )
        );

        if (success && abi.decode(result, (bool))) {
            return true;
        }

        // VULNERABLE: Fall back to less secure verifier
        // Fallback verifier might have relaxed requirements
        (success, result) = fallbackVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[8],uint256[])",
                proof,
                publicInputs
            )
        );

        if (success) {
            return abi.decode(result, (bool)); // FALLBACK BYPASS!
        }

        return false;
    }

    /**
     * @notice VULNERABILITY 17: Version-based bypass
     */
    uint256 public verifierVersion = 1;

    function verifyWithVersion(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        uint256 version
    ) external view returns (bool) {
        // VULNERABLE: Old versions have known vulnerabilities
        if (version < verifierVersion) {
            // Should reject old versions
            // But instead uses old (vulnerable) verification logic
            return _verifyV1(proof, publicInputs); // OLD VERSION BYPASS!
        }

        return _verifyV2(proof, publicInputs);
    }

    function _verifyV1(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        // V1 has known vulnerability
        return true; // Weak verification
    }

    function _verifyV2(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        // V2 is more secure
        return proof[0] != 0; // Slightly better, but still placeholder
    }
}

/**
 * @title CircuitBypass
 * @notice Circuit-specific bypass vulnerabilities
 */
contract CircuitBypass {
    /**
     * @notice VULNERABILITY 18: Circuit hash mismatch
     * @dev Doesn't verify proof is for correct circuit
     */
    function verifyWithoutCircuitCheck(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        bytes32 circuitHash
    ) external pure returns (bool) {
        // VULNERABLE: Accepts proof for ANY circuit
        // Should verify: proof is for circuit with hash = circuitHash
        // Missing: Circuit identifier validation

        // BYPASS: Can use proof from different circuit
        return true; // No circuit check!
    }

    /**
     * @notice VULNERABILITY 19: Wrong circuit version accepted
     */
    mapping(bytes32 => bool) public approvedCircuits;

    function verifyWithCircuitVersion(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        bytes32 circuitHash
    ) external view returns (bool) {
        // VULNERABLE: Doesn't check if circuit is approved
        // Just checks if hash is non-zero
        if (circuitHash != bytes32(0)) {
            return true; // CIRCUIT VERSION BYPASS!
        }

        // Should check: require(approvedCircuits[circuitHash], "Unapproved circuit");

        return false;
    }
}
