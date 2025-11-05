// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrustedSetupVulnerabilities
 * @notice Trusted Setup Ceremony and Parameter Vulnerabilities
 *
 * VULNERABILITY: Trusted setup and ceremony security
 * CATEGORY: Zero-Knowledge Proof Security
 *
 * BACKGROUND:
 * Many ZK systems (zkSNARKs like Groth16) require a trusted setup ceremony
 * to generate proving and verifying keys. If the ceremony is compromised
 * or parameters are mishandled, the entire system's security can be broken.
 *
 * TRUSTED SETUP RISKS:
 * 1. Toxic waste (setup secret) not destroyed
 * 2. Single-party ceremony (no distributed trust)
 * 3. Parameter substitution (using wrong verification key)
 * 4. Setup reuse across different circuits
 * 5. Outdated parameters after circuit changes
 * 6. Missing parameter validation
 * 7. Ceremony manipulation
 *
 * REAL-WORLD EXAMPLES:
 * - Zcash Sprout → Sapling upgrade (new ceremony required)
 * - Various projects using Universal Setup (PLONK, Marlin)
 * - Compromised ceremonies leading to counterfeit proof generation
 *
 * TESTED DETECTORS:
 * - zk-trusted-setup-missing
 * - zk-parameter-validation
 * - zk-setup-reuse
 * - zk-outdated-parameters
 * - zk-toxic-waste
 */

/**
 * @title SetupParameterSubstitution
 * @notice Verification key substitution vulnerabilities
 */
contract SetupParameterSubstitution {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic; // Input coefficients
    }

    VerifyingKey public vk;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    /**
     * @notice VULNERABILITY 1: Admin can change verification key
     * @dev No protection against malicious key substitution
     */
    function updateVerifyingKey(VerifyingKey calldata newVk) external {
        // VULNERABLE: Admin can replace VK with compromised one
        require(msg.sender == admin, "Not admin");

        // MISSING: No validation that new VK is legitimate
        // MISSING: No multi-sig or timelock protection
        // MISSING: No verification that new VK matches circuit hash

        vk = newVk;

        // ATTACK: Admin can substitute VK from compromised ceremony
        // or VK for different circuit, breaking all security
    }

    /**
     * @notice VULNERABILITY 2: No VK hash verification
     */
    bytes32 public expectedVkHash;

    function updateVerifyingKeyWithHash(
        VerifyingKey calldata newVk,
        bytes32 vkHash
    ) external {
        require(msg.sender == admin, "Not admin");

        // VULNERABLE: expectedVkHash can also be changed by admin
        // No immutable commitment to correct VK

        require(keccak256(abi.encode(newVk)) == vkHash, "VK hash mismatch");

        vk = newVk;
        expectedVkHash = vkHash;
    }

    /**
     * @notice VULNERABILITY 3: VK not bound to circuit
     */
    function verifyProofWithoutBinding(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: No check that VK corresponds to correct circuit
        // Could be using VK from different circuit entirely

        // MISSING: Circuit identifier in VK
        // MISSING: Circuit hash validation

        return _verify(proof, publicInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        // Simplified verification
        return vk.alpha[0] != 0 && proof[0] != 0;
    }
}

/**
 * @title SetupReuseVulnerability
 * @notice Trusted setup reuse across circuits
 */
contract CircuitV1 {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic;
    }

    VerifyingKey public vk;

    constructor(VerifyingKey memory _vk) {
        vk = _vk;
    }

    function verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        return _verify(proof, publicInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        return vk.alpha[0] != 0;
    }
}

contract CircuitV2 {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic;
    }

    VerifyingKey public vk;

    constructor(VerifyingKey memory _vk) {
        vk = _vk;
    }

    /**
     * @notice VULNERABILITY 4: Reusing setup from CircuitV1
     * @dev CircuitV2 should have its own trusted setup ceremony
     */
    function verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: If vk is reused from CircuitV1, security is broken
        // Different circuits MUST have different trusted setups

        // ATTACK: If same setup parameters used, toxic waste from
        // CircuitV1 ceremony can be used to forge proofs for CircuitV2

        return _verify(proof, publicInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        return vk.alpha[0] != 0;
    }
}

/**
 * @title OutdatedParameterVault
 * @notice Using outdated parameters after circuit upgrade
 */
contract OutdatedParameterVault {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic;
    }

    VerifyingKey public currentVk;
    VerifyingKey public previousVk;

    uint256 public version;
    bool public allowOldProofs;

    /**
     * @notice VULNERABILITY 5: Accepts proofs from old circuit version
     * @dev After circuit upgrade, old proofs should be rejected
     */
    function verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        uint256 proofVersion
    ) external view returns (bool) {
        if (proofVersion == version) {
            return _verifyWithVk(proof, publicInputs, currentVk);
        }

        // VULNERABLE: Accepts old proofs if flag is set
        if (allowOldProofs && proofVersion == version - 1) {
            // SECURITY RISK: Old circuit might have known vulnerabilities
            // that were fixed in new version
            return _verifyWithVk(proof, publicInputs, previousVk);
        }

        return false;
    }

    /**
     * @notice VULNERABILITY 6: No sunset period for old parameters
     */
    function upgradeParameters(VerifyingKey calldata newVk) external {
        // VULNERABLE: Immediately switches to new parameters
        // Should have grace period where both old and new are invalid
        // to prevent front-running attacks

        previousVk = currentVk;
        currentVk = newVk;
        version++;

        // MISSING: Sunset period where no proofs accepted
        // during parameter transition
    }

    function _verifyWithVk(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        VerifyingKey memory vk
    ) internal pure returns (bool) {
        return vk.alpha[0] != 0 && proof[0] != 0;
    }
}

/**
 * @title CeremonyManipulation
 * @notice Trusted setup ceremony manipulation
 */
contract CeremonyManipulation {
    struct CeremonyContribution {
        address contributor;
        bytes32 contributionHash;
        uint256 timestamp;
    }

    CeremonyContribution[] public contributions;
    bool public ceremonyFinalized;

    /**
     * @notice VULNERABILITY 7: Single contribution can finalize ceremony
     * @dev Should require multiple independent contributions
     */
    function contribute(bytes32 contributionHash) external {
        require(!ceremonyFinalized, "Ceremony finalized");

        // VULNERABLE: Accepts any contribution without validation
        // MISSING: Proof of computation
        // MISSING: Verification of contribution validity
        // MISSING: Minimum number of contributors

        contributions.push(CeremonyContribution({
            contributor: msg.sender,
            timestamp: block.timestamp,
            contributionHash: contributionHash
        }));
    }

    /**
     * @notice VULNERABILITY 8: Admin can finalize with single contribution
     */
    address public admin;

    function finalizeCeremony() external {
        require(msg.sender == admin, "Not admin");

        // VULNERABLE: Can finalize with insufficient contributions
        // Should require minimum threshold (e.g., 10+ contributors)

        if (contributions.length < 2) {
            // WEAK: Only requires 2 contributions
            revert("Need more contributions");
        }

        ceremonyFinalized = true;

        // MISSING: Verification that contributions are independent
        // MISSING: Proof that toxic waste was destroyed
    }

    /**
     * @notice VULNERABILITY 9: No contribution verification
     */
    function verifyContribution(
        uint256 index,
        bytes calldata proof
    ) external view returns (bool) {
        require(index < contributions.length, "Invalid index");

        // VULNERABLE: No actual verification of contribution validity
        // Should verify that contribution correctly built on previous
        // and that contributor performed computation correctly

        // MISSING: Zero-knowledge proof that contribution is valid
        // MISSING: Verification of contribution chain

        return true; // Placeholder - no real verification!
    }
}

/**
 * @title ParameterValidation
 * @notice Missing parameter validation
 */
contract ParameterValidation {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][2] ic;
    }

    VerifyingKey public vk;

    /**
     * @notice VULNERABILITY 10: No validation of VK components
     * @dev VK components must satisfy certain mathematical properties
     */
    function setVerifyingKey(VerifyingKey calldata newVk) external {
        // VULNERABLE: No validation that VK components are valid points
        // on the elliptic curve used in the pairing

        // MISSING validations:
        // 1. Points are on curve
        // 2. Points are in correct subgroup
        // 3. Points are not identity/infinity
        // 4. IC length matches expected number of public inputs

        vk = newVk;

        // ATTACK: Invalid curve points can break verification or
        // allow forged proofs
    }

    /**
     * @notice VULNERABILITY 11: IC array size not validated
     */
    function verifyWithIC(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: No check that IC length matches publicInputs length
        if (vk.ic[0].length != publicInputs.length + 1) {
            // Should revert, but might not be checked
            // MISSING: require(vk.ic[0].length == publicInputs.length + 1, "IC size mismatch");
        }

        return _verify(proof, publicInputs);
    }

    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        return vk.alpha[0] != 0;
    }
}

/**
 * @title ToxicWasteLeakage
 * @notice Toxic waste handling vulnerabilities
 */
contract ToxicWasteLeakage {
    // Simulated toxic waste (in real ceremony, this would never be stored!)
    uint256 private tau; // Toxic waste parameter
    uint256 private alphaTau;
    uint256 private betaTau;

    bool public setupComplete;

    /**
     * @notice VULNERABILITY 12: Toxic waste stored in contract
     * @dev CRITICAL: Toxic waste must NEVER be stored or recoverable
     */
    function performSetup(
        uint256 _tau,
        uint256 _alphaTau,
        uint256 _betaTau
    ) external {
        require(!setupComplete, "Setup already done");

        // VULNERABLE: Storing toxic waste in contract state
        // CRITICAL SECURITY VIOLATION!
        tau = _tau;
        alphaTau = _alphaTau;
        betaTau = _betaTau;

        // Generate VK from parameters (simplified)
        // ...

        setupComplete = true;

        // MISSING: Secure deletion of toxic waste
        // In proper ceremony, toxic waste must be destroyed
        // and proven to be destroyed
    }

    /**
     * @notice VULNERABILITY 13: Toxic waste accessible via getter
     */
    function getTau() external view returns (uint256) {
        // CRITICAL VULNERABILITY: Exposing toxic waste
        // With toxic waste, can forge arbitrary proofs!
        return tau;
    }

    /**
     * @notice VULNERABILITY 14: Toxic waste in event logs
     */
    event SetupComplete(uint256 tau, uint256 alphaTau, uint256 betaTau);

    function setupWithEvent(
        uint256 _tau,
        uint256 _alphaTau,
        uint256 _betaTau
    ) external {
        // VULNERABLE: Toxic waste emitted in event
        // Events are permanently stored in blockchain history!
        emit SetupComplete(_tau, _alphaTau, _betaTau);

        // Even if variables are deleted, toxic waste is in event logs
        setupComplete = true;
    }
}

/**
 * @title UniversalSetupMisuse
 * @notice Universal/Updatable setup misuse
 */
contract UniversalSetupMisuse {
    bytes32 public srsHash; // Structured Reference String hash

    /**
     * @notice VULNERABILITY 15: Using untrusted universal setup
     * @dev Universal setup (PLONK, etc.) still requires trust in ceremony
     */
    function setSRS(bytes calldata srs) external {
        // VULNERABLE: Accepts any SRS without validation
        // Should verify SRS comes from trusted ceremony

        // MISSING: Verification that SRS is from known good ceremony
        // MISSING: Check against published ceremony outputs
        // MISSING: Community-verified SRS hash

        srsHash = keccak256(srs);
    }

    /**
     * @notice VULNERABILITY 16: No SRS size validation
     */
    function verifyWithSRS(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata srs
    ) external pure returns (bool) {
        // VULNERABLE: No validation of SRS size
        // SRS must be large enough for circuit size

        // MISSING: require(srs.length >= minimumSize, "SRS too small");

        // Using undersized SRS can break security

        return proof[0] != 0;
    }

    /**
     * @notice VULNERABILITY 17: SRS not bound to circuit
     */
    function verifyWithUnboundSRS(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // VULNERABLE: No verification that SRS matches circuit requirements
        // Different circuits might need different SRS properties

        // MISSING: Circuit-specific SRS validation

        return srsHash != bytes32(0);
    }
}

/**
 * @title MultiCircuitSetup
 * @notice Multiple circuits sharing setup
 */
contract MultiCircuitSetup {
    mapping(bytes32 => bool) public approvedCircuits;
    bytes32 public sharedSetupHash;

    /**
     * @notice VULNERABILITY 18: Circuits sharing setup parameters
     * @dev Each circuit should have independent setup
     */
    function addCircuit(bytes32 circuitHash) external {
        // VULNERABLE: Multiple circuits sharing same setup
        // If one circuit is compromised, all are at risk

        // MISSING: Independent setup verification per circuit
        // MISSING: Isolation between circuits

        approvedCircuits[circuitHash] = true;
    }

    /**
     * @notice VULNERABILITY 19: No circuit isolation
     */
    function verify(
        bytes32 circuitHash,
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        require(approvedCircuits[circuitHash], "Circuit not approved");

        // VULNERABLE: All circuits use sharedSetupHash
        // Compromise in one circuit can affect others

        return sharedSetupHash != bytes32(0) && proof[0] != 0;
    }
}

/**
 * @title CeremonyTransparency
 * @notice Lack of ceremony transparency
 */
contract CeremonyTransparency {
    bytes32 public finalParametersHash;
    bool public ceremonyComplete;

    /**
     * @notice VULNERABILITY 20: No public verifiability
     * @dev Ceremony results not publicly verifiable
     */
    function finalizeCeremony(bytes32 parametersHash) external {
        // VULNERABLE: Parameters just accepted without proof

        // MISSING: Transcript of all contributions
        // MISSING: Proof that each contribution was valid
        // MISSING: Public verification procedure
        // MISSING: Independent audits

        finalParametersHash = parametersHash;
        ceremonyComplete = true;
    }

    /**
     * @notice VULNERABILITY 21: No contribution attestations
     */
    function verifyContributor(address contributor) external pure returns (bool) {
        // VULNERABLE: No way to verify contributor participation

        // MISSING: Cryptographic attestation from contributors
        // MISSING: Proof that contributor destroyed their secret

        return true; // No verification!
    }
}
