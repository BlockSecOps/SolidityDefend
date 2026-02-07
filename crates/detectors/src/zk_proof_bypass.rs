use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ZK proof verification bypass vulnerabilities
pub struct ZkProofBypassDetector {
    base: BaseDetector,
}

impl ZkProofBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("zk-proof-bypass".to_string()),
                "ZK Proof Verification Bypass".to_string(),
                "Detects missing or incomplete ZK proof verification in rollup contracts, including proof replay vulnerabilities, public input manipulation, and batch submission without proper verification".to_string(),
                vec![DetectorCategory::L2, DetectorCategory::ZKRollup],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for ZkProofBypassDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Only run this detector on ZK rollup contracts
        if !contract_classification::is_zk_rollup_contract(ctx) {
            return Ok(findings); // Not a ZK rollup - skip analysis
        }

        // Exclude EIP-4844 blob/data-availability contracts that may share
        // some ZK terminology but are not ZK rollup proof verifiers
        if self.is_blob_or_da_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: This detector is specifically about ZK *rollup* proof
        // verification bypass (batch submission, state transitions). Contracts
        // that use ZK proofs for other purposes (voting, identity, privacy
        // pools, bridges, oracles, MEV protection, gas griefing) are not
        // rollup verifiers and should be skipped.
        if !self.has_rollup_signals(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);
            let is_view_or_pure = function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure;

            // Check for batch submission functions (state-changing only)
            if !is_view_or_pure
                && self.is_batch_submission_function(function.name.name, &func_source)
            {
                let issues = self.check_proof_verification(&func_source);

                if !issues.is_empty() {
                    let issues_text = issues.join(" ");
                    let message = format!(
                        "Function '{}' submits batches without proper ZK proof verification. {} \
                        Missing verification allows invalid state transitions to be accepted.",
                        function.name.name, issues_text
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_confidence(Confidence::High)
                        .with_fix_suggestion(format!(
                            "Add ZK proof verification to '{}': \
                            (1) Call verifier contract with proof and public inputs, \
                            (2) Require verification returns true before accepting batch, \
                            (3) Validate all public inputs match batch data, \
                            (4) Verify proof corresponds to correct circuit/proving system, \
                            (5) Check verifier contract is immutable and trusted.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for proof verification functions
            if self.is_proof_verification_function(function.name.name, &func_source) {
                let issues = self.check_verification_implementation(&func_source, is_view_or_pure);

                if !issues.is_empty() {
                    let issues_text = issues.join(" ");
                    let message = format!(
                        "Function '{}' implements proof verification with potential bypasses. {} \
                        Weak verification undermines the security guarantees of the ZK rollup.",
                        function.name.name, issues_text
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(20) // CWE-20: Improper Input Validation
                        .with_confidence(Confidence::High)
                        .with_fix_suggestion(format!(
                            "Strengthen verification in '{}': \
                            (1) Implement replay protection using proof hash or batch ID, \
                            (2) Validate all public inputs are correctly formatted, \
                            (3) Check proof size and format match expected parameters, \
                            (4) Ensure verifier contract call cannot be skipped, \
                            (5) Add event emission for proof verification.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for public input handling (state-changing only)
            if !is_view_or_pure && self.is_public_input_function(function.name.name, &func_source) {
                let issues = self.check_public_input_validation(&func_source);

                if !issues.is_empty() {
                    let issues_text = issues.join(" ");
                    let message = format!(
                        "Function '{}' handles public inputs without proper validation. {} \
                        Public input manipulation can lead to accepting invalid proofs.",
                        function.name.name, issues_text
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(20) // CWE-20: Improper Input Validation
                        .with_fix_suggestion(format!(
                            "Add public input validation to '{}': \
                            (1) Reconstruct public input hash from batch data, \
                            (2) Compare against provided public input to prevent manipulation, \
                            (3) Validate all public inputs are within valid ranges, \
                            (4) Check state root transitions are consistent, \
                            (5) Verify batch metadata matches public inputs.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ZkProofBypassDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    /// Check if the contract has rollup-specific signals (batch submission,
    /// state root transitions, L2/rollup terminology).
    ///
    /// Many contracts use ZK proofs (voting, identity, privacy pools, bridges,
    /// oracles, etc.) but are not rollup verifiers. This detector specifically
    /// targets rollup proof verification bypass, so we require at least one
    /// rollup-specific signal to avoid FPs on non-rollup ZK contracts.
    fn has_rollup_signals(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();
        let name_lower = ctx.contract.name.name.to_lowercase();

        // Contract name contains rollup-related terms
        if name_lower.contains("rollup")
            || name_lower.contains("sequencer")
            || name_lower.contains("batchverif")
        {
            return true;
        }

        // Batch submission patterns (the primary target of this detector)
        if source_lower.contains("submitbatch")
            || source_lower.contains("commitbatch")
            || source_lower.contains("executebatch")
            || source_lower.contains("provebatch")
            || source_lower.contains("commitblocks")
        {
            return true;
        }

        // State root transition patterns (hallmark of rollups)
        let has_state_root = source_lower.contains("stateroot")
            || source.contains("stateRoot")
            || source.contains("state_root");
        let has_batch_or_l2 = source_lower.contains("batch")
            || source_lower.contains("l2")
            || source_lower.contains("rollup");

        if has_state_root && has_batch_or_l2 {
            return true;
        }

        // Verifier contract name with rollup context
        if name_lower.contains("verifier")
            && (source_lower.contains("batch")
                || source_lower.contains("stateroot")
                || source_lower.contains("rollup"))
        {
            return true;
        }

        // Strong ZK proof system indicators (snark/stark/plonk/groth16)
        // combined with batch or state root signals
        let has_strong_zk = source_lower.contains("snark")
            || source_lower.contains("stark")
            || source_lower.contains("plonk")
            || source_lower.contains("groth16")
            || source_lower.contains("pairing")
            || source_lower.contains("bn256")
            || source_lower.contains("bls12");

        if has_strong_zk && has_state_root {
            return true;
        }

        false
    }

    /// Check if the contract is an EIP-4844 blob or data-availability contract.
    /// These contracts share some ZK-like terminology (proof, verify, batch,
    /// stateRoot) but are not ZK rollup proof verifiers.
    fn is_blob_or_da_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();
        let name_lower = ctx.contract.name.name.to_lowercase();

        // Strong blob/DA indicators
        let has_blob_indicator = source_lower.contains("blobhash")
            || source_lower.contains("blob_hash")
            || source_lower.contains("eip4844")
            || source_lower.contains("eip-4844")
            || source.contains("point_evaluation_precompile")
            || source.contains("POINT_EVALUATION_PRECOMPILE")
            || source_lower.contains("versionedhash")
            || name_lower.contains("blob");

        // Must also lack strong ZK-specific indicators to be classified as blob-only
        let has_strong_zk = source_lower.contains("snark")
            || source_lower.contains("stark")
            || source_lower.contains("plonk")
            || source_lower.contains("groth16")
            || source_lower.contains("pairing")
            || source_lower.contains("bn256")
            || source_lower.contains("bls12");

        has_blob_indicator && !has_strong_zk
    }

    fn is_batch_submission_function(&self, name: &str, _source: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Only match explicit batch submission function names.
        // The previous source-content fallback (checking for "batch" + "commit"/"execute"
        // in the function body) was too broad and matched non-ZK batch operations.
        let patterns = [
            "commitbatches",
            "executebatches",
            "provebatches",
            "submitbatch",
            "commitblocks",
            "verifyandexecutebatch",
        ];

        patterns.iter().any(|pattern| name_lower.contains(pattern))
    }

    fn is_proof_verification_function(&self, name: &str, source: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Exclude functions that manage verification parameters rather than
        // performing proof verification (e.g., updateVerifyingKey, setVerifyingKey,
        // verifyContribution, verifyContributor)
        let excluded_prefixes = ["update", "set", "get", "remove", "delete", "init"];
        let excluded_suffixes = [
            "contribution",
            "contributor",
            "key",
            "keys",
            "identity",
            "ic",
            "srs",
        ];

        for prefix in &excluded_prefixes {
            if name_lower.starts_with(prefix) {
                return false;
            }
        }
        for suffix in &excluded_suffixes {
            if name_lower.ends_with(suffix) {
                return false;
            }
        }

        // Strong name-based matches: function name explicitly involves proof verification
        let strong_patterns = ["verifyproof", "verifybatchproof", "verifyaggregatedproof"];
        if strong_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
        {
            return true;
        }

        // Moderate name-based match: function is named exactly "verify" or starts
        // with "verify" and the function body references proof-related terms
        if name_lower == "verify"
            || (name_lower.starts_with("verify")
                && (source.contains("proof") || source.contains("Proof")))
        {
            return true;
        }

        false
    }

    fn is_public_input_function(&self, name: &str, _source: &str) -> bool {
        let patterns = [
            "validatePublicInput",
            "checkPublicInput",
            "reconstructPublicInput",
        ];

        let name_lower = name.to_lowercase();
        // FP Reduction: Only match by function name, not by source content.
        // The previous `source.contains("publicInput")` check was far too broad
        // and matched every function in a ZK contract that takes publicInputs as
        // a parameter, producing findings for generic verify/deposit/withdraw
        // functions that merely accept public inputs but don't validate them.
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
    }

    fn check_proof_verification(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Missing verifier call
        let has_verifier_call = source.contains("verifier.verify")
            || source.contains(".verifyProof")
            || source.contains("IVerifier")
            || source.contains("verify(");

        if !has_verifier_call {
            issues.push(
                "No verifier contract call detected. Must call external verifier to validate ZK proof."
                    .to_string(),
            );
        }

        // Pattern 2: No require check on verification result
        if source.contains("verify") && !source.contains("require") && !source.contains("revert") {
            issues.push(
                "Verification result not enforced with require(). Proof verification can be bypassed."
                    .to_string(),
            );
        }

        // Pattern 3: Missing public input validation
        if !source.contains("publicInput") && !source.contains("public_input") {
            issues.push(
                "No public input parameter. ZK proofs must be verified against specific public inputs."
                    .to_string(),
            );
        }

        issues
    }

    fn check_verification_implementation(
        &self,
        source: &str,
        is_view_or_pure: bool,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No proof format validation -- this is the strongest signal
        // of a weak verifier implementation
        if source.contains("proof") && !source.contains("length") && !source.contains(".length") {
            issues.push(
                "Missing proof format validation. Should check proof data length and structure."
                    .to_string(),
            );
        }

        // Pattern 2: Missing public input reconstruction
        if !source.contains("keccak256")
            && !source.contains("sha256")
            && !source.contains("hash")
            && !source.contains("Hash")
        {
            issues.push(
                "No public input hash computation. Should reconstruct hash from batch data to prevent manipulation."
                    .to_string(),
            );
        }

        // The following checks only apply to state-changing functions since
        // view/pure functions cannot emit events or write state for replay tracking.
        if !is_view_or_pure {
            // Pattern 3: Missing replay protection
            if source.contains("verify")
                && !source.contains("proven")
                && !source.contains("verified")
                && !source.contains("nullifier")
                && !source.contains("used")
            {
                issues.push(
                    "No replay protection. Should track verified proofs to prevent replay attacks."
                        .to_string(),
                );
            }

            // Pattern 4: Missing event emission
            if !source.contains("emit") {
                issues.push(
                    "No event emission for proof verification. Should emit event for monitoring and auditing."
                        .to_string(),
                );
            }
        }

        issues
    }

    fn check_public_input_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No hash comparison
        if source.contains("publicInput") && !source.contains("==") {
            issues.push(
                "Public input not compared against reconstructed value. Attacker can provide manipulated inputs."
                    .to_string(),
            );
        }

        // Pattern 2: Missing state root validation
        if !source.contains("oldStateRoot")
            && !source.contains("newStateRoot")
            && !source.contains("stateRoot")
        {
            issues.push(
                "Missing state root in public inputs. Should validate state root transitions."
                    .to_string(),
            );
        }

        // Pattern 3: No batch metadata validation
        if !source.contains("batchNumber") && !source.contains("timestamp") {
            issues.push(
                "Missing batch metadata validation. Should verify batch number and timestamp in public inputs."
                    .to_string(),
            );
        }

        // Pattern 4: Missing range checks
        if source.contains("publicInput") && !source.contains("require") {
            issues.push(
                "No require statements for public input validation. Should enforce value ranges and constraints."
                    .to_string(),
            );
        }

        issues
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Default for ZkProofBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ZkProofBypassDetector::new();
        assert_eq!(detector.name(), "ZK Proof Verification Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "zk-proof-bypass");
        assert!(detector.categories().contains(&DetectorCategory::L2));
        assert!(detector.categories().contains(&DetectorCategory::ZKRollup));
    }

    #[test]
    fn test_is_batch_submission_function() {
        let detector = ZkProofBypassDetector::new();

        // True positives: explicit batch submission names
        assert!(detector.is_batch_submission_function("commitBatches", ""));
        assert!(detector.is_batch_submission_function("executeBatches", ""));
        assert!(detector.is_batch_submission_function("proveBatches", ""));
        assert!(detector.is_batch_submission_function("submitBatch", ""));

        // True negatives: non-batch functions
        assert!(!detector.is_batch_submission_function("withdraw", ""));
        assert!(!detector.is_batch_submission_function("deposit", ""));

        // False positive reduction: source-content fallback no longer matches
        assert!(!detector.is_batch_submission_function("processData", "batch commit execute"));
    }

    #[test]
    fn test_is_proof_verification_function() {
        let detector = ZkProofBypassDetector::new();

        // True positives: proof verification functions
        assert!(detector.is_proof_verification_function("verifyProof", ""));
        assert!(detector.is_proof_verification_function("verifyAggregatedProof", ""));
        assert!(detector.is_proof_verification_function("verify", ""));
        assert!(detector.is_proof_verification_function("verifyBatch", "proof verification"));

        // True negatives: non-verification functions
        assert!(!detector.is_proof_verification_function("submit", ""));
        assert!(!detector.is_proof_verification_function("deposit", ""));

        // False positive reduction: parameter/key management functions excluded
        assert!(!detector.is_proof_verification_function("updateVerifyingKey", "proof"));
        assert!(!detector.is_proof_verification_function("setVerifyingKey", "proof"));
        assert!(!detector.is_proof_verification_function("getVerifyingKey", "proof"));
        assert!(!detector.is_proof_verification_function("verifyContribution", "proof"));
        assert!(!detector.is_proof_verification_function("verifyContributor", "proof"));
        assert!(!detector.is_proof_verification_function("verifyIdentity", "proof"));
    }

    #[test]
    fn test_is_proof_verification_function_verify_prefix_needs_proof_context() {
        let detector = ZkProofBypassDetector::new();

        // "verify" prefix without proof context should not match
        assert!(!detector.is_proof_verification_function("verifyOwner", ""));
        assert!(!detector.is_proof_verification_function("verifySignature", "signature ecrecover"));

        // "verify" prefix with proof context should match
        assert!(detector.is_proof_verification_function("verifyWithPublicInputs", "proof data"));
        assert!(detector.is_proof_verification_function("verifyRecursive", "recursive proof"));
    }

    #[test]
    fn test_blob_da_contract_exclusion() {
        let detector = ZkProofBypassDetector::new();

        // EIP-4844 blob contracts should be excluded (uses source-level indicators)
        let blob_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract BlobProcessor {
                    address constant POINT_EVALUATION_PRECOMPILE = address(0x0a);
                    function processBlobData(bytes32 versionedHash) external {
                        // Uses blobhash opcode for EIP-4844
                    }
                    function verifyBlobProof(bytes memory proof) external view returns (bool) {
                        (bool success,) = POINT_EVALUATION_PRECOMPILE.staticcall(
                            abi.encode(versionedHash, proof)
                        );
                        return success;
                    }
                }
                "#,
        );
        assert!(detector.is_blob_or_da_contract(&blob_ctx));

        // Real ZK contracts with pairing should not be excluded
        let zk_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKVerifier {
                    function verifyProof(uint256[8] calldata proof) external returns (bool) {
                        return pairing(proof);
                    }
                }
                "#,
        );
        assert!(!detector.is_blob_or_da_contract(&zk_ctx));

        // Contract with both blob and ZK (snark) indicators should not be excluded
        let mixed_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKBlobVerifier {
                    function verifyProof(uint256[8] calldata proof) external returns (bool) {
                        // Uses both blobhash and snark verification
                        return snark_verify(proof);
                    }
                }
                "#,
        );
        assert!(!detector.is_blob_or_da_contract(&mixed_ctx));
    }

    #[test]
    fn test_check_proof_verification_missing_verifier() {
        let detector = ZkProofBypassDetector::new();
        let source = "function commitBatches() public { }";
        let issues = detector.check_proof_verification(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("verifier contract call")));
    }

    #[test]
    fn test_check_proof_verification_with_verifier() {
        let detector = ZkProofBypassDetector::new();
        let source = r#"
            function commitBatches(bytes calldata proof, uint256[] calldata publicInput) public {
                require(verifier.verify(proof, publicInput), "Invalid proof");
                require(!proofHash[keccak256(proof)]);
                proofHash[keccak256(proof)] = true;
            }
        "#;
        let issues = detector.check_proof_verification(source);

        // Should have minimal issues with proper verification
        assert!(issues.is_empty());
    }

    #[test]
    fn test_check_verification_implementation() {
        let detector = ZkProofBypassDetector::new();
        let source =
            "function verifyProof(bytes calldata proof) public returns (bool) { return true; }";
        let issues = detector.check_verification_implementation(source, false);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("replay protection")));
    }

    #[test]
    fn test_check_verification_skips_state_checks_for_view_pure() {
        let detector = ZkProofBypassDetector::new();

        // A view function: should not flag replay protection or event emission
        let source = "function verifyProof(bytes calldata proof) public view returns (bool) { return true; }";
        let issues = detector.check_verification_implementation(source, true);

        // Should not contain replay or event emission issues
        assert!(!issues.iter().any(|i| i.contains("replay protection")));
        assert!(!issues.iter().any(|i| i.contains("event emission")));

        // Should still flag proof format validation and hash computation
        assert!(issues.iter().any(|i| i.contains("proof format")));
    }

    #[test]
    fn test_check_public_input_validation() {
        let detector = ZkProofBypassDetector::new();
        let source = "function validatePublicInput(uint256[] calldata publicInput) public { }";
        let issues = detector.check_public_input_validation(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("state root")));
    }

    #[test]
    fn test_check_public_input_with_validation() {
        let detector = ZkProofBypassDetector::new();
        let source = r#"
            function validatePublicInput(uint256[] calldata publicInput) public {
                bytes32 computed = keccak256(abi.encodePacked(oldStateRoot, newStateRoot, batchNumber));
                require(publicInput[0] == uint256(computed));
                require(batchNumber > lastBatchNumber);
            }
        "#;
        let issues = detector.check_public_input_validation(source);

        // Should have fewer issues with proper validation
        assert!(issues.len() < 2);
    }

    #[test]
    fn test_consolidated_findings_per_function() {
        // Verify that check methods return multiple issues but the detect loop
        // consolidates them into a single finding per function
        let detector = ZkProofBypassDetector::new();
        let source = "function verify(bytes calldata proof) public { return true; }";
        let issues = detector.check_verification_implementation(source, false);

        // Multiple issues should exist
        assert!(
            issues.len() >= 2,
            "Expected multiple issues, got {}",
            issues.len()
        );

        // But when reported, they would be joined into one finding (tested
        // at integration level via the detect method)
    }

    #[test]
    fn test_batch_submission_no_longer_matches_generic_source() {
        let detector = ZkProofBypassDetector::new();

        // Previously this would match due to source-content fallback
        // Now it should not match because the function name is not a batch name
        assert!(!detector.is_batch_submission_function(
            "withdraw",
            "process batch and commit data then execute"
        ));
        assert!(!detector.is_batch_submission_function(
            "processBlob",
            "submitBatch commit execute batch stateRoot"
        ));
    }

    #[test]
    fn test_has_rollup_signals_batch_submission() {
        let detector = ZkProofBypassDetector::new();

        // Contracts with batch submission patterns should have rollup signals
        let rollup_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKRollup {
                    function submitBatch(uint256[8] calldata proof) external {
                        // Submit batch
                    }
                }
            "#,
        );
        assert!(detector.has_rollup_signals(&rollup_ctx));
    }

    #[test]
    fn test_has_rollup_signals_state_root_with_batch() {
        let detector = ZkProofBypassDetector::new();

        // Contracts with stateRoot + batch should have rollup signals
        let rollup_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKVerifier {
                    bytes32 public stateRoot;
                    function processBatch(bytes calldata batch, uint256[8] calldata proof) external {
                        stateRoot = keccak256(batch);
                    }
                }
            "#,
        );
        assert!(detector.has_rollup_signals(&rollup_ctx));
    }

    #[test]
    fn test_has_rollup_signals_false_for_non_rollup_zk() {
        let detector = ZkProofBypassDetector::new();

        // ZK voting contract should not have rollup signals
        let voting_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKVoting {
                    function vote(uint256[8] calldata proof) external {
                        // Vote with proof
                    }
                }
            "#,
        );
        assert!(!detector.has_rollup_signals(&voting_ctx));

        // ZK identity contract should not have rollup signals
        let identity_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKIdentity {
                    function verifyIdentity(uint256[8] calldata proof) external {
                        // Verify identity
                    }
                }
            "#,
        );
        assert!(!detector.has_rollup_signals(&identity_ctx));

        // ZK privacy pool should not have rollup signals
        let privacy_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKPrivacyPool {
                    function withdraw(uint256[8] calldata proof, bytes32 nullifier) external {
                        // Privacy pool withdrawal
                    }
                }
            "#,
        );
        assert!(!detector.has_rollup_signals(&privacy_ctx));
    }

    #[test]
    fn test_has_rollup_signals_snark_with_state_root() {
        let detector = ZkProofBypassDetector::new();

        // Strong ZK (snark) + stateRoot should have rollup signals
        let rollup_ctx = crate::types::test_utils::create_test_context(
            r#"
                contract ZKVerifier {
                    bytes32 public stateRoot;
                    function verify(uint256[8] calldata proof) external returns (bool) {
                        // SNARK verification for state transition
                        return snark_verify(proof);
                    }
                }
            "#,
        );
        assert!(detector.has_rollup_signals(&rollup_ctx));
    }

    #[test]
    fn test_is_public_input_function_name_only() {
        let detector = ZkProofBypassDetector::new();

        // Function name should match
        assert!(detector.is_public_input_function("validatePublicInput", ""));
        assert!(detector.is_public_input_function("checkPublicInput", ""));
        assert!(detector.is_public_input_function("reconstructPublicInput", ""));

        // Source containing "publicInput" alone should NOT match
        // (this was the FP-heavy pattern before the fix)
        assert!(!detector.is_public_input_function(
            "verifyProof",
            "require(verifier.verify(proof, publicInput))"
        ));
        assert!(!detector.is_public_input_function("withdraw", "uint256[] calldata publicInput"));
    }
}
