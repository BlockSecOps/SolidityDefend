use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

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

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for batch submission functions
            if self.is_batch_submission_function(&function.name.name, &func_source) {
                let issues = self.check_proof_verification(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' submits batches without proper ZK proof verification. {} \
                        Missing verification allows invalid state transitions to be accepted.",
                        function.name.name, issue
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
            if self.is_proof_verification_function(&function.name.name, &func_source) {
                let issues = self.check_verification_implementation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' implements proof verification with potential bypasses. {} \
                        Weak verification undermines the security guarantees of the ZK rollup.",
                        function.name.name, issue
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

            // Check for public input handling
            if self.is_public_input_function(&function.name.name, &func_source) {
                let issues = self.check_public_input_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' handles public inputs without proper validation. {} \
                        Public input manipulation can lead to accepting invalid proofs.",
                        function.name.name, issue
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

    fn is_batch_submission_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "commitBatches",
            "executeBatches",
            "proveBatches",
            "submitBatch",
            "commitBlocks",
            "verifyAndExecuteBatch",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("batch") && (source.contains("commit") || source.contains("execute")))
    }

    fn is_proof_verification_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "verifyProof",
            "verifyAggregatedProof",
            "verifyBatchProof",
            "verify",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("proof") && source.contains("verify"))
    }

    fn is_public_input_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "validatePublicInput",
            "checkPublicInput",
            "reconstructPublicInput",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || source.contains("publicInput")
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
                "No verifier contract call detected. Must call external verifier to validate ZK proof"
                    .to_string(),
            );
        }

        // Pattern 2: No require check on verification result
        if source.contains("verify") && !source.contains("require") && !source.contains("revert") {
            issues.push(
                "Verification result not enforced with require(). Proof verification can be bypassed"
                    .to_string(),
            );
        }

        // Pattern 3: Missing public input validation
        if !source.contains("publicInput") && !source.contains("public_input") {
            issues.push(
                "No public input parameter. ZK proofs must be verified against specific public inputs"
                    .to_string(),
            );
        }

        // Pattern 4: No proof replay protection
        if !source.contains("proofHash")
            && !source.contains("batchId")
            && !source.contains("commitmentHash")
        {
            issues.push(
                "Missing proof replay protection. Store proof hash or batch ID to prevent reuse"
                    .to_string(),
            );
        }

        issues
    }

    fn check_verification_implementation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Missing replay protection
        if source.contains("verify") && !source.contains("proven") && !source.contains("verified") {
            issues.push(
                "No replay protection. Should track verified proofs to prevent replay attacks"
                    .to_string(),
            );
        }

        // Pattern 2: No proof format validation
        if source.contains("proof") && !source.contains("length") {
            issues.push(
                "Missing proof format validation. Should check proof data length and structure"
                    .to_string(),
            );
        }

        // Pattern 3: Missing public input reconstruction
        if !source.contains("keccak256") && !source.contains("sha256") && !source.contains("hash") {
            issues.push(
                "No public input hash computation. Should reconstruct hash from batch data to prevent manipulation"
                    .to_string(),
            );
        }

        // Pattern 4: No verifier address validation
        if source.contains("verifier") && !source.contains("immutable") && !source.contains("constant") {
            issues.push(
                "Verifier address not immutable. Should use immutable verifier address to prevent upgrades to malicious verifier"
                    .to_string(),
            );
        }

        // Pattern 5: Missing event emission
        if !source.contains("emit") {
            issues.push(
                "No event emission for proof verification. Should emit event for monitoring and auditing"
                    .to_string(),
            );
        }

        issues
    }

    fn check_public_input_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No hash comparison
        if source.contains("publicInput") && !source.contains("==") {
            issues.push(
                "Public input not compared against reconstructed value. Attacker can provide manipulated inputs"
                    .to_string(),
            );
        }

        // Pattern 2: Missing state root validation
        if !source.contains("oldStateRoot")
            && !source.contains("newStateRoot")
            && !source.contains("stateRoot")
        {
            issues.push(
                "Missing state root in public inputs. Should validate state root transitions"
                    .to_string(),
            );
        }

        // Pattern 3: No batch metadata validation
        if !source.contains("batchNumber") && !source.contains("timestamp") {
            issues.push(
                "Missing batch metadata validation. Should verify batch number and timestamp in public inputs"
                    .to_string(),
            );
        }

        // Pattern 4: Missing range checks
        if source.contains("publicInput") && !source.contains("require") {
            issues.push(
                "No require statements for public input validation. Should enforce value ranges and constraints"
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

        assert!(detector.is_batch_submission_function("commitBatches", ""));
        assert!(detector.is_batch_submission_function("executeBatches", ""));
        assert!(detector.is_batch_submission_function("proveBatches", ""));
        assert!(!detector.is_batch_submission_function("withdraw", ""));
    }

    #[test]
    fn test_is_proof_verification_function() {
        let detector = ZkProofBypassDetector::new();

        assert!(detector.is_proof_verification_function("verifyProof", ""));
        assert!(detector.is_proof_verification_function("verifyAggregatedProof", ""));
        assert!(detector.is_proof_verification_function("verify", ""));
        assert!(!detector.is_proof_verification_function("submit", ""));
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
        assert!(issues.len() == 0);
    }

    #[test]
    fn test_check_verification_implementation() {
        let detector = ZkProofBypassDetector::new();
        let source = "function verifyProof(bytes calldata proof) public returns (bool) { return true; }";
        let issues = detector.check_verification_implementation(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("replay protection")));
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
}
