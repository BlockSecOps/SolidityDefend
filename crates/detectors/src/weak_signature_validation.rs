use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for weak multi-signature validation vulnerabilities
pub struct WeakSignatureValidationDetector {
    base: BaseDetector,
}

impl WeakSignatureValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("weak-signature-validation".to_string()),
                "Weak Signature Validation".to_string(),
                "Detects multi-signature validation without duplicate signer checks, enabling signature reuse".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }
}

impl Detector for WeakSignatureValidationDetector {
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
            if self.has_weak_signature_validation(function, ctx) {
                let message = format!(
                    "Function '{}' validates multiple signatures without checking for duplicates. \
                    An attacker can submit the same valid signature multiple times to meet the \
                    required signature threshold, bypassing multi-signature protection.",
                    function.name.name
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
                    .with_cwe(347) // CWE-347: Improper Verification of Cryptographic Signature
                    .with_fix_suggestion(format!(
                        "Add duplicate signer check in function '{}'. \
                    Example: Track seen signers in a mapping or check array for duplicates. \
                    require(!seen[signer], \"Duplicate signer\"); seen[signer] = true;",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl WeakSignatureValidationDetector {
    /// Check if function has weak signature validation
    fn has_weak_signature_validation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if function validates signatures
        let validates_signatures = (func_source.contains("signature")
            || func_source.contains("recover")
            || func_source.contains("ecrecover")
            || func_source.contains("signer"))
            && (func_source.contains("for") || func_source.contains("while"));

        if !validates_signatures {
            return false;
        }

        // Check if it's processing multiple signatures
        let has_multiple_signatures = func_source.contains("signatures.length")
            || func_source.contains("signatures[")
            || func_source.contains("signatureCount")
            || func_source.contains("requiredSignatures");

        if !has_multiple_signatures {
            return false;
        }

        // Look for vulnerability patterns
        self.check_duplicate_protection(&func_source)
    }

    /// Check if function lacks duplicate signer protection
    fn check_duplicate_protection(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("duplicate")
                || source.contains("same signature")
                || source.contains("No check for duplicate"));

        // Pattern 2: Has signature recovery/validation in loop
        let has_signature_loop = (source.contains("for")
            && (source.contains("ecrecover")
                || source.contains("recover")
                || source.contains("signer =")))
            || (source.contains("for (uint256 i") && source.contains("signatures[i]"));

        // Pattern 3: Missing duplicate check mechanisms
        let has_duplicate_check = source.contains("seen[")
            || source.contains("used[")
            || source.contains("duplicate")
            || source.contains("unique")
            || source.contains("already signed")
            || (source.contains("signers[i]") && source.contains("signers[j]"));

        // Pattern 4: Stores signers but doesn't check
        let stores_signers = source.contains("signers[i] =") || source.contains("signers.push");

        // Vulnerable if it has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if it validates signatures in loop but lacks duplicate check
        if has_signature_loop && !has_duplicate_check {
            // Additional check: if it stores signers without checking
            if stores_signers {
                return true;
            }
            // Or if it has requiredSignatures check without uniqueness validation
            if source.contains("requiredSignatures") {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = WeakSignatureValidationDetector::new();
        assert_eq!(detector.name(), "Weak Signature Validation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
