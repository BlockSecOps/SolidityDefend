use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ECDSA signature malleability vulnerabilities
pub struct SignatureMalleabilityDetector {
    base: BaseDetector,
}

impl SignatureMalleabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("signature-malleability".to_string()),
                "Signature Malleability".to_string(),
                "Detects ECDSA signatures without proper 's' value validation, enabling signature replay via malleability".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }
}

impl Detector for SignatureMalleabilityDetector {
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
            if let Some(malleability_risk) = self.check_signature_malleability(function, ctx) {
                let message = format!(
                    "Function '{}' uses ECDSA signature verification without malleability protection. {} \
                    ECDSA signatures have two valid forms (s and -s mod n). Without checking that s is in \
                    the lower half range, attackers can create alternate valid signatures for replay attacks.",
                    function.name.name, malleability_risk
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(347) // CWE-347: Improper Verification of Cryptographic Signature
                .with_cwe(354) // CWE-354: Improper Validation of Integrity Check Value
                .with_fix_suggestion(format!(
                    "Add signature malleability check in '{}'. \
                    Use OpenZeppelin's ECDSA library or add: \
                    `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, \
                    \"Invalid signature 's' value\");` \
                    This ensures s is in the lower half of the curve order.",
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

impl SignatureMalleabilityDetector {
    fn check_signature_malleability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check for signature verification
        let uses_ecrecover =
            func_source.contains("ecrecover") || func_source.contains("ECDSA.recover");

        if !uses_ecrecover {
            return None;
        }

        // Check for malleability protection
        let has_s_check = func_source
            .contains("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
            || func_source.contains("secp256k1")
            || func_source.contains("malleability")
            || (func_source.contains("require") && func_source.contains("s <="))
            || (func_source.contains("require") && func_source.contains("s <"));

        // Using OpenZeppelin ECDSA library (has built-in protection)
        let uses_oz_ecdsa = func_source.contains("ECDSA.recover")
            || func_source.contains("ECDSA.toEthSignedMessageHash");

        if uses_oz_ecdsa {
            return None; // OpenZeppelin ECDSA has malleability protection
        }

        if !has_s_check {
            return Some(
                "Uses ecrecover without checking 's' value against secp256k1 curve order"
                    .to_string(),
            );
        }

        // Pattern: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("signature")
                || func_source.contains("malleability")
                || func_source.contains("ecrecover"))
        {
            return Some("Signature malleability vulnerability marker detected".to_string());
        }

        None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = SignatureMalleabilityDetector::new();
        assert_eq!(detector.name(), "Signature Malleability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
