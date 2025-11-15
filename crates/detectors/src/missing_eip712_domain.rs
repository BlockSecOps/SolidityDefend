use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

/// Detector for missing EIP-712 domain separator in signature validation
pub struct MissingEIP712DomainDetector {
    base: BaseDetector,
}

impl Default for MissingEIP712DomainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingEIP712DomainDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-eip712-domain".to_string()),
                "Missing EIP-712 Domain Separator".to_string(),
                "Detects signature verification without proper EIP-712 domain separator, leading to cross-contract and cross-chain replay vulnerabilities".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }

    fn check_missing_eip712_domain(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);

        // Check if function uses ecrecover
        if !func_source.contains("ecrecover") {
            return None;
        }

        // Skip if uses OpenZeppelin ECDSA library (has built-in protection)
        if func_source.contains("ECDSA.recover") || func_source.contains("ECDSA.tryRecover") {
            return None;
        }

        // Check for proper EIP-712 domain separator usage
        let has_eip712 = func_source.contains("\\x19\\x01") && func_source.contains("DOMAIN_SEPARATOR");
        let has_domain_construction = func_source.contains("EIP712Domain") && func_source.contains("chainId");
        let has_eip191_prefix = func_source.contains("\\x19Ethereum Signed Message") ||
                                 func_source.contains("toEthSignedMessageHash");

        if has_eip712 || has_domain_construction || has_eip191_prefix {
            return None;
        }

        // Check for test contracts
        if func_source.contains("contract Test") || func_source.contains("contract Mock") {
            return None;
        }

        Some(
            "Uses ecrecover() without proper EIP-712 domain separator. \
            Signatures are vulnerable to replay attacks across contracts and chains."
                .to_string(),
        )
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

impl Detector for MissingEIP712DomainDetector {
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
            if let Some(issue) = self.check_missing_eip712_domain(function, ctx) {
                let message = format!(
                    "Function '{}' {}",
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
                    .with_fix_suggestion(
                        "Implement proper EIP-712 domain separator:\n\
                        1. Define DOMAIN_SEPARATOR with all required fields (name, version, chainId, verifyingContract)\n\
                        2. Use structured data hashing with EIP-712\n\
                        3. Include domain separator in signature hash: keccak256(abi.encodePacked(\"\\x19\\x01\", DOMAIN_SEPARATOR, structHash))\n\
                        4. Or use OpenZeppelin's EIP712 implementation"
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = MissingEIP712DomainDetector::new();
        assert_eq!(detector.name(), "Missing EIP-712 Domain Separator");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
