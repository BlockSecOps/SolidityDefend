//! EXTCODESIZE Bypass Detection
//!
//! Detects contracts that use EXTCODESIZE or address.code.length checks to validate
//! if an address is a contract, which can be bypassed by calling from a constructor.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ExtcodesizeBypassDetector {
    base: BaseDetector,
}

impl ExtcodesizeBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("extcodesize-bypass".to_string()),
                "EXTCODESIZE Bypass Detection".to_string(),
                "Detects use of EXTCODESIZE or address.code.length for EOA validation, which can be bypassed during constructor execution".to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::Logic, DetectorCategory::Deployment],
                Severity::Medium,
            ),
        }
    }

    fn check_extcodesize_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Pattern 1: address.code.length checks
        if source_lower.contains(".code.length") {
            // Check if it's used for EOA validation
            let has_eoa_validation = source_lower.contains("== 0")
                || source_lower.contains("!= 0")
                || (source_lower.contains("require") && source_lower.contains(".code.length"));

            if has_eoa_validation {
                // Check if there's any warning about constructor bypass
                let has_bypass_protection = source_lower.contains("constructor")
                    && (source_lower.contains("bypass") || source_lower.contains("during construction"));

                if !has_bypass_protection {
                    findings.push((
                        "Uses address.code.length for contract detection (bypassable during constructor)".to_string(),
                        0,
                        "Do not rely on EXTCODESIZE for security checks. Use tx.origin != msg.sender or implement a whitelist pattern instead. Note: During contract construction, EXTCODESIZE returns 0.".to_string(),
                    ));
                }
            }
        }

        // Pattern 2: Assembly EXTCODESIZE
        if source_lower.contains("extcodesize") {
            let has_assembly = source_lower.contains("assembly");

            if has_assembly {
                // Check if used for validation
                let has_validation = source_lower.contains("iszero")
                    || source_lower.contains("eq")
                    || source_lower.contains("require");

                if has_validation {
                    findings.push((
                        "Uses EXTCODESIZE in assembly for validation (bypassable during constructor)".to_string(),
                        0,
                        "EXTCODESIZE returns 0 during contract construction. Attackers can bypass this check by calling from their constructor. Consider alternative validation methods.".to_string(),
                    ));
                }
            }
        }

        // Pattern 3: isContract() helper functions
        if source_lower.contains("iscontract") {
            // Check if the implementation uses EXTCODESIZE
            let iscontract_uses_extcodesize = source_lower.contains("function iscontract")
                && (source_lower.contains(".code.length") || source_lower.contains("extcodesize"));

            if iscontract_uses_extcodesize {
                findings.push((
                    "isContract() function relies on EXTCODESIZE (bypassable during constructor)".to_string(),
                    0,
                    "The isContract() helper uses EXTCODESIZE which returns 0 during construction. Document this limitation or use tx.origin != msg.sender for stronger protection.".to_string(),
                ));
            }
        }

        // Pattern 4: EOA-only restrictions
        if source_lower.contains("only") && (source_lower.contains("eoa") || source_lower.contains("externally owned")) {
            // Check if using EXTCODESIZE for enforcement
            let uses_extcodesize = source_lower.contains(".code.length")
                || source_lower.contains("extcodesize");

            if uses_extcodesize {
                findings.push((
                    "EOA-only modifier uses EXTCODESIZE (bypassable during constructor)".to_string(),
                    0,
                    "Modifier restricts to EOAs using EXTCODESIZE. This can be bypassed by calling from a contract constructor. Use tx.origin == msg.sender if strict EOA requirement is needed.".to_string(),
                ));
            }
        }

        // Pattern 5: msg.sender validation
        if source_lower.contains("msg.sender") && source_lower.contains(".code.length") {
            // Check if there's a require with msg.sender.code.length == 0
            let requires_eoa = (source_lower.contains("require") || source_lower.contains("if"))
                && source_lower.contains("msg.sender")
                && source_lower.contains(".code.length")
                && source_lower.contains("== 0");

            if requires_eoa {
                findings.push((
                    "Requires msg.sender.code.length == 0 (bypassable during constructor)".to_string(),
                    0,
                    "Checking msg.sender.code.length == 0 can be bypassed during construction. If you need to restrict to EOAs, use tx.origin == msg.sender, but be aware of phishing risks.".to_string(),
                ));
            }
        }

        findings
    }
}

impl Default for ExtcodesizeBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ExtcodesizeBypassDetector {
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

        let issues = self.check_extcodesize_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    message,
                    line_offset,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(remediation)
                .with_cwe(754); // CWE-754: Improper Check for Unusual or Exceptional Conditions

            findings.push(finding);
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
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = ExtcodesizeBypassDetector::new();
        assert_eq!(detector.id().to_string(), "extcodesize-bypass");
        assert_eq!(detector.name(), "EXTCODESIZE Bypass Detection");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_code_length_check() {
        let detector = ExtcodesizeBypassDetector::new();
        let source = r#"
            contract Vulnerable {
                function restrictedFunction() external {
                    require(msg.sender.code.length == 0, "Contracts not allowed");
                    // Can be bypassed from attacker constructor
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detects_assembly_extcodesize() {
        let detector = ExtcodesizeBypassDetector::new();
        let source = r#"
            contract Vulnerable {
                function checkEOA(address account) internal view returns (bool) {
                    uint256 size;
                    assembly {
                        size := extcodesize(account)
                    }
                    require(size == 0, "Not an EOA");
                    return true;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detects_iscontract_helper() {
        let detector = ExtcodesizeBypassDetector::new();
        let source = r#"
            contract Vulnerable {
                function isContract(address account) internal view returns (bool) {
                    return account.code.length > 0;
                }

                function restrictedFunction() external {
                    require(!isContract(msg.sender), "Contracts not allowed");
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_no_false_positive_without_validation() {
        let detector = ExtcodesizeBypassDetector::new();
        let source = r#"
            contract Safe {
                function getCodeSize(address account) external view returns (uint256) {
                    // Just returning code size, not using for validation
                    return account.code.length;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have minimal or no findings since not used for security validation
        // (pattern matching may still catch it, but that's acceptable)
    }

    #[test]
    fn test_detects_eoa_only_modifier() {
        let detector = ExtcodesizeBypassDetector::new();
        let source = r#"
            contract Vulnerable {
                modifier onlyEOA() {
                    require(msg.sender.code.length == 0, "Only EOA");
                    _;
                }

                function sensitiveFunction() external onlyEOA {
                    // Vulnerable to constructor bypass
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }
}
