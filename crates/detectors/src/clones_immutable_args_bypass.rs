use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ClonesWithImmutableArgs bypass vulnerability
///
/// Detects usage of ClonesWithImmutableArgs pattern where "immutable" arguments
/// can be bypassed via crafted calldata. The args are read from calldata, not storage.
///
/// Vulnerable pattern:
/// ```solidity
/// contract Clone {
///     function getOwner() public view returns (address) {
///         return _getArgAddress(0); // Reads from calldata!
///     }
///     function doSomething() external {
///         require(msg.sender == getOwner()); // Can be bypassed!
///     }
/// }
/// ```
pub struct ClonesImmutableArgsBypassDetector {
    base: BaseDetector,
}

impl Default for ClonesImmutableArgsBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClonesImmutableArgsBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("clones-immutable-args-bypass"),
                "ClonesWithImmutableArgs Bypass".to_string(),
                "Detects ClonesWithImmutableArgs pattern where 'immutable' arguments can be \
                 spoofed via crafted calldata. These args are read from calldata at runtime, \
                 not stored in contract storage, making them vulnerable to manipulation."
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::AccessControl,
                ],
                Severity::High,
            ),
        }
    }

    /// Check if contract uses ClonesWithImmutableArgs pattern
    fn uses_immutable_args(&self, source: &str) -> bool {
        source.contains("_getArgAddress")
            || source.contains("_getArgUint256")
            || source.contains("_getArgUint128")
            || source.contains("_getArgUint64")
            || source.contains("_getArgBytes32")
            || source.contains("_getArgBytes")
            || source.contains("ClonesWithImmutableArgs")
            || source.contains("Clone.sol")
    }

    /// Find usages of _getArg functions for access control
    fn find_access_control_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for _getArg in require/if statements
            if (trimmed.contains("require(") || trimmed.contains("if ("))
                && (trimmed.contains("_getArgAddress")
                    || trimmed.contains("_getArgUint")
                    || trimmed.contains("_getArgBytes32"))
            {
                findings.push((line_num as u32 + 1, "access control check".to_string()));
            }

            // Check for msg.sender comparison with _getArg result
            if trimmed.contains("msg.sender")
                && (trimmed.contains("_getArgAddress") || trimmed.contains("getOwner"))
            {
                findings.push((line_num as u32 + 1, "sender comparison".to_string()));
            }

            // Check for owner/admin getter using _getArg
            if (trimmed.contains("function owner")
                || trimmed.contains("function admin")
                || trimmed.contains("function getOwner"))
                && source.contains("_getArgAddress")
            {
                // Check if the function body uses _getArgAddress
                let func_end = std::cmp::min(line_num + 10, lines.len());
                let func_context: String = lines[line_num..func_end].join("\n");
                if func_context.contains("_getArgAddress") {
                    findings.push((line_num as u32 + 1, "owner/admin getter".to_string()));
                }
            }
        }

        findings
    }

    /// Check for critical value retrieval using _getArg
    fn find_critical_value_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for fee/amount retrieval
            if (trimmed.contains("fee") || trimmed.contains("Fee") || trimmed.contains("amount"))
                && (trimmed.contains("_getArgUint") || trimmed.contains("_getArgBytes"))
            {
                findings.push((line_num as u32 + 1, "fee/amount value".to_string()));
            }

            // Check for token address retrieval
            if (trimmed.contains("token") || trimmed.contains("Token"))
                && trimmed.contains("_getArgAddress")
            {
                findings.push((line_num as u32 + 1, "token address".to_string()));
            }

            // Check for recipient address retrieval
            if (trimmed.contains("recipient")
                || trimmed.contains("beneficiary")
                || trimmed.contains("treasury"))
                && trimmed.contains("_getArgAddress")
            {
                findings.push((line_num as u32 + 1, "recipient address".to_string()));
            }
        }

        findings
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ClonesImmutableArgsBypassDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check contracts using ClonesWithImmutableArgs
        if !self.uses_immutable_args(source) {
            return Ok(findings);
        }

        // Check for access control using immutable args
        let access_usages = self.find_access_control_usage(source);
        for (line, usage_type) in access_usages {
            let message = format!(
                "Contract '{}' uses ClonesWithImmutableArgs for {} at line {}. \
                 'Immutable' args are read from calldata at runtime and can be spoofed \
                 by attackers using specially crafted transactions. Do not use these \
                 values for access control or security-critical decisions.",
                contract_name, usage_type, line
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Store security-critical values in contract storage instead of relying \
                     on ClonesWithImmutableArgs:\n\n\
                     // Instead of:\n\
                     function owner() public view returns (address) {\n\
                         return _getArgAddress(0); // VULNERABLE\n\
                     }\n\n\
                     // Use storage:\n\
                     address private _owner;\n\
                     function initialize(address owner_) external initializer {\n\
                         _owner = owner_;\n\
                     }\n\
                     function owner() public view returns (address) {\n\
                         return _owner; // SAFE\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for critical values using immutable args (lower confidence)
        let value_usages = self.find_critical_value_usage(source);
        for (line, usage_type) in value_usages {
            let message = format!(
                "Contract '{}' retrieves {} using ClonesWithImmutableArgs. \
                 These values can be manipulated via crafted calldata. \
                 Ensure these values are validated before use.",
                contract_name, usage_type
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add validation for critical values or store them in contract storage:\n\n\
                     // Validate immutable args against known good values:\n\
                     function validateArgs() internal view {\n\
                         require(_getArgAddress(0) == expectedAddress, \"Invalid arg\");\n\
                     }"
                    .to_string(),
                );

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

    #[test]
    fn test_detector_properties() {
        let detector = ClonesImmutableArgsBypassDetector::new();
        assert_eq!(detector.name(), "ClonesWithImmutableArgs Bypass");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_uses_immutable_args() {
        let detector = ClonesImmutableArgsBypassDetector::new();

        let code_with_args = r#"
            contract Clone {
                function owner() public view returns (address) {
                    return _getArgAddress(0);
                }
            }
        "#;
        assert!(detector.uses_immutable_args(code_with_args));

        let code_without_args = r#"
            contract Normal {
                address public owner;
            }
        "#;
        assert!(!detector.uses_immutable_args(code_without_args));
    }

    #[test]
    fn test_access_control_detection() {
        let detector = ClonesImmutableArgsBypassDetector::new();

        let vulnerable = r#"
            contract Clone {
                function doSomething() external {
                    require(msg.sender == _getArgAddress(0), "Not owner");
                }
            }
        "#;
        let findings = detector.find_access_control_usage(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_critical_value_detection() {
        let detector = ClonesImmutableArgsBypassDetector::new();

        let code = r#"
            contract Clone {
                function getFee() public view returns (uint256) {
                    uint256 fee = _getArgUint256(32);
                    return fee;
                }
            }
        "#;
        let findings = detector.find_critical_value_usage(code);
        assert!(!findings.is_empty());
    }
}
