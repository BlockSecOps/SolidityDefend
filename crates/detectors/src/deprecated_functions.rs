use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for deprecated Solidity functions and patterns
pub struct DeprecatedFunctionsDetector {
    base: BaseDetector,
}

impl DeprecatedFunctionsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("deprecated-functions".to_string()),
                "Deprecated Functions".to_string(),
                "Detects usage of deprecated Solidity functions and patterns that should be replaced with modern alternatives".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Low,
            ),
        }
    }
}

impl Detector for DeprecatedFunctionsDetector {
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
        let contract_source = ctx.source_code.as_str();

        // Check for deprecated patterns in the entire contract
        let deprecated_patterns = vec![
            (".send(", "Use .call{value: amount}(\"\") instead of .send() for better error handling"),
            ("selfdestruct(", "selfdestruct is deprecated. Consider alternative contract upgrade patterns"),
            ("block.difficulty", "block.difficulty deprecated post-merge. Use block.prevrandao instead"),
            ("throw", "throw keyword removed. Use require(), assert(), or revert() instead"),
            ("suicide(", "suicide renamed to selfdestruct (also deprecated). Use upgrade patterns"),
            ("constant view", "constant keyword deprecated. Use view or pure instead"),
            ("constant pure", "constant keyword deprecated. Use view or pure instead"),
            ("var ", "var keyword removed. Use explicit types like uint256, address, etc."),
            ("years", "time unit 'years' removed. Use explicit seconds calculation"),
        ];

        for (pattern, fix_msg) in deprecated_patterns {
            if contract_source.contains(pattern) {
                let message = format!(
                    "Deprecated function or pattern detected: '{}'. {}",
                    pattern.trim_end_matches('('),
                    fix_msg
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    1,
                    0,
                    20,
                )
                .with_cwe(477) // CWE-477: Use of Obsolete Function
                .with_fix_suggestion(format!(
                    "Replace deprecated '{}'. {}",
                    pattern.trim_end_matches('('),
                    fix_msg
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DeprecatedFunctionsDetector::new();
        assert_eq!(detector.name(), "Deprecated Functions");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }
}
