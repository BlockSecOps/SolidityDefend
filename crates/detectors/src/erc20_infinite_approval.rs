use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for infinite/unlimited ERC-20 approval risks
pub struct Erc20InfiniteApprovalDetector {
    base: BaseDetector,
}

impl Erc20InfiniteApprovalDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc20-infinite-approval".to_string()),
                "Infinite Approval Risk".to_string(),
                "Detects contracts that accept or encourage unlimited ERC-20 approvals".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                Severity::Low,
            ),
        }
    }
}

impl Detector for Erc20InfiniteApprovalDetector {
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
            if let Some(issue) = self.check_infinite_approval(function, ctx) {
                let message = format!(
                    "Function '{}' has infinite approval risk. {} \
                    This creates permanent security risk if contract is compromised.",
                    function.name.name,
                    issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_fix_suggestion(format!(
                    "Mitigate infinite approval risks in '{}'. Solutions: (1) Implement EIP-2612 permit() with deadline, \
                    (2) Add approval cap limits, (3) Provide documentation warnings, (4) Implement approval revocation",
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

impl Erc20InfiniteApprovalDetector {
    fn check_infinite_approval(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Look for patterns that suggest infinite approval
        let checks_for_max = func_source.contains("type(uint256).max") ||
                            func_source.contains("2**256 - 1") ||
                            func_source.contains("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") ||
                            func_source.contains("MAX_UINT256") ||
                            func_source.contains("UINT256_MAX");

        if checks_for_max {
            // Check if it's requiring max approval (bad)
            let requires_max = func_source.contains("require") &&
                              func_source.contains("allowance") &&
                              checks_for_max;

            if requires_max {
                return Some("Requires infinite approval (type(uint256).max)".to_string());
            }

            // Check if it's just checking for infinite approval (informational)
            let checks_allowance = func_source.contains("allowance") &&
                                  (func_source.contains(">=") || func_source.contains("=="));

            if checks_allowance {
                return Some("Checks for infinite approval, encouraging unlimited approvals".to_string());
            }
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
        let detector = Erc20InfiniteApprovalDetector::new();
        assert_eq!(detector.name(), "Infinite Approval Risk");
        assert_eq!(detector.default_severity(), Severity::Low);
    }
}
