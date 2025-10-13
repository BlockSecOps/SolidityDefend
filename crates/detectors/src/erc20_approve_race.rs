use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ERC-20 approve race condition vulnerabilities (SWC-114)
pub struct Erc20ApproveRaceDetector {
    base: BaseDetector,
}

impl Erc20ApproveRaceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc20-approve-race".to_string()),
                "ERC-20 Approve Race Condition".to_string(),
                "Detects ERC-20 approve functions vulnerable to front-running race conditions (SWC-114)".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for Erc20ApproveRaceDetector {
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
            if let Some(issue) = self.check_approve_race(function, ctx) {
                let message = format!(
                    "Function '{}' has approve race condition vulnerability. {} \
                    Vulnerable to front-running attack (SWC-114).",
                    function.name.name, issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Race Condition
                .with_fix_suggestion(format!(
                    "Fix '{}' race condition. Solutions: (1) Require current allowance == 0 before changes, \
                    (2) Use increaseAllowance/decreaseAllowance pattern, (3) Add expectedCurrentValue parameter",
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

impl Erc20ApproveRaceDetector {
    fn check_approve_race(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let name_lower = function.name.name.to_lowercase();

        if name_lower != "approve" {
            return None;
        }

        // Check for race condition mitigations
        let has_require_zero = func_source.contains("require")
            && func_source.contains("allowance")
            && (func_source.contains("== 0") || func_source.contains("!= 0"));

        let has_expected_param = function.parameters.iter().any(|param| {
            let param_name = param
                .name
                .as_ref()
                .map(|n| n.name.to_lowercase())
                .unwrap_or_default();
            param_name.contains("expected") || param_name.contains("current")
        });

        let has_safe_patterns = func_source.contains("SafeERC20")
            || func_source.contains("safeApprove")
            || has_expected_param;

        if !has_require_zero && !has_safe_patterns {
            return Some("Standard ERC-20 approve without race condition protection".to_string());
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
        let detector = Erc20ApproveRaceDetector::new();
        assert_eq!(detector.name(), "ERC-20 Approve Race Condition");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }
}
