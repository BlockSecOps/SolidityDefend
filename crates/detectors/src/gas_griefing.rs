use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for gas griefing attack vulnerabilities
pub struct GasGriefingDetector {
    base: BaseDetector,
}

impl GasGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("gas-griefing".to_string()),
                "Gas Griefing Attack".to_string(),
                "Detects vulnerabilities where attackers can grief users by forcing high gas consumption".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::ExternalCalls],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for GasGriefingDetector {
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
            if let Some(gas_issue) = self.check_gas_griefing(function, ctx) {
                let message = format!(
                    "Function '{}' has gas griefing vulnerability. {} \
                    Attackers can force users to waste gas or cause transactions to fail.",
                    function.name.name, gas_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_cwe(405) // CWE-405: Asymmetric Resource Consumption
                .with_fix_suggestion(format!(
                    "Mitigate gas griefing in '{}'. \
                    Use pull pattern for transfers, limit array sizes, add gas stipends, \
                    implement gas-efficient loops, avoid unbounded operations, use OpenZeppelin SafeERC20.",
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

impl GasGriefingDetector {
    fn check_gas_griefing(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: External call in loop without gas limit
        let has_loop = func_source.contains("for") || func_source.contains("while");
        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer")
            || func_source.contains(".send");

        if has_loop && has_external_call && !func_source.contains("gas:") {
            return Some(format!(
                "External call in loop without gas limit, \
                attacker can grief by consuming all gas"
            ));
        }

        // Pattern 2: Transfer without gas stipend
        if has_external_call && !func_source.contains("gas(") && func_source.contains(".transfer") {
            return Some(format!(
                "Transfer without gas stipend, \
                recipient can grief by consuming gas in fallback"
            ));
        }

        // Pattern 3: Push pattern for mass distribution
        let distributes_to_many =
            has_loop && (func_source.contains("transfer") || func_source.contains("balances["));

        if distributes_to_many && !func_source.contains("pull") {
            return Some(format!(
                "Push pattern for mass distribution, \
                single failing recipient can grief entire distribution"
            ));
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
        let detector = GasGriefingDetector::new();
        assert_eq!(detector.name(), "Gas Griefing Attack");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
