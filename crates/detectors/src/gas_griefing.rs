use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for gas griefing attack vulnerabilities
pub struct GasGriefingDetector {
    base: BaseDetector,
}

impl Default for GasGriefingDetector {
    fn default() -> Self {
        Self::new()
    }
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
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: External .call{} in loop without explicit gas limit
        // Note: .transfer() is SAFE - it has built-in 2300 gas stipend and reverts on failure
        // Note: .send() is SAFE - it has built-in 2300 gas stipend and returns false on failure
        // Only .call{} without gas limits is vulnerable to gas griefing
        let has_loop = func_source.contains("for") || func_source.contains("while");
        let has_unsafe_call = func_source.contains(".call{") || func_source.contains(".call(");

        // .call{} without gas: specification forwards all gas - vulnerable to griefing
        if has_loop && has_unsafe_call {
            // Check if gas limit is specified
            let has_gas_limit = func_source.contains("gas:")
                || func_source.contains("gas(")
                || func_source.contains(".call{value:") && func_source.contains("gas:");

            if !has_gas_limit {
                return Some(
                    "External .call{} in loop without gas limit forwards all gas to recipient, \
                    attacker can grief by consuming all gas in fallback function. \
                    Use .call{value: amount, gas: 10000}(\"\") or .transfer() instead"
                        .to_string(),
                );
            }
        }

        // Pattern 2: Push pattern for mass ETH distribution with .call{}
        // Only flag if using .call{} (not .transfer() which is safe)
        // .transfer() has built-in 2300 gas limit and reverts on failure - not a griefing vector
        if has_loop && has_unsafe_call {
            let distributes_to_many = func_source.contains("recipients")
                || func_source.contains("addresses")
                || func_source.contains("payees")
                || (func_source.contains("[") && func_source.contains("].length"));

            if distributes_to_many
                && !func_source.contains("pull")
                && !func_source.contains("withdraw")
            {
                return Some(
                    "Push pattern for mass ETH distribution using .call{} in loop. \
                    Single recipient with malicious fallback can consume excessive gas. \
                    Consider: (1) Use pull pattern (withdrawals), (2) Add gas limits, \
                    (3) Use .transfer() for small amounts, (4) Implement batch size limits"
                        .to_string(),
                );
            }
        }

        // Pattern 3: Delegatecall in loop (extremely dangerous)
        if has_loop && func_source.contains("delegatecall") {
            return Some(
                "Delegatecall in loop is extremely dangerous. \
                Malicious contract can consume all gas or manipulate storage"
                    .to_string(),
            );
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
