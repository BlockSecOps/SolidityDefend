use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for short address attack vulnerability
///
/// Detects functions that accept address parameters but don't validate msg.data.length.
/// Short address attacks occur when an attacker provides a truncated address, causing
/// the EVM to pad it and potentially shift other parameters like amounts.
pub struct ShortAddressDetector {
    base: BaseDetector,
}

impl Default for ShortAddressDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ShortAddressDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("short-address-attack".to_string()),
                "Short Address Attack".to_string(),
                "Detects missing msg.data.length validation that enables short address attacks"
                    .to_string(),
                vec![
                    DetectorCategory::Validation,
                    DetectorCategory::BestPractices,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Check if function is vulnerable to short address attack
    fn check_short_address_vulnerability(
        &self,
        function_source: &str,
        function_name: &str,
    ) -> bool {
        // Must accept address parameters
        let has_address_param = function_source.contains("address _")
            || function_source.contains("address to")
            || function_source.contains("address from")
            || function_source.contains("address recipient")
            || function_source.contains("address spender");

        if !has_address_param {
            return false;
        }

        // Likely vulnerable functions (transfer, approve, etc.)
        let is_transfer_like = function_name.to_lowercase().contains("transfer")
            || function_name.to_lowercase().contains("approve")
            || function_name.to_lowercase().contains("send")
            || function_name.to_lowercase().contains("withdraw")
            || function_name.to_lowercase().contains("deposit");

        // Also check if function has value/amount parameter (typical for short address attack)
        let has_value_param = function_source.contains("uint256 _value")
            || function_source.contains("uint256 value")
            || function_source.contains("uint256 _amount")
            || function_source.contains("uint256 amount")
            || function_source.contains("uint _value")
            || function_source.contains("uint _amount");

        // Check if msg.data.length validation is present
        let has_data_length_check = function_source.contains("msg.data.length")
            || function_source.contains("calldata.length");

        // Vulnerable if:
        // - Has address parameter AND
        // - Has value/amount parameter AND
        // - Is a transfer-like function AND
        // - No msg.data.length validation
        has_address_param && has_value_param && is_transfer_like && !has_data_length_check
    }
}

impl Detector for ShortAddressDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // Check all functions
        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            if self.check_short_address_vulnerability(&func_source, function.name.name) {
                let message = format!(
                    "Function '{}' may be vulnerable to short address attack. \
                    Accepts address and value parameters but doesn't validate msg.data.length. \
                    An attacker can provide a truncated address causing the EVM to pad it, \
                    potentially shifting the value parameter and allowing larger transfers than intended.",
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
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(707) // CWE-707: Improper Neutralization
                    .with_fix_suggestion(format!(
                        "Add msg.data.length validation to '{}'. \
                        Add at function start: require(msg.data.length >= 68, \"Invalid input length\"); \
                        For functions with address+uint256: 4 bytes (selector) + 32 bytes (address) + 32 bytes (uint256) = 68 bytes minimum. \
                        Adjust the required length based on your function's parameters.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ShortAddressDetector {
    /// Extract function source code from context
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
        let detector = ShortAddressDetector::new();
        assert_eq!(detector.name(), "Short Address Attack");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
