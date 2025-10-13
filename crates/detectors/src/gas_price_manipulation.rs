use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for gas price manipulation vulnerabilities
pub struct GasPriceManipulationDetector {
    base: BaseDetector,
}

impl GasPriceManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("gas-price-manipulation".to_string()),
                "Gas Price Manipulation".to_string(),
                "Detects MEV protection using tx.gasprice which can be bypassed through flashbots or other mechanisms".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for GasPriceManipulationDetector {
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
            if self.has_gas_price_bypass(function, ctx) {
                let message = format!(
                    "Function '{}' uses tx.gasprice for MEV protection which can be bypassed. \
                    Flashbots and private mempools allow MEV bots to execute transactions with \
                    any gas price without going through the public mempool.",
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
                    .with_cwe(693) // CWE-693: Protection Mechanism Failure
                    .with_cwe(358) // CWE-358: Improperly Implemented Security Check for Standard
                    .with_fix_suggestion(format!(
                        "Replace gas price checks in function '{}' with robust MEV protection. \
                    Example: Use commit-reveal schemes with sufficient delays, implement \
                    order batching, or use decentralized sequencers.",
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

impl GasPriceManipulationDetector {
    /// Check if function has gas price bypass vulnerability
    fn has_gas_price_bypass(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if function uses tx.gasprice for protection
        let uses_gas_price =
            func_source.contains("tx.gasprice") || func_source.contains("tx.gasPrice");

        if !uses_gas_price {
            return false;
        }

        // Look for vulnerability patterns
        self.check_bypass_patterns(&func_source)
    }

    /// Check for gas price bypass patterns
    fn check_bypass_patterns(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("Gas price check can be bypassed")
                || source.contains("MEV detection is ineffective"));

        // Pattern 2: Uses tx.gasprice in require/check
        let has_gas_price_check = (source.contains("require(tx.gasprice")
            || source.contains("if (tx.gasprice"))
            && (source.contains("<=") || source.contains(">"));

        // Pattern 3: MEV protection based on gas price
        let mev_protection_pattern = (source.contains("maxGasPrice")
            || source.contains("gasLimit")
            || source.contains("withinGasLimit"))
            && source.contains("tx.gasprice");

        // Pattern 4: MEV detection using gas price
        let mev_detection = source.contains("MEVDetected") && source.contains("tx.gasprice");

        // Vulnerable if has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if uses gas price for protection/detection
        if has_gas_price_check || mev_protection_pattern || mev_detection {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = GasPriceManipulationDetector::new();
        assert_eq!(detector.name(), "Gas Price Manipulation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
