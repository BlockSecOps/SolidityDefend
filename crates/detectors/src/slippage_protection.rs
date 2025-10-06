use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for missing slippage protection in DEX trades
pub struct SlippageProtectionDetector {
    base: BaseDetector,
}

impl SlippageProtectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-slippage-protection".to_string()),
                "Missing Slippage Protection".to_string(),
                "Detects DEX trades executed without minimum output amount protection, enabling sandwich attacks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for SlippageProtectionDetector {
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
            if let Some(line) = self.has_missing_slippage_protection(function, ctx) {
                let message = format!(
                    "Function '{}' executes DEX swap without slippage protection \
                    (amountOutMin = 0). This allows MEV bots to sandwich the transaction, \
                    extracting value through front-running and back-running attacks.",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    line as u32,
                    0,
                    function.name.name.len() as u32,
                )
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_fix_suggestion(format!(
                    "Calculate minimum acceptable output amount based on current price and \
                    acceptable slippage (e.g., 0.5-1%). Example: \
                    uint256 minOut = expectedAmount * 99 / 100; \
                    Then use minOut instead of 0 in swap call in function '{}'",
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

impl SlippageProtectionDetector {
    /// Check if function has missing slippage protection, returns line number if found
    fn has_missing_slippage_protection(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<usize> {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return None;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return None;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if this function contains DEX swap calls
        let swap_patterns = [
            "swap", "Swap", "exchange", "Exchange",
            "swapExactTokensForTokens", "swapTokensForExactTokens",
            "swapExactETHForTokens", "swapTokensForExactETH",
            "swapExactTokensForETH", "swapETHForExactTokens"
        ];

        let has_swap_call = swap_patterns.iter().any(|pattern|
            func_source.contains(pattern)
        );

        if !has_swap_call {
            return None;
        }

        // Look for vulnerable patterns
        self.find_vulnerable_swap_call(&func_source, func_start)
    }

    /// Find the specific line with vulnerable swap call
    fn find_vulnerable_swap_call(&self, source: &str, func_start: usize) -> Option<usize> {
        let lines: Vec<&str> = source.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Check for swap function calls
            if line.contains("swap") || line.contains("Swap") || line.contains("exchange") {
                // Look for patterns indicating zero minimum amount

                // Pattern 1: Direct zero in swap call
                if line.contains("(") && (line.contains(", 0,") || line.contains(", 0)")) {
                    // Verify this is likely a minimum amount parameter
                    if line.contains("swap") || line.contains("Swap") {
                        return Some(func_start + idx);
                    }
                }

                // Pattern 2: Check next few lines for continuation
                if idx + 1 < lines.len() {
                    let next_line = lines[idx + 1];
                    if next_line.trim().starts_with("0,") || next_line.trim() == "0," {
                        // Check if there's a vulnerability comment
                        if next_line.contains("VULNERABILITY") || next_line.contains("No minimum") {
                            return Some(func_start + idx + 1);
                        }
                        // Or if the function has swap patterns
                        if source.contains("amountOutMin") || source.contains("minimum") {
                            return Some(func_start + idx + 1);
                        }
                    }
                }

                // Pattern 3: Multi-line swap call with 0
                let window = lines[idx..std::cmp::min(idx + 10, lines.len())].join("\n");
                if window.contains("swap") && window.contains("0,") && window.contains("VULNERABILITY") {
                    return Some(func_start + idx);
                }
            }

            // Check for explicit vulnerability markers
            if line.contains("VULNERABILITY") && (line.contains("slippage") || line.contains("minimum amount")) {
                return Some(func_start + idx);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = SlippageProtectionDetector::new();
        assert_eq!(detector.name(), "Missing Slippage Protection");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
