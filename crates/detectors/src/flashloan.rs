use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for flash loan vulnerability patterns
pub struct VulnerablePatternsDetector {
    base: BaseDetector,
}

impl VulnerablePatternsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashloan-vulnerable-patterns".to_string()),
                "Flash Loan Vulnerable Patterns".to_string(),
                "Function vulnerable to flash loan attacks due to reliance on spot prices".to_string(),
                vec![DetectorCategory::FlashLoanAttacks],
                Severity::High,
            ),
        }
    }
}

impl Detector for VulnerablePatternsDetector {
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
            if self.is_vulnerable_to_flash_loan(function) {
                let message = format!(
                    "Function '{}' may be vulnerable to flash loan attacks due to reliance on spot prices",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_cwe(20)  // CWE-20: Improper Input Validation
                .with_fix_suggestion(format!(
                    "Use time-weighted average prices (TWAP) or multiple oracle sources instead of spot prices in function '{}'",
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

impl VulnerablePatternsDetector {
    /// Check if a function is vulnerable to flash loan attacks
    fn is_vulnerable_to_flash_loan(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            // Look for patterns that suggest vulnerability:
            // 1. Uses spot prices from DEX
            // 2. Relies on balance checks without proper protection
            // 3. Has liquidation or trading logic
            let function_name = function.name.name.to_lowercase();
            let vulnerable_patterns = [
                "liquidate", "swap", "trade", "arbitrage",
                "getprice", "price", "exchange", "mint", "redeem"
            ];

            if vulnerable_patterns.iter().any(|pattern| function_name.contains(pattern)) {
                return self.uses_spot_prices(&body.statements);
            }
        }
        false
    }

    /// Check if statements use spot prices (simplified heuristic)
    fn uses_spot_prices(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall { function, .. }) => {
                    if let ast::Expression::MemberAccess { member, .. } = function {
                        let method_name = member.name.to_lowercase();
                        if method_name.contains("getprice") ||
                           method_name.contains("getamount") ||
                           method_name.contains("getreserves") ||
                           method_name.contains("balanceof") {
                            return true;
                        }
                    }
                }
                ast::Statement::Block(block) => {
                    if self.uses_spot_prices(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}