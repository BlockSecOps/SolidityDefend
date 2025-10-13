use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct SandwichAttackDetector {
    base: BaseDetector,
}
pub struct FrontRunningDetector {
    base: BaseDetector,
}

impl SandwichAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("sandwich-attack".to_string()),
                "Sandwich Attack".to_string(),
                "Vulnerable to sandwich attacks".to_string(),
                vec![DetectorCategory::MEV],
                Severity::Medium,
            ),
        }
    }
}

impl FrontRunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("front-running".to_string()),
                "Front Running".to_string(),
                "Vulnerable to front-running attacks".to_string(),
                vec![DetectorCategory::MEV],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for SandwichAttackDetector {
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
            if self.is_vulnerable_to_sandwich_attack(function) {
                let message = format!(
                    "Function '{}' may be vulnerable to sandwich attacks due to predictable execution order",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                .with_fix_suggestion(format!(
                    "Consider implementing commit-reveal schemes or using a decentralized oracle in function '{}'",
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

impl SandwichAttackDetector {
    /// Check if function is vulnerable to sandwich attacks
    fn is_vulnerable_to_sandwich_attack(&self, function: &ast::Function<'_>) -> bool {
        let function_name = function.name.name.to_lowercase();

        // Functions that typically handle user-specified amounts/prices are vulnerable
        let vulnerable_patterns = [
            "swap",
            "trade",
            "exchange",
            "buy",
            "sell",
            "deposit",
            "withdraw",
            "mint",
            "redeem",
            "liquidate",
            "arbitrage",
        ];

        if vulnerable_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern))
        {
            // Check if function uses external price sources or user inputs
            if let Some(body) = &function.body {
                return self.uses_external_price_or_user_input(&body.statements);
            }
        }

        false
    }

    /// Check if statements use external prices or user inputs that can be manipulated
    fn uses_external_price_or_user_input(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall { function, .. }) => {
                    if let ast::Expression::MemberAccess { member, .. } = function {
                        let method = member.name.to_lowercase();
                        if method.contains("getprice")
                            || method.contains("getamount")
                            || method.contains("swap")
                            || method.contains("quote")
                        {
                            return true;
                        }
                    }
                }
                ast::Statement::Block(block) => {
                    if self.uses_external_price_or_user_input(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

impl Detector for FrontRunningDetector {
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
            if self.is_vulnerable_to_front_running(function) {
                let message = format!(
                    "Function '{}' may be vulnerable to front-running attacks",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                .with_fix_suggestion(format!(
                    "Consider using commit-reveal schemes, time delays, or batch processing in function '{}'",
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

impl FrontRunningDetector {
    /// Check if function is vulnerable to front-running attacks
    fn is_vulnerable_to_front_running(&self, function: &ast::Function<'_>) -> bool {
        let function_name = function.name.name.to_lowercase();

        // Functions that are commonly front-run
        let vulnerable_patterns = [
            "auction",
            "bid",
            "offer",
            "buy",
            "sell",
            "mint",
            "claim",
            "reward",
            "withdraw",
            "liquidate",
            "arbitrage",
            "purchase",
        ];

        if vulnerable_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern))
        {
            // Check if function has time-sensitive or first-come-first-served logic
            if let Some(body) = &function.body {
                return self.has_time_sensitive_logic(&body.statements);
            }
        }

        false
    }

    /// Check if statements contain time-sensitive logic vulnerable to front-running
    fn has_time_sensitive_logic(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall { function, .. }) => {
                    if let ast::Expression::MemberAccess { member, .. } = function {
                        let method = member.name.to_lowercase();
                        // Look for time-based or quantity-based constraints
                        if method.contains("timestamp")
                            || method.contains("deadline")
                            || method.contains("supply")
                            || method.contains("available")
                        {
                            return true;
                        }
                    }
                }
                ast::Statement::Block(block) => {
                    if self.has_time_sensitive_logic(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}
