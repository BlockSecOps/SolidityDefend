use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{is_test_contract, is_oracle_implementation};

/// Detector for single oracle source dependencies
pub struct SingleSourceDetector {
    base: BaseDetector,
}

/// Detector for missing price validation
pub struct PriceValidationDetector {
    base: BaseDetector,
}

impl Default for SingleSourceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleSourceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("single-oracle-source".to_string()),
                "Single Oracle Source".to_string(),
                "Contract relies on a single oracle source for critical price data".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }

    /// Check if function has slippage protection which mitigates oracle manipulation risk
    fn has_slippage_protection(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();
        lower.contains("minoutput")
            || lower.contains("minamount")
            || lower.contains("minreturn")
            || lower.contains("maxslippage")
            || lower.contains("amountoutmin")
            || lower.contains("amountinmax")
            || lower.contains("min_output")
            || lower.contains("min_amount")
            || lower.contains("slippage")
            || lower.contains("deadline")
            // Check for explicit bound checks on amounts
            || (lower.contains("require") && (lower.contains(">= min") || lower.contains("<= max")))
    }

    /// Phase 9 FP Reduction: Check if using Chainlink oracle pattern
    /// Chainlink is a well-established, reliable oracle infrastructure
    fn is_using_chainlink(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        lower.contains("aggregatorv3interface")
            || lower.contains("aggregatorinterface")
            || lower.contains("latestrounddata")
            || lower.contains("getlatestprice")
            || lower.contains("pricefeed")
            || lower.contains("chainlink")
            || lower.contains("datafeedstore")
    }

    /// Phase 9 FP Reduction: Check if using TWAP oracle pattern
    /// TWAP oracles are resistant to flash loan manipulation
    fn is_using_twap(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        lower.contains("twap")
            || lower.contains("timewightedaverage")
            || lower.contains("pricecumulativelast")
            || lower.contains("observe(")
            || lower.contains("consult(")
            || lower.contains("oraclecumulative")
            || lower.contains("gettwap")
    }

    fn _is_oracle_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => match function {
                ast::Expression::MemberAccess { member, .. } => {
                    let member_name = &member.name;
                    member_name.contains("price")
                        || member_name.contains("rate")
                        || *member_name == "latestRoundData"
                        || *member_name == "getPrice"
                        || *member_name == "decimals"
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn count_oracle_sources(&self, function: &ast::Function<'_>) -> usize {
        let mut oracle_sources = std::collections::HashSet::new();

        if let Some(body) = &function.body {
            self.collect_oracle_sources(&body.statements, &mut oracle_sources);
        }

        oracle_sources.len()
    }

    fn collect_oracle_sources(
        &self,
        statements: &[ast::Statement<'_>],
        sources: &mut std::collections::HashSet<String>,
    ) {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    self.extract_oracle_source(expr, sources);
                }
                ast::Statement::Block(block) => {
                    self.collect_oracle_sources(&block.statements, sources);
                }
                _ => {}
            }
        }
    }

    fn extract_oracle_source(
        &self,
        expr: &ast::Expression<'_>,
        sources: &mut std::collections::HashSet<String>,
    ) {
        if let ast::Expression::FunctionCall { function, .. } = expr {
            if let ast::Expression::MemberAccess { expression, .. } = function {
                if let ast::Expression::Identifier(id) = expression {
                    sources.insert(id.name.to_string());
                }
            }
        }
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

impl Detector for SingleSourceDetector {
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
        let source = &ctx.source_code;

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip contracts that ARE oracle implementations
        // Oracle contracts providing data don't need multiple oracle sources themselves
        if is_oracle_implementation(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip if using Chainlink (trusted decentralized oracle)
        if self.is_using_chainlink(source) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip if using TWAP (manipulation resistant)
        if self.is_using_twap(source) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let oracle_count = self.count_oracle_sources(function);
            if oracle_count == 1 {
                // Get function source to check for slippage protection
                let func_source = self.get_function_source(function, ctx);

                // Skip if function has slippage protection - mitigates oracle manipulation
                if self.has_slippage_protection(&func_source) {
                    continue;
                }

                let message = format!(
                    "Function '{}' relies on a single oracle source, creating centralization risk",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(693) // CWE-693: Protection Mechanism Failure
                .with_fix_suggestion(format!(
                    "Use multiple oracle sources and implement price aggregation in function '{}'",
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

impl Default for PriceValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-price-validation".to_string()),
                "Missing Price Validation".to_string(),
                "Oracle price data is used without proper validation".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }

    fn has_price_validation(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            self.check_statements_for_validation(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_validation(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall { function, .. }) => {
                    if let ast::Expression::Identifier(id) = function {
                        if id.name == "require" || id.name == "assert" {
                            return true;
                        }
                    }
                }
                ast::Statement::If { .. } => {
                    return true; // Basic check for conditional validation
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_validation(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn uses_oracle_data(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            self.check_statements_for_oracle_usage(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_oracle_usage(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.expression_uses_oracle(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_oracle_usage(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn expression_uses_oracle(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => match function {
                ast::Expression::MemberAccess { member, .. } => {
                    let member_name = &member.name;
                    member_name.contains("price")
                        || member_name.contains("rate")
                        || *member_name == "latestRoundData"
                }
                _ => false,
            },
            _ => false,
        }
    }
}

impl Detector for PriceValidationDetector {
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
            if self.uses_oracle_data(function) && !self.has_price_validation(function) {
                let message = format!(
                    "Function '{}' uses oracle price data without proper validation",
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
                    .with_fix_suggestion(format!(
                        "Add validation checks for oracle price data in function '{}'",
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
