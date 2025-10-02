use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for single oracle source dependencies
pub struct SingleSourceDetector {
    base: BaseDetector,
}

/// Detector for missing price validation
pub struct PriceValidationDetector {
    base: BaseDetector,
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

    fn is_oracle_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    ast::Expression::MemberAccess { member, .. } => {
                        let member_name = &member.name;
                        member_name.contains("price") ||
                        member_name.contains("rate") ||
                        *member_name == "latestRoundData" ||
                        *member_name == "getPrice" ||
                        *member_name == "decimals"
                    }
                    _ => false,
                }
            }
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

    fn collect_oracle_sources(&self, statements: &[ast::Statement<'_>], sources: &mut std::collections::HashSet<String>) {
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

    fn extract_oracle_source(&self, expr: &ast::Expression<'_>, sources: &mut std::collections::HashSet<String>) {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                if let ast::Expression::MemberAccess { expression, .. } = function {
                    if let ast::Expression::Identifier(id) = expression {
                        sources.insert(id.name.to_string());
                    }
                }
            }
            _ => {}
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

        for function in ctx.get_functions() {
            let oracle_count = self.count_oracle_sources(function);
            if oracle_count == 1 {
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
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    ast::Expression::MemberAccess { member, .. } => {
                        let member_name = &member.name;
                        member_name.contains("price") ||
                        member_name.contains("rate") ||
                        *member_name == "latestRoundData"
                    }
                    _ => false,
                }
            }
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

                let finding = self.base.create_finding(
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