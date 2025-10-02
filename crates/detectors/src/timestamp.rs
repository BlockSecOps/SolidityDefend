use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct BlockDependencyDetector { base: BaseDetector }

impl BlockDependencyDetector {
    pub fn new() -> Self {
        Self { base: BaseDetector::new(DetectorId("block-dependency".to_string()), "Block Dependency".to_string(), "Dangerous dependence on block properties".to_string(), vec![DetectorCategory::Timestamp], Severity::Medium) }
    }
}

impl Detector for BlockDependencyDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for function in ctx.get_functions() {
            if self.has_timestamp_dependency(function) {
                let message = format!(
                    "Function '{}' has dangerous dependence on block timestamp or number",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                .with_fix_suggestion(format!(
                    "Avoid using block.timestamp or block.number for critical logic in function '{}', use block hashes or external randomness",
                    function.name.name
                ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any { self }
}

impl BlockDependencyDetector {
    /// Check if function has dangerous timestamp dependencies
    fn has_timestamp_dependency(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            self.check_statements_for_timestamp_use(&body.statements)
        } else {
            false
        }
    }

    /// Check statements for timestamp/block property usage
    fn check_statements_for_timestamp_use(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.expression_uses_timestamp(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_timestamp_use(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if expression uses timestamp or block properties
    fn expression_uses_timestamp(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess { expression, member, .. } => {
                if let ast::Expression::Identifier(id) = expression {
                    if id.name == "block" {
                        let member_name = member.name.to_lowercase();
                        return member_name == "timestamp" || member_name == "number" || member_name == "difficulty";
                    }
                }
            }
            ast::Expression::FunctionCall { function, .. } => {
                if let ast::Expression::Identifier(id) = function {
                    // Check for now() function which is alias for block.timestamp
                    return id.name == "now";
                }
            }
            _ => {}
        }
        false
    }
}
