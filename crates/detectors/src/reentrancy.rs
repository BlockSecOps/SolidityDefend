use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for classic reentrancy vulnerabilities
pub struct ClassicReentrancyDetector {
    base: BaseDetector,
}

/// Detector for read-only reentrancy vulnerabilities
pub struct ReadOnlyReentrancyDetector {
    base: BaseDetector,
}

impl ClassicReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("classic-reentrancy".to_string()),
                "Classic Reentrancy".to_string(),
                "State changes after external calls enable reentrancy attacks".to_string(),
                vec![DetectorCategory::ReentrancyAttacks],
                Severity::High,
            ),
        }
    }

    fn has_external_call(&self, function: &ast::Function<'_>) -> bool {
        // Check for external calls in function body
        if let Some(body) = &function.body {
            self.check_statements_for_external_calls(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_external_calls(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.is_external_call(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_external_calls(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn is_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    ast::Expression::MemberAccess { .. } => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn has_state_changes_after_calls(&self, function: &ast::Function<'_>) -> bool {
        // Simplified check - in real implementation would need more sophisticated CFG analysis
        if let Some(body) = &function.body {
            let mut found_external_call = false;
            for stmt in &body.statements {
                if !found_external_call && self.statement_has_external_call(stmt) {
                    found_external_call = true;
                } else if found_external_call && self.statement_has_state_change(stmt) {
                    return true;
                }
            }
        }
        false
    }

    fn statement_has_external_call(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.is_external_call(expr),
            _ => false,
        }
    }

    fn statement_has_state_change(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment { .. }) => true,
            _ => false,
        }
    }
}

impl Detector for ClassicReentrancyDetector {
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
            if self.has_external_call(function) && self.has_state_changes_after_calls(function) {
                let message = format!(
                    "Function '{}' may be vulnerable to reentrancy attacks due to state changes after external calls",
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
                .with_fix_suggestion(format!(
                    "Apply checks-effects-interactions pattern or use a reentrancy guard in function '{}'",
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

impl ReadOnlyReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("readonly-reentrancy".to_string()),
                "Read-Only Reentrancy".to_string(),
                "Read-only functions may be vulnerable to view reentrancy".to_string(),
                vec![DetectorCategory::ReentrancyAttacks],
                Severity::Medium,
            ),
        }
    }

    fn is_view_function(&self, function: &ast::Function<'_>) -> bool {
        matches!(function.mutability, ast::StateMutability::View)
    }

    fn relies_on_external_state(&self, function: &ast::Function<'_>) -> bool {
        // Check if function reads from external contracts
        if let Some(body) = &function.body {
            self.check_statements_for_external_reads(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_external_reads(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.is_external_read(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_external_reads(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn is_external_read(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess { expression, .. } => {
                // Check if this is reading from an external contract
                matches!(expression, ast::Expression::Identifier(_))
            }
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    ast::Expression::MemberAccess { .. } => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

impl Detector for ReadOnlyReentrancyDetector {
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
            if self.is_view_function(function) && self.relies_on_external_state(function) {
                let message = format!(
                    "View function '{}' may be vulnerable to read-only reentrancy",
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
                .with_fix_suggestion(format!(
                    "Consider using a reentrancy guard or caching external state in function '{}'",
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