use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

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
                    // Direct member access pattern: obj.method()
                    ast::Expression::MemberAccess { .. } => true,
                    // Nested function call pattern: obj.method{options}()
                    ast::Expression::FunctionCall {
                        function: inner_function,
                        ..
                    } => {
                        // Check if the inner function is a MemberAccess (e.g., msg.sender.call)
                        matches!(inner_function, ast::Expression::MemberAccess { .. })
                    }
                    _ => false,
                }
            }
            ast::Expression::Assignment { right, .. } => {
                // Check if assignment right side contains external call: result = call(...)
                self.is_external_call(right)
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                // Check both sides of binary operations for external calls
                self.is_external_call(left) || self.is_external_call(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                // Check unary operation operand for external calls
                self.is_external_call(operand)
            }
            ast::Expression::IndexAccess { base, index, .. } => {
                // Check index access expressions for external calls
                self.is_external_call(base) || index.map_or(false, |idx| self.is_external_call(idx))
            }
            ast::Expression::MemberAccess { expression, .. } => {
                // Check member access base expression for external calls
                self.is_external_call(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                // Check all parts of conditional expressions for external calls
                self.is_external_call(condition)
                    || self.is_external_call(true_expression)
                    || self.is_external_call(false_expression)
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
            ast::Statement::Block(block) => {
                // Recursively check all statements in the block
                self.check_statements_for_external_calls(&block.statements)
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                // Check condition expression and both branches
                self.is_external_call(condition)
                    || self.statement_has_external_call(then_branch)
                    || else_branch.map_or(false, |stmt| self.statement_has_external_call(stmt))
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                // Check condition and loop body
                self.is_external_call(condition) || self.statement_has_external_call(body)
            }
            ast::Statement::For {
                condition,
                update,
                body,
                ..
            } => {
                // Check condition, update expression, and loop body
                condition
                    .as_ref()
                    .map_or(false, |cond| self.is_external_call(cond))
                    || update
                        .as_ref()
                        .map_or(false, |upd| self.is_external_call(upd))
                    || self.statement_has_external_call(body)
            }
            ast::Statement::VariableDeclaration { initial_value, .. } => {
                // Check if variable is initialized with external call: bool result = call(...)
                initial_value
                    .as_ref()
                    .map_or(false, |expr| self.is_external_call(expr))
            }
            ast::Statement::TryStatement {
                expression,
                body,
                catch_clauses,
                ..
            } => {
                // Check try expression and all catch clauses
                self.is_external_call(expression)
                    || self.statement_has_external_call(&ast::Statement::Block(body.clone()))
                    || catch_clauses.iter().any(|catch_clause| {
                        self.statement_has_external_call(&ast::Statement::Block(
                            catch_clause.body.clone(),
                        ))
                    })
            }
            ast::Statement::Return { value, .. } => {
                // Check if return expression contains external call: return call(...)
                value
                    .as_ref()
                    .map_or(false, |expr| self.is_external_call(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Check if emit contains external call: emit Event(call(...))
                self.is_external_call(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Check if revert contains external call: revert Error(call(...))
                error_call
                    .as_ref()
                    .map_or(false, |expr| self.is_external_call(expr))
            }
            _ => false,
        }
    }

    fn statement_has_state_change(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment { .. }) => true,
            ast::Statement::Block(block) => {
                // Recursively check all statements in the block for state changes
                block
                    .statements
                    .iter()
                    .any(|s| self.statement_has_state_change(s))
            }
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                // Check both branches for state changes
                self.statement_has_state_change(then_branch)
                    || else_branch.map_or(false, |stmt| self.statement_has_state_change(stmt))
            }
            ast::Statement::While { body, .. } => {
                // Check loop body for state changes
                self.statement_has_state_change(body)
            }
            ast::Statement::For { body, .. } => {
                // Check loop body for state changes
                self.statement_has_state_change(body)
            }
            ast::Statement::VariableDeclaration { initial_value, .. } => {
                // Variable declarations themselves don't change contract state
                // but the initial value might contain state changes
                initial_value
                    .as_ref()
                    .map_or(false, |expr| self.expression_has_state_change(expr))
            }
            ast::Statement::TryStatement {
                expression,
                body,
                catch_clauses,
                ..
            } => {
                // Check try expression, try body, and all catch clauses for state changes
                self.expression_has_state_change(expression)
                    || self.statement_has_state_change(&ast::Statement::Block(body.clone()))
                    || catch_clauses.iter().any(|catch_clause| {
                        self.statement_has_state_change(&ast::Statement::Block(
                            catch_clause.body.clone(),
                        ))
                    })
            }
            ast::Statement::Return { value, .. } => {
                // Return expressions might contain state changes: return (balance = 0, result)
                value
                    .as_ref()
                    .map_or(false, |expr| self.expression_has_state_change(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Emit expressions might contain state changes: emit Event(balance = 0)
                self.expression_has_state_change(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Revert expressions might contain state changes: revert Error(balance = 0)
                error_call
                    .as_ref()
                    .map_or(false, |expr| self.expression_has_state_change(expr))
            }
            _ => false,
        }
    }

    /// Get function source code
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

    /// Check if an expression contains state changes (assignments)
    fn expression_has_state_change(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::Assignment { .. } => true,
            ast::Expression::BinaryOperation { left, right, .. } => {
                // Check both sides of binary operations
                self.expression_has_state_change(left) || self.expression_has_state_change(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                // Check unary operation operand
                self.expression_has_state_change(operand)
            }
            ast::Expression::FunctionCall { arguments, .. } => {
                // Check function call arguments for state changes
                arguments
                    .iter()
                    .any(|arg| self.expression_has_state_change(arg))
            }
            ast::Expression::IndexAccess { base, index, .. } => {
                // Check index access expressions
                self.expression_has_state_change(base)
                    || index.map_or(false, |idx| self.expression_has_state_change(idx))
            }
            ast::Expression::MemberAccess { expression, .. } => {
                // Check member access base expression
                self.expression_has_state_change(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                // Check all parts of conditional expression
                self.expression_has_state_change(condition)
                    || self.expression_has_state_change(true_expression)
                    || self.expression_has_state_change(false_expression)
            }
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

        // Skip if this is an ERC-4337 paymaster/account abstraction contract
        // Paymasters have their own security model with EntryPoint validation
        // State changes after external calls are part of the ERC-4337 design
        let is_paymaster = utils::is_erc4337_paymaster(ctx);
        if is_paymaster {
            return Ok(findings); // Paymaster reentrancy is handled by ERC-4337 spec
        }

        // Skip if this is an AMM pool - AMM pools have lock() modifiers for reentrancy protection
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if self.has_external_call(function) && self.has_state_changes_after_calls(function) {
                // Get function source to check for reentrancy guards
                let func_source = self.get_function_source(function, ctx);

                // Skip if function has reentrancy guard (nonReentrant, lock(), etc.)
                if utils::has_reentrancy_guard(&func_source, &ctx.source_code) {
                    continue;
                }

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
            ast::Expression::FunctionCall { function, .. } => match function {
                ast::Expression::MemberAccess { .. } => true,
                _ => false,
            },
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
