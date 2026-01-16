use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct UncheckedCallDetector {
    base: BaseDetector,
}

impl Default for UncheckedCallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UncheckedCallDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("unchecked-external-call".to_string()),
                "Unchecked External Call".to_string(),
                "External calls without return value checking".to_string(),
                vec![DetectorCategory::ExternalCalls],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for UncheckedCallDetector {
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
            if let Some(body) = &function.body {
                self.check_statements_for_unchecked_calls(
                    &body.statements,
                    ctx,
                    &mut findings,
                    function,
                );
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UncheckedCallDetector {
    /// Check statements for unchecked external calls
    fn check_statements_for_unchecked_calls(
        &self,
        statements: &[ast::Statement<'_>],
        ctx: &AnalysisContext<'_>,
        findings: &mut Vec<Finding>,
        function: &ast::Function<'_>,
    ) {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall {
                    function: call_expr,
                    ..
                }) => {
                    if self.is_external_call(call_expr) && !self.return_value_checked(stmt) {
                        let message = format!(
                            "External call in function '{}' does not check return value",
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
                            .with_cwe(252) // CWE-252: Unchecked Return Value
                            .with_fix_suggestion(format!(
                                "Check the return value of external calls in function '{}'",
                                function.name.name
                            ));

                        findings.push(finding);
                    }
                }
                ast::Statement::Block(block) => {
                    self.check_statements_for_unchecked_calls(
                        &block.statements,
                        ctx,
                        findings,
                        function,
                    );
                }
                _ => {}
            }
        }
    }

    /// Check if expression is an external call
    /// Only flags actual low-level call patterns: .call{}, .delegatecall{}, .staticcall{}, .send(), .transfer()
    /// Does NOT flag: array.push(), mapping access, or general method calls
    fn is_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        if let ast::Expression::MemberAccess {
            expression, member, ..
        } = expr
        {
            // Only flag actual external call patterns - low-level calls
            let method = member.name.to_lowercase();

            // These are the only real external call patterns that need return value checking:
            // - .call{value:...}() - returns (bool, bytes)
            // - .delegatecall() - returns (bool, bytes)
            // - .staticcall() - returns (bool, bytes)
            // - .send() - returns bool
            //
            // NOT external calls (should not be flagged):
            // - .transfer() - reverts on failure, no return value to check
            // - array.push() - internal array operation
            // - mapping[key] - storage access
            // - contract.function() - handled by Solidity (reverts on failure)
            if method == "call" || method == "delegatecall" || method == "staticcall" || method == "send" {
                // Verify the expression is an address-like type, not an array or mapping
                // Skip if it looks like array/internal operations
                if !self.is_array_or_internal_operation(expression) {
                    return true;
                }
            }

            // Note: .transfer() reverts on failure, so there's no return value to check
            // It's not an unchecked call pattern - it fails loudly
        }
        false
    }

    /// Check if expression looks like an internal/array operation (not an external call target)
    fn is_array_or_internal_operation(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            // Array access like shareholders[i] or direct identifier like shareholders
            ast::Expression::Identifier(id) => {
                let name = id.name.to_lowercase();
                // Common array/mapping variable names
                name.contains("array") || name.contains("list") || name.contains("holders")
                    || name.contains("shareholders") || name.contains("members")
                    || name.contains("users") || name.contains("addresses")
                    || name.contains("balances") || name.contains("allowances")
                    || name.contains("shares") || name.contains("tokens")
                    || name.ends_with("s") && name.len() > 3 // plurals often indicate arrays
            }
            // Index access like mapping[key] or array[index]
            ast::Expression::IndexAccess { .. } => true,
            // Member access chain - check inner expression
            ast::Expression::MemberAccess { expression, member, .. } => {
                // If accessing .length, it's an array
                if member.name == "length" {
                    return true;
                }
                self.is_array_or_internal_operation(expression)
            }
            _ => false,
        }
    }

    /// Check if return value is checked (simplified heuristic)
    fn return_value_checked(&self, stmt: &ast::Statement<'_>) -> bool {
        // This is a simplified check - in a real implementation we'd need
        // to track if the return value is assigned to a variable or used in a require
        match stmt {
            ast::Statement::Expression(_) => false, // Bare expression call
            _ => true, // If it's in any other context, assume it's checked
        }
    }
}
