use anyhow::Result;
use ast;
use std::any::Any;

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for division before multiplication which causes precision loss
pub struct DivisionOrderDetector {
    base: BaseDetector,
}

impl DivisionOrderDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("division-before-multiplication"),
                "Division Before Multiplication".to_string(),
                "Detects operations that perform division before multiplication, causing precision loss".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Analyze an expression for division-before-multiplication patterns
    fn analyze_expression_for_division_order(
        &self,
        expr: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        match expr {
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                location,
            } => {
                match operator {
                    ast::BinaryOperator::Mul => {
                        // Check if left operand contains division
                        if self.contains_division(left) {
                            let message = "Division before multiplication detected - this may cause precision loss".to_string();
                            let finding = self.base.create_finding(
                                ctx,
                                message,
                                location.start().line() as u32,
                                location.start().column() as u32,
                                location.byte_length() as u32,
                            )
                            .with_cwe(682) // CWE-682: Incorrect Calculation
                            .with_fix_suggestion(
                                "Reorder operations to multiply before dividing, or use fixed-point arithmetic".to_string()
                            );
                            findings.push(finding);
                        }

                        // Check if right operand contains division
                        if self.contains_division(right) {
                            let message = "Division before multiplication detected in right operand - this may cause precision loss".to_string();
                            let finding = self
                                .base
                                .create_finding(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                )
                                .with_cwe(682)
                                .with_fix_suggestion(
                                    "Reorder operations to multiply before dividing".to_string(),
                                );
                            findings.push(finding);
                        }
                    }
                    ast::BinaryOperator::Div => {
                        // Check for chained divisions (which compound precision loss)
                        if self.contains_division(left) {
                            let message = "Multiple consecutive divisions detected - this compounds precision loss".to_string();
                            let finding = self.base.create_finding(
                                ctx,
                                message,
                                location.start().line() as u32,
                                location.start().column() as u32,
                                location.byte_length() as u32,
                            )
                            .with_cwe(682)
                            .with_fix_suggestion(
                                "Combine divisions into a single operation or use higher precision arithmetic".to_string()
                            );
                            findings.push(finding);
                        }
                    }
                    _ => {}
                }

                // Recursively check operands
                findings.extend(self.analyze_expression_for_division_order(left, ctx));
                findings.extend(self.analyze_expression_for_division_order(right, ctx));
            }
            ast::Expression::Assignment {
                operator,
                left: _,
                right,
                location,
            } => {
                match operator {
                    ast::AssignmentOperator::MulAssign => {
                        // Check for division in right operand of *=
                        if self.contains_division(right) {
                            let message =
                                "Division before multiplication assignment detected".to_string();
                            let finding = self
                                .base
                                .create_finding(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                )
                                .with_cwe(682);
                            findings.push(finding);
                        }
                    }
                    ast::AssignmentOperator::DivAssign => {
                        // Check for compound division assignments
                        if self.contains_division(right) {
                            let message =
                                "Multiple division operations detected in assignment".to_string();
                            let finding = self
                                .base
                                .create_finding(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                )
                                .with_cwe(682);
                            findings.push(finding);
                        }
                    }
                    _ => {}
                }

                findings.extend(self.analyze_expression_for_division_order(right, ctx));
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                location,
                ..
            } => {
                // Check function arguments for division patterns
                for arg in arguments {
                    findings.extend(self.analyze_expression_for_division_order(arg, ctx));
                }

                // Special case: Check for patterns like mulDiv(a/b, c, d) where first param has division
                if let ast::Expression::Identifier(id) = function {
                    if id.name.to_lowercase().contains("mul") && arguments.len() >= 2 {
                        if self.contains_division(&arguments[0]) {
                            let message =
                                "Division in first argument of multiplication function".to_string();
                            let finding = self
                                .base
                                .create_finding(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                )
                                .with_cwe(682);
                            findings.push(finding);
                        }
                    }
                }
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                findings.extend(self.analyze_expression_for_division_order(condition, ctx));
                findings.extend(self.analyze_expression_for_division_order(true_expression, ctx));
                findings.extend(self.analyze_expression_for_division_order(false_expression, ctx));
            }
            _ => {}
        }

        findings
    }

    /// Check if an expression contains a division operation
    fn contains_division(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                ..
            } => {
                matches!(operator, ast::BinaryOperator::Div)
                    || self.contains_division(left)
                    || self.contains_division(right)
            }
            ast::Expression::Assignment {
                operator, right, ..
            } => {
                matches!(operator, ast::AssignmentOperator::DivAssign)
                    || self.contains_division(right)
            }
            ast::Expression::FunctionCall { arguments, .. } => {
                arguments.iter().any(|arg| self.contains_division(arg))
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.contains_division(condition)
                    || self.contains_division(true_expression)
                    || self.contains_division(false_expression)
            }
            _ => false,
        }
    }

    /// Analyze return statements for division-before-multiplication
    fn analyze_return_statement(
        &self,
        stmt: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let ast::Statement::Return {
            value: Some(expr),
            location,
        } = stmt
        {
            // Check for division before multiplication in return expressions
            if let ast::Expression::BinaryOperation {
                operator: ast::BinaryOperator::Mul,
                left,
                ..
            } = expr
            {
                if self.contains_division(left) {
                    let message =
                        "Return statement contains division before multiplication".to_string();
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(682)
                        .with_fix_suggestion(
                            "Consider reordering operations or using higher precision arithmetic"
                                .to_string(),
                        );
                    findings.push(finding);
                }
            }

            findings.extend(self.analyze_expression_for_division_order(expr, ctx));
        }

        findings
    }

    /// Check for division-before-multiplication in loop operations
    fn analyze_loop_for_precision_loss(
        &self,
        stmt: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        match stmt {
            ast::Statement::For {
                update: Some(update),
                body,
                location,
                ..
            } => {
                // Check update expression in for loop
                if self.contains_division_before_multiplication(update) {
                    let message =
                        "Division before multiplication in loop update may compound precision loss"
                            .to_string();
                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                            Severity::High, // Higher severity in loops
                        )
                        .with_cwe(682)
                        .with_fix_suggestion(
                            "Move division outside the loop or use fixed-point arithmetic"
                                .to_string(),
                        );
                    findings.push(finding);
                }

                findings.extend(self.analyze_statement(body, ctx).unwrap_or_default());
            }
            ast::Statement::While { body, .. } => {
                findings.extend(self.analyze_statement(body, ctx).unwrap_or_default());
            }
            _ => {}
        }

        findings
    }

    /// Check if expression has division before multiplication pattern
    fn contains_division_before_multiplication(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::BinaryOperation {
                operator: ast::BinaryOperator::Mul,
                left,
                ..
            } => self.contains_division(left),
            ast::Expression::Assignment {
                operator: ast::AssignmentOperator::MulAssign,
                right,
                ..
            } => self.contains_division(right),
            _ => false,
        }
    }
}

impl Detector for DivisionOrderDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze all functions in the contract
        for function in ctx.get_functions() {
            findings.extend(self.analyze_function(function, ctx)?);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AstAnalyzer for DivisionOrderDetector {
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Some(body) = &function.body {
            for stmt in &body.statements {
                findings.extend(self.analyze_statement(stmt, ctx)?);
            }
        }

        Ok(findings)
    }

    fn analyze_statement(
        &self,
        statement: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        match statement {
            ast::Statement::Expression(expression) => {
                findings.extend(self.analyze_expression_for_division_order(expression, ctx));
            }
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => {
                findings.extend(self.analyze_expression_for_division_order(expr, ctx));
            }
            ast::Statement::Return { .. } => {
                findings.extend(self.analyze_return_statement(statement, ctx));
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                findings.extend(self.analyze_expression_for_division_order(condition, ctx));
                findings.extend(self.analyze_statement(then_branch, ctx)?);
                if let Some(else_stmt) = else_branch {
                    findings.extend(self.analyze_statement(else_stmt, ctx)?);
                }
            }
            ast::Statement::For { .. } | ast::Statement::While { .. } => {
                findings.extend(self.analyze_loop_for_precision_loss(statement, ctx));
            }
            ast::Statement::Block(block) => {
                for stmt in &block.statements {
                    findings.extend(self.analyze_statement(stmt, ctx)?);
                }
            }
            ast::Statement::TryStatement {
                body,
                catch_clauses,
                ..
            } => {
                for stmt in &body.statements {
                    findings.extend(self.analyze_statement(stmt, ctx)?);
                }
                for catch in catch_clauses {
                    for stmt in &catch.body.statements {
                        findings.extend(self.analyze_statement(stmt, ctx)?);
                    }
                }
            }
            _ => {}
        }

        Ok(findings)
    }

    fn analyze_expression(
        &self,
        expression: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_expression_for_division_order(expression, ctx))
    }

    fn analyze_modifier(
        &self,
        _modifier: &ast::Modifier<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Modifiers typically don't contain complex arithmetic
        Ok(Vec::new())
    }
}
