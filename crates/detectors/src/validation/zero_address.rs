use anyhow::Result;
use ast;
use std::any::Any;

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for missing zero address checks in critical functions
pub struct ZeroAddressDetector {
    base: BaseDetector,
}

impl ZeroAddressDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-zero-address-check"),
                "Missing Zero Address Check".to_string(),
                "Detects functions that accept address parameters without checking for address(0)"
                    .to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }

    /// Analyze a function for missing zero address checks
    fn analyze_function_for_zero_address_checks(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip view/pure functions that don't modify state
        if matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) {
            return findings;
        }

        // Find address parameters
        let address_params = self.find_address_parameters(function);

        if address_params.is_empty() {
            return findings;
        }

        // Check if function body contains zero address checks
        if let Some(body) = &function.body {
            let checked_params = self.find_zero_address_checks(body, &address_params);

            // Extract function source code for string-based checking
            let function_source = self.extract_function_source(&ctx.source_code, function);

            // Report unchecked parameters
            for param in &address_params {
                // Use both AST-based and string-based checking (fallback for AST parsing issues)
                let is_checked = checked_params.contains(&param.name) ||
                                crate::utils::has_zero_address_check(&function_source, &param.name);

                if !is_checked {
                    let severity = self.determine_severity_for_function(function, param);
                    let message = format!(
                        "Address parameter '{}' in function '{}' is not checked for zero address",
                        param.name, function.name.name
                    );

                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            message,
                            param.location.start().line() as u32,
                            param.location.start().column() as u32,
                            param.location.byte_length() as u32,
                            severity,
                        )
                        .with_cwe(476) // CWE-476: NULL Pointer Dereference
                        .with_fix_suggestion(format!(
                            "Add require({} != address(0), \"Zero address not allowed\");",
                            param.name
                        ));
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Find address parameters in function signature
    fn find_address_parameters(&self, function: &ast::Function<'_>) -> Vec<AddressParam> {
        let mut address_params = Vec::new();

        for param in &function.parameters {
            if let Some(name) = &param.name {
                if self.is_address_type(&param.type_name) {
                    address_params.push(AddressParam {
                        name: name.name.to_string(),
                        location: name.location.clone(),
                        is_critical: self.is_critical_address_param(name.name),
                    });
                }
            }
        }

        address_params
    }

    /// Check if a type is an address type
    fn is_address_type(&self, type_name: &ast::TypeName<'_>) -> bool {
        match type_name {
            ast::TypeName::Elementary(ast::ElementaryType::Address) => true,
            _ => false,
        }
    }

    /// Extract function source code from full source using location information
    fn extract_function_source(&self, source: &str, function: &ast::Function<'_>) -> String {
        let location = &function.location;
        let start_offset = location.start().offset();
        let end_offset = location.end().offset();

        if start_offset < source.len() && end_offset <= source.len() && start_offset < end_offset {
            source[start_offset..end_offset].to_string()
        } else {
            // Fallback to empty string if offsets are invalid
            String::new()
        }
    }

    /// Determine if an address parameter is critical based on naming
    fn is_critical_address_param(&self, param_name: &str) -> bool {
        let name_lower = param_name.to_lowercase();

        // Critical address parameter patterns
        name_lower.contains("owner")
            || name_lower.contains("admin")
            || name_lower.contains("authority")
            || name_lower.contains("controller")
            || name_lower.contains("manager")
            || name_lower.contains("governance")
            || name_lower.contains("treasury")
            || name_lower.contains("recipient")
            || name_lower.contains("beneficiary")
            || name_lower.contains("delegate")
            || name_lower.starts_with("to")
            || name_lower.starts_with("from")
            || name_lower == "target"
            || name_lower == "destination"
            || name_lower == "spender"
    }

    /// Find zero address checks in function body
    fn find_zero_address_checks(
        &self,
        block: &ast::Block<'_>,
        address_params: &[AddressParam],
    ) -> std::collections::HashSet<String> {
        let mut checked_params = std::collections::HashSet::new();

        for stmt in &block.statements {
            self.find_checks_in_statement(stmt, address_params, &mut checked_params);
        }

        checked_params
    }

    /// Recursively find zero address checks in statements
    fn find_checks_in_statement(
        &self,
        stmt: &ast::Statement<'_>,
        address_params: &[AddressParam],
        checked_params: &mut std::collections::HashSet<String>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.find_checks_in_expression(expr, address_params, checked_params);
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.find_checks_in_expression(condition, address_params, checked_params);
                self.find_checks_in_statement(then_branch, address_params, checked_params);
                if let Some(else_stmt) = else_branch {
                    self.find_checks_in_statement(else_stmt, address_params, checked_params);
                }
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                self.find_checks_in_expression(condition, address_params, checked_params);
                self.find_checks_in_statement(body, address_params, checked_params);
            }
            ast::Statement::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(init_stmt) = init {
                    self.find_checks_in_statement(init_stmt, address_params, checked_params);
                }
                if let Some(cond_expr) = condition {
                    self.find_checks_in_expression(cond_expr, address_params, checked_params);
                }
                if let Some(update_expr) = update {
                    self.find_checks_in_expression(update_expr, address_params, checked_params);
                }
                self.find_checks_in_statement(body, address_params, checked_params);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.find_checks_in_statement(inner_stmt, address_params, checked_params);
                }
            }
            _ => {}
        }
    }

    /// Find zero address checks in expressions
    fn find_checks_in_expression(
        &self,
        expr: &ast::Expression<'_>,
        address_params: &[AddressParam],
        checked_params: &mut std::collections::HashSet<String>,
    ) {
        match expr {
            // Look for patterns like: param != address(0) or address(0) != param
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                ..
            } => {
                if matches!(operator, ast::BinaryOperator::NotEqual) {
                    let left_id = self.get_identifier_name(left);
                    let right_id = self.get_identifier_name(right);
                    let left_is_zero = self.is_zero_address(left);
                    let right_is_zero = self.is_zero_address(right);

                    // Check if one side is a parameter and the other is address(0)
                    if let (Some(param_name), true) = (&left_id, right_is_zero) {
                        if address_params.iter().any(|p| &p.name == param_name) {
                            checked_params.insert(param_name.clone());
                        }
                    } else if let (Some(param_name), true) = (&right_id, left_is_zero) {
                        if address_params.iter().any(|p| &p.name == param_name) {
                            checked_params.insert(param_name.clone());
                        }
                    }
                }

                // Recursively check nested expressions
                self.find_checks_in_expression(left, address_params, checked_params);
                self.find_checks_in_expression(right, address_params, checked_params);
            }

            // Look for require() calls with zero address checks
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                if let ast::Expression::Identifier(id) = &**function {
                    if id.name == "require" && !arguments.is_empty() {
                        // Check the require condition
                        self.find_checks_in_expression(
                            &arguments[0],
                            address_params,
                            checked_params,
                        );
                    }
                }

                // Also check nested function calls
                self.find_checks_in_expression(function, address_params, checked_params);
                for arg in arguments {
                    self.find_checks_in_expression(arg, address_params, checked_params);
                }
            }

            // Check other expression types
            ast::Expression::Assignment { right, .. } => {
                self.find_checks_in_expression(right, address_params, checked_params);
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.find_checks_in_expression(condition, address_params, checked_params);
                self.find_checks_in_expression(true_expression, address_params, checked_params);
                self.find_checks_in_expression(false_expression, address_params, checked_params);
            }
            _ => {}
        }
    }

    /// Get identifier name from expression if it's an identifier
    fn get_identifier_name(&self, expr: &ast::Expression<'_>) -> Option<String> {
        match expr {
            ast::Expression::Identifier(id) => Some(id.name.to_string()),
            _ => None,
        }
    }

    /// Check if expression represents address(0)
    fn is_zero_address(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            // Check for TypeCast first (address(0) is often represented as TypeCast)
            ast::Expression::TypeCast {
                type_name,
                expression,
                ..
            } => {
                if self.is_address_type(type_name) {
                    if let ast::Expression::Literal { value, .. } = &**expression {
                        return match value {
                            ast::LiteralValue::Number(num) => *num == "0",
                            ast::LiteralValue::HexString(hex) => *hex == "0x0" || *hex == "0x00",
                            _ => false,
                        };
                    }
                }
                false
            }

            // Direct address(0) call
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                if let ast::Expression::Identifier(id) = &**function {
                    if id.name == "address" && arguments.len() == 1 {
                        if let ast::Expression::Literal { value, .. } = &arguments[0] {
                            if let ast::LiteralValue::Number(num) = value {
                                return *num == "0";
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Determine severity based on function context and parameter criticality
    fn determine_severity_for_function(
        &self,
        function: &ast::Function<'_>,
        param: &AddressParam,
    ) -> Severity {
        let function_name = function.name.name.to_lowercase();

        // Critical functions that should always check for zero address
        if function_name.contains("transfer")
            || function_name.contains("approve")
            || function_name.contains("mint")
            || function_name.contains("burn")
            || function_name.contains("withdraw")
            || function_name.contains("deposit")
            || function_name.contains("owner")
            || function_name.contains("admin")
            || function_name.contains("governance")
            || function_name.contains("delegate")
        {
            return Severity::High;
        }

        // Parameter-based severity
        if param.is_critical {
            return Severity::High;
        }

        // Constructor functions are critical
        if matches!(function.function_type, ast::FunctionType::Constructor) {
            return Severity::High;
        }

        // External/public functions are more critical than internal/private
        match function.visibility {
            ast::Visibility::External | ast::Visibility::Public => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// Check if function has any state-changing operations
    fn _has_state_changes(&self, function: &ast::Function<'_>) -> bool {
        !matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        )
    }

    /// Analyze statement for zero address usage patterns
    fn analyze_statement_for_zero_address_usage(
        &self,
        stmt: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment {
                left,
                right,
                location,
                ..
            }) => {
                // Check for assignments to address variables without validation
                if let ast::Expression::Identifier(id) = left {
                    if id.name.to_lowercase().contains("address")
                        || id.name.to_lowercase().contains("owner")
                        || id.name.to_lowercase().contains("recipient")
                    {
                        // Check if the right side could be zero
                        if self.could_be_zero_address(right) {
                            let message = format!(
                                "Assignment to '{}' may result in zero address without validation",
                                id.name
                            );
                            let finding = self
                                .base
                                .create_finding(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                )
                                .with_cwe(476)
                                .with_fix_suggestion(
                                    "Add validation to ensure the address is not zero".to_string(),
                                );
                            findings.push(finding);
                        }
                    }
                }
            }
            _ => {}
        }

        findings
    }

    /// Check if an expression could potentially be zero address
    fn could_be_zero_address(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            // Direct identifiers could be zero
            ast::Expression::Identifier(_) => true,

            // Function calls could return zero
            ast::Expression::FunctionCall { .. } => true,

            // Member access could be zero
            ast::Expression::MemberAccess { .. } => true,

            // Array access could be zero
            ast::Expression::IndexAccess { .. } => true,

            // Literals - check if actually zero
            ast::Expression::Literal { value, .. } => match value {
                ast::LiteralValue::Address(addr) => addr.starts_with("0x0"),
                _ => false,
            },

            _ => false,
        }
    }
}

/// Information about an address parameter
#[derive(Debug, Clone)]
struct AddressParam {
    name: String,
    location: ast::SourceLocation,
    is_critical: bool,
}

impl Detector for ZeroAddressDetector {
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

impl AstAnalyzer for ZeroAddressDetector {
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_function_for_zero_address_checks(function, ctx))
    }

    fn analyze_statement(
        &self,
        statement: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_statement_for_zero_address_usage(statement, ctx))
    }

    fn analyze_expression(
        &self,
        expression: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for direct zero address comparisons that might be backwards
        match expression {
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                location,
            } => {
                if matches!(operator, ast::BinaryOperator::Equal) {
                    // Warn about using == with address(0) instead of !=
                    if self.is_zero_address(left) || self.is_zero_address(right) {
                        let message = "Equality comparison with address(0) detected - consider using != for validation".to_string();
                        let finding = self.base.create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(480) // CWE-480: Use of Incorrect Operator
                        .with_fix_suggestion(
                            "Use != to check that address is not zero, or use == in appropriate context".to_string()
                        );
                        findings.push(finding);
                    }
                }
            }
            _ => {}
        }

        Ok(findings)
    }

    fn analyze_modifier(
        &self,
        _modifier: &ast::Modifier<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Zero address checks are typically in function bodies, not modifiers
        // However, modifiers could also validate addresses
        Ok(Vec::new())
    }
}
