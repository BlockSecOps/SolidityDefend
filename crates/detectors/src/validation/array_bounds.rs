use anyhow::Result;
use std::any::Any;
use std::collections::HashMap;
use ast::{self, Located};

use crate::detector::{Detector, DetectorCategory, BaseDetector, AstAnalyzer};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for array bounds checking vulnerabilities
pub struct ArrayBoundsDetector {
    base: BaseDetector,
}

impl ArrayBoundsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("array-bounds-check"),
                "Array Bounds Check".to_string(),
                "Detects potential array out-of-bounds access and missing length validation".to_string(),
                vec![DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }

    /// Analyze a function for array bounds issues
    fn analyze_function_for_array_bounds(&self, function: &ast::Function<'_>, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(body) = &function.body {
            // Identify array parameters and variables
            let arrays = self.identify_arrays(function, ctx);

            // Check for unchecked array access
            findings.extend(self.check_unchecked_array_access(body, &arrays, ctx));

            // Check for loop bounds issues
            findings.extend(self.check_loop_array_bounds(body, &arrays, ctx));

            // Check for missing length validation
            findings.extend(self.check_missing_length_validation(function, &arrays, ctx));

            // Check for off-by-one errors
            findings.extend(self.check_off_by_one_errors(body, &arrays, ctx));
        }

        findings
    }

    /// Identify array variables and parameters in the function
    fn identify_arrays(&self, function: &ast::Function<'_>, ctx: &AnalysisContext<'_>) -> HashMap<String, ArrayInfo> {
        let mut arrays = HashMap::new();

        // Check function parameters
        for param in &function.parameters {
            if let Some(name) = &param.name {
                let array_info = self.get_array_info(&param.type_name, &name.location);
                if let Some(info) = array_info {
                    arrays.insert(name.name.to_string(), info);
                }
            }
        }

        // Check state variables (simplified - in real implementation would analyze contract state)
        for state_var in &ctx.contract.state_variables {
            let array_info = self.get_array_info(&state_var.type_name, &state_var.location);
            if let Some(info) = array_info {
                arrays.insert(state_var.name.name.to_string(), info);
            }
        }

        arrays
    }

    /// Extract array information from type name
    fn get_array_info(&self, type_name: &ast::TypeName<'_>, location: &ast::SourceLocation) -> Option<ArrayInfo> {
        match type_name {
            ast::TypeName::Array { base_type, length } => {
                Some(ArrayInfo {
                    base_type: format!("{:?}", base_type), // Simplified - would need proper type formatting
                    is_dynamic: length.is_none(),
                    fixed_length: length.and_then(|_| Some(0)), // Would need to evaluate expression
                    location: location.clone(),
                    dimensions: 1,
                })
            }
            _ => None,
        }
    }

    /// Check for unchecked array access patterns
    fn check_unchecked_array_access(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_unchecked_access(stmt, arrays, &mut findings, ctx);
        }

        findings
    }

    /// Check statement for unchecked array access
    fn check_statement_for_unchecked_access(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.check_expression_for_unchecked_access(expr, arrays, findings, ctx);
            }
            ast::Statement::VariableDeclaration { initial_value: Some(expr), .. } => {
                self.check_expression_for_unchecked_access(expr, arrays, findings, ctx);
            }
            ast::Statement::If { condition, then_branch, else_branch, .. } => {
                self.check_expression_for_unchecked_access(condition, arrays, findings, ctx);
                self.check_statement_for_unchecked_access(then_branch, arrays, findings, ctx);
                if let Some(else_stmt) = else_branch {
                    self.check_statement_for_unchecked_access(else_stmt, arrays, findings, ctx);
                }
            }
            ast::Statement::While { condition, body, .. } => {
                self.check_expression_for_unchecked_access(condition, arrays, findings, ctx);
                self.check_statement_for_unchecked_access(body, arrays, findings, ctx);
            }
            ast::Statement::For { init, condition, update, body, .. } => {
                if let Some(init_stmt) = init {
                    self.check_statement_for_unchecked_access(init_stmt, arrays, findings, ctx);
                }
                if let Some(cond_expr) = condition {
                    self.check_expression_for_unchecked_access(cond_expr, arrays, findings, ctx);
                }
                if let Some(update_expr) = update {
                    self.check_expression_for_unchecked_access(update_expr, arrays, findings, ctx);
                }
                self.check_statement_for_unchecked_access(body, arrays, findings, ctx);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_unchecked_access(inner_stmt, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Check expression for unchecked array access
    fn check_expression_for_unchecked_access(
        &self,
        expr: &ast::Expression<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>
    ) {
        match expr {
            ast::Expression::IndexAccess { base, index, location } => {
                // Check if base is an array
                if let ast::Expression::Identifier(id) = base {
                    if arrays.contains_key(id.name) {
                        // Check if index is validated
                        if let Some(index_expr) = index {
                            if !self.is_index_validated(index_expr, id.name, arrays) {
                                let message = format!(
                                    "Array access to '{}' may be out of bounds - index not validated",
                                    id.name
                                );

                                let severity = if arrays[id.name].is_dynamic {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                };

                                let finding = self.base.create_finding_with_severity(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                    severity,
                                )
                                .with_cwe(125) // CWE-125: Out-of-bounds Read
                                .with_fix_suggestion(
                                    format!("Add bounds check: require(index < {}.length, \"Index out of bounds\");", id.name)
                                );
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.check_expression_for_unchecked_access(left, arrays, findings, ctx);
                self.check_expression_for_unchecked_access(right, arrays, findings, ctx);
            }
            ast::Expression::Assignment { left, right, .. } => {
                self.check_expression_for_unchecked_access(left, arrays, findings, ctx);
                self.check_expression_for_unchecked_access(right, arrays, findings, ctx);
            }
            ast::Expression::FunctionCall { function, arguments, .. } => {
                self.check_expression_for_unchecked_access(function, arrays, findings, ctx);
                for arg in arguments {
                    self.check_expression_for_unchecked_access(arg, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Check if an index is properly validated
    fn is_index_validated(&self, index_expr: &ast::Expression<'_>, _array_name: &str, _arrays: &HashMap<String, ArrayInfo>) -> bool {
        // Simplified validation check - in a real implementation, this would analyze
        // the control flow to see if there are bounds checks before this access
        match index_expr {
            // Literal indices might be safe if they're small constants
            ast::Expression::Literal { value, .. } => {
                if let ast::LiteralValue::Number(num) = value {
                    // Consider literal 0, 1, 2 as potentially safe (though still needs verification)
                    match num.parse::<u32>() {
                        Ok(n) => n < 10, // Conservative - assume small literals might be safe
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            // Variables and complex expressions are considered unvalidated
            _ => false,
        }
    }

    /// Check for loop bounds issues
    fn check_loop_array_bounds(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_loop_bounds(stmt, arrays, &mut findings, ctx);
        }

        findings
    }

    /// Check statement for loop bounds issues
    fn check_statement_for_loop_bounds(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>
    ) {
        match stmt {
            ast::Statement::For { condition, body, location, .. } => {
                // Check if the loop condition properly bounds array access
                if let Some(cond_expr) = condition {
                    let array_accesses = self.find_array_accesses_in_body(body, arrays);

                    for array_name in array_accesses {
                        if !self.loop_condition_bounds_array(cond_expr, &array_name) {
                            let message = format!(
                                "Loop may access array '{}' out of bounds - condition doesn't properly validate array length",
                                array_name
                            );
                            let finding = self.base.create_finding_with_severity(
                                ctx,
                                message,
                                location.start().line() as u32,
                                location.start().column() as u32,
                                location.byte_length() as u32,
                                Severity::High,
                            )
                            .with_cwe(119) // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
                            .with_fix_suggestion(
                                format!("Use proper loop bounds: for (uint i = 0; i < {}.length; i++)", array_name)
                            );
                            findings.push(finding);
                        }
                    }
                }

                // Recursively check nested loops
                self.check_statement_for_loop_bounds(body, arrays, findings, ctx);
            }
            ast::Statement::While { condition: _, body, .. } => {
                // While loops with array access are generally more dangerous
                let array_accesses = self.find_array_accesses_in_body(body, arrays);

                if !array_accesses.is_empty() {
                    let message = "While loop contains array access - ensure proper bounds checking".to_string();
                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        stmt.location().start().line() as u32,
                        stmt.location().start().column() as u32,
                        stmt.location().byte_length() as u32,
                    )
                    .with_cwe(835) // CWE-835: Loop with Unreachable Exit Condition
                    .with_fix_suggestion(
                        "Add explicit bounds checking in while loop condition".to_string()
                    );
                    findings.push(finding);
                }

                self.check_statement_for_loop_bounds(body, arrays, findings, ctx);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_loop_bounds(inner_stmt, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Find array accesses within a statement body
    fn find_array_accesses_in_body(&self, stmt: &ast::Statement<'_>, arrays: &HashMap<String, ArrayInfo>) -> Vec<String> {
        let mut accesses = Vec::new();
        self.collect_array_accesses_from_stmt(stmt, arrays, &mut accesses);
        accesses
    }

    /// Recursively collect array accesses from statement
    fn collect_array_accesses_from_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        accesses: &mut Vec<String>
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.collect_array_accesses_from_expr(expr, arrays, accesses);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.collect_array_accesses_from_stmt(inner_stmt, arrays, accesses);
                }
            }
            _ => {}
        }
    }

    /// Collect array accesses from expression
    fn collect_array_accesses_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        accesses: &mut Vec<String>
    ) {
        match expr {
            ast::Expression::IndexAccess { base, .. } => {
                if let ast::Expression::Identifier(id) = base {
                    if arrays.contains_key(id.name) {
                        accesses.push(id.name.to_string());
                    }
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.collect_array_accesses_from_expr(left, arrays, accesses);
                self.collect_array_accesses_from_expr(right, arrays, accesses);
            }
            _ => {}
        }
    }

    /// Check if loop condition properly bounds the given array
    fn loop_condition_bounds_array(&self, condition: &ast::Expression<'_>, array_name: &str) -> bool {
        match condition {
            ast::Expression::BinaryOperation { operator, right, .. } => {
                if matches!(operator, ast::BinaryOperator::Less | ast::BinaryOperator::LessEqual) {
                    // Check if right side is array.length
                    if let ast::Expression::MemberAccess { expression, member, .. } = right {
                        if let ast::Expression::Identifier(id) = expression {
                            return id.name == array_name && member.name == "length";
                        }
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Check for missing length validation in function parameters
    fn check_missing_length_validation(
        &self,
        function: &ast::Function<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for multiple array parameters that should have matching lengths
        let array_params: Vec<_> = function.parameters.iter()
            .filter_map(|param| {
                if let Some(name) = &param.name {
                    if arrays.contains_key(name.name) {
                        Some((name.name.to_string(), &param.location))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if array_params.len() > 1 {
            // Multiple arrays should likely have length validation
            let message = format!(
                "Function '{}' has multiple array parameters but no apparent length validation",
                function.name.name
            );
            let finding = self.base.create_finding(
                ctx,
                message,
                function.name.location.start().line() as u32,
                function.name.location.start().column() as u32,
                function.name.location.byte_length() as u32,
            )
            .with_cwe(20) // CWE-20: Improper Input Validation
            .with_fix_suggestion(
                "Add length validation: require(array1.length == array2.length, \"Array length mismatch\");".to_string()
            );
            findings.push(finding);
        }

        findings
    }

    /// Check for off-by-one errors in array access
    fn check_off_by_one_errors(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_off_by_one(stmt, arrays, &mut findings, ctx);
        }

        findings
    }

    /// Check statement for off-by-one errors
    fn check_statement_for_off_by_one(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>
    ) {
        match stmt {
            ast::Statement::For { condition, location, .. } => {
                if let Some(cond_expr) = condition {
                    if self.has_potential_off_by_one(cond_expr, arrays) {
                        let message = "Potential off-by-one error in loop condition - check array bounds".to_string();
                        let finding = self.base.create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(193) // CWE-193: Off-by-one Error
                        .with_fix_suggestion(
                            "Verify loop bounds: use < for exclusive bounds, <= for inclusive bounds".to_string()
                        );
                        findings.push(finding);
                    }
                }
            }
            ast::Statement::Expression(ast::Expression::IndexAccess { base, index, location }) => {
                if let (ast::Expression::Identifier(id), Some(index_expr)) = (base, index) {
                    if arrays.contains_key(id.name) {
                        if self.index_might_be_off_by_one(index_expr) {
                            let message = format!(
                                "Potential off-by-one error in array access to '{}'",
                                id.name
                            );
                            let finding = self.base.create_finding(
                                ctx,
                                message,
                                location.start().line() as u32,
                                location.start().column() as u32,
                                location.byte_length() as u32,
                            )
                            .with_cwe(193)
                            .with_fix_suggestion(
                                "Verify array index calculation is correct".to_string()
                            );
                            findings.push(finding);
                        }
                    }
                }
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_off_by_one(inner_stmt, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Check if condition has potential off-by-one error
    fn has_potential_off_by_one(&self, condition: &ast::Expression<'_>, _arrays: &HashMap<String, ArrayInfo>) -> bool {
        match condition {
            ast::Expression::BinaryOperation { operator, right, .. } => {
                // Check for <= array.length (should usually be < array.length)
                if matches!(operator, ast::BinaryOperator::LessEqual) {
                    if let ast::Expression::MemberAccess { member, .. } = right {
                        return member.name == "length";
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Check if index expression might have off-by-one error
    fn index_might_be_off_by_one(&self, index_expr: &ast::Expression<'_>) -> bool {
        match index_expr {
            // Expressions like length, length + 1, etc.
            ast::Expression::MemberAccess { member, .. } => {
                return member.name == "length";
            }
            ast::Expression::BinaryOperation { operator, left, right, .. } => {
                if matches!(operator, ast::BinaryOperator::Add) {
                    // Check for length + something
                    if let ast::Expression::MemberAccess { member, .. } = left {
                        if member.name == "length" {
                            return true;
                        }
                    }
                    if let ast::Expression::MemberAccess { member, .. } = right {
                        if member.name == "length" {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
        false
    }
}

/// Information about an array variable
#[derive(Debug, Clone)]
struct ArrayInfo {
    base_type: String,
    is_dynamic: bool,
    fixed_length: Option<u32>,
    location: ast::SourceLocation,
    dimensions: u8,
}

impl Detector for ArrayBoundsDetector {
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

impl AstAnalyzer for ArrayBoundsDetector {
    fn analyze_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        Ok(self.analyze_function_for_array_bounds(function, ctx))
    }

    fn analyze_statement(&self, statement: &ast::Statement<'_>, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for direct array access in statements
        match statement {
            ast::Statement::Expression(ast::Expression::IndexAccess { base, index, location }) => {
                if let (ast::Expression::Identifier(id), Some(_)) = (base, index) {
                    // Simplified check for array access without validation context
                    let message = format!("Array access to '{}' - ensure bounds are checked", id.name);
                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        location.start().line() as u32,
                        location.start().column() as u32,
                        location.byte_length() as u32,
                    )
                    .with_cwe(125);
                    findings.push(finding);
                }
            }
            _ => {}
        }

        Ok(findings)
    }

    fn analyze_expression(&self, expression: &ast::Expression<'_>, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze array access expressions
        match expression {
            ast::Expression::IndexAccess { base, index, location } => {
                if let ast::Expression::Identifier(_id) = base {
                    if index.is_none() {
                        let message = "Array access with empty index detected".to_string();
                        let finding = self.base.create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(125);
                        findings.push(finding);
                    }
                }
            }
            _ => {}
        }

        Ok(findings)
    }

    fn analyze_modifier(&self, _modifier: &ast::Modifier<'_>, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        // Array bounds checking is typically in function bodies, not modifiers
        Ok(Vec::new())
    }
}