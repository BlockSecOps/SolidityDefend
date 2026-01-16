use anyhow::Result;
use ast;
use std::any::Any;
use std::collections::HashSet;

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for parameter consistency and validation issues
pub struct ParameterConsistencyDetector {
    base: BaseDetector,
}

impl Default for ParameterConsistencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ParameterConsistencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("parameter-consistency"),
                "Parameter Consistency Check".to_string(),
                "Detects inconsistent parameter validation and mismatched array lengths"
                    .to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }

    /// Analyze a function for parameter consistency issues
    fn analyze_function_for_parameter_consistency(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Extract parameter information
        let params = self.extract_parameter_info(function);

        // Check for multiple array parameters without length validation
        findings.extend(self.check_array_length_consistency(&params, function, ctx));

        // Check for missing parameter validation
        findings.extend(self.check_missing_parameter_validation(&params, function, ctx));

        // Check for inconsistent parameter ordering
        findings.extend(self.check_parameter_ordering(&params, function, ctx));

        // Check for parameter shadowing
        findings.extend(self.check_parameter_shadowing(&params, function, ctx));

        // Check function body for parameter usage patterns
        if let Some(body) = &function.body {
            findings.extend(self.check_parameter_usage_patterns(body, &params, ctx));
        }

        findings
    }

    /// Extract parameter information from function
    fn extract_parameter_info(&self, function: &ast::Function<'_>) -> Vec<ParameterInfo> {
        let mut params = Vec::new();

        for (index, param) in function.parameters.iter().enumerate() {
            if let Some(name) = &param.name {
                let param_info = ParameterInfo {
                    name: name.name.to_string(),
                    type_info: self.analyze_parameter_type(&param.type_name),
                    location: name.location.clone(),
                    _index: index,
                    _storage_location: param.storage_location,
                };
                params.push(param_info);
            }
        }

        params
    }

    /// Analyze parameter type to extract useful information
    fn analyze_parameter_type(&self, type_name: &ast::TypeName<'_>) -> ParameterType {
        match type_name {
            ast::TypeName::Elementary(elementary) => match elementary {
                ast::ElementaryType::Address => ParameterType::Address,
                ast::ElementaryType::Bool => ParameterType::Bool,
                ast::ElementaryType::Uint(_) => ParameterType::Uint,
                ast::ElementaryType::Int(_) => ParameterType::Int,
                ast::ElementaryType::Bytes => ParameterType::Bytes,
                ast::ElementaryType::String => ParameterType::String,
                _ => ParameterType::Other,
            },
            ast::TypeName::Array { .. } => ParameterType::Array,
            ast::TypeName::Mapping { .. } => ParameterType::Mapping,
            ast::TypeName::UserDefined(_) => ParameterType::UserDefined,
            _ => ParameterType::Other,
        }
    }

    /// Check for array length consistency issues
    fn check_array_length_consistency(
        &self,
        params: &[ParameterInfo],
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find array parameters
        let array_params: Vec<_> = params
            .iter()
            .filter(|p| matches!(p.type_info, ParameterType::Array))
            .collect();

        if array_params.len() > 1 {
            // Multiple arrays should likely have matching lengths
            let array_names: Vec<_> = array_params.iter().map(|p| &p.name).collect();

            // Check if function body validates array lengths
            if let Some(body) = &function.body {
                if !self.has_array_length_validation(body, &array_names) {
                    let message = format!(
                        "Function '{}' has multiple array parameters ({}) but no length consistency validation",
                        function.name.name,
                        array_names
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
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
                        format!("Add validation: require({}.length == {}.length, \"Array length mismatch\");",
                               array_names[0], array_names[1])
                    );
                    findings.push(finding);
                }
            }
        }

        // Check for arrays with related parameters (like amounts and recipients)
        findings.extend(self.check_related_array_parameters(params, function, ctx));

        findings
    }

    /// Check if function body has array length validation
    fn has_array_length_validation(&self, block: &ast::Block<'_>, array_names: &[&String]) -> bool {
        for stmt in &block.statements {
            if self.statement_validates_array_lengths(stmt, array_names) {
                return true;
            }
        }
        false
    }

    /// Check if statement validates array lengths
    fn statement_validates_array_lengths(
        &self,
        stmt: &ast::Statement<'_>,
        array_names: &[&String],
    ) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.expression_validates_array_lengths(expr, array_names)
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    if self.statement_validates_array_lengths(inner_stmt, array_names) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check if expression validates array lengths
    fn expression_validates_array_lengths(
        &self,
        expr: &ast::Expression<'_>,
        array_names: &[&String],
    ) -> bool {
        if let ast::Expression::FunctionCall {
            function,
            arguments,
            ..
        } = expr
        {
            // Check for require() calls
            if let ast::Expression::Identifier(id) = function {
                if id.name == "require" && !arguments.is_empty() {
                    // Check if the condition compares array lengths
                    return self.condition_compares_array_lengths(&arguments[0], array_names);
                }
            }
        }
        false
    }

    /// Check if condition compares array lengths
    fn condition_compares_array_lengths(
        &self,
        condition: &ast::Expression<'_>,
        array_names: &[&String],
    ) -> bool {
        if let ast::Expression::BinaryOperation {
            operator,
            left,
            right,
            ..
        } = condition
        {
            if matches!(operator, ast::BinaryOperator::Equal) {
                // Check if both sides are array.length references
                let left_array = self.get_array_length_reference(left);
                let right_array = self.get_array_length_reference(right);

                if let (Some(left_name), Some(right_name)) = (left_array, right_array) {
                    return array_names.contains(&&left_name) && array_names.contains(&&right_name);
                }
            }
        }
        false
    }

    /// Get array name if expression is array.length
    fn get_array_length_reference(&self, expr: &ast::Expression<'_>) -> Option<String> {
        if let ast::Expression::MemberAccess {
            expression, member, ..
        } = expr
        {
            if member.name == "length" {
                if let ast::Expression::Identifier(id) = expression {
                    return Some(id.name.to_string());
                }
            }
        }
        None
    }

    /// Check for related array parameters that should be validated together
    fn check_related_array_parameters(
        &self,
        params: &[ParameterInfo],
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for common patterns like (addresses[], amounts[])
        let related_pairs = [
            ("address", "amount"),
            ("recipient", "amount"),
            ("token", "amount"),
            ("user", "balance"),
            ("from", "to"),
            ("sender", "receiver"),
        ];

        for (first_pattern, second_pattern) in &related_pairs {
            let first_params: Vec<_> = params
                .iter()
                .filter(|p| {
                    p.name.to_lowercase().contains(first_pattern)
                        && matches!(p.type_info, ParameterType::Array)
                })
                .collect();

            let second_params: Vec<_> = params
                .iter()
                .filter(|p| {
                    p.name.to_lowercase().contains(second_pattern)
                        && matches!(p.type_info, ParameterType::Array)
                })
                .collect();

            if !first_params.is_empty() && !second_params.is_empty() {
                let message = format!(
                    "Function '{}' has related array parameters '{}' and '{}' that should be validated for equal length",
                    function.name.name, first_params[0].name, second_params[0].name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.location.byte_length() as u32,
                )
                .with_cwe(20)
                .with_fix_suggestion(
                    format!("Add validation: require({}.length == {}.length, \"Related arrays must have equal length\");",
                           first_params[0].name, second_params[0].name)
                );
                findings.push(finding);
            }
        }

        findings
    }

    /// Check for missing parameter validation
    fn check_missing_parameter_validation(
        &self,
        params: &[ParameterInfo],
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip view/pure functions - they don't modify state so validation is less critical
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return findings;
        }

        // Skip internal/private functions - they're called by trusted code
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return findings;
        }

        // Check for validation modifiers that likely validate addresses
        let has_validation_modifier = function.modifiers.iter().any(|m| {
            let mod_name = m.name.as_str().to_lowercase();
            mod_name.contains("valid")
                || mod_name.contains("nonzero")
                || mod_name.contains("notzero")
                || mod_name.contains("notEmpty")
        });

        if has_validation_modifier {
            // Assume modifier handles validation
            return findings;
        }

        if let Some(body) = &function.body {
            let validated_params = self.find_validated_parameters(body);

            // Also check source code for text-based validation patterns
            let func_source = self.get_function_source(function, ctx);

            for param in params {
                if self.parameter_needs_validation(param) && !validated_params.contains(&param.name)
                {
                    // Additional source-based check for validation patterns
                    let param_validated_in_source = self.check_source_validation(&func_source, &param.name);
                    if param_validated_in_source {
                        continue;
                    }

                    let severity = self.determine_validation_severity(param, function);
                    let message = format!(
                        "Parameter '{}' of type '{}' may need validation",
                        param.name,
                        self.type_to_string(&param.type_info)
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
                        .with_cwe(20)
                        .with_fix_suggestion(self.suggest_validation_for_parameter(param));
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Get function source code for text-based analysis
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext<'_>) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if parameter is validated in source code using text patterns
    fn check_source_validation(&self, source: &str, param_name: &str) -> bool {
        let source_lower = source.to_lowercase();
        let param_lower = param_name.to_lowercase();

        // Check for require statements with parameter
        if source_lower.contains(&format!("require({}", param_lower))
            || source_lower.contains(&format!("require( {}", param_lower))
        {
            return true;
        }

        // Check for if-revert patterns
        if source_lower.contains(&format!("if ({}", param_lower))
            && (source_lower.contains("revert") || source_lower.contains("revert("))
        {
            return true;
        }

        // Check for address(0) comparison with this parameter
        if source_lower.contains(&format!("{} != address(0)", param_lower))
            || source_lower.contains(&format!("{} == address(0)", param_lower))
            || source_lower.contains(&format!("address(0) != {}", param_lower))
            || source_lower.contains(&format!("address(0) == {}", param_lower))
        {
            return true;
        }

        false
    }

    /// Check if parameter needs validation
    fn parameter_needs_validation(&self, param: &ParameterInfo) -> bool {
        match param.type_info {
            ParameterType::Address => true,
            ParameterType::Uint | ParameterType::Int => {
                // Numeric parameters often need range validation
                param.name.to_lowercase().contains("amount")
                    || param.name.to_lowercase().contains("value")
                    || param.name.to_lowercase().contains("price")
                    || param.name.to_lowercase().contains("rate")
                    || param.name.to_lowercase().contains("percent")
            }
            ParameterType::Array => true,
            _ => false,
        }
    }

    /// Determine severity for missing validation
    fn determine_validation_severity(
        &self,
        param: &ParameterInfo,
        function: &ast::Function<'_>,
    ) -> Severity {
        // Critical parameters in critical functions
        if matches!(param.type_info, ParameterType::Address)
            && (param.name.to_lowercase().contains("owner")
                || param.name.to_lowercase().contains("admin")
                || function.name.name.to_lowercase().contains("transfer"))
        {
            return Severity::High;
        }

        // Arrays are generally medium risk
        if matches!(param.type_info, ParameterType::Array) {
            return Severity::Medium;
        }

        Severity::Low
    }

    /// Convert parameter type to string for messages
    fn type_to_string(&self, param_type: &ParameterType) -> &'static str {
        match param_type {
            ParameterType::Address => "address",
            ParameterType::Bool => "bool",
            ParameterType::Uint => "uint",
            ParameterType::Int => "int",
            ParameterType::Bytes => "bytes",
            ParameterType::String => "string",
            ParameterType::Array => "array",
            ParameterType::Mapping => "mapping",
            ParameterType::UserDefined => "user-defined",
            ParameterType::Other => "other",
        }
    }

    /// Suggest appropriate validation for parameter
    fn suggest_validation_for_parameter(&self, param: &ParameterInfo) -> String {
        match param.type_info {
            ParameterType::Address => {
                format!(
                    "require({} != address(0), \"Invalid address\");",
                    param.name
                )
            }
            ParameterType::Uint | ParameterType::Int => {
                if param.name.to_lowercase().contains("amount") {
                    format!("require({} > 0, \"Amount must be positive\");", param.name)
                } else {
                    format!("Add appropriate range validation for {}", param.name)
                }
            }
            ParameterType::Array => {
                format!(
                    "require({}.length > 0, \"Array cannot be empty\");",
                    param.name
                )
            }
            _ => "Add appropriate validation".to_string(),
        }
    }

    /// Find parameters that are validated in function body
    fn find_validated_parameters(&self, block: &ast::Block<'_>) -> HashSet<String> {
        let mut validated = HashSet::new();

        for stmt in &block.statements {
            self.collect_validated_parameters_from_stmt(stmt, &mut validated);
        }

        validated
    }

    /// Collect validated parameters from statement
    fn collect_validated_parameters_from_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        validated: &mut HashSet<String>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.collect_validated_parameters_from_expr(expr, validated);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.collect_validated_parameters_from_stmt(inner_stmt, validated);
                }
            }
            _ => {}
        }
    }

    /// Collect validated parameters from expression
    fn collect_validated_parameters_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        validated: &mut HashSet<String>,
    ) {
        if let ast::Expression::FunctionCall {
            function,
            arguments,
            ..
        } = expr
        {
            // Check for require() calls
            if let ast::Expression::Identifier(id) = function {
                if id.name == "require" && !arguments.is_empty() {
                    self.extract_validated_params_from_condition(&arguments[0], validated);
                }
            }
        }
    }

    /// Extract validated parameters from require condition
    fn extract_validated_params_from_condition(
        &self,
        condition: &ast::Expression<'_>,
        validated: &mut HashSet<String>,
    ) {
        if let ast::Expression::BinaryOperation { left, right, .. } = condition {
            self.extract_param_names_from_expr(left, validated);
            self.extract_param_names_from_expr(right, validated);
        }
    }

    /// Extract parameter names from expression
    fn extract_param_names_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        validated: &mut HashSet<String>,
    ) {
        match expr {
            ast::Expression::Identifier(id) => {
                validated.insert(id.name.to_string());
            }
            ast::Expression::MemberAccess { expression, .. } => {
                self.extract_param_names_from_expr(expression, validated);
            }
            _ => {}
        }
    }

    /// Check for parameter ordering issues
    fn check_parameter_ordering(
        &self,
        params: &[ParameterInfo],
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for common ordering patterns
        if params.len() >= 2 {
            // Address parameters should typically come before amount parameters
            for i in 0..params.len() - 1 {
                if matches!(
                    params[i].type_info,
                    ParameterType::Uint | ParameterType::Int
                ) && matches!(params[i + 1].type_info, ParameterType::Address)
                    && params[i].name.to_lowercase().contains("amount")
                {
                    let message = format!(
                        "Parameter ordering in function '{}': address parameter '{}' should typically come before amount parameter '{}'",
                        function.name.name,
                        params[i + 1].name,
                        params[i].name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.location.byte_length() as u32,
                        )
                        .with_cwe(1188) // CWE-1188: Insecure Default Initialization of Resource
                        .with_fix_suggestion(
                            "Consider reordering parameters: address before amount".to_string(),
                        );
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check for parameter shadowing
    fn check_parameter_shadowing(
        &self,
        _params: &[ParameterInfo],
        _function: &ast::Function<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        // DISABLED: Parameter shadowing check is overly pedantic
        // Common parameter names like "owner", "token", "balance" are legitimate
        // and don't necessarily shadow state variables. Many legitimate patterns:
        // - transferOwnership(address owner) - parameter "owner" is the new owner
        // - transfer(address token, uint amount) - parameter "token" is the token to transfer
        // - deposit(uint balance) - parameter "balance" is the deposit amount
        //
        // The Solidity compiler already warns about actual shadowing (same name in scope).
        // This check creates noise with false positives on legitimate parameter names.
        //
        // TODO: Only flag if we can prove the parameter name actually shadows a state variable

        Vec::new()
    }

    /// Check parameter usage patterns in function body
    fn check_parameter_usage_patterns(
        &self,
        _block: &ast::Block<'_>,
        _params: &[ParameterInfo],
        _ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        // DISABLED: "Unused parameter" detection is unreliable
        // The find_used_parameters() function doesn't correctly identify all usage patterns:
        // - Mapping access: balanceOf[param]
        // - Array access: items[param]
        // - Struct member access patterns
        // - Parameters used in modifiers
        //
        // This causes many false positives where parameters ARE used but flagged as unused.
        // The Solidity compiler already warns about truly unused parameters.
        //
        // TODO: Improve AST traversal to correctly identify all parameter usage patterns

        Vec::new()
    }

    /// Find parameters used in function body
    #[allow(dead_code)]
    fn find_used_parameters(&self, block: &ast::Block<'_>) -> HashSet<String> {
        let mut used = HashSet::new();

        for stmt in &block.statements {
            self.collect_used_identifiers_from_stmt(stmt, &mut used);
        }

        used
    }

    /// Collect used identifiers from statement
    #[allow(dead_code)]
    fn collect_used_identifiers_from_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        used: &mut HashSet<String>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.collect_used_identifiers_from_expr(expr, used);
            }
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => {
                self.collect_used_identifiers_from_expr(expr, used);
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.collect_used_identifiers_from_expr(condition, used);
                self.collect_used_identifiers_from_stmt(then_branch, used);
                if let Some(else_stmt) = else_branch {
                    self.collect_used_identifiers_from_stmt(else_stmt, used);
                }
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.collect_used_identifiers_from_stmt(inner_stmt, used);
                }
            }
            _ => {}
        }
    }

    /// Collect used identifiers from expression
    #[allow(dead_code)]
    fn collect_used_identifiers_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        used: &mut HashSet<String>,
    ) {
        match expr {
            ast::Expression::Identifier(id) => {
                used.insert(id.name.to_string());
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.collect_used_identifiers_from_expr(left, used);
                self.collect_used_identifiers_from_expr(right, used);
            }
            ast::Expression::Assignment { left, right, .. } => {
                self.collect_used_identifiers_from_expr(left, used);
                self.collect_used_identifiers_from_expr(right, used);
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.collect_used_identifiers_from_expr(function, used);
                for arg in arguments {
                    self.collect_used_identifiers_from_expr(arg, used);
                }
            }
            ast::Expression::MemberAccess { expression, .. } => {
                self.collect_used_identifiers_from_expr(expression, used);
            }
            ast::Expression::IndexAccess { base, index, .. } => {
                self.collect_used_identifiers_from_expr(base, used);
                if let Some(index_expr) = index {
                    self.collect_used_identifiers_from_expr(index_expr, used);
                }
            }
            _ => {}
        }
    }
}

/// Information about a function parameter
#[derive(Debug, Clone)]
struct ParameterInfo {
    name: String,
    type_info: ParameterType,
    location: ast::SourceLocation,
    _index: usize,
    _storage_location: Option<ast::StorageLocation>,
}

/// Simplified parameter type classification
#[derive(Debug, Clone, PartialEq)]
enum ParameterType {
    Address,
    Bool,
    Uint,
    Int,
    Bytes,
    String,
    Array,
    Mapping,
    UserDefined,
    Other,
}

impl Detector for ParameterConsistencyDetector {
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

        // Skip analysis for standard protocols - they follow established patterns
        // ERC20, ERC721, ERC4626, etc. have well-defined interfaces with specific behaviors
        let source_lower = ctx.source_code.to_lowercase();
        let is_standard_token = (source_lower.contains("function transfer(address")
            || source_lower.contains("function transferfrom("))
            && source_lower.contains("balanceof")
            && source_lower.contains("erc20")
            || source_lower.contains("erc721")
            || source_lower.contains("erc1155");

        if is_standard_token {
            // Only check array length consistency for standard tokens
            // Skip pedantic parameter validation checks
            for function in ctx.get_functions() {
                let params = self.extract_parameter_info(function);
                findings.extend(self.check_array_length_consistency(&params, function, ctx));
            }
            return Ok(findings);
        }

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

impl AstAnalyzer for ParameterConsistencyDetector {
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_function_for_parameter_consistency(function, ctx))
    }

    fn analyze_statement(
        &self,
        _statement: &ast::Statement<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Parameter consistency is primarily a function-level analysis
        Ok(Vec::new())
    }

    fn analyze_expression(
        &self,
        _expression: &ast::Expression<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Parameter consistency is primarily a function-level analysis
        Ok(Vec::new())
    }

    fn analyze_modifier(
        &self,
        _modifier: &ast::Modifier<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Parameter consistency is primarily a function-level analysis
        Ok(Vec::new())
    }
}
