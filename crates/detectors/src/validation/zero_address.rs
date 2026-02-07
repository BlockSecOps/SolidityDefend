use anyhow::Result;
use ast;
use std::any::Any;

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for missing zero address checks in critical functions
pub struct ZeroAddressDetector {
    base: BaseDetector,
}

impl Default for ZeroAddressDetector {
    fn default() -> Self {
        Self::new()
    }
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

        // Phase 6: Skip constructors - they set initial state safely
        // Constructor address parameters are typically set once at deployment
        if matches!(function.function_type, ast::FunctionType::Constructor) {
            return findings;
        }

        // Skip internal/private functions - they're called by trusted code
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return findings;
        }

        // Skip standard token/vault interface functions - zero address behavior is by design
        // ERC20: transfer to address(0) burns tokens (allowed by spec)
        // ERC20: approve address(0) revokes approval (allowed by spec)
        // ERC721: transferFrom to address(0) burns NFT (allowed by spec)
        // ERC-4626: redeem/withdraw have `owner` param meaning share-owner, not access control
        let func_name_lower = function.name.name.to_lowercase();
        let is_standard_token_function = func_name_lower == "transfer"
            || func_name_lower == "transferfrom"
            || func_name_lower == "approve"
            || func_name_lower == "safetransfer"
            || func_name_lower == "safetransferfrom"
            || func_name_lower == "burn"  // Burn explicitly sends to zero
            || func_name_lower == "burnfrom"
            || func_name_lower == "mint"  // Mint often allows flexible recipient
            || func_name_lower == "mintto"
            || func_name_lower == "redeem"  // ERC-4626 vault function
            || func_name_lower == "deposit" // ERC-4626 vault function
            || func_name_lower == "withdraw"; // ERC-4626 vault function - owner param is beneficiary

        if is_standard_token_function {
            return findings;
        }

        // FP Reduction: Skip social recovery / multi-step governance functions
        // These functions use guardian validation, timelocks, and multi-approval processes
        // rather than parameter-level zero-address checks
        let is_recovery_function =
            func_name_lower.contains("recovery") || func_name_lower.contains("recover");

        if is_recovery_function {
            return findings;
        }

        // FP Reduction: Skip functions with empty bodies
        // Functions with no statements have no state changes to protect
        if let Some(body) = &function.body {
            if body.statements.is_empty() {
                return findings;
            }
        } else {
            // No body at all (interface/abstract function)
            return findings;
        }

        // FP Reduction: Skip functions with access control modifiers
        // Functions protected by onlyOwner, onlyAdmin, etc. have trusted callers
        // who are expected to provide valid addresses
        let has_access_control_modifier = function.modifiers.iter().any(|m| {
            let mod_name = m.name.name.to_lowercase();
            mod_name.contains("only")
                || mod_name.contains("auth")
                || mod_name.contains("restrict")
                || mod_name.contains("admin")
                || mod_name.contains("owner")
                || mod_name.contains("guard")
                || mod_name == "initializer"
                || mod_name == "reinitializer"
        });

        if has_access_control_modifier {
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

            // FP Reduction: Skip functions with inline access control (require(msg.sender == ...))
            // When a function has access control, the caller is trusted to provide valid addresses.
            // This covers patterns like: require(msg.sender == owner), require(msg.sender == admin)
            let has_inline_access_control = function_source.contains("msg.sender ==")
                || function_source.contains("== msg.sender")
                || function_source.contains("isGuardian")
                || function_source.contains("isAuthorized");

            if has_inline_access_control {
                return findings;
            }

            // FP Reduction: Skip initialize/init functions entirely
            // Initialize functions are either:
            // 1. Protected by initializer modifier (already caught above)
            // 2. Protected by an init guard (require(!initialized), etc.)
            // 3. Completely unprotected (the bigger issue is unprotected-initializer)
            // In all cases, the zero-address check is a secondary concern compared to
            // the initialization protection issue. The unprotected-initializer detector
            // handles the primary security concern.
            if func_name_lower == "initialize" || func_name_lower == "init" {
                return findings;
            }

            // FP Reduction: Skip owner/admin-setting functions that lack access control entirely
            // If a function like setOwner() has NO access control (no modifier, no msg.sender check),
            // the missing access control is a far more critical vulnerability than missing zero-address
            // check. The access control detectors (enhanced-access-control, swc105, etc.) handle this.
            // Reporting zero-address here adds noise without actionable value.
            // Note: If the function had access control, we would have already returned above.
            let is_owner_setter = func_name_lower == "setowner"
                || func_name_lower == "changeowner"
                || func_name_lower == "transferownership"
                || func_name_lower == "setadmin"
                || func_name_lower == "changeadmin";

            if is_owner_setter {
                return findings;
            }

            // Report unchecked parameters - but ONLY for truly critical parameters
            for param in &address_params {
                // Skip non-critical parameters entirely - no need to report them
                // This reduces FPs for transfer destinations, spenders, etc.
                if !param.is_critical {
                    continue;
                }

                // Use both AST-based and string-based checking (fallback for AST parsing issues)
                let is_checked = checked_params.contains(&param.name)
                    || crate::utils::has_zero_address_check(&function_source, &param.name);

                if !is_checked {
                    let severity = self.determine_severity_for_function(function, param);
                    let message = format!(
                        "Critical address parameter '{}' in function '{}' is not checked for zero address",
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
    /// Critical = parameters that control contract functionality/access
    /// NOT critical = transfer destinations (zero address often intentional for burns)
    fn is_critical_address_param(&self, param_name: &str) -> bool {
        let name_lower = param_name.to_lowercase();

        // FP Reduction Phase 2: Parameters that intentionally allow zero address
        // - "fallback*" - zero means disable fallback
        // - "new*" parameters in upgrade functions - often validated elsewhere
        // - Generic single-letter or very short names
        let is_intentionally_nullable = name_lower.contains("fallback")
            || name_lower.contains("optional")
            || name_lower.contains("default")
            || name_lower == "a"
            || name_lower == "b"
            || name_lower == "_a"
            || name_lower == "_b";

        if is_intentionally_nullable {
            return false;
        }

        // CRITICAL address parameters that MUST be checked for zero:
        // These control contract functionality, access, or ownership
        // FP Reduction Phase 2: Be more specific - only core access control
        let is_access_control = name_lower == "owner"
            || name_lower == "newowner"
            || name_lower == "_owner"
            || name_lower == "_newowner"
            || name_lower == "pendingowner"
            || name_lower == "_pendingowner"
            || name_lower == "admin"
            || name_lower == "_admin"
            || (name_lower.contains("admin") && !name_lower.contains("pool"))  // FP: poolAdmin often checked elsewhere
            || name_lower == "governance"
            || name_lower == "_governance";

        // FP Reduction Phase 2: Contract addresses that are CRITICAL
        // But exclude addresses that may be intentionally disabled
        let is_critical_contract_address = name_lower == "implementation"
            || name_lower == "_implementation"
            || name_lower == "newimplementation"
            || name_lower == "beacon"
            || name_lower == "_beacon";

        // NOT CRITICAL - transfer destinations where zero address may be intentional:
        // - "to" / "recipient" / "beneficiary" - often zero for burn operations
        // - "from" - checked by transferFrom, often msg.sender
        // - "spender" - approve(address(0)) is used to revoke approvals
        // - "target" / "destination" - may be intentionally flexible
        // Phase 6: Added more non-critical patterns
        // - "sender", "origin", "caller" - already validated by EVM
        // - "_receiver", "_beneficiary" - commonly flexible parameters
        // Phase 2: Added more patterns that are commonly flexible
        let is_transfer_destination = name_lower.starts_with("to")
            || name_lower == "recipient"
            || name_lower == "beneficiary"
            || name_lower.starts_with("from")
            || name_lower == "spender"
            || name_lower == "target"
            || name_lower == "destination"
            || name_lower == "account"
            || name_lower == "user"
            || name_lower == "sender"
            || name_lower == "origin"
            || name_lower == "caller"
            || name_lower == "_receiver"
            || name_lower == "_beneficiary"
            || name_lower == "_to"
            || name_lower == "_from"
            || name_lower == "_recipient"
            || name_lower.contains("receiver")
            // FP Reduction Phase 2: More flexible patterns
            || name_lower.contains("token")  // token addresses often optional
            || name_lower.contains("oracle")  // oracles can be disabled
            || name_lower.contains("factory")
            || name_lower.contains("router")
            || name_lower.contains("vault")
            || name_lower.contains("pool")
            || name_lower.contains("manager")  // manager roles often flexible
            || name_lower.contains("controller")
            || name_lower.contains("operator")
            || name_lower.contains("asset");

        // Only flag as critical if it's a core access control or critical implementation address
        // AND not a transfer destination or intentionally nullable
        (is_access_control || is_critical_contract_address) && !is_transfer_destination
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

        if let ast::Statement::Expression(ast::Expression::Assignment {
            left,
            right,
            location,
            ..
        }) = stmt
        {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // FP Reduction Phase 2: Skip test/mock contracts
        let file_path = ctx.file_path.to_lowercase();
        if file_path.contains("/mock")
            || file_path.contains("/test/")
            || file_path.contains(".t.sol")
            || file_path.contains("mock")
        {
            return Ok(findings);
        }

        // FP Reduction Phase 2: Skip vendored dependencies
        // These are audited third-party code
        if file_path.contains("/dependencies/")
            || file_path.contains("/vendor/")
            || file_path.contains("@openzeppelin")
            || file_path.contains("openzeppelin-contracts")
        {
            return Ok(findings);
        }

        // Analyze all functions in the contract
        for function in ctx.get_functions() {
            findings.extend(self.analyze_function(function, ctx)?);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        if let ast::Expression::BinaryOperation {
            operator,
            left,
            right,
            location,
        } = expression
        {
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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
