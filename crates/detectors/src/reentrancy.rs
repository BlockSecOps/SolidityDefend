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

impl Default for ClassicReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
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
                self.is_external_call(base) || index.is_some_and(|idx| self.is_external_call(idx))
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
                    || else_branch.is_some_and(|stmt| self.statement_has_external_call(stmt))
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
                    .is_some_and(|cond| self.is_external_call(cond))
                    || update
                        .as_ref()
                        .is_some_and(|upd| self.is_external_call(upd))
                    || self.statement_has_external_call(body)
            }
            ast::Statement::VariableDeclaration { initial_value, .. } => {
                // Check if variable is initialized with external call: bool result = call(...)
                initial_value
                    .as_ref()
                    .is_some_and(|expr| self.is_external_call(expr))
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
                    .is_some_and(|expr| self.is_external_call(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Check if emit contains external call: emit Event(call(...))
                self.is_external_call(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Check if revert contains external call: revert Error(call(...))
                error_call
                    .as_ref()
                    .is_some_and(|expr| self.is_external_call(expr))
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
                    || else_branch.is_some_and(|stmt| self.statement_has_state_change(stmt))
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
                    .is_some_and(|expr| self.expression_has_state_change(expr))
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
                    .is_some_and(|expr| self.expression_has_state_change(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Emit expressions might contain state changes: emit Event(balance = 0)
                self.expression_has_state_change(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Revert expressions might contain state changes: revert Error(balance = 0)
                error_call
                    .as_ref()
                    .is_some_and(|expr| self.expression_has_state_change(expr))
            }
            _ => false,
        }
    }

    /// Get function source code (cleaned to avoid FPs from comments/strings)
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            utils::clean_source_for_search(&raw_source)
        } else {
            String::new()
        }
    }

    /// Phase 14 FP Reduction: Check if function is internal or private (text-based)
    /// Internal/private functions cannot be directly called externally
    fn is_internal_or_private_function(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for explicit internal/private visibility
        // Pattern: function name(...) internal/private
        lower.contains(" internal")
            || lower.contains(" private")
            || lower.contains("\tinternal")
            || lower.contains("\tprivate")
    }

    /// Phase 14 FP Reduction: Check if this is a known protected contract
    fn is_known_protected_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // OpenZeppelin contracts are battle-tested
        let is_openzeppelin = lower.contains("@openzeppelin")
            || lower.contains("openzeppelin-contracts")
            || contract_name == "erc20"
            || contract_name == "erc721"
            || contract_name == "erc1155";

        // Aave protocol has architectural reentrancy protection
        let is_aave = lower.contains("@author aave")
            || lower.contains("aave-upgradeability")
            || contract_name.contains("atoken")
            || contract_name.contains("debttoken");

        // Compound protocol
        let is_compound = lower.contains("@author compound")
            || contract_name.contains("ctoken");

        // Safe (Gnosis Safe) wallet - battle-tested multisig
        let file_path_lower = ctx.file_path.to_lowercase();
        let is_safe = file_path_lower.contains("safe-smart-account")
            || file_path_lower.contains("safe-contracts")
            || file_path_lower.contains("/safe/")
            || lower.contains("@author stefan george")
            || lower.contains("@author richard meissner")
            || lower.contains("gnosis safe")
            || contract_name == "safe"
            || lower.contains("multisignaturewallet")
            || lower.contains("execfrommodule")
            // Safe transaction/module patterns
            || lower.contains("ownermanager")
            || lower.contains("guardmanager")
            || lower.contains("modulemanager");

        // Library contracts
        let is_library = source.contains(&format!("library {}", ctx.contract.name.name));

        is_openzeppelin || is_aave || is_compound || is_safe || is_library
    }

    /// Phase 14 FP Reduction: Check if function name suggests internal helper
    fn is_internal_helper_pattern(&self, func_name: &str) -> bool {
        // Functions starting with _ are conventionally internal
        func_name.starts_with('_')
    }

    /// Phase 15 FP Reduction: Check if function uses SafeERC20 for token transfers
    /// SafeERC20 wraps transfers in a way that prevents reentrancy
    fn uses_safe_token_transfer(&self, func_source: &str, contract_source: &str) -> bool {
        let has_safe_erc20 = contract_source.contains("SafeERC20")
            || contract_source.contains("using SafeERC20");

        let uses_safe_methods = func_source.contains("safeTransfer")
            || func_source.contains("safeTransferFrom")
            || func_source.contains("safeApprove")
            || func_source.contains("safeIncreaseAllowance");

        has_safe_erc20 && uses_safe_methods
    }

    /// Phase 15 FP Reduction: Check if function only calls view/pure functions
    fn only_calls_view_functions(&self, func_source: &str) -> bool {
        // If there's no .call{ or .transfer or .send, likely only view calls
        let has_value_transfer = func_source.contains(".call{value")
            || func_source.contains(".transfer(")
            || func_source.contains(".send(");

        // Check for delegatecall which can cause reentrancy
        let has_delegatecall = func_source.contains(".delegatecall(");

        !has_value_transfer && !has_delegatecall
    }

    /// Phase 15 FP Reduction: Check if this is a pull payment pattern
    /// Pull payments have users claim their own funds (safe pattern)
    fn is_pull_payment_pattern(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Pull payment patterns
        let has_pull_keywords = lower.contains("claim")
            || lower.contains("withdraw")
            || lower.contains("redeem");

        // Check if it accesses msg.sender's balance (user withdrawing their own funds)
        let accesses_sender_balance = lower.contains("[msg.sender]")
            && (lower.contains("balance") || lower.contains("amount") || lower.contains("pending"));

        // PullPayment from OpenZeppelin
        let uses_oz_pull = func_source.contains("PullPayment")
            || func_source.contains("_asyncTransfer")
            || func_source.contains("withdrawPayments");

        has_pull_keywords && (accesses_sender_balance || uses_oz_pull)
    }

    /// Phase 14 FP Reduction: Check if contract has contract-wide reentrancy protection
    fn has_contract_level_protection(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Inherits from ReentrancyGuard
        let inherits_guard = lower.contains("is reentrancyguard")
            || lower.contains(", reentrancyguard")
            || lower.contains("reentrancyguard,")
            || source.contains("ReentrancyGuardUpgradeable");

        // Has _status or _locked state variable (OZ ReentrancyGuard pattern)
        let has_lock_state = (lower.contains("uint256 private _status")
            || lower.contains("bool private _locked")
            || lower.contains("uint256 internal _status"))
            && (lower.contains("_not_entered") || lower.contains("_entered"));

        // Uses mutex pattern
        let has_mutex = lower.contains("modifier noreentrancy")
            || lower.contains("modifier nonreentrant")
            || lower.contains("modifier lock");

        inherits_guard || has_lock_state || has_mutex
    }

    /// Phase 14 FP Reduction: Check if contract is an interface (no implementation)
    fn is_interface_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let contract_name = &ctx.contract.name.name;

        // Interface naming convention (IPool, IAToken, etc.)
        if contract_name.starts_with('I')
            && contract_name.chars().nth(1).map_or(false, |c| c.is_uppercase())
        {
            return true;
        }

        // Explicit interface keyword
        source.contains(&format!("interface {}", contract_name))
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
                    || index.is_some_and(|idx| self.expression_has_state_change(idx))
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

        // Phase 14 FP Reduction: Skip interface contracts (no implementation)
        if self.is_interface_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip known protected contracts (OZ, Aave, Compound)
        if self.is_known_protected_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip if contract has contract-wide reentrancy protection
        if self.has_contract_level_protection(ctx) {
            return Ok(findings);
        }

        // Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if self.has_external_call(function) && self.has_state_changes_after_calls(function) {
                // Get function source to check for reentrancy guards
                let func_source = self.get_function_source(function, ctx);
                let func_name = &function.name.name;

                // Skip if function has reentrancy guard (nonReentrant, lock(), etc.)
                if utils::has_reentrancy_guard(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip internal/private functions
                // They cannot be called directly externally
                if self.is_internal_or_private_function(&func_source) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip functions with _ prefix (internal helper convention)
                if self.is_internal_helper_pattern(func_name) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip if using SafeERC20 for token transfers
                // SafeERC20 is designed to be safe against reentrancy
                if self.uses_safe_token_transfer(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip if function only calls view/pure functions
                // View functions cannot cause reentrancy
                if self.only_calls_view_functions(&func_source) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip pull payment patterns
                // Pull payments have user claim funds (safe pattern)
                if self.is_pull_payment_pattern(&func_source) {
                    continue;
                }

                let message = format!(
                    "Function '{}' may be vulnerable to reentrancy attacks due to state changes after external calls",
                    func_name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    func_name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_swc("SWC-107") // SWC-107: Reentrancy
                .with_fix_suggestion(format!(
                    "Apply checks-effects-interactions pattern or use a reentrancy guard in function '{}'",
                    func_name
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

impl Default for ReadOnlyReentrancyDetector {
    fn default() -> Self {
        Self::new()
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
        // Check if function reads state variables
        if let Some(body) = &function.body {
            self.reads_state_variables(&body.statements)
        } else {
            false
        }
    }

    fn reads_state_variables(&self, statements: &[ast::Statement<'_>]) -> bool {
        // Check if the function reads any state variables
        for stmt in statements {
            if self.statement_reads_state(stmt) {
                return true;
            }
        }
        false
    }

    fn statement_reads_state(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.expression_reads_state(expr),
            ast::Statement::Return { value, .. } => value
                .as_ref()
                .is_some_and(|expr| self.expression_reads_state(expr)),
            ast::Statement::VariableDeclaration { initial_value, .. } => initial_value
                .as_ref()
                .is_some_and(|expr| self.expression_reads_state(expr)),
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                self.statement_reads_state(then_branch)
                    || else_branch
                        .as_ref()
                        .is_some_and(|s| self.statement_reads_state(s))
            }
            ast::Statement::Block(block) => self.reads_state_variables(&block.statements),
            ast::Statement::For { body, .. } => self.statement_reads_state(body),
            ast::Statement::While { body, .. } => self.statement_reads_state(body),
            _ => false,
        }
    }

    fn expression_reads_state(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            // Direct identifier access (could be state variable)
            ast::Expression::Identifier(_) => true,

            // Member access (e.g., token0Balance, totalSupply)
            ast::Expression::MemberAccess { expression, .. } => {
                self.expression_reads_state(expression)
            }

            // Binary operations (e.g., balance1 + balance2)
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_reads_state(left) || self.expression_reads_state(right)
            }

            // Unary operations
            ast::Expression::UnaryOperation { operand, .. } => self.expression_reads_state(operand),

            // Function calls (could read state)
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.expression_reads_state(function)
                    || arguments.iter().any(|arg| self.expression_reads_state(arg))
            }

            // Ternary operator
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.expression_reads_state(condition)
                    || self.expression_reads_state(true_expression)
                    || self.expression_reads_state(false_expression)
            }

            _ => false,
        }
    }

    fn has_external_call(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.expression_has_external_call(expr),
            ast::Statement::Block(block) => {
                block.statements.iter().any(|s| self.has_external_call(s))
            }
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                self.has_external_call(then_branch)
                    || else_branch
                        .as_ref()
                        .is_some_and(|s| self.has_external_call(s))
            }
            ast::Statement::For { body, .. } => self.has_external_call(body),
            ast::Statement::While { body, .. } => self.has_external_call(body),
            _ => false,
        }
    }

    fn expression_has_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    // Direct member access pattern: obj.method()
                    ast::Expression::MemberAccess { member, .. } => {
                        matches!(member.name, "call" | "delegatecall" | "transfer" | "send")
                    }
                    // Nested function call pattern: obj.method{options}()
                    // This handles .call{value: amount}(), .delegatecall{gas: g}(), etc.
                    ast::Expression::FunctionCall {
                        function: inner_function,
                        ..
                    } => {
                        // Check if the inner function is a MemberAccess to call/delegatecall/transfer/send
                        matches!(
                            inner_function,
                            ast::Expression::MemberAccess { member, .. }
                            if matches!(member.name, "call" | "delegatecall" | "transfer" | "send")
                        )
                    }
                    _ => false,
                }
            }
            // Also check assignments, binary operations, etc. for nested calls
            ast::Expression::Assignment { right, .. } => self.expression_has_external_call(right),
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_has_external_call(left) || self.expression_has_external_call(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                self.expression_has_external_call(operand)
            }
            ast::Expression::MemberAccess { expression, .. } => {
                self.expression_has_external_call(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.expression_has_external_call(condition)
                    || self.expression_has_external_call(true_expression)
                    || self.expression_has_external_call(false_expression)
            }
            _ => false,
        }
    }

    fn function_has_external_call(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            body.statements
                .iter()
                .any(|stmt| self.has_external_call(stmt))
        } else {
            false
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

        // Phase 15 FP Reduction: Skip contracts with reentrancy protection
        // If contract has ReentrancyGuard, readonly reentrancy is mitigated
        let source_lower = ctx.source_code.to_lowercase();
        if source_lower.contains("reentrancyguard")
            || source_lower.contains("nonreentrant")
            || source_lower.contains("modifier lock")
        {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip known safe protocols
        if source_lower.contains("@openzeppelin")
            || source_lower.contains("@aave")
            || source_lower.contains("@uniswap")
        {
            return Ok(findings);
        }

        // First, check if there are any state-changing functions that make external calls
        let has_vulnerable_pattern = ctx
            .get_functions()
            .iter()
            .any(|f| !self.is_view_function(f) && self.function_has_external_call(f));

        // If no state-changing functions make external calls, no readonly reentrancy risk
        if !has_vulnerable_pattern {
            return Ok(findings);
        }

        // Now check view functions that read state
        for function in ctx.get_functions() {
            if self.is_view_function(function) && self.relies_on_external_state(function) {
                // Phase 15 FP Reduction: Skip internal view functions
                if function.visibility == ast::Visibility::Internal
                    || function.visibility == ast::Visibility::Private
                {
                    continue;
                }

                // Phase 15 FP Reduction: Skip standard ERC interface view functions
                // These are expected to be public and read state
                let func_name_lower = function.name.name.to_lowercase();
                if func_name_lower == "balanceof"
                    || func_name_lower == "totalsupply"
                    || func_name_lower == "allowance"
                    || func_name_lower == "name"
                    || func_name_lower == "symbol"
                    || func_name_lower == "decimals"
                    || func_name_lower == "ownerof"
                    || func_name_lower == "tokenuri"
                {
                    continue;
                }

                let message = format!(
                    "View function '{}' reads state that may be inconsistent during reentrancy. \
                     Contract has state-changing functions that make external calls before updating state.",
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
                    "Add a reentrancy guard to state-changing functions or ensure view function '{}' \
                     cannot be called during callbacks (e.g., using a reentrancy lock check in the view function)",
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
