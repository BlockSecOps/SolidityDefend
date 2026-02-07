use anyhow::Result;
use ast;
use std::any::Any;
use std::collections::{HashMap, HashSet};

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for state machine vulnerabilities and invalid state transitions
pub struct StateMachineDetector {
    base: BaseDetector,
}

impl Default for StateMachineDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachineDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("invalid-state-transition"),
                "Invalid State Transition".to_string(),
                "Detects invalid state machine transitions and uninitialized states".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Analyze a function for state machine vulnerabilities
    fn analyze_function_for_state_issues(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(body) = &function.body {
            // Track state variables and their modifications
            let state_vars = self.identify_state_variables(ctx);
            let state_changes = self.track_state_changes(body, &state_vars);

            // Check for uninitialized state access
            findings.extend(self.check_uninitialized_state_access(body, &state_vars, ctx));

            // Check for invalid state transitions
            findings.extend(self.check_invalid_state_transitions(&state_changes, ctx));

            // Check for state variables modified without proper checks
            findings.extend(self.check_unchecked_state_modifications(body, &state_vars, ctx));

            // Check for reentrancy affecting state machine
            findings.extend(self.check_reentrancy_state_issues(body, &state_vars, ctx));
        }

        findings
    }

    /// Identify state variables in the contract
    fn identify_state_variables(&self, ctx: &AnalysisContext<'_>) -> HashSet<String> {
        let mut state_vars = HashSet::new();

        // Look for common state variable patterns
        for state_var in &ctx.contract.state_variables {
            let var_name = state_var.name.name.to_string();

            // Check for enum state variables (common state machine pattern)
            if let ast::TypeName::UserDefined(type_id) = &state_var.type_name {
                if type_id.name.to_lowercase().contains("state")
                    || type_id.name.to_lowercase().contains("phase")
                    || type_id.name.to_lowercase().contains("status")
                {
                    state_vars.insert(var_name.clone());
                }
            }

            // Check for boolean state flags
            if let ast::TypeName::Elementary(ast::ElementaryType::Bool) = &state_var.type_name {
                if var_name.to_lowercase().contains("initialized")
                    || var_name.to_lowercase().contains("active")
                    || var_name.to_lowercase().contains("paused")
                    || var_name.to_lowercase().contains("enabled")
                    || var_name.to_lowercase().contains("locked")
                {
                    state_vars.insert(var_name.clone());
                }
            }

            // Check for variables with state-like names
            if var_name.to_lowercase().contains("state")
                || var_name.to_lowercase().contains("phase")
                || var_name.to_lowercase().contains("stage")
                || var_name.to_lowercase().contains("round")
            {
                state_vars.insert(var_name);
            }
        }

        state_vars
    }

    /// Track state changes throughout the function
    fn track_state_changes(
        &self,
        block: &ast::Block<'_>,
        state_vars: &HashSet<String>,
    ) -> HashMap<String, Vec<ast::SourceLocation>> {
        let mut changes = HashMap::new();

        for stmt in &block.statements {
            self.collect_state_changes_from_stmt(stmt, state_vars, &mut changes);
        }

        changes
    }

    /// Recursively collect state changes from statements
    fn collect_state_changes_from_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        state_vars: &HashSet<String>,
        changes: &mut HashMap<String, Vec<ast::SourceLocation>>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.collect_state_changes_from_expr(expr, state_vars, changes);
            }
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => {
                self.collect_state_changes_from_expr(expr, state_vars, changes);
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.collect_state_changes_from_expr(condition, state_vars, changes);
                self.collect_state_changes_from_stmt(then_branch, state_vars, changes);
                if let Some(else_stmt) = else_branch {
                    self.collect_state_changes_from_stmt(else_stmt, state_vars, changes);
                }
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                self.collect_state_changes_from_expr(condition, state_vars, changes);
                self.collect_state_changes_from_stmt(body, state_vars, changes);
            }
            ast::Statement::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(init_stmt) = init {
                    self.collect_state_changes_from_stmt(init_stmt, state_vars, changes);
                }
                if let Some(cond_expr) = condition {
                    self.collect_state_changes_from_expr(cond_expr, state_vars, changes);
                }
                if let Some(update_expr) = update {
                    self.collect_state_changes_from_expr(update_expr, state_vars, changes);
                }
                self.collect_state_changes_from_stmt(body, state_vars, changes);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.collect_state_changes_from_stmt(inner_stmt, state_vars, changes);
                }
            }
            _ => {}
        }
    }

    /// Collect state changes from expressions
    fn collect_state_changes_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        state_vars: &HashSet<String>,
        changes: &mut HashMap<String, Vec<ast::SourceLocation>>,
    ) {
        match expr {
            ast::Expression::Assignment { left, .. } => {
                if let ast::Expression::Identifier(id) = left {
                    if state_vars.contains(id.name) {
                        changes
                            .entry(id.name.to_string())
                            .or_default()
                            .push(id.location.clone());
                    }
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.collect_state_changes_from_expr(left, state_vars, changes);
                self.collect_state_changes_from_expr(right, state_vars, changes);
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.collect_state_changes_from_expr(function, state_vars, changes);
                for arg in arguments {
                    self.collect_state_changes_from_expr(arg, state_vars, changes);
                }
            }
            _ => {}
        }
    }

    /// Check for uninitialized state access
    fn check_uninitialized_state_access(
        &self,
        block: &ast::Block<'_>,
        state_vars: &HashSet<String>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut initialized_vars = HashSet::new();

        for stmt in &block.statements {
            self.analyze_stmt_for_uninitialized_access(
                stmt,
                state_vars,
                &mut initialized_vars,
                &mut findings,
                ctx,
            );
        }

        findings
    }

    /// Analyze statement for uninitialized state access
    fn analyze_stmt_for_uninitialized_access(
        &self,
        stmt: &ast::Statement<'_>,
        state_vars: &HashSet<String>,
        initialized_vars: &mut HashSet<String>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                // Check for reads before writes
                self.check_expr_for_uninitialized_reads(
                    expr,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );

                // Track assignments to mark variables as initialized
                if let ast::Expression::Assignment { left, .. } = expr {
                    if let ast::Expression::Identifier(id) = left {
                        if state_vars.contains(id.name) {
                            initialized_vars.insert(id.name.to_string());
                        }
                    }
                }
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.check_expr_for_uninitialized_reads(
                    condition,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );

                // Analyze branches with separate initialization tracking
                let mut then_initialized = initialized_vars.clone();
                self.analyze_stmt_for_uninitialized_access(
                    then_branch,
                    state_vars,
                    &mut then_initialized,
                    findings,
                    ctx,
                );

                if let Some(else_stmt) = else_branch {
                    let mut else_initialized = initialized_vars.clone();
                    self.analyze_stmt_for_uninitialized_access(
                        else_stmt,
                        state_vars,
                        &mut else_initialized,
                        findings,
                        ctx,
                    );

                    // Only consider variables initialized if they're initialized in both branches
                    initialized_vars.retain(|var| {
                        then_initialized.contains(var) && else_initialized.contains(var)
                    });
                    for var in &then_initialized {
                        if else_initialized.contains(var) {
                            initialized_vars.insert(var.clone());
                        }
                    }
                } else {
                    // If no else branch, can't guarantee initialization
                    // Don't merge then_initialized back
                }
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.analyze_stmt_for_uninitialized_access(
                        inner_stmt,
                        state_vars,
                        initialized_vars,
                        findings,
                        ctx,
                    );
                }
            }
            _ => {}
        }
    }

    /// Check expression for reads of uninitialized state variables
    fn check_expr_for_uninitialized_reads(
        &self,
        expr: &ast::Expression<'_>,
        state_vars: &HashSet<String>,
        initialized_vars: &HashSet<String>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
    ) {
        match expr {
            ast::Expression::Identifier(id) => {
                if state_vars.contains(id.name) && !initialized_vars.contains(id.name) {
                    let message = format!(
                        "State variable '{}' may be accessed before initialization",
                        id.name
                    );
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            id.location.start().line() as u32,
                            id.location.start().column() as u32,
                            id.location.byte_length() as u32,
                        )
                        .with_cwe(908) // CWE-908: Use of Uninitialized Resource
                        .with_fix_suggestion(
                            "Ensure state variable is properly initialized before use".to_string(),
                        );
                    findings.push(finding);
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.check_expr_for_uninitialized_reads(
                    left,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );
                self.check_expr_for_uninitialized_reads(
                    right,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );
            }
            ast::Expression::Assignment { right, .. } => {
                // Only check the right side for reads (left side is a write)
                self.check_expr_for_uninitialized_reads(
                    right,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.check_expr_for_uninitialized_reads(
                    function,
                    state_vars,
                    initialized_vars,
                    findings,
                    ctx,
                );
                for arg in arguments {
                    self.check_expr_for_uninitialized_reads(
                        arg,
                        state_vars,
                        initialized_vars,
                        findings,
                        ctx,
                    );
                }
            }
            _ => {}
        }
    }

    /// Check for invalid state transitions
    fn check_invalid_state_transitions(
        &self,
        state_changes: &HashMap<String, Vec<ast::SourceLocation>>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (state_var, locations) in state_changes {
            // Multiple state changes in the same function may indicate complex transitions
            if locations.len() > 2 {
                let message = format!(
                    "State variable '{}' is modified {} times in the same function - this may indicate complex or invalid state transitions",
                    state_var,
                    locations.len()
                );
                let finding = self.base.create_finding(
                    ctx,
                    message,
                    locations[0].start().line() as u32,
                    locations[0].start().column() as u32,
                    locations[0].byte_length() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                .with_fix_suggestion(
                    "Consider consolidating state changes or using explicit state transition functions".to_string()
                );
                findings.push(finding);
            }
        }

        findings
    }

    /// Check for state modifications without proper validation
    fn check_unchecked_state_modifications(
        &self,
        block: &ast::Block<'_>,
        state_vars: &HashSet<String>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if the function itself has validation modifiers (indicated by require at top)
        let has_function_level_guard = self.block_has_require_or_guard(block);

        for stmt in &block.statements {
            self.check_stmt_for_unchecked_modifications(
                stmt,
                state_vars,
                &mut findings,
                ctx,
                has_function_level_guard,
            );
        }

        findings
    }

    /// Check if a block contains require/assert/revert at the start (function-level validation)
    fn block_has_require_or_guard(&self, block: &ast::Block<'_>) -> bool {
        for stmt in &block.statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.is_require_or_validation_call(expr) {
                        return true;
                    }
                }
                // If we hit a non-validation statement first, stop looking
                ast::Statement::If { .. }
                | ast::Statement::For { .. }
                | ast::Statement::While { .. } => break,
                _ => {}
            }
        }
        false
    }

    /// Check if an expression is a require/assert/revert call
    fn is_require_or_validation_call(&self, expr: &ast::Expression<'_>) -> bool {
        if let ast::Expression::FunctionCall { function, .. } = expr {
            if let ast::Expression::Identifier(id) = function {
                return matches!(id.name, "require" | "assert" | "revert");
            }
        }
        false
    }

    /// Check statement for unchecked state modifications
    fn check_stmt_for_unchecked_modifications(
        &self,
        stmt: &ast::Statement<'_>,
        state_vars: &HashSet<String>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
        is_guarded: bool,
    ) {
        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment { left, location, .. }) => {
                if let ast::Expression::Identifier(id) = left {
                    if state_vars.contains(id.name) {
                        // Skip if we're inside a guard context (if statement, after require, etc.)
                        if !is_guarded {
                            let message = format!(
                                "State variable '{}' is modified without proper validation or state checks",
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
                                .with_cwe(20) // CWE-20: Improper Input Validation
                                .with_fix_suggestion(
                                    "Add proper validation before modifying state variables"
                                        .to_string(),
                                );
                            findings.push(finding);
                        }
                    }
                }
            }
            // Assignments inside if statements are considered guarded
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                // Both branches are guarded by the condition
                self.check_stmt_for_unchecked_modifications(
                    then_branch,
                    state_vars,
                    findings,
                    ctx,
                    true, // guarded by condition
                );
                if let Some(else_stmt) = else_branch {
                    self.check_stmt_for_unchecked_modifications(
                        else_stmt, state_vars, findings, ctx, true, // guarded by condition
                    );
                }
            }
            ast::Statement::Block(block) => {
                // Check if this block has its own guards
                let block_guarded = is_guarded || self.block_has_require_or_guard(block);
                for inner_stmt in &block.statements {
                    self.check_stmt_for_unchecked_modifications(
                        inner_stmt,
                        state_vars,
                        findings,
                        ctx,
                        block_guarded,
                    );
                }
            }
            _ => {}
        }
    }

    /// Check for reentrancy issues affecting state machine
    fn check_reentrancy_state_issues(
        &self,
        block: &ast::Block<'_>,
        state_vars: &HashSet<String>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find external calls and check if state vars are modified AFTER them
        let stmts = &block.statements;
        for (idx, stmt) in stmts.iter().enumerate() {
            if let Some((call_location, call_line)) = self.find_external_call_in_stmt(stmt) {
                // Check subsequent statements for state modifications
                for subsequent_stmt in stmts.iter().skip(idx + 1) {
                    if let Some(modified_var) =
                        self.find_state_modification_in_stmt(subsequent_stmt, state_vars)
                    {
                        let message = format!(
                            "State variable '{}' modified after external call - potential reentrancy affecting state machine",
                            modified_var
                        );
                        let finding = self
                            .base
                            .create_finding_with_severity(
                                ctx,
                                message,
                                call_line,
                                call_location.start().column() as u32,
                                call_location.byte_length() as u32,
                                Severity::Critical,
                            )
                            .with_cwe(841)
                            .with_fix_suggestion(
                                "Use checks-effects-interactions pattern or reentrancy guards"
                                    .to_string(),
                            );
                        findings.push(finding);
                        break; // Only one finding per external call
                    }
                }
            }
        }

        findings
    }

    /// Find an external call in a statement, returning its location if found
    fn find_external_call_in_stmt(
        &self,
        stmt: &ast::Statement<'_>,
    ) -> Option<(ast::SourceLocation, u32)> {
        match stmt {
            ast::Statement::Expression(expr) => self.find_external_call_in_expr(expr),
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => self.find_external_call_in_expr(expr),
            _ => None,
        }
    }

    /// Find an external call in an expression
    fn find_external_call_in_expr(
        &self,
        expr: &ast::Expression<'_>,
    ) -> Option<(ast::SourceLocation, u32)> {
        match expr {
            ast::Expression::FunctionCall {
                function, location, ..
            } => {
                if self.is_external_call(function) {
                    Some((location.clone(), location.start().line() as u32))
                } else {
                    None
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => self
                .find_external_call_in_expr(left)
                .or_else(|| self.find_external_call_in_expr(right)),
            ast::Expression::Assignment { right, .. } => self.find_external_call_in_expr(right),
            _ => None,
        }
    }

    /// Find state modification in a statement
    fn find_state_modification_in_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        state_vars: &HashSet<String>,
    ) -> Option<String> {
        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment { left, .. }) => {
                if let ast::Expression::Identifier(id) = left {
                    if state_vars.contains(id.name) {
                        return Some(id.name.to_string());
                    }
                }
                None
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    if let Some(var) = self.find_state_modification_in_stmt(inner_stmt, state_vars)
                    {
                        return Some(var);
                    }
                }
                None
            }
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                if let Some(var) = self.find_state_modification_in_stmt(then_branch, state_vars) {
                    return Some(var);
                }
                if let Some(else_stmt) = else_branch {
                    return self.find_state_modification_in_stmt(else_stmt, state_vars);
                }
                None
            }
            _ => None,
        }
    }

    /// Check if an expression represents an external call
    fn is_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess { member, .. } => {
                // Common external call patterns
                member.name == "call"
                    || member.name == "delegatecall"
                    || member.name == "send"
                    || member.name == "transfer"
            }
            _ => false,
        }
    }
}

impl Detector for StateMachineDetector {
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

impl AstAnalyzer for StateMachineDetector {
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_function_for_state_issues(function, ctx))
    }

    fn analyze_statement(
        &self,
        statement: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // This detector primarily works at the function level, but can analyze individual statements
        if let ast::Statement::Expression(ast::Expression::Assignment { left, location, .. }) =
            statement
        {
            if let ast::Expression::Identifier(id) = left {
                // Simple check for potential state variable assignment
                if id.name.to_lowercase().contains("state") {
                    let message =
                        format!("Potential state variable '{}' assignment detected", id.name);
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(362);
                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn analyze_expression(
        &self,
        expression: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for state-related expressions
        if let ast::Expression::Identifier(id) = expression {
            if id.name.to_lowercase().contains("state")
                && id.name.to_lowercase().contains("uninitialized")
            {
                let message = format!(
                    "Potential uninitialized state variable access: '{}'",
                    id.name
                );
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        id.location.start().line() as u32,
                        id.location.start().column() as u32,
                        id.location.byte_length() as u32,
                    )
                    .with_cwe(908);
                findings.push(finding);
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
        // State machine issues are typically in function bodies, not modifiers
        Ok(Vec::new())
    }
}
