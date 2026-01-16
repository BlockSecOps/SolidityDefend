use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::erc_standard_compliance;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing access control modifiers on critical functions
pub struct MissingModifiersDetector {
    base: BaseDetector,
}

/// Detector for unprotected initializer functions
pub struct UnprotectedInitializerDetector {
    base: BaseDetector,
}

impl Default for UnprotectedInitializerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedInitializerDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unprotected-initializer"),
                "Unprotected Initializer".to_string(),
                "Initializer functions lack proper access control".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for UnprotectedInitializerDetector {
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

        // Check for functions that look like initializers
        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Look for initializer function patterns
            let function_name = function.name.name.to_lowercase();
            let is_initializer = function_name.contains("init")
                || function_name.contains("setup")
                || function_name.contains("configure")
                || function_name == "initialize";

            if is_initializer {
                // Check if it has access control
                if !self.has_access_control_modifiers(function) {
                    let message = format!(
                        "Initializer function '{}' lacks access control and can be called by anyone",
                        function.name.name
                    );

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(665) // CWE-665: Improper Initialization
                    .with_fix_suggestion(format!(
                        "Add an access control modifier to '{}' or ensure it can only be called once during deployment",
                        function.name.name
                    ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UnprotectedInitializerDetector {
    /// Check if a function has access control modifiers
    fn has_access_control_modifiers(&self, function: &ast::Function<'_>) -> bool {
        if function.modifiers.is_empty() {
            return false;
        }

        // Look for access control patterns
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("restricted")
                || modifier_name.contains("protected")
            {
                return true;
            }
        }

        false
    }
}

impl Default for MissingModifiersDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingModifiersDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-access-modifiers"),
                "Missing Access Control Modifiers".to_string(),
                "Detects functions that perform critical operations without proper access control modifiers".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if a function name suggests it needs access control
    /// Returns true only for truly admin-only patterns, not user-facing functions
    fn requires_access_control(&self, function_name: &str) -> bool {
        let name_lower = function_name.to_lowercase();

        // High confidence - these are always admin functions
        let admin_only_patterns = [
            "selfdestruct",
            "destroy",
            "suicide",
            "kill",
            "pause",
            "unpause",
            "emergency",
            "upgrade",
            "migrate",
            "setowner",
            "setadmin",
            "setfee",
            "setconfig",
            "configure",
            "renounceownership",
            "transferownership",
            "grant",
            "revoke",
            "enable",
            "disable",
            "setwhitelist",
            "setblacklist",
        ];

        // These patterns are admin-only when they're the FULL name (not part of a user function)
        let admin_exact = [
            "withdraw", // user-facing if "withdrawFrom" or has amount param
            "mint",     // user-facing if minting to msg.sender
            "burn",     // user-facing if burning from msg.sender
            "rescue",
            "recover",
            "distribute",
            "allocate",
        ];

        // High-confidence: admin-only patterns that always need protection
        if admin_only_patterns.iter().any(|p| name_lower.contains(p)) {
            return true;
        }

        // Medium-confidence: exact match for certain patterns
        // Skip patterns that are commonly user-facing
        // "transfer", "approve", "send", "claim" are typically user-facing in ERC tokens
        if admin_exact.iter().any(|p| name_lower == *p) {
            return true;
        }

        // Skip common user-facing patterns that should NOT require access control
        let user_facing_patterns = [
            "transfer",     // ERC20/721 transfer
            "approve",      // ERC20/721 approve
            "send",         // User sends their own tokens
            "claim",        // Users claim their rewards
            "stake",        // Users stake their tokens
            "unstake",      // Users unstake their tokens
            "deposit",      // Users deposit their tokens
            "redeem",       // Users redeem their tokens
            "swap",         // Users swap tokens
            "buy",          // Users buy
            "sell",         // Users sell
        ];

        if user_facing_patterns.iter().any(|p| name_lower.contains(p)) {
            return false; // These are user-facing, don't require owner access control
        }

        false
    }

    /// Check if a function has access control modifiers
    fn has_access_control(&self, function: &ast::Function<'_>) -> bool {
        // Check if function has any modifiers
        if function.modifiers.is_empty() {
            return false;
        }

        // Look for common access control modifier patterns
        let access_control_modifiers = [
            "onlyowner",
            "onlyadmin",
            "onlyauthorized",
            "onlyminter",
            "onlyburner",
            "onlygovernance",
            "onlycontroller",
            "onlymanager",
            "restricted",
            "authorized",
            "protected",
            "secure",
        ];

        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if access_control_modifiers
                .iter()
                .any(|ac| modifier_name.contains(ac))
            {
                return true;
            }
        }

        false
    }

    /// Check if a function is user-facing (operates on msg.sender's own resources)
    fn is_user_facing_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);

        // User-facing functions typically access msg.sender's own balance/tokens
        let accesses_own_balance = func_source.contains("balances[msg.sender]")
            || func_source.contains("balanceOf[msg.sender]")
            || func_source.contains("_balances[msg.sender]")
            || func_source.contains("userBalance[msg.sender]")
            || func_source.contains("shares[msg.sender]");

        // User-facing functions check authorization via msg.sender
        let checks_sender = func_source.contains("msg.sender ==")
            || func_source.contains("msg.sender !=")
            || func_source.contains("owner == msg.sender")
            || func_source.contains("msg.sender == owner");

        // User-facing functions often have require checks on msg.sender's balance
        let requires_sender_balance = func_source.contains("require(")
            && func_source.contains("msg.sender")
            && (func_source.contains("balance") || func_source.contains("shares"));

        // ERC-4337 paymaster functions use msg.sender in mapping keys for access control
        // sessionKeys[msg.sender][key], guardians[msg.sender], etc.
        let paymaster_sender_pattern = (func_source.contains("[msg.sender]")
            && (func_source.contains("sessionKeys")
                || func_source.contains("guardians")
                || func_source.contains("threshold")
                || func_source.contains("spendingLimits")
                || func_source.contains("deposits")))
            || (func_source.contains("isGuardian(") && func_source.contains("msg.sender"));

        accesses_own_balance || checks_sender || requires_sender_balance || paymaster_sender_pattern
    }

    /// Get function source code for analysis
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
}

impl Detector for MissingModifiersDetector {
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
            // Skip interface functions (they have no body)
            if function.body.is_none() {
                continue;
            }

            // Skip view/pure functions, constructors, and internal functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
                || function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            // NEW: Skip ERC standard-compliant functions (they SHOULD be public)
            if erc_standard_compliance::is_standard_compliant_function(function.name.name, ctx) {
                continue; // This is a required public function per ERC standards
            }

            // NEW: Skip user-facing functions (operate on msg.sender's own resources)
            if self.is_user_facing_function(function, ctx) {
                continue; // User-facing functions are supposed to be public
            }

            // Check if function name suggests it needs access control
            if self.requires_access_control(function.name.name) {
                // Check if it has proper access control
                if !self.has_access_control(function) {
                    let message = format!(
                        "Function '{}' performs critical operations but lacks access control modifiers",
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
                        .with_cwe(284) // CWE-284: Improper Access Control
                        .with_confidence(Confidence::High) // NEW: High confidence when truly missing
                        .with_fix_suggestion(format!(
                            "Add an access control modifier like 'onlyOwner' to function '{}'",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Detector for unprotected initializer functions
pub struct UnprotectedInitDetector {
    base: BaseDetector,
}

impl Default for UnprotectedInitDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedInitDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unprotected-initializer"),
                "Unprotected Initializer".to_string(),
                "Detects initializer functions that can be called by anyone".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if a function is an initializer
    fn is_initializer(&self, function: &ast::Function<'_>) -> bool {
        let init_patterns = ["initialize", "init", "setup", "configure"];
        let name_lower = function.name.name.to_lowercase();

        init_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
    }

    /// Check if initializer has proper protection
    fn has_initializer_protection(&self, function: &ast::Function<'_>) -> bool {
        // Check for initializer modifier from OpenZeppelin
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("initializer") {
                return true;
            }
        }

        // Check for access control on initializer
        if function.modifiers.iter().any(|m| {
            let name = m.name.name.to_lowercase();
            name.contains("owner") || name.contains("admin") || name.contains("authorized")
        }) {
            return true;
        }

        false
    }
}

impl Detector for UnprotectedInitDetector {
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

        for function in ctx.get_functions() {
            if self.is_initializer(function) && !self.has_initializer_protection(function) {
                let message = format!(
                    "Initializer function '{}' is unprotected and can be called by anyone",
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
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(format!(
                        "Add 'initializer' modifier or access control to function '{}'",
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

/// Detector for functions using default visibility (in older Solidity versions)
pub struct DefaultVisibilityDetector {
    base: BaseDetector,
}

impl Default for DefaultVisibilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultVisibilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("default-visibility"),
                "Default Visibility".to_string(),
                "Detects functions and state variables using default visibility".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }

    /// Check if this is an old Solidity version where default visibility is public
    fn uses_old_solidity(&self, ctx: &AnalysisContext<'_>) -> bool {
        // This is a simplified check - in practice we'd parse pragma directives
        // For now, assume any contract without explicit visibility is old
        ctx.source_code.contains("pragma solidity ^0.4")
            || ctx.source_code.contains("pragma solidity 0.4")
    }
}

impl Detector for DefaultVisibilityDetector {
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

        if !self.uses_old_solidity(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // In old Solidity versions, functions without explicit visibility are public
            // For now, we'll check if visibility is Public as a heuristic
            if function.visibility == ast::Visibility::Public {
                let message = format!(
                    "Function '{}' uses default visibility (public in older Solidity)",
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
                    .with_cwe(200) // CWE-200: Information Exposure
                    .with_fix_suggestion(format!(
                        "Explicitly declare visibility for function '{}'",
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

/// Detector for state variables without explicit visibility modifiers
pub struct StateVariableVisibilityDetector {
    base: BaseDetector,
}

impl Default for StateVariableVisibilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StateVariableVisibilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-visibility-modifier"),
                "Missing Visibility Modifier".to_string(),
                "Detects state variables without explicit visibility modifiers".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Low,
            ),
        }
    }

    fn is_state_variable_line(&self, line: &str) -> bool {
        let trimmed = line.trim();

        // Skip empty lines, comments, and function signatures
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("*")
            || trimmed.contains("function ")
            || trimmed.contains("constructor")
            || trimmed.contains("modifier ")
            || trimmed.contains("event ")
            || trimmed.contains("error ")
            || trimmed.contains("returns")
        {
            return false;
        }

        // Strip inline comments for semicolon check
        let code_part = if let Some(idx) = trimmed.find("//") {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        // Check if line starts with a type declaration (state variable pattern)
        let type_prefixes = [
            "address ", "uint", "int", "bool ", "bytes", "string ",
            "mapping(", "struct ", "enum ",
        ];

        // Must start with type and not be inside a function (no memory/calldata)
        let starts_with_type = type_prefixes.iter().any(|prefix| trimmed.starts_with(prefix));

        // Variables inside functions have memory/calldata keywords
        let is_local_var = trimmed.contains("memory") || trimmed.contains("calldata");

        // Must end with semicolon to be a declaration (check code part, not comments)
        let is_declaration = code_part.ends_with(';');

        starts_with_type && !is_local_var && is_declaration
    }
}

impl Detector for StateVariableVisibilityDetector {
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

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let visibility_keywords = ["public", "private", "internal", "constant", "immutable"];

        // Track brace depth to distinguish contract-level (state) variables from local variables
        // Depth 0: outside contracts
        // Depth 1: inside contract body (state variables live here)
        // Depth 2+: inside functions/modifiers/constructors (local variables live here)
        let mut brace_depth: i32 = 0;
        let mut in_function_signature = false;

        for (line_num, line) in ctx.source_code.lines().enumerate() {
            let trimmed = line.trim();

            // Strip inline comments for analysis
            let code_part = if let Some(idx) = trimmed.find("//") {
                trimmed[..idx].trim()
            } else {
                trimmed
            };

            // Track function/modifier/constructor signatures (may span multiple lines)
            if code_part.contains("function ")
                || code_part.contains("constructor")
                || code_part.contains("modifier ")
                || code_part.contains("fallback(")
                || code_part.contains("receive(")
            {
                in_function_signature = true;
            }

            // Count braces to track depth
            for ch in code_part.chars() {
                if ch == '{' {
                    if in_function_signature {
                        // Function body starts
                        in_function_signature = false;
                    }
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth = brace_depth.saturating_sub(1);
                }
            }

            // Only check for state variables at contract level (depth 1)
            // Depth 2+ means we're inside a function body where local variables are valid
            if brace_depth != 1 {
                continue;
            }

            if !self.is_state_variable_line(line) {
                continue;
            }

            // Check if any visibility keyword is present in the code (not comments)
            let has_visibility = visibility_keywords.iter().any(|kw| code_part.contains(kw));

            if !has_visibility {
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        "State variable declared without explicit visibility modifier".to_string(),
                        (line_num + 1) as u32,
                        1,
                        line.len() as u32,
                    )
                    .with_cwe(710)
                    .with_fix_suggestion(
                        "Add explicit visibility: 'address private owner;' or 'address internal owner;'".to_string(),
                    );
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
