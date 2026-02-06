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

        // FP Reduction: Skip contracts that are clearly not upgradeable
        // Unprotected initializers are primarily a concern for proxy/upgradeable contracts.
        // Non-upgradeable contracts use constructors; initialize() in those contexts is
        // either a safe constructor-replacement or already protected by init guards.
        if !self.is_upgradeable_context(ctx) {
            return Ok(findings);
        }

        // Check for functions that look like initializers
        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Look for initializer function patterns (strict matching)
            let function_name = function.name.name.to_lowercase();
            let is_initializer = function_name == "initialize"
                || function_name == "init"
                || function_name == "setup"
                || function_name == "configure"
                || function_name.starts_with("initialize_")
                || function_name.starts_with("init_");

            if !is_initializer {
                continue;
            }

            // Check if it has modifier-based access control
            if self.has_access_control_modifiers(function) {
                continue;
            }

            // FP Reduction: Check for inline access control in the function body
            let func_source = self.get_function_source(function, ctx);
            if self.has_inline_access_control(&func_source) {
                continue;
            }

            // FP Reduction: Check for initialization guard patterns
            // (require(!initialized), require(owner == address(0)), etc.)
            if self.has_init_guard(&func_source, ctx) {
                continue;
            }

            // FP Reduction: Skip simple ownership-setting initializers
            // Functions that only set owner = parameter are a common safe pattern
            // when called immediately during deployment. The first caller becomes owner,
            // which is the deployer. This is NOT a vulnerability in practice.
            if self.is_simple_ownership_setter(&func_source) {
                continue;
            }

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

            // CRITICAL FP FIX: Recognize OpenZeppelin's initializer modifier
            // The `initializer` modifier from @openzeppelin/contracts-upgradeable
            // prevents re-initialization and is proper protection.
            if modifier_name == "initializer" || modifier_name.contains("initializer") {
                return true;
            }

            // Also check for reinitializer
            if modifier_name.contains("reinitializer") {
                return true;
            }

            // Check for onlyInitializing
            if modifier_name == "onlyinitializing" {
                return true;
            }

            // Standard access control patterns
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

    /// Get function source code for inline analysis
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

    /// Check for inline access control patterns in the function body
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for require/if with msg.sender checks
        let has_sender_check =
            (lower.contains("require(") || lower.contains("if (") || lower.contains("if("))
                && (lower.contains("msg.sender ==")
                    || lower.contains("== msg.sender")
                    || lower.contains("msg.sender !=")
                    || lower.contains("!= msg.sender"));

        // Check for role-based inline checks
        let has_role_check = lower.contains("require(isowner")
            || lower.contains("require(isadmin")
            || lower.contains("require(hasrole")
            || lower.contains("_checkowner")
            || lower.contains("_checkrole");

        // Check for revert patterns indicating access control
        let has_revert = lower.contains("revert unauthorized")
            || lower.contains("revert notowner")
            || lower.contains("revert notadmin")
            || lower.contains("revert accessdenied")
            || lower.contains("revert onlyowner");

        has_sender_check || has_role_check || has_revert
    }

    /// Check for initialization guard patterns that prevent re-calling
    fn has_init_guard(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = func_source.to_lowercase();
        let contract_lower = ctx.source_code.to_lowercase();

        // Pattern 1: Explicit initialized flag check
        // require(!initialized) or require(!_initialized) or require(initialized == false)
        let has_initialized_check = lower.contains("!initialized")
            || lower.contains("!_initialized")
            || lower.contains("initialized == false")
            || lower.contains("_initialized == false")
            || lower.contains("initialized != true")
            || lower.contains("require(!initialized")
            || lower.contains("require(!_initialized");

        // Pattern 2: Zero-address owner check as init guard
        // require(owner == address(0)) means "only callable when not yet initialized"
        let has_zero_owner_check = lower.contains("owner == address(0)")
            || lower.contains("_owner == address(0)")
            || lower.contains("owner == address(0x0)")
            || lower.contains("owner() == address(0)");

        // Pattern 3: Contract has an initialized state variable used as guard
        let has_initialized_var = contract_lower.contains("bool")
            && (contract_lower.contains("initialized") || contract_lower.contains("_initialized"));

        // Pattern 4: Sets initialized = true (function is self-guarding)
        let sets_initialized =
            lower.contains("initialized = true") || lower.contains("_initialized = true");

        // Guard is present if there's a check, OR if the function sets the guard
        // and the contract has the variable
        (has_initialized_check)
            || (has_zero_owner_check)
            || (has_initialized_var && sets_initialized)
    }

    /// Determine if the contract is in an upgradeable/proxy context
    /// Only upgradeable contracts need initializer protection -- standalone
    /// contracts use constructors and initialize() is typically a safe pattern.
    fn is_upgradeable_context(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check inheritance for upgradeable patterns
        for base in ctx.contract.inheritance.iter() {
            let base_name = base.base.name.to_lowercase();
            if base_name.contains("upgradeable")
                || base_name.contains("upgradeabl")
                || base_name.contains("proxy")
                || base_name.contains("initializable")
            {
                return true;
            }
        }

        // Check source for proxy/upgradeable keywords
        let has_proxy_patterns = source_lower.contains("delegatecall")
            || source_lower.contains("eip1967")
            || source_lower.contains("upgradeto")
            || source_lower.contains("upgradeable")
            || source_lower.contains("proxy")
            || source_lower.contains("implementation_slot")
            || source_lower.contains("initializable");

        // Check for OpenZeppelin's Initializable import
        let has_initializable_import = source_lower.contains("import")
            && (source_lower.contains("initializable") || source_lower.contains("upgradeable"));

        has_proxy_patterns || has_initializable_import
    }

    /// Check if the initializer is a simple ownership setter
    /// Functions like `function initialize(address _owner) { owner = _owner; }`
    /// are a common safe constructor-replacement pattern. The deployer calls this
    /// immediately after deployment to set up the owner.
    fn is_simple_ownership_setter(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check if the function body primarily sets an owner/admin variable
        let sets_owner = lower.contains("owner =")
            || lower.contains("_owner =")
            || lower.contains("admin =")
            || lower.contains("_admin =");

        if !sets_owner {
            return false;
        }

        // Count the number of state-changing operations (assignments with =)
        // A simple setter has very few operations (1-3 lines of actual logic)
        let lines: Vec<&str> = func_source
            .lines()
            .map(|l| l.trim())
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with("//")
                    && !l.starts_with("/*")
                    && !l.starts_with("*")
                    && !l.starts_with("function ")
                    && !l.starts_with("}")
                    && !l.starts_with("{")
            })
            .collect();

        // A simple ownership setter typically has 1-3 lines of logic
        // (e.g., owner = _owner; and maybe an event emission)
        lines.len() <= 4
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
            "transfer", // ERC20/721 transfer
            "approve",  // ERC20/721 approve
            "send",     // User sends their own tokens
            "claim",    // Users claim their rewards
            "stake",    // Users stake their tokens
            "unstake",  // Users unstake their tokens
            "deposit",  // Users deposit their tokens
            "redeem",   // Users redeem their tokens
            "swap",     // Users swap tokens
            "buy",      // Users buy
            "sell",     // Users sell
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

    /// Phase 15 FP Reduction: Check for inline access control patterns
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for require/revert with msg.sender checks
        let has_sender_require = (lower.contains("require(") || lower.contains("if ("))
            && (lower.contains("msg.sender ==")
                || lower.contains("== msg.sender")
                || lower.contains("msg.sender !=")
                || lower.contains("!= msg.sender"));

        // Check for onlyXXX style inline checks
        let has_inline_only = lower.contains("require(isowner")
            || lower.contains("require(isadmin")
            || lower.contains("require(hasrole")
            || lower.contains("_checkowner")
            || lower.contains("_checkrole");

        // Check for revert patterns
        let has_revert_unauthorized = lower.contains("revert unauthorized")
            || lower.contains("revert notowner")
            || lower.contains("revert notadmin")
            || lower.contains("revert accessdenied");

        has_sender_require || has_inline_only || has_revert_unauthorized
    }

    /// Phase 15 FP Reduction: Check if function has owner check
    fn has_owner_check(&self, func_source: &str, contract_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Contract has Ownable pattern
        let has_ownable = contract_source.to_lowercase().contains("ownable")
            || contract_source.contains("owner")
            || contract_source.contains("_owner");

        // Function checks owner
        let checks_owner = lower.contains("msg.sender == owner")
            || lower.contains("owner == msg.sender")
            || lower.contains("msg.sender == _owner")
            || lower.contains("_owner == msg.sender")
            || lower.contains("owner()")
            || lower.contains("_checkowner");

        has_ownable && checks_owner
    }

    /// Phase 15 FP Reduction: Check if function is meant to be called only during construction
    fn is_constructor_callable_only(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = func_source.to_lowercase();

        // Check if this looks like initialization that checks if already initialized
        let has_init_check = lower.contains("!initialized")
            || lower.contains("initialized == false")
            || lower.contains("require(!_initialized")
            || lower.contains("require(_initialized == false");

        // Check if contract has initialized state variable
        let contract_lower = ctx.source_code.to_lowercase();
        let has_initialized_var = contract_lower.contains("bool private _initialized")
            || contract_lower.contains("bool internal _initialized")
            || contract_lower.contains("bool public initialized");

        has_init_check && has_initialized_var
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
                // Check if it has proper access control via modifiers
                if self.has_access_control(function) {
                    continue;
                }

                // Phase 15 FP Reduction: Check for inline access control
                let func_source = self.get_function_source(function, ctx);
                if self.has_inline_access_control(&func_source) {
                    continue;
                }

                // Phase 15 FP Reduction: Check if function is in a contract with Ownable
                // and has require(msg.sender == owner) check
                if self.has_owner_check(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip constructor-callable only patterns
                // These are functions meant to be called only during deployment
                if self.is_constructor_callable_only(&func_source, ctx) {
                    continue;
                }

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
            "address ", "uint", "int", "bool ", "bytes", "string ", "mapping(", "struct ", "enum ",
        ];

        // Must start with type and not be inside a function (no memory/calldata)
        let starts_with_type = type_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));

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
