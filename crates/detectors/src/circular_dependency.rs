use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::safe_call_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_batch_execution_pattern, is_secure_example_file, is_test_contract};

/// Detector for circular dependency vulnerabilities
pub struct CircularDependencyDetector {
    base: BaseDetector,
}

impl Default for CircularDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CircularDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("circular-dependency".to_string()),
                "Circular Dependency".to_string(),
                "Detects circular dependencies between contracts that can lead to deadlocks, infinite recursion, or DOS attacks".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::ExternalCalls],
                Severity::High,
            ),
        }
    }
}

impl Detector for CircularDependencyDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Phase 10: Skip test contracts and secure examples
        if is_test_contract(ctx) || is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // Phase 53 FP Reduction: Skip proxy contracts
        // Proxy patterns (fallback -> _delegate -> implementation) are intentional, not circular
        let source = &ctx.source_code;
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("library ERC1967Utils")
            || (source.contains("function _delegate(") && source.contains("fallback()"));

        if is_proxy_contract {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Phase 10: Skip batch execution patterns (multicall, executeBatch, etc.)
            let func_source = self.get_function_source(function, ctx);
            if is_batch_execution_pattern(function.name.name, &func_source) {
                continue;
            }

            if let Some(dependency_issue) = self.check_circular_dependency(function, ctx) {
                // NEW: Calculate confidence based on protection mechanisms
                let confidence = self.calculate_confidence(&func_source, &dependency_issue);

                let message = format!(
                    "Function '{}' has circular dependency vulnerability. {} \
                    Circular dependencies can cause stack overflow, DOS attacks, or make contracts unupgradeable.",
                    function.name.name, dependency_issue
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
                    .with_cwe(674) // CWE-674: Uncontrolled Recursion
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_confidence(confidence) // NEW: Set confidence
                    .with_fix_suggestion(format!(
                        "Break circular dependency in '{}'. \
                    Use events instead of callbacks, implement depth limits for recursive calls, \
                    add reentrancy guards, use pull pattern instead of push, \
                    implement circuit breakers, and add visited tracking for graph traversal.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CircularDependencyDetector {
    /// Standard ERC callback functions that are safe (reentrancy-protected by ERC design)
    fn is_standard_callback(&self, function_name: &str) -> bool {
        let name_lower = function_name.to_lowercase();

        // ERC-721 safe transfer callbacks
        if name_lower == "onerc721received" || name_lower == "on721received" {
            return true;
        }

        // ERC-1155 callbacks
        if name_lower == "onerc1155received"
            || name_lower == "onerc1155batchreceived"
            || name_lower == "on1155received"
        {
            return true;
        }

        // ERC-777 hooks
        if name_lower == "tokensreceived" || name_lower == "tokenssent" {
            return true;
        }

        // ERC-3156 flash loan callback
        if name_lower == "onflashloan" {
            return true;
        }

        // Uniswap/DEX callbacks
        if name_lower == "uniswapv2call"
            || name_lower == "uniswapv3swapcallback"
            || name_lower == "pancakecall"
            || name_lower.starts_with("uniswapv")
        {
            return true;
        }

        false
    }

    /// Phase 6: Check if function is a standard ERC transfer (not circular)
    fn is_standard_transfer(&self, function_name: &str) -> bool {
        let name_lower = function_name.to_lowercase();
        name_lower == "transfer"
            || name_lower == "transferfrom"
            || name_lower == "safetransfer"
            || name_lower == "safetransferfrom"
            || name_lower == "_transfer"
            || name_lower == "_safetransfer"
            || name_lower == "approve"
    }

    /// Phase 6: Check if function uses OpenZeppelin access control (safe patterns)
    fn has_oz_access_control(&self, func_source: &str) -> bool {
        func_source.contains("onlyRole")
            || func_source.contains("hasRole")
            || func_source.contains("AccessControl")
            || func_source.contains("_checkRole")
    }

    /// Check if a keyword appears as a function call (e.g., ".notify(" or "notify(")
    /// rather than as a variable name, parameter name, or inside a string/encoded call.
    fn is_function_call_pattern(func_source: &str, keyword: &str) -> bool {
        // Check for direct method call: .keyword( or keyword(
        let call_pattern = format!(".{}(", keyword);
        let direct_call = format!("{}(", keyword);

        if func_source.contains(&call_pattern) {
            return true;
        }

        // Check for direct call only if the keyword is followed by ( at a word boundary
        // This avoids matching e.g., "updateBalance(" when checking for "update("
        // We want to match standalone calls like "notify(" but not "notifyAdmin(" for the
        // generic "notify" keyword
        for (idx, _) in func_source.match_indices(&direct_call) {
            // Make sure this is at a word boundary (preceded by space, newline, or start)
            if idx == 0 {
                return true;
            }
            let prev_char = func_source.as_bytes()[idx - 1];
            if prev_char == b' '
                || prev_char == b'\n'
                || prev_char == b'\t'
                || prev_char == b';'
                || prev_char == b'{'
                || prev_char == b'}'
                || prev_char == b'('
                || prev_char == b','
            {
                return true;
            }
        }

        false
    }

    /// Check if source contains actual contract deployment (new ContractName(...))
    /// as opposed to variable declarations like "uint256 newAmount"
    fn has_contract_deployment(func_source: &str) -> bool {
        // Look for "new " followed by an uppercase letter (contract name convention)
        for (idx, _) in func_source.match_indices("new ") {
            let after = &func_source[idx + 4..];
            if let Some(first_char) = after.chars().next() {
                if first_char.is_uppercase() {
                    return true;
                }
            }
        }
        false
    }

    /// Check if contract source defines or references interface/abstract contracts
    /// that would create non-circular type references
    fn is_interface_or_abstract_reference(ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        // If the contract itself is an interface or abstract, its references are type-only
        source.contains("interface ") && !source.contains("contract ")
            || ctx.contract.name.name.starts_with('I')
                && ctx.contract.name.name.len() > 1
                && ctx
                    .contract
                    .name
                    .name
                    .chars()
                    .nth(1)
                    .map_or(false, |c| c.is_uppercase())
    }

    /// Check for circular dependency vulnerabilities
    fn check_circular_dependency(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Skip standard ERC callbacks - these are designed to be called during transfers
        // and have built-in reentrancy protections in ERC standards
        if self.is_standard_callback(function.name.name) {
            return None;
        }

        // Phase 6: Skip standard ERC transfers - these follow well-defined patterns
        if self.is_standard_transfer(function.name.name) {
            return None;
        }

        // Phase 6: Skip functions with OpenZeppelin access control
        if self.has_oz_access_control(&func_source) {
            return None;
        }

        // NEW: Skip functions that are safe from circular dependencies
        if safe_call_patterns::is_safe_from_circular_deps(function, &func_source, ctx) {
            return None; // Safe pattern detected - no circular risk
        }

        // Skip interface-only contracts - references through interfaces are type-level,
        // not actual circular instantiation
        if Self::is_interface_or_abstract_reference(ctx) {
            return None;
        }

        // Tighter external call detection
        // FP Reduction (v1.10.15 round 2): Removed the overly broad
        // (contains("external") && contains("()")) check, which matched any
        // external function with empty parens anywhere in the body (constructors,
        // comments, etc.). Only match actual low-level calls or delegatecall.
        let makes_external_call = func_source.contains(".call(")
            || func_source.contains(".call{")
            || func_source.contains("delegatecall");

        if !makes_external_call {
            return None;
        }

        // Pattern 1: Callback pattern without reentrancy guard
        // Tightened: "callback"/"Callback"/"onReceive" must appear as function call patterns
        // or as part of function name, not just anywhere in source (e.g., in comments or
        // encoded strings). "hook" must appear as a call like ".hook(" or "_hook("
        let has_callback = Self::is_function_call_pattern(&func_source, "callback")
            || Self::is_function_call_pattern(&func_source, "Callback")
            || Self::is_function_call_pattern(&func_source, "onReceive")
            || func_source.contains("_hook(")
            || func_source.contains(".hook(")
            || function.name.name.to_lowercase().contains("callback")
            || function.name.name.to_lowercase().contains("onreceive");

        let no_reentrancy_guard = has_callback
            && !func_source.contains("nonReentrant")
            && !func_source.contains("locked")
            && !func_source.contains("require(!_locked");

        if no_reentrancy_guard {
            return Some(
                "Callback pattern without reentrancy guard, \
                enables circular call chains and reentrancy attacks"
                    .to_string(),
            );
        }

        // Pattern 2: Recursive or self-calling patterns without depth limit
        // Only flag when there's actual evidence of recursive/circular patterns.
        //
        // FP Reduction (v1.10.15 round 2):
        // - address(this).call(payload) is a self-dispatch pattern (bridge message execution,
        //   proxy forwarding), NOT circular recursion unless the function calls itself by name.
        //   Require evidence that the function actually recurses into itself.
        // - For fallback/receive (empty name), calls_same_function must be skipped since
        //   searching for "(" matches everything.
        // - Standard proxy fallbacks that forward via assembly delegatecall are intentional
        //   forwarding, not circular dependencies.
        // - The function's own declaration line is excluded from the self-call search,
        //   since get_function_source() includes the signature.
        let has_recursive_name = function.name.name.to_lowercase().contains("recursive")
            || function.name.name.to_lowercase().contains("traverse")
            || function.name.name.to_lowercase().contains("walk");

        // Only check calls_same_function for named functions (not fallback/receive).
        // Also exclude the function's own declaration line.
        let calls_same_function = if function.name.name.is_empty() {
            false
        } else {
            let call_pattern = format!("{}(", function.name.name);
            // Skip the function signature: look only in lines after the first
            if let Some(first_newline) = func_source.find('\n') {
                let body = &func_source[first_newline..];
                body.contains(&call_pattern)
            } else {
                false
            }
        };

        // address(this).call() alone is a self-dispatch pattern, not recursion.
        // Only flag as recursive if the function also calls itself by name or has
        // a recursive function name.
        let has_self_recursive_call = func_source.contains("address(this)")
            && (func_source.contains(".call(") || func_source.contains("delegatecall"))
            && (calls_same_function || has_recursive_name);

        let is_recursive_pattern =
            has_self_recursive_call || has_recursive_name || calls_same_function;

        let no_depth_limit = is_recursive_pattern
            && !func_source.contains("depth")
            && !func_source.contains("level")
            && !func_source.contains("maxRecursion")
            && !func_source.contains("visited");

        if no_depth_limit && is_recursive_pattern {
            return Some(
                "Recursive pattern without depth limit, \
                circular calls can cause stack overflow"
                    .to_string(),
            );
        }

        // Pattern 3: Observer pattern with notification loops
        // TIGHTENED: Require actual observer/notification call patterns, not just
        // keywords appearing as variable names, parameter names, or in encoded strings.
        // - "notify" must appear as a function call: .notify( or notifyObservers( etc.
        // - "update" is too generic; only flag notifyX/updateObservers-style calls
        // - "observer" and "listener" as parameter names do NOT indicate observer pattern
        let has_observer_call_pattern = Self::is_function_call_pattern(&func_source, "notifyObservers")
                || Self::is_function_call_pattern(&func_source, "notifyListeners")
                || Self::is_function_call_pattern(&func_source, "notifyAll")
                || Self::is_function_call_pattern(&func_source, "updateObservers")
                || Self::is_function_call_pattern(&func_source, "updateListeners")
                || (func_source.contains("for ") && func_source.contains("observers[")
                    && (Self::is_function_call_pattern(&func_source, "notify")
                        || Self::is_function_call_pattern(&func_source, "update")))
                // Detect iterator-based observer calling: loop over an array and
                // call each element via .call( -- this is the structural observer
                // pattern regardless of the specific function being called.
                || (func_source.contains("for ")
                    && (func_source.contains("observers[") || func_source.contains("listeners[")
                        || func_source.contains("subscribers[") || func_source.contains("hooks["))
                    && (func_source.contains(".call(") || func_source.contains(".call{")))
                // Also detect when the function itself is named as a notification entry point
                || (function.name.name.to_lowercase().contains("notify")
                    && func_source.contains("for ")
                    && (func_source.contains(".call(") || func_source.contains(".call{")));

        let no_loop_protection = has_observer_call_pattern
            && !func_source.contains("visited")
            && !func_source.contains("notified")
            && !func_source.contains("break");

        if no_loop_protection {
            return Some(
                "Observer notification without loop protection, \
                observers can create notification cycles"
                    .to_string(),
            );
        }

        // Pattern 4: Recursive token transfer without guard
        let is_transfer = func_source.contains("transfer")
            || func_source.contains("Transfer")
            || function.name.name.to_lowercase().contains("transfer");

        let has_hook = func_source.contains("beforeTransfer")
            || func_source.contains("afterTransfer")
            || func_source.contains("_beforeTokenTransfer");

        let recursive_transfer = is_transfer && has_hook && !func_source.contains("nonReentrant");

        if recursive_transfer {
            return Some(
                "Transfer with hooks can create circular dependency, \
                hook can trigger another transfer creating infinite loop"
                    .to_string(),
            );
        }

        // Pattern 5: Delegation chain without cycle detection
        // TIGHTENED (v1.10.15 round 2): Only flag when there's evidence of actual
        // delegation CHAINING (multi-hop delegation that could form cycles), not
        // simple one-hop delegatecall to a user-provided or stored address.
        //
        // A simple `target.delegatecall(data)` is a user-controlled delegatecall
        // vulnerability (caught by delegatecall-user-controlled detector), NOT a
        // circular dependency. Circular dependency requires evidence that the
        // delegated-to contract can delegate back, forming a cycle.
        //
        // Evidence of chaining:
        // - _delegate() helper (OpenZeppelin proxy internal forwarding)
        // - Multiple delegatecall targets or a delegation registry
        // - Proxy + implementation pattern with mutual references
        // - Function iterates over a list of delegates
        let has_delegate_helper = func_source.contains("_delegate(");
        let has_delegation_registry = func_source.contains("delegates[")
            || func_source.contains("delegateList[")
            || func_source.contains("delegationChain");
        let has_proxy_cycle_risk = func_source.contains("proxy")
            && func_source.contains("implementation")
            && func_source.contains("delegatecall");
        let has_multi_hop = func_source.contains("_delegate(")
            && (func_source.contains("for ") || func_source.contains("while "));

        let is_delegation_chain =
            has_delegate_helper || has_delegation_registry || has_proxy_cycle_risk || has_multi_hop;

        let no_cycle_detection = is_delegation_chain
            && !func_source.contains("visited")
            && !func_source.contains("checked");

        if no_cycle_detection {
            return Some(
                "Delegation chain without cycle detection, \
                circular delegations can cause infinite loops"
                    .to_string(),
            );
        }

        // Pattern 6: Cross-contract state dependencies (TIGHTENED)
        // Only flag if BOTH reads external state AND writes state in circular manner
        let reads_external_state = (func_source.contains(".balanceOf(address(this))")
            || func_source.contains(".totalSupply()")
            || func_source.contains(".getReserves()"))
            && !func_source.contains("view")
            && !func_source.contains("pure");

        // Must have state writes AND external reads in vulnerable pattern
        let has_state_writes =
            func_source.contains(" = ") || func_source.contains("+=") || func_source.contains("-=");

        // Must have callback potential - require actual low-level call with callback
        let has_callback_potential = func_source.contains(".call(")
            || func_source.contains(".call{")
            || Self::is_function_call_pattern(&func_source, "callback");

        let dependency_cycle = reads_external_state && has_state_writes && has_callback_potential;

        if dependency_cycle {
            return Some(
                "Reads external contract state during state changes with callback potential, \
                creates interdependency that can deadlock"
                    .to_string(),
            );
        }

        // Pattern 7: Upgrade circular dependency
        // TIGHTENED: Only flag actual proxy/implementation upgrade functions, not
        // any function that happens to contain the word "upgrade" (e.g., upgradeUserTier).
        let is_proxy_upgrade = func_source.contains("setImplementation")
            || func_source.contains("upgradeTo(")
            || func_source.contains("upgradeToAndCall(")
            || func_source.contains("_upgradeBeaconToAndCall(")
            || (function.name.name.to_lowercase().contains("upgrade")
                && (func_source.contains("implementation")
                    || func_source.contains("delegatecall")));

        let calls_dependency =
            is_proxy_upgrade && makes_external_call && !func_source.contains("require");

        if calls_dependency {
            return Some(
                "Upgrade function calls external contracts, \
                circular upgrade dependencies can brick contract"
                    .to_string(),
            );
        }

        // Pattern 8: Event-based circular triggers
        // TIGHTENED: Only flag when there is an actual listener registry/notification
        // mechanism, not just a parameter or variable named "listener".
        // Require evidence of listener iteration (for loop + listeners array) or
        // explicit subscriber notification calls.
        let emits_event = func_source.contains("emit");

        let has_listener_registry = func_source.contains("listeners[")
            || func_source.contains("subscribers[")
            || Self::is_function_call_pattern(&func_source, "notifyListeners")
            || Self::is_function_call_pattern(&func_source, "notifySubscribers");

        let event_triggers_call = emits_event && makes_external_call && has_listener_registry;

        if event_triggers_call {
            return Some(
                "Emits event that triggers external call in same function, \
                can create circular event-call chains"
                    .to_string(),
            );
        }

        // Pattern 9: Factory pattern circular reference
        // TIGHTENED: Require actual contract deployment (new ContractName(...))
        // not just "new " appearing in variable declarations like "uint256 newAmount".
        let is_factory = func_source.contains("deploy")
            || function.name.name.to_lowercase().contains("deploy")
            || (function.name.name.to_lowercase().contains("create")
                && func_source.contains("factory"));

        let has_deployment = Self::has_contract_deployment(&func_source);

        let circular_factory = is_factory && has_deployment && makes_external_call;

        if circular_factory {
            return Some(
                "Factory creates contracts that call back to factory, \
                circular creation dependencies"
                    .to_string(),
            );
        }

        // Pattern 10: Approval-transfer circular dependency
        // TIGHTENED: Only flag when the function actually calls BOTH approve and transfer
        // as function calls, not just containing the words (e.g., "transferAmount" variable).
        let is_approval_function = function.name.name.to_lowercase() == "approve"
            || function.name.name.to_lowercase().contains("approve");

        let calls_transfer = Self::is_function_call_pattern(&func_source, "transfer")
            || Self::is_function_call_pattern(&func_source, "transferFrom")
            || Self::is_function_call_pattern(&func_source, "safeTransfer");

        let approval_transfers = is_approval_function && calls_transfer;

        if approval_transfers {
            return Some(
                "Approval function triggers transfer creating circular dependency, \
                approve->transfer->approve loops possible"
                    .to_string(),
            );
        }

        None
    }

    /// Calculate confidence based on protection mechanisms and issue type
    fn calculate_confidence(&self, func_source: &str, issue: &str) -> Confidence {
        let mut protection_count = 0;

        // Count protection mechanisms
        if safe_call_patterns::has_reentrancy_protection(func_source) {
            protection_count += 1;
        }

        if safe_call_patterns::has_depth_limit(func_source) {
            protection_count += 1;
        }

        if safe_call_patterns::has_cycle_detection(func_source) {
            protection_count += 1;
        }

        if safe_call_patterns::has_try_catch_protection(func_source) {
            protection_count += 1;
        }

        // Higher severity issues get higher confidence
        let is_high_severity = issue.contains("callback")
            || issue.contains("infinite loop")
            || issue.contains("stack overflow");

        match protection_count {
            0 if is_high_severity => Confidence::High, // No protection, high severity
            0 => Confidence::Medium,                   // No protection, lower severity
            1 => Confidence::Medium,                   // Some protection
            _ => Confidence::Low,                      // Multiple protections (2+)
        }
    }

    /// Get function source code
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = CircularDependencyDetector::new();
        assert_eq!(detector.name(), "Circular Dependency");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
