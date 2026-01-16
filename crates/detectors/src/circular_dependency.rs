use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::safe_call_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

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

        for function in ctx.get_functions() {
            if let Some(dependency_issue) = self.check_circular_dependency(function, ctx) {
                let func_source = self.get_function_source(function, ctx);

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

        // NEW: Skip functions that are safe from circular dependencies
        if safe_call_patterns::is_safe_from_circular_deps(function, &func_source, ctx) {
            return None; // Safe pattern detected - no circular risk
        }

        // NEW: Tighter external call detection (not just any parentheses!)
        let makes_external_call = func_source.contains(".call(")
            || func_source.contains(".call{")
            || func_source.contains("delegatecall")
            || (func_source.contains("external") && func_source.contains("()"));

        if !makes_external_call {
            return None;
        }

        // Pattern 1: Callback pattern without reentrancy guard
        let has_callback = func_source.contains("callback")
            || func_source.contains("Callback")
            || func_source.contains("onReceive")
            || func_source.contains("hook");

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

        // Pattern 2: Mutual contract calls without depth limit
        let calls_external =
            func_source.contains(".") && (func_source.contains("()") || func_source.contains("("));

        let no_depth_limit = calls_external
            && !func_source.contains("depth")
            && !func_source.contains("level")
            && !func_source.contains("count");

        if no_depth_limit && makes_external_call {
            return Some(
                "External contract calls without depth limit, \
                circular calls can cause stack overflow"
                    .to_string(),
            );
        }

        // Pattern 3: Observer pattern with notification loops
        let notifies_observers = func_source.contains("notify")
            || func_source.contains("update")
            || func_source.contains("observer")
            || func_source.contains("listener");

        let no_loop_protection = notifies_observers
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
        let is_delegation = func_source.contains("delegate")
            || func_source.contains("proxy")
            || function.name.name.to_lowercase().contains("delegate");

        let no_cycle_detection = is_delegation
            && calls_external
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

        // Must have callback potential
        let has_callback_potential = func_source.contains(".call(")
            || func_source.contains("callback")
            || func_source.contains("hook");

        let dependency_cycle = reads_external_state && has_state_writes && has_callback_potential;

        if dependency_cycle {
            return Some(
                "Reads external contract state during state changes with callback potential, \
                creates interdependency that can deadlock"
                    .to_string(),
            );
        }

        // Pattern 7: Upgrade circular dependency
        let is_upgrade = func_source.contains("upgrade")
            || func_source.contains("setImplementation")
            || function.name.name.to_lowercase().contains("upgrade");

        let calls_dependency = is_upgrade && calls_external && !func_source.contains("require");

        if calls_dependency {
            return Some(
                "Upgrade function calls external contracts, \
                circular upgrade dependencies can brick contract"
                    .to_string(),
            );
        }

        // Pattern 8: Event-based circular triggers
        let emits_event = func_source.contains("emit");

        let event_triggers_call = emits_event
            && calls_external
            && (func_source.contains("listener") || func_source.contains("subscriber"));

        if event_triggers_call {
            return Some(
                "Emits event that triggers external call in same function, \
                can create circular event-call chains"
                    .to_string(),
            );
        }

        // Pattern 9: Factory pattern circular reference
        let is_factory = func_source.contains("create")
            || func_source.contains("deploy")
            || function.name.name.to_lowercase().contains("create");

        let circular_factory = is_factory && func_source.contains("new ") && calls_external;

        if circular_factory {
            return Some(
                "Factory creates contracts that call back to factory, \
                circular creation dependencies"
                    .to_string(),
            );
        }

        // Pattern 10: Approval-transfer circular dependency
        let is_approval = func_source.contains("approve")
            || function.name.name.to_lowercase().contains("approve");

        let approval_transfers = is_approval && func_source.contains("transfer");

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
