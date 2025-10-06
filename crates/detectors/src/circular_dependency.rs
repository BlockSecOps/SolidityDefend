use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for circular dependency vulnerabilities
pub struct CircularDependencyDetector {
    base: BaseDetector,
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
                let message = format!(
                    "Function '{}' has circular dependency vulnerability. {} \
                    Circular dependencies can cause stack overflow, DOS attacks, or make contracts unupgradeable.",
                    function.name.name,
                    dependency_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(674) // CWE-674: Uncontrolled Recursion
                .with_cwe(834) // CWE-834: Excessive Iteration
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
    /// Check for circular dependency vulnerabilities
    fn check_circular_dependency(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function makes external calls that could create circular dependencies
        let makes_external_call = func_source.contains(".call") ||
                                 func_source.contains("(") && func_source.contains(")") ||
                                 func_source.contains("interface");

        if !makes_external_call {
            return None;
        }

        // Pattern 1: Callback pattern without reentrancy guard
        let has_callback = func_source.contains("callback") ||
                          func_source.contains("Callback") ||
                          func_source.contains("onReceive") ||
                          func_source.contains("hook");

        let no_reentrancy_guard = has_callback &&
                                 !func_source.contains("nonReentrant") &&
                                 !func_source.contains("locked") &&
                                 !func_source.contains("require(!_locked");

        if no_reentrancy_guard {
            return Some(format!(
                "Callback pattern without reentrancy guard, \
                enables circular call chains and reentrancy attacks"
            ));
        }

        // Pattern 2: Mutual contract calls without depth limit
        let calls_external = func_source.contains(".") &&
                            (func_source.contains("()") || func_source.contains("("));

        let no_depth_limit = calls_external &&
                            !func_source.contains("depth") &&
                            !func_source.contains("level") &&
                            !func_source.contains("count");

        if no_depth_limit && makes_external_call {
            return Some(format!(
                "External contract calls without depth limit, \
                circular calls can cause stack overflow"
            ));
        }

        // Pattern 3: Observer pattern with notification loops
        let notifies_observers = func_source.contains("notify") ||
                                func_source.contains("update") ||
                                func_source.contains("observer") ||
                                func_source.contains("listener");

        let no_loop_protection = notifies_observers &&
                                !func_source.contains("visited") &&
                                !func_source.contains("notified") &&
                                !func_source.contains("break");

        if no_loop_protection {
            return Some(format!(
                "Observer notification without loop protection, \
                observers can create notification cycles"
            ));
        }

        // Pattern 4: Recursive token transfer without guard
        let is_transfer = func_source.contains("transfer") ||
                         func_source.contains("Transfer") ||
                         function.name.name.to_lowercase().contains("transfer");

        let has_hook = func_source.contains("beforeTransfer") ||
                      func_source.contains("afterTransfer") ||
                      func_source.contains("_beforeTokenTransfer");

        let recursive_transfer = is_transfer && has_hook &&
                                !func_source.contains("nonReentrant");

        if recursive_transfer {
            return Some(format!(
                "Transfer with hooks can create circular dependency, \
                hook can trigger another transfer creating infinite loop"
            ));
        }

        // Pattern 5: Delegation chain without cycle detection
        let is_delegation = func_source.contains("delegate") ||
                           func_source.contains("proxy") ||
                           function.name.name.to_lowercase().contains("delegate");

        let no_cycle_detection = is_delegation &&
                                calls_external &&
                                !func_source.contains("visited") &&
                                !func_source.contains("checked");

        if no_cycle_detection {
            return Some(format!(
                "Delegation chain without cycle detection, \
                circular delegations can cause infinite loops"
            ));
        }

        // Pattern 6: Cross-contract state dependencies
        let reads_external_state = func_source.contains(".balance") ||
                                   func_source.contains(".totalSupply") ||
                                   (func_source.contains(".") && func_source.contains("()"));

        let dependency_cycle = reads_external_state &&
                              makes_external_call &&
                              !func_source.contains("view") &&
                              !func_source.contains("pure");

        if dependency_cycle {
            return Some(format!(
                "Reads external contract state during state changes, \
                creates interdependency that can deadlock"
            ));
        }

        // Pattern 7: Upgrade circular dependency
        let is_upgrade = func_source.contains("upgrade") ||
                        func_source.contains("setImplementation") ||
                        function.name.name.to_lowercase().contains("upgrade");

        let calls_dependency = is_upgrade &&
                              calls_external &&
                              !func_source.contains("require");

        if calls_dependency {
            return Some(format!(
                "Upgrade function calls external contracts, \
                circular upgrade dependencies can brick contract"
            ));
        }

        // Pattern 8: Event-based circular triggers
        let emits_event = func_source.contains("emit");

        let event_triggers_call = emits_event &&
                                 calls_external &&
                                 (func_source.contains("listener") ||
                                  func_source.contains("subscriber"));

        if event_triggers_call {
            return Some(format!(
                "Emits event that triggers external call in same function, \
                can create circular event-call chains"
            ));
        }

        // Pattern 9: Factory pattern circular reference
        let is_factory = func_source.contains("create") ||
                        func_source.contains("deploy") ||
                        function.name.name.to_lowercase().contains("create");

        let circular_factory = is_factory &&
                              func_source.contains("new ") &&
                              calls_external;

        if circular_factory {
            return Some(format!(
                "Factory creates contracts that call back to factory, \
                circular creation dependencies"
            ));
        }

        // Pattern 10: Approval-transfer circular dependency
        let is_approval = func_source.contains("approve") ||
                         function.name.name.to_lowercase().contains("approve");

        let approval_transfers = is_approval &&
                                func_source.contains("transfer");

        if approval_transfers {
            return Some(format!(
                "Approval function triggers transfer creating circular dependency, \
                approve->transfer->approve loops possible"
            ));
        }

        None
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
