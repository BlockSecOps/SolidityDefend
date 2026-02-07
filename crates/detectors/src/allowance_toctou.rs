use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ERC20 allowance time-of-check-time-of-use (TOCTOU) vulnerabilities
///
/// This detector identifies patterns where code checks an allowance value and makes
/// decisions based on it, but the allowance could change between the check and use,
/// leading to race conditions and unexpected behavior.
///
/// **Vulnerability:** CWE-367 (Time-of-check Time-of-use Race Condition)
/// **Severity:** Medium
///
/// ## Description
///
/// Allowance TOCTOU occurs when:
/// 1. Contract checks `allowance(owner, spender)` value
/// 2. Makes decision or calculation based on that value
/// 3. Uses allowance later (e.g., `transferFrom`)
/// 4. Allowance could be changed between check and use
///
/// This creates race conditions where:
/// - User's allowance changes mid-execution
/// - Contract operates on stale allowance data
/// - Unexpected behavior or failed transactions
/// - Potential for exploitation in multi-step operations
///
/// Common vulnerable patterns:
/// - Check allowance, calculate amount, then transfer
/// - Multi-transaction flows relying on allowance state
/// - Caching allowance values across function calls
/// - Conditional logic based on allowance checks
///
pub struct AllowanceToctouDetector {
    base: BaseDetector,
}

impl Default for AllowanceToctouDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowanceToctouDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("allowance-toctou".to_string()),
                "Allowance Time-of-Check-Time-of-Use".to_string(),
                "Detects race conditions where allowance is checked but may change before use"
                    .to_string(),
                vec![
                    DetectorCategory::Logic,
                    DetectorCategory::DeFi,
                    DetectorCategory::MEV,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Checks if function has allowance TOCTOU vulnerability
    fn has_allowance_toctou(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Skip if function is internal/private
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return None;
        }

        // Check for allowance() calls
        let has_allowance_check =
            func_source.contains("allowance(") || func_source.contains(".allowance(");

        if !has_allowance_check {
            return None;
        }

        // Check for transferFrom (allowance usage)
        let has_transfer_from =
            func_source.contains("transferFrom(") || func_source.contains(".transferFrom(");

        // Check for state-changing operations between check and use
        let has_external_call = func_source.contains(".call(")
            || func_source.contains(".delegatecall(")
            || func_source.contains("external") && func_source.contains("()");

        // Check for multi-step operations
        let is_multi_step = func_name_lower.contains("batch")
            || func_name_lower.contains("multi")
            || func_name_lower.contains("claim")
            || func_name_lower.contains("process")
            || func_source.contains("for ")
            || func_source.contains("while ");

        // Check for conditional logic based on allowance
        let has_allowance_conditional = (func_source.contains("if")
            || func_source.contains("require"))
            && func_source.contains("allowance");

        // Check for revalidation first (applies to all patterns with transferFrom)
        let has_revalidation = if has_transfer_from {
            self.has_allowance_revalidation(&func_source)
        } else {
            false
        };

        // Pattern 1: Allowance check with transferFrom (classic TOCTOU)
        if has_allowance_check && has_transfer_from && !has_revalidation {
            return Some(format!(
                "Allowance TOCTOU vulnerability. Function '{}' checks allowance but doesn't \
                re-validate before transferFrom. Allowance could change between check and use",
                function.name.name
            ));
        }

        // Pattern 2: Allowance-based conditional with external calls
        // Skip if has revalidation or reentrancy protection
        if has_allowance_conditional && has_external_call && !has_revalidation {
            let has_reentrancy_guard = func_source.contains("nonReentrant")
                || func_source.contains("locked")
                || func_source.contains("reentrancy");

            if !has_reentrancy_guard {
                return Some(format!(
                    "Allowance TOCTOU in conditional logic. Function '{}' makes decisions based on \
                    allowance but calls external contracts. Allowance could be modified mid-execution",
                    function.name.name
                ));
            }
        }

        // Pattern 3: Multi-step operation relying on allowance
        // Only flag if no revalidation AND no lock mechanism
        if has_allowance_check
            && is_multi_step
            && !has_revalidation
            && !self.has_allowance_lock(&func_source)
            && has_transfer_from
        {
            return Some(format!(
                "Allowance TOCTOU in multi-step operation. Function '{}' performs multiple \
                operations based on allowance without locking it. Race condition possible",
                function.name.name
            ));
        }

        // Pattern 4: Allowance check without immediate use
        if has_allowance_check && !has_transfer_from && !self.is_view_function(function) {
            // This might be storing allowance for later use
            let stores_allowance = func_source.contains("allowance")
                && (func_source.contains("=") || func_source.contains("storage"));

            // Skip if this is creating a lock structure (valid pattern)
            let is_creating_lock = (func_name_lower.contains("create")
                || func_name_lower.contains("lock")
                || func_name_lower.contains("snapshot"))
                && (func_source.contains("Lock")
                    || func_source.contains("lock")
                    || func_source.contains("Snapshot"));

            if stores_allowance && !is_creating_lock {
                return Some(format!(
                    "Stale allowance data. Function '{}' caches allowance value which may \
                    become outdated. Should re-check allowance when actually used",
                    function.name.name
                ));
            }
        }

        None
    }

    /// Checks if allowance is re-validated before use
    fn has_allowance_revalidation(&self, source: &str) -> bool {
        // Look for patterns that re-validate allowance immediately before transferFrom
        // This is a heuristic - not perfect but catches common patterns

        let lines: Vec<&str> = source.lines().collect();
        let mut last_allowance_check: Option<usize> = None;
        let mut transfer_from_line: Option<usize> = None;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("allowance(") || line.contains(".allowance(") {
                last_allowance_check = Some(i);
            }
            if line.contains("transferFrom(") || line.contains(".transferFrom(") {
                transfer_from_line = Some(i);

                // If allowance check is immediately before transferFrom (within 5 lines)
                // consider it re-validated
                if let Some(check_line) = last_allowance_check {
                    if i - check_line <= 5 {
                        return true;
                    }
                }
            }
        }

        // Also check for require statements with allowance right before transferFrom
        if let (Some(check), Some(transfer)) = (last_allowance_check, transfer_from_line) {
            if transfer - check <= 3 {
                // Check if there's a require or validation between them
                for line in &lines[check..transfer] {
                    if line.contains("require") && line.contains("allowance") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Checks if function implements allowance locking mechanism
    fn has_allowance_lock(&self, source: &str) -> bool {
        // Look for patterns that lock allowance during execution
        source.contains("lock")
            || source.contains("snapshot")
            || source.contains("freeze")
            || (source.contains("nonReentrant") && source.contains("allowance"))
    }

    /// Checks if function is view/pure (read-only)
    fn is_view_function(&self, function: &ast::Function<'_>) -> bool {
        function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
    }

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

impl Detector for AllowanceToctouDetector {
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

        for function in ctx.get_functions() {
            if let Some(issue) = self.has_allowance_toctou(function, ctx) {
                let message = format!(
                    "Function '{}' has allowance TOCTOU vulnerability. {} \
                    This creates a race condition where allowance can change between check and use, \
                    leading to unexpected behavior or failed transactions",
                    function.name.name, issue
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
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use Race Condition
                    .with_cwe(362) // CWE-362: Concurrent Execution
                    .with_fix_suggestion(format!(
                        "Fix allowance TOCTOU in '{}'. Implement: \
                        (1) Re-validate allowance immediately before transferFrom: \
                        require(token.allowance(owner, address(this)) >= amount, 'Insufficient allowance'); \
                        (2) Use try-catch around transferFrom to handle allowance changes gracefully; \
                        (3) For multi-step operations, snapshot allowance at start and validate throughout; \
                        (4) Consider using permit (EIP-2612) for atomic approve+transfer; \
                        (5) Add reentrancy protection if external calls are made between check and use",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_metadata() {
        let detector = AllowanceToctouDetector::new();
        assert_eq!(detector.id().0, "allowance-toctou");
        assert_eq!(detector.name(), "Allowance Time-of-Check-Time-of-Use");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detector_categories() {
        let detector = AllowanceToctouDetector::new();
        let categories = detector.categories();
        assert!(categories.contains(&DetectorCategory::Logic));
        assert!(categories.contains(&DetectorCategory::DeFi));
        assert!(categories.contains(&DetectorCategory::MEV));
    }
}
