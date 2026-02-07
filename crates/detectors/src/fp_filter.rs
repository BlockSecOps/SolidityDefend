//! Pipeline-level false positive filter.
//!
//! This module provides a post-detection filter that suppresses common false positive
//! patterns across all detectors at once. The filter runs after all detectors produce
//! findings but before output, using AST metadata to identify findings in safe contexts.
//!
//! Enabled via `--fp-filter` CLI flag. Off by default to preserve existing behavior.

use std::collections::HashSet;

use ast::{ContractType, FunctionType, StateMutability, Visibility};

use crate::types::{AnalysisContext, Finding};

/// Common admin modifier names that indicate access-controlled functions.
const ADMIN_MODIFIERS: &[&str] = &[
    "onlyOwner",
    "onlyAdmin",
    "onlyRole",
    "onlyGovernance",
    "onlyOperator",
    "onlyManager",
    "onlyGuardian",
    "onlyMultisig",
    "onlyAuthorized",
    "onlyKeeper",
    "whenNotPaused",
];

/// Detector ID prefixes for DoS/frontrunning/MEV detectors that should be
/// suppressed in admin-controlled functions.
const ADMIN_SUPPRESSIBLE_PREFIXES: &[&str] = &[
    "dos-",
    "front-running",
    "sandwich-",
    "mev-",
    "frontrunning",
    "block-stuffing",
    "jit-liquidity",
    "backrunning",
    "token-launch-mev",
    "nft-mint-mev",
    "oracle-update-mev",
    "liquidation-mev",
    "governance-proposal-mev",
    "cross-domain-mev",
    "order-flow-auction",
    "encrypted-mempool",
    "bundle-inclusion",
    "token-transfer-frontrun",
    "price-manipulation-frontrun",
    "proposal-frontrunning",
];

/// Pipeline-level false positive filter.
///
/// Applies context-aware suppression rules to findings based on the contract
/// and function AST metadata. This reduces noise from detectors that flag
/// patterns in contexts where they are not exploitable.
pub struct FpFilter {
    /// Detector IDs that should NOT be filtered for view/pure functions.
    view_pure_exceptions: HashSet<String>,
    /// Detector IDs that should NOT be filtered for internal/private functions.
    internal_private_exceptions: HashSet<String>,
    /// Detector IDs that should NOT be filtered for admin functions.
    admin_exceptions: HashSet<String>,
}

impl FpFilter {
    /// Create a new FP filter with default exception lists.
    pub fn new() -> Self {
        let view_pure_exceptions: HashSet<String> = [
            "missing-visibility-modifier",
            "unused-state-variables",
            "private-variable-exposure",
            "floating-pragma",
            "deprecated-functions",
            "shadowing-variables",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let internal_private_exceptions: HashSet<String> = [
            "missing-visibility-modifier",
            "unused-state-variables",
            "shadowing-variables",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let admin_exceptions: HashSet<String> = [
            "missing-access-control",
            "centralization-risk",
            "emergency-pause-centralization",
            "unprotected-initializer",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            view_pure_exceptions,
            internal_private_exceptions,
            admin_exceptions,
        }
    }

    /// Filter findings using AST context from the analyzed contract.
    ///
    /// Returns only findings that pass all filter rules (i.e., are not suppressed).
    pub fn filter<'a>(
        &self,
        findings: Vec<Finding>,
        ctx: &AnalysisContext<'a>,
    ) -> Vec<Finding> {
        // Rule 1: Skip all findings for interface contracts
        if ctx.contract.contract_type == ContractType::Interface {
            return Vec::new();
        }

        // Rule 2: For library contracts, suppress state-mutation-related detectors
        let is_library = ctx.contract.contract_type == ContractType::Library;

        findings
            .into_iter()
            .filter(|finding| {
                let detector_id = &finding.detector_id.0;

                // Rule 2: Library filter — suppress most findings in libraries
                if is_library && !self.is_code_quality_detector(detector_id) {
                    return false;
                }

                // Find the enclosing function for this finding
                let enclosing_fn = self.find_enclosing_function(finding, ctx);

                if let Some(func) = enclosing_fn {
                    // Rule 3: Skip view/pure functions (unless excepted)
                    if (func.mutability == StateMutability::View
                        || func.mutability == StateMutability::Pure)
                        && !self.view_pure_exceptions.contains(detector_id)
                    {
                        return false;
                    }

                    // Rule 4: Skip internal/private functions (unless excepted)
                    if (func.visibility == Visibility::Internal
                        || func.visibility == Visibility::Private)
                        && !self.internal_private_exceptions.contains(detector_id)
                    {
                        return false;
                    }

                    // Rule 5: Skip constructor functions
                    if func.function_type == FunctionType::Constructor {
                        return false;
                    }

                    // Rule 6: Skip fallback/receive for non-proxy-specific detectors
                    if (func.function_type == FunctionType::Fallback
                        || func.function_type == FunctionType::Receive)
                        && !self.is_proxy_detector(detector_id)
                    {
                        return false;
                    }

                    // Rule 7: Skip admin-controlled functions for DoS/frontrunning/MEV
                    if self.has_admin_modifier(func)
                        && self.is_admin_suppressible(detector_id)
                        && !self.admin_exceptions.contains(detector_id)
                    {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    /// Find the function that encloses the given finding based on line numbers.
    fn find_enclosing_function<'a, 'arena>(
        &self,
        finding: &Finding,
        ctx: &'a AnalysisContext<'arena>,
    ) -> Option<&'a ast::Function<'arena>> {
        let finding_line = finding.primary_location.line as usize;

        ctx.contract.functions.iter().find(|f| {
            let (start, end) = f.location.line_span();
            finding_line >= start && finding_line <= end
        })
    }

    /// Check if a function has an admin modifier.
    fn has_admin_modifier(&self, func: &ast::Function<'_>) -> bool {
        func.modifiers.iter().any(|m| {
            let name = m.name.as_str();
            ADMIN_MODIFIERS.iter().any(|admin| name.contains(admin))
        })
    }

    /// Check if a detector ID is for a DoS/frontrunning/MEV detector
    /// that should be suppressed in admin-controlled functions.
    fn is_admin_suppressible(&self, detector_id: &str) -> bool {
        ADMIN_SUPPRESSIBLE_PREFIXES
            .iter()
            .any(|prefix| detector_id.starts_with(prefix) || detector_id.contains(prefix))
    }

    /// Check if a detector is proxy-specific (should still fire in fallback/receive).
    fn is_proxy_detector(&self, detector_id: &str) -> bool {
        detector_id.contains("proxy")
            || detector_id.contains("delegatecall")
            || detector_id.contains("fallback")
            || detector_id.contains("diamond")
            || detector_id.contains("upgrade")
            || detector_id.contains("eip1967")
    }

    /// Check if a detector is a code quality / informational detector
    /// that should still fire in library contracts.
    fn is_code_quality_detector(&self, detector_id: &str) -> bool {
        detector_id.contains("floating-pragma")
            || detector_id.contains("deprecated")
            || detector_id.contains("shadowing")
            || detector_id.contains("unused-state")
            || detector_id.contains("missing-visibility")
            || detector_id.contains("redundant")
    }
}

impl Default for FpFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, DetectorId, Finding, Severity, SourceLocation};

    fn make_finding(detector_id: &str, line: u32) -> Finding {
        Finding::new(
            DetectorId::new(detector_id),
            Severity::High,
            Confidence::High,
            format!("Test finding from {}", detector_id),
            SourceLocation::new("test.sol".to_string(), line, 1, 10),
        )
    }

    #[test]
    fn test_fp_filter_creation() {
        let filter = FpFilter::new();
        assert!(filter
            .view_pure_exceptions
            .contains("missing-visibility-modifier"));
        assert!(filter
            .internal_private_exceptions
            .contains("unused-state-variables"));
        assert!(filter.admin_exceptions.contains("centralization-risk"));
    }

    #[test]
    fn test_is_admin_suppressible() {
        let filter = FpFilter::new();
        assert!(filter.is_admin_suppressible("dos-unbounded-operation"));
        assert!(filter.is_admin_suppressible("front-running-mitigation"));
        assert!(filter.is_admin_suppressible("mev-extractable-value"));
        assert!(filter.is_admin_suppressible("sandwich-conditional-swap"));
        assert!(!filter.is_admin_suppressible("classic-reentrancy"));
        assert!(!filter.is_admin_suppressible("vault-share-inflation"));
    }

    #[test]
    fn test_is_proxy_detector() {
        let filter = FpFilter::new();
        assert!(filter.is_proxy_detector("proxy-storage-collision"));
        assert!(filter.is_proxy_detector("fallback-delegatecall-unprotected"));
        assert!(filter.is_proxy_detector("diamond-storage-collision"));
        assert!(!filter.is_proxy_detector("classic-reentrancy"));
    }

    #[test]
    fn test_is_code_quality_detector() {
        let filter = FpFilter::new();
        assert!(filter.is_code_quality_detector("floating-pragma"));
        assert!(filter.is_code_quality_detector("deprecated-functions"));
        assert!(filter.is_code_quality_detector("shadowing-variables"));
        assert!(!filter.is_code_quality_detector("classic-reentrancy"));
    }

    #[test]
    fn test_filter_interface_contract() {
        use crate::types::test_utils::create_test_context;

        // Create context - we'll test the interface filtering by checking the contract type
        let filter = FpFilter::new();
        let findings = vec![
            make_finding("classic-reentrancy", 5),
            make_finding("missing-access-control", 10),
        ];

        // For a regular contract, findings should pass through (no function match = conservative)
        let ctx = create_test_context("contract Test { }");
        let result = filter.filter(findings.clone(), &ctx);
        // Without function enclosure match, findings pass through
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_admin_modifier_detection() {
        let filter = FpFilter::new();
        // Test that the static data is sensible
        assert!(ADMIN_MODIFIERS.contains(&"onlyOwner"));
        assert!(ADMIN_MODIFIERS.contains(&"onlyRole"));
        assert!(ADMIN_MODIFIERS.contains(&"whenNotPaused"));
        assert_eq!(filter.admin_exceptions.len(), 4);
    }
}
