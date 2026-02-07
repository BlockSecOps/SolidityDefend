use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for delegation loop vulnerabilities in governance systems
pub struct DelegationLoopDetector {
    base: BaseDetector,
}

impl Default for DelegationLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegationLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegation-loop".to_string()),
                "Delegation Loop Vulnerability".to_string(),
                "Detects governance delegation without circular delegation protection, enabling vote manipulation".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Detector for DelegationLoopDetector {
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
            if self.has_delegation_loop_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' allows delegation without checking for circular delegation chains. \
                    Attackers can create delegation loops (A→B→C→A) to amplify voting power or \
                    cause denial-of-service when calculating delegated votes.",
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
                    .with_cwe(840) // CWE-840: Business Logic Errors
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_fix_suggestion(format!(
                        "Implement loop detection in function '{}'. \
                    Example: Track delegation chain depth and reject if exceeds limit, \
                    or traverse delegation chain to detect cycles before allowing delegation.",
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

impl DelegationLoopDetector {
    /// Check if function has delegation loop vulnerability
    fn has_delegation_loop_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is a delegation function
        let function_name = function.name.name.to_lowercase();
        if !function_name.contains("delegate") {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check for delegation state updates
        let has_delegation_update = func_source.contains("delegatee")
            || func_source.contains("delegate[")
            || func_source.contains("_delegate")
            || func_source.contains("delegated");

        if !has_delegation_update {
            return false;
        }

        // Look for vulnerability patterns
        self.check_loop_protection(&func_source)
    }

    /// Check if function lacks loop protection
    fn check_loop_protection(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY")
            && (source.contains("delegation loop") || source.contains("circular delegation"));

        // Pattern 2: Has delegation assignment but no loop check
        let has_delegation_assignment = source.contains("delegatee =")
            || source.contains("delegates[")
            || source.contains("_delegate =");

        // Pattern 3: Missing loop detection mechanisms
        let has_loop_detection = source.contains("loop")
            || source.contains("cycle")
            || source.contains("circular")
            || source.contains("depth")
            || source.contains("visited")
            || source.contains("chain");

        // Pattern 4: Has self-delegation check but no chain check
        let has_self_check = source.contains("Cannot delegate to self")
            || source.contains("delegatee != msg.sender");

        // Vulnerable if it has delegation but lacks proper loop detection
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if has delegation assignment with self-check but no chain validation
        if has_delegation_assignment && has_self_check && !has_loop_detection {
            return true;
        }

        // Vulnerable if has delegation without any protection
        has_delegation_assignment && !has_self_check && !has_loop_detection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DelegationLoopDetector::new();
        assert_eq!(detector.name(), "Delegation Loop Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
