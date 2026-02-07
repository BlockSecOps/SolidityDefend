use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for SWC-106: Unprotected SELFDESTRUCT Instruction
///
/// Detects selfdestruct/suicide operations that lack proper access control,
/// allowing anyone to destroy the contract and steal remaining Ether.
///
/// Vulnerable patterns:
/// - Public/external functions with selfdestruct without access control
/// - Selfdestruct with user-controlled beneficiary address
/// - Missing ownership checks before contract destruction
pub struct UnprotectedSelfdestructDetector {
    base: BaseDetector,
}

impl Default for UnprotectedSelfdestructDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedSelfdestructDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("swc106-unprotected-selfdestruct"),
                "Unprotected SELFDESTRUCT (SWC-106)".to_string(),
                "Detects selfdestruct operations without proper access control, \
                 allowing unauthorized contract destruction and fund theft"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if function contains selfdestruct
    fn has_selfdestruct(&self, source: &str) -> bool {
        source.contains("selfdestruct(") || source.contains("suicide(")
    }

    /// Check if function has access control
    fn has_access_control(&self, function: &ast::Function<'_>, source: &str) -> bool {
        // Check for access control modifiers
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("restricted")
                || modifier_name.contains("admin")
                || modifier_name.contains("owner")
                || modifier_name.contains("governance")
            {
                return true;
            }
        }

        // Check for inline access control patterns
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender==")
            || source.contains("require(_msgSender() ==")
            || source.contains("if (msg.sender !=")
            || source.contains("require(owner ==")
            || source.contains("_checkOwner()")
            || source.contains("hasRole(")
            || source.contains("_checkRole(")
    }

    /// Check if selfdestruct has user-controlled beneficiary
    fn has_user_controlled_beneficiary(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check if any function parameter is used as selfdestruct beneficiary
        for param in &function.parameters {
            if let Some(param_name) = &param.name {
                let param_name_str = &param_name.name;

                // Check if parameter type suggests an address
                let type_str = format!("{:?}", param.type_name);
                let is_address_param = type_str.contains("address") || type_str.contains("Address");

                if is_address_param {
                    // Check if this parameter is used in selfdestruct
                    if source.contains(&format!("selfdestruct({})", param_name_str))
                        || source.contains(&format!("selfdestruct(payable({}))", param_name_str))
                        || source.contains(&format!("suicide({})", param_name_str))
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if selfdestruct has time-lock or governance protection
    fn has_timelock_or_governance(&self, source: &str) -> bool {
        source.contains("timelock")
            || source.contains("delay")
            || source.contains("proposedAt")
            || source.contains("governance")
            || source.contains("multisig")
            || source.contains("vote")
            || source.contains("proposal")
    }

    /// Check for inline access control patterns only (for testing)
    #[cfg(test)]
    fn has_access_control_inline(&self, source: &str) -> bool {
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender==")
            || source.contains("require(_msgSender() ==")
            || source.contains("if (msg.sender !=")
            || source.contains("require(owner ==")
            || source.contains("_checkOwner()")
            || source.contains("hasRole(")
            || source.contains("_checkRole(")
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        // Include lines before to catch modifiers
        let extended_start = start.saturating_sub(3);

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if extended_start < source_lines.len() && end < source_lines.len() {
            source_lines[extended_start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Detector for UnprotectedSelfdestructDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        for function in ctx.get_functions() {
            let func_source = self.get_function_source(function, ctx);

            // Only check functions that contain selfdestruct
            if !self.has_selfdestruct(&func_source) {
                continue;
            }

            // Check visibility - internal/private are lower risk but still flag them
            let is_public = function.visibility == ast::Visibility::Public
                || function.visibility == ast::Visibility::External;

            // Check for access control
            let has_access_control = self.has_access_control(function, &func_source);

            // Check for user-controlled beneficiary
            let has_user_controlled = self.has_user_controlled_beneficiary(&func_source, function);

            // Check for timelock/governance
            let has_timelock = self.has_timelock_or_governance(&func_source);

            // Determine severity and confidence based on patterns
            let (severity, confidence, issue_type) = if is_public && !has_access_control {
                (
                    Severity::Critical,
                    Confidence::High,
                    "publicly accessible without access control",
                )
            } else if has_user_controlled && !has_access_control {
                (
                    Severity::Critical,
                    Confidence::High,
                    "has user-controlled beneficiary without authorization",
                )
            } else if is_public && has_access_control && !has_timelock {
                (
                    Severity::Medium,
                    Confidence::Medium,
                    "lacks timelock protection for immediate destruction",
                )
            } else if !is_public && !has_access_control {
                (
                    Severity::Medium,
                    Confidence::Low,
                    "internal function lacks access control (could be called by public function)",
                )
            } else {
                continue; // Well-protected selfdestruct
            };

            let message = format!(
                "Function '{}' contains selfdestruct that {}. \
                 Selfdestruct permanently destroys the contract and sends all remaining \
                 Ether to the specified address, bypassing any fallback functions.",
                function.name.name, issue_type
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
                .with_swc("SWC-106")
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_confidence(confidence)
                .with_fix_suggestion(format!(
                    "Protect selfdestruct in '{}' with:\n\
                     1. Add 'onlyOwner' modifier or equivalent access control\n\
                     2. Implement a timelock (e.g., 48-hour delay) before destruction\n\
                     3. Consider using upgradeable proxy patterns instead of selfdestruct\n\
                     4. If selfdestruct is necessary, hardcode a safe beneficiary address\n\
                     Note: After EIP-6780 (Cancun), selfdestruct only destroys in same transaction as creation",
                    function.name.name
                ));

            // Override severity if needed
            let mut finding = finding;
            if severity != self.base.default_severity {
                finding.severity = severity;
            }

            findings.push(finding);
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
    fn test_detector_properties() {
        let detector = UnprotectedSelfdestructDetector::new();
        assert_eq!(detector.name(), "Unprotected SELFDESTRUCT (SWC-106)");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_has_selfdestruct() {
        let detector = UnprotectedSelfdestructDetector::new();
        assert!(detector.has_selfdestruct("selfdestruct(owner)"));
        assert!(detector.has_selfdestruct("selfdestruct(payable(msg.sender))"));
        assert!(detector.has_selfdestruct("suicide(owner)")); // Old syntax
        assert!(!detector.has_selfdestruct("transfer(owner)"));
    }

    #[test]
    fn test_access_control_patterns() {
        let detector = UnprotectedSelfdestructDetector::new();

        // Test inline access control detection
        assert!(detector.has_access_control_inline("require(msg.sender == owner)"));
        assert!(detector.has_access_control_inline("_checkOwner()"));
        assert!(detector.has_access_control_inline("hasRole(ADMIN_ROLE, msg.sender)"));
        assert!(!detector.has_access_control_inline("selfdestruct(owner)"));
    }
}
