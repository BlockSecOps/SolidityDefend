//! Role Hierarchy Bypass Detector
//!
//! Detects role hierarchy violations in OpenZeppelin AccessControl systems where
//! lower privilege roles can execute admin functions. This was the cause of the
//! KiloEx DEX $7M loss in 2024.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct RoleHierarchyBypassDetector {
    base: BaseDetector,
}

impl RoleHierarchyBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("role-hierarchy-bypass".to_string()),
                "Role Hierarchy Bypass".to_string(),
                "Detects role hierarchy violations where lower privilege roles can execute admin functions".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Default for RoleHierarchyBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RoleHierarchyBypassDetector {
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

        let lower = ctx.source_code.to_lowercase();

        // Check for OpenZeppelin AccessControl usage
        let uses_access_control = lower.contains("accesscontrol")
            || lower.contains("hasrole")
            || lower.contains("grantrole")
            || lower.contains("revokerole");

        if !uses_access_control {
            return Ok(findings);
        }

        // Pattern 1: Role grant without DEFAULT_ADMIN_ROLE check
        let has_grant_role = lower.contains("grantrole") || lower.contains("_grantrole");
        if has_grant_role {
            let has_admin_check = lower.contains("default_admin_role")
                || lower.contains("onlyrole(0x00)")
                || lower.contains("require(_msgSender() == owner");

            if !has_admin_check {
                let finding = self.base.create_finding(
                    ctx,
                    "grantRole function lacks DEFAULT_ADMIN_ROLE check - lower privilege roles may grant roles".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add onlyRole(DEFAULT_ADMIN_ROLE) modifier to grantRole function or use OpenZeppelin's AccessControl directly".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Multiple roles with overlapping admin privileges
        let role_count = lower.matches("bytes32 public constant").count();
        if role_count > 1 {
            let has_role_admin = lower.contains("_setRoleAdmin") || lower.contains("getroleadmin");
            if !has_role_admin {
                let finding = self.base.create_finding(
                    ctx,
                    "Multiple roles defined without explicit role admin hierarchy - may lead to privilege confusion".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use _setRoleAdmin to establish clear role hierarchy where admin roles control lower privilege roles".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Role-protected functions without hierarchy validation
        let has_only_role = lower.contains("onlyrole(");
        let has_require_role = lower.contains("require(hasrole(");

        if (has_only_role || has_require_role) && role_count > 2 {
            // Check if there are critical functions (upgrade, pause, withdraw) accessible by non-admin roles
            let has_critical_functions = lower.contains("function upgradeto")
                || lower.contains("function pause")
                || lower.contains("function withdraw")
                || lower.contains("function transferownership");

            if has_critical_functions {
                let finding = self.base.create_finding(
                    ctx,
                    "Critical functions may be accessible by non-admin roles - verify role hierarchy is correctly enforced".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Ensure critical functions like upgradeTo, pause, withdraw use DEFAULT_ADMIN_ROLE or highest privilege role".to_string()
                );

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
