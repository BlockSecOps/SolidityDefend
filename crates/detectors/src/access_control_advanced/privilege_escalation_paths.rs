//! Privilege Escalation Paths Detector
//!
//! Detects indirect paths to gain higher privileges through function chains,
//! delegatecall vulnerabilities, and role manipulation sequences.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct PrivilegeEscalationPathsDetector {
    base: BaseDetector,
}

impl PrivilegeEscalationPathsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("privilege-escalation-paths".to_string()),
                "Privilege Escalation Paths".to_string(),
                "Detects indirect paths to gain higher privileges through function chains"
                    .to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Default for PrivilegeEscalationPathsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PrivilegeEscalationPathsDetector {
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

        // Check for role-based access control systems
        let uses_roles =
            lower.contains("hasrole") || lower.contains("onlyrole") || lower.contains("grantrole");

        if !uses_roles {
            return Ok(findings);
        }

        // Pattern 1: Public/external functions that call grantRole without proper checks
        let has_grant_role = lower.contains("grantrole");
        let has_public_grant_wrapper = (lower.contains("function add")
            && lower.contains("grantrole"))
            || (lower.contains("function register") && lower.contains("grantrole"))
            || (lower.contains("function setup") && lower.contains("grantrole"));

        if has_grant_role && has_public_grant_wrapper {
            let has_proper_protection = lower.contains("onlyowner")
                || lower.contains("onlyrole(default_admin_role)")
                || lower.contains("require(msg.sender == owner");

            if !has_proper_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Function wrapping grantRole may lack sufficient access control - indirect privilege escalation possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Ensure all functions that call grantRole are protected with onlyRole(DEFAULT_ADMIN_ROLE) or equivalent".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Delegatecall in privileged functions
        let has_delegatecall = lower.contains("delegatecall") || lower.contains(".delegatecall");
        let has_privileged_functions = lower.contains("onlyowner")
            || lower.contains("onlyrole")
            || lower.contains("onlyadmin");

        if has_delegatecall && has_privileged_functions {
            let has_target_validation = lower.contains("require(istrusted")
                || lower.contains("whitelist")
                || lower.contains("allowedtargets");

            if !has_target_validation {
                let finding = self.base.create_finding(
                    ctx,
                    "Delegatecall in privileged context without target validation - attacker could escalate privileges".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add strict whitelist validation for delegatecall targets in privileged functions".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Functions that modify access control state without proper guards
        let has_state_modification = lower.contains("_setuprole")
            || lower.contains("_grantrole")
            || lower.contains("_setroleadmin");

        if has_state_modification {
            // Check if these internal functions are called from public/external functions
            let has_public_entry = lower.contains("function initialize")
                || lower.contains("function setup")
                || lower.contains("function configure");

            if has_public_entry {
                let has_initializer_guard = lower.contains("initializer")
                    || lower.contains("onlyonce")
                    || lower.contains("require(!initialized");

                if !has_initializer_guard {
                    let finding = self.base.create_finding(
                        ctx,
                        "Setup/initialization functions modify roles without proper guards - may be callable multiple times".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Add initializer modifier or initialization check to prevent re-initialization attacks".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 4: Role transfer without two-step process
        let has_owner_transfer = lower.contains("transferownership")
            || lower.contains("changeowner")
            || lower.contains("setowner");

        if has_owner_transfer {
            let has_two_step = lower.contains("acceptownership")
                || lower.contains("claimownership")
                || lower.contains("pendingowner");

            if !has_two_step {
                let finding = self.base.create_finding(
                    ctx,
                    "Ownership/role transfer lacks two-step process - single transaction can grant complete control".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement two-step ownership transfer: propose→accept pattern to prevent accidental privilege loss".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Functions that combine multiple privilege operations
        let role_count = lower.matches("grantrole").count();
        if role_count > 1 {
            // Check if multiple grantRole calls happen in single function
            let lines: Vec<&str> = ctx.source_code.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("grantrole") {
                    // Look ahead for more grantRole in nearby lines
                    let mut nearby_grants = 0;
                    for j in (i.saturating_sub(5))..=(i + 5).min(lines.len() - 1) {
                        if lines[j].to_lowercase().contains("grantrole") {
                            nearby_grants += 1;
                        }
                    }

                    if nearby_grants > 1 {
                        let finding = self.base.create_finding(
                            ctx,
                            "Multiple role grants in single function - creates atomic privilege escalation path".to_string(),
                            (i + 1) as u32,
                            1,
                            line.len() as u32,
                        )
                        .with_fix_suggestion(
                            "Consider separating role grants into individual timelock-controlled operations".to_string()
                        );

                        findings.push(finding);
                        break; // Only report once
                    }
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
