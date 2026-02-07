//! Guardian Role Centralization Detector
//!
//! Detects guardian/emergency roles with excessive power that create single points
//! of failure and rug pull risks. Emergency powers should be limited in scope
//! and subject to multisig or DAO control.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct GuardianRoleCentralizationDetector {
    base: BaseDetector,
}

impl GuardianRoleCentralizationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("guardian-role-centralization".to_string()),
                "Guardian Role Centralization".to_string(),
                "Detects guardian/emergency roles with excessive power creating centralization risks".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }
}

impl Default for GuardianRoleCentralizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for GuardianRoleCentralizationDetector {
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
        let source = ctx.source_code.as_str();

        // CRITICAL FP FIX: Check for actual guardian role definitions, not just keywords
        // A contract with emergencyWithdraw() does NOT have a "guardian role"
        // We need to check for explicit guardian role infrastructure:
        // - State variable: address public guardian, address guardian
        // - Role constant: GUARDIAN_ROLE
        // - Modifier: onlyGuardian, modifier guardian
        // - Function for setting guardian: setGuardian, updateGuardian

        let has_guardian_state = lower.contains("address guardian")
            || lower.contains("address public guardian")
            || lower.contains("address private guardian")
            || source.contains("GUARDIAN_ROLE")
            || lower.contains("bytes32 guardian");

        let has_guardian_modifier = lower.contains("onlyguardian")
            || lower.contains("modifier guardian")
            || (lower.contains("only") && lower.contains("guardian") && lower.contains("modifier"));

        let has_guardian_setter = lower.contains("function setguardian")
            || lower.contains("function updateguardian")
            || lower.contains("function changeguardian");

        // Must have actual guardian infrastructure (state var + modifier or setter)
        let has_actual_guardian_role =
            has_guardian_state && (has_guardian_modifier || has_guardian_setter);

        // Similarly check for keeper role (actual infrastructure, not just keywords)
        let has_keeper_state = lower.contains("address keeper")
            || lower.contains("address public keeper")
            || source.contains("KEEPER_ROLE");

        let has_keeper_modifier = lower.contains("onlykeeper") || lower.contains("modifier keeper");

        let has_actual_keeper_role = has_keeper_state && has_keeper_modifier;

        // Skip if no actual guardian/keeper role infrastructure
        if !has_actual_guardian_role && !has_actual_keeper_role {
            return Ok(findings);
        }

        // Pattern 1: Guardian can pause without timelock or multisig
        let has_pause = lower.contains("function pause")
            || lower.contains("function emergencypause")
            || lower.contains("function shutdown");

        if has_pause && (has_actual_guardian_role || has_actual_keeper_role) {
            let has_multisig_protection = lower.contains("multisig")
                || lower.contains("threshold")
                || lower.contains("requiresignatures")
                || lower.contains("gnosis");

            let has_timelock =
                lower.contains("timelock") || lower.contains("delay") || lower.contains("schedule");

            if !has_multisig_protection && !has_timelock {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian/emergency role can pause system without multisig or timelock - single point of failure".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require multisig approval or implement delay mechanism for emergency pause actions".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Guardian can withdraw funds
        let has_withdrawal = lower.contains("function withdraw")
            || lower.contains("function emergencywithdraw")
            || lower.contains("function rescue");

        if has_withdrawal && (has_actual_guardian_role || has_actual_keeper_role) {
            // Check if guardian modifier is used with withdrawal
            let guardian_withdraw_patterns = ["onlyguardian", "onlyemergency", "onlykeeper"];

            let guardian_can_withdraw = guardian_withdraw_patterns
                .iter()
                .any(|pattern| lower.contains(pattern));

            if guardian_can_withdraw {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian role has direct withdrawal access - creates rug pull risk without DAO/multisig control".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Emergency withdrawals should route to DAO treasury or require multisig, not go directly to guardian".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Guardian role assigned to EOA instead of multisig
        let has_guardian_assignment = lower.contains("guardian =")
            || lower.contains("_guardian =")
            || lower.contains("setguardian");

        if has_guardian_assignment {
            let has_multisig_mention = lower.contains("multisig")
                || lower.contains("gnosissafe")
                || lower.contains("timelock");

            if !has_multisig_mention {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian role assignment without mention of multisig/DAO - likely controlled by single EOA".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Assign guardian role to multisig contract (e.g., Gnosis Safe) rather than EOA".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Guardian can upgrade contracts
        let has_upgrade = lower.contains("function upgradeto")
            || lower.contains("function upgradeimplementation")
            || lower.contains("_upgradeto");

        if has_upgrade && (has_actual_guardian_role || has_actual_keeper_role) {
            // Check if guardian has upgrade powers
            let can_upgrade = lower.contains("onlyguardian")
                && (lower.contains("upgradeto") || lower.contains("upgrade"));

            if can_upgrade {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian role can upgrade contracts - bypasses normal governance for critical changes".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Upgrades should require DAO vote or admin multisig, not emergency guardian role".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Too many functions accessible by guardian
        let guardian_function_count = lower.matches("onlyguardian").count()
            + lower.matches("onlyemergency").count()
            + lower.matches("onlykeeper").count();

        if guardian_function_count > 3 {
            let finding = self.base.create_finding(
                ctx,
                format!(
                    "Guardian role has access to {} functions - excessive power concentration",
                    guardian_function_count
                ),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Limit guardian role to truly emergency functions only (pause/unpause), separate other admin functions to DAO".to_string()
            );

            findings.push(finding);
        }

        // Pattern 6: Guardian without revocation mechanism
        if (has_actual_guardian_role || has_actual_keeper_role) {
            let has_revoke = lower.contains("revokeguardian")
                || lower.contains("removeguardian")
                || lower.contains("revokerole");

            if !has_revoke {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian role lacks explicit revocation mechanism - may be irremovable if compromised".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement guardian revocation function callable by DAO/owner for emergency scenarios".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 7: Guardian without time-bound powers
        if (has_actual_guardian_role || has_actual_keeper_role) {
            let has_time_limit = lower.contains("guardianexpiry")
                || lower.contains("validuntil")
                || lower.contains("expirationtime");

            let has_permanent_guardian = has_guardian_assignment && !has_time_limit;

            if has_permanent_guardian {
                let finding = self.base.create_finding(
                    ctx,
                    "Guardian role has no expiration time - permanent emergency powers create long-term centralization".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Consider time-bound guardian powers that expire and require DAO renewal".to_string()
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
