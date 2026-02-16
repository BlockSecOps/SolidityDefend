//! Account Abstraction Social Recovery Attacks Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct SocialRecoveryDetector {
    base: BaseDetector,
}

impl SocialRecoveryDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-social-recovery".to_string()),
                "Social Recovery Attacks".to_string(),
                "Detects insufficient guardian thresholds, missing timelock delays, and recovery manipulation risks".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Extract source code for just this contract (not the whole file).
    fn get_contract_source<'a>(&self, ctx: &'a AnalysisContext) -> &'a str {
        let source = &ctx.source_code;
        let start = ctx.contract.location.start().offset();
        let end = ctx.contract.location.end().offset();
        if end <= start || start >= source.len() {
            return "";
        }
        &source[start..end.min(source.len())]
    }

    /// Determine if this specific contract (not the whole file) is a social recovery contract.
    fn is_social_recovery_contract(&self, ctx: &AnalysisContext) -> bool {
        let contract_name = ctx.contract.name.name.to_lowercase();
        let contract_source = self.get_contract_source(ctx).to_lowercase();

        // Skip paymaster contracts -- they handle gas payment, not account recovery
        if contract_name.contains("paymaster")
            || ctx
                .get_functions()
                .iter()
                .any(|f| f.name.name == "validatePaymasterUserOp")
        {
            return false;
        }

        // Skip nonce managers, session key contracts, signature aggregators, etc.
        if contract_name.contains("nonce")
            || contract_name.contains("sessionkey")
            || contract_name.contains("aggregator")
            || contract_name.contains("delegation")
            || contract_name.contains("hardware")
        {
            return false;
        }

        // The contract must have social-recovery-specific patterns in ITS OWN source
        let has_guardian = contract_source.contains("guardian");
        let has_recovery_func = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("recovery") || name.contains("recover")
        });
        let has_add_guardian = ctx
            .get_functions()
            .iter()
            .any(|f| f.name.name.to_lowercase().contains("addguardian"));

        // Must have guardian concept AND recovery functions in this contract
        has_guardian && (has_recovery_func || has_add_guardian)
    }

    /// Check if this contract has comprehensive social recovery protections.
    fn has_secure_social_recovery(&self, ctx: &AnalysisContext) -> bool {
        let contract_source = self.get_contract_source(ctx);
        let contract_lower = contract_source.to_lowercase();

        // Check for timelock protection
        let has_timelock = contract_source.contains("RECOVERY_TIMELOCK")
            || contract_source.contains("RECOVERY_DELAY")
            || (contract_lower.contains("timelock") && contract_lower.contains("timestamp"));

        // Check for guardian threshold enforcement
        let has_threshold = contract_lower.contains("threshold")
            && (contract_lower.contains(">=") || contract_lower.contains(">"));

        // Check for guardian validation (isGuardian check or guardian mapping + require)
        let has_guardian_validation = contract_lower.contains("isguardian")
            || (contract_lower.contains("guardian") && contract_lower.contains("require"));

        // Check for approval tracking
        let has_approval_tracking =
            contract_lower.contains("approval") || contract_lower.contains("approvalcount");

        // Check for executed flag (replay protection)
        let has_executed_flag =
            contract_lower.contains("executed") && contract_lower.contains("bool");

        // Check for minimum guardian count
        let has_min_guardians = contract_source.contains("MIN_GUARDIANS")
            || (contract_lower.contains("minimum") && contract_lower.contains("guardian"));

        // Secure if it has timelock + threshold + guardian validation
        if has_timelock && has_threshold && has_guardian_validation {
            return true;
        }

        // Secure if it has comprehensive protections (timelock + min guardians + approval tracking + executed flag)
        if has_timelock && has_min_guardians && has_approval_tracking && has_executed_flag {
            return true;
        }

        false
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let contract_source = self.get_contract_source(ctx);
        let contract_lower = contract_source.to_lowercase();

        // Check recovery execution functions
        if name.contains("recover") || name.contains("executerecovery") {
            // Check for insufficient threshold
            let has_threshold = contract_lower.contains("threshold")
                && (contract_lower.contains(">=") || contract_lower.contains(">"));
            let has_quorum = contract_lower.contains("quorum");
            let has_count_check = contract_lower.contains("count") && contract_lower.contains(">=");

            if !has_threshold && !has_quorum && !has_count_check {
                issues.push((
                    "No guardian threshold validation (single guardian can recover)".to_string(),
                    Severity::Critical,
                    "Add threshold: require(approvalCount >= threshold, \"Insufficient approvals\"); // threshold should be > 50%".to_string()
                ));
            }

            // Check for missing timelock delay
            let has_timelock = (contract_lower.contains("timelock")
                || contract_lower.contains("delay"))
                && contract_lower.contains("timestamp");
            let has_recovery_period = contract_lower.contains("recoveryperiod")
                || contract_lower.contains("waitingperiod");

            if !has_timelock && !has_recovery_period {
                issues.push((
                    "No timelock delay for recovery (instant takeover)".to_string(),
                    Severity::High,
                    "Add timelock: require(block.timestamp >= recoveryInitiated + RECOVERY_DELAY, \"Timelock active\");".to_string()
                ));
            }

            // Check for owner cancellation mechanism
            let has_cancel =
                contract_lower.contains("cancel") && contract_lower.contains("recovery");
            let has_veto = contract_lower.contains("veto");

            if !has_cancel && !has_veto {
                issues.push((
                    "No owner veto mechanism for ongoing recovery".to_string(),
                    Severity::Medium,
                    "Add veto: function cancelRecovery() external { require(msg.sender == owner, \"Only owner\"); delete pendingRecovery; }".to_string()
                ));
            }

            // Check for guardian validation
            let has_guardian_check = contract_lower.contains("isguardian")
                || (contract_lower.contains("guardian") && contract_lower.contains("mapping"));

            if !has_guardian_check {
                issues.push((
                    "No guardian validation (anyone can participate in recovery)".to_string(),
                    Severity::Critical,
                    "Validate guardians: require(isGuardian[msg.sender], \"Not a guardian\");"
                        .to_string(),
                ));
            }

            // Check for replay protection
            let has_nonce =
                contract_lower.contains("nonce") || contract_lower.contains("recoveryid");

            if !has_nonce {
                issues.push((
                    "No replay protection in recovery process".to_string(),
                    Severity::High,
                    "Add nonce: require(recoveryNonce == expectedNonce, \"Invalid nonce\"); recoveryNonce++;".to_string()
                ));
            }
        }

        // Check guardian addition/removal functions
        if name.contains("addguardian") || name.contains("removeguardian") {
            // Check for owner-only access
            let has_owner_check = contract_lower.contains("owner")
                && (contract_lower.contains("require") || contract_lower.contains("onlyowner"));

            if !has_owner_check {
                issues.push((
                    "Anyone can add/remove guardians (no access control)".to_string(),
                    Severity::Critical,
                    "Add access control: require(msg.sender == owner, \"Only owner can manage guardians\");".to_string()
                ));
            }

            // Check for minimum guardian count
            let has_min_count = contract_lower.contains("min")
                && (contract_lower.contains("guardian") || contract_lower.contains("count"));

            if name.contains("remove") && !has_min_count {
                issues.push((
                    "No minimum guardian count enforcement".to_string(),
                    Severity::Medium,
                    "Enforce minimum: require(guardianCount - 1 >= MIN_GUARDIANS, \"Cannot go below minimum\");".to_string()
                ));
            }

            // Check for duplicate guardian prevention
            let has_duplicate_check = contract_lower.contains("!isguardian")
                || contract_lower.contains("require(!guardian");

            if name.contains("add") && !has_duplicate_check {
                issues.push((
                    "No duplicate guardian prevention".to_string(),
                    Severity::Low,
                    "Prevent duplicates: require(!isGuardian[guardian], \"Already a guardian\");"
                        .to_string(),
                ));
            }
        }

        // Check recovery initiation
        if name.contains("initiate") && name.contains("recovery") {
            // Check for rate limiting
            let has_rate_limit = contract_lower.contains("lastrecovery")
                || (contract_lower.contains("timestamp") && contract_lower.contains("cooldown"));

            if !has_rate_limit {
                issues.push((
                    "No rate limiting on recovery attempts (spam risk)".to_string(),
                    Severity::Medium,
                    "Add cooldown: require(block.timestamp >= lastRecoveryAttempt + COOLDOWN_PERIOD, \"Cooldown active\");".to_string()
                ));
            }

            // Check for notification/event emission
            let has_event = contract_lower.contains("emit") && contract_lower.contains("recovery");

            if !has_event {
                issues.push((
                    "No event emission for recovery initiation (owner not notified)".to_string(),
                    Severity::Medium,
                    "Emit event: emit RecoveryInitiated(newOwner, block.timestamp + RECOVERY_DELAY);".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for SocialRecoveryDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SocialRecoveryDetector {
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

        // Step 1: Check if this specific contract is a social recovery contract
        if !self.is_social_recovery_contract(ctx) {
            return Ok(findings);
        }

        // Step 2: Check if this contract already has comprehensive protections (secure version)
        if self.has_secure_social_recovery(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Consolidate all per-function issues into 1 finding per contract
        let mut all_issues: Vec<(String, Severity, String)> = Vec::new();
        let mut first_line: u32 = 1;

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                if first_line == 1 {
                    first_line = function.name.location.start().line() as u32;
                }
                all_issues.push((
                    format!("{} in '{}'", message, function.name.name),
                    severity,
                    remediation,
                ));
            }
        }

        if !all_issues.is_empty() {
            let max_severity = all_issues
                .iter()
                .map(|(_, s, _)| *s)
                .max()
                .unwrap_or(Severity::Medium);
            let issue_titles: Vec<&str> = all_issues.iter().map(|(t, _, _)| t.as_str()).collect();
            let consolidated_msg = format!(
                "Social recovery contract '{}' has {} issues: {}",
                ctx.contract.name.name,
                all_issues.len(),
                issue_titles.join("; ")
            );
            let remediations: Vec<&str> = all_issues.iter().map(|(_, _, r)| r.as_str()).collect();
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    consolidated_msg,
                    first_line,
                    0,
                    20,
                    max_severity,
                )
                .with_cwe(287)
                .with_cwe(285)
                .with_fix_suggestion(remediations.join("\n\n"));
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
