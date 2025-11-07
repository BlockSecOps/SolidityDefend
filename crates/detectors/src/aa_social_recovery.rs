//! Account Abstraction Social Recovery Attacks Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::access_control_patterns;
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

    fn is_social_recovery_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("guardian") || source.contains("recovery"))
            && (source.contains("recover") || source.contains("addguardian"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check recovery execution functions
        if name.contains("recover") || name.contains("executerecovery") {
            // Check for insufficient threshold
            let has_threshold = source_lower.contains("threshold")
                && (source_lower.contains(">=") || source_lower.contains(">"));
            let has_quorum = source_lower.contains("quorum");
            let has_count_check = source_lower.contains("count") && source_lower.contains(">=");

            if !has_threshold && !has_quorum && !has_count_check {
                issues.push((
                    "No guardian threshold validation (single guardian can recover)".to_string(),
                    Severity::Critical,
                    "Add threshold: require(approvalCount >= threshold, \"Insufficient approvals\"); // threshold should be > 50%".to_string()
                ));
            }

            // Check for missing timelock delay
            let has_timelock = (source_lower.contains("timelock")
                || source_lower.contains("delay"))
                && source_lower.contains("timestamp");
            let has_recovery_period =
                source_lower.contains("recoveryperiod") || source_lower.contains("waitingperiod");

            if !has_timelock && !has_recovery_period {
                issues.push((
                    "No timelock delay for recovery (instant takeover)".to_string(),
                    Severity::High,
                    "Add timelock: require(block.timestamp >= recoveryInitiated + RECOVERY_DELAY, \"Timelock active\");".to_string()
                ));
            }

            // Check for owner cancellation mechanism
            let has_cancel = source_lower.contains("cancel") && source_lower.contains("recovery");
            let has_veto = source_lower.contains("veto");

            if !has_cancel && !has_veto {
                issues.push((
                    "No owner veto mechanism for ongoing recovery".to_string(),
                    Severity::Medium,
                    "Add veto: function cancelRecovery() external { require(msg.sender == owner, \"Only owner\"); delete pendingRecovery; }".to_string()
                ));
            }

            // Check for guardian validation
            let has_guardian_check = source_lower.contains("isguardian")
                || (source_lower.contains("guardian") && source_lower.contains("mapping"));

            if !has_guardian_check {
                issues.push((
                    "No guardian validation (anyone can participate in recovery)".to_string(),
                    Severity::Critical,
                    "Validate guardians: require(isGuardian[msg.sender], \"Not a guardian\");"
                        .to_string(),
                ));
            }

            // Check for replay protection
            let has_nonce = source_lower.contains("nonce") || source_lower.contains("recoveryid");

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
            let has_owner_check = source_lower.contains("owner")
                && (source_lower.contains("require") || source_lower.contains("onlyowner"));

            if !has_owner_check {
                issues.push((
                    "Anyone can add/remove guardians (no access control)".to_string(),
                    Severity::Critical,
                    "Add access control: require(msg.sender == owner, \"Only owner can manage guardians\");".to_string()
                ));
            }

            // Check for minimum guardian count
            let has_min_count = source_lower.contains("min")
                && (source_lower.contains("guardian") || source_lower.contains("count"));

            if name.contains("remove") && !has_min_count {
                issues.push((
                    "No minimum guardian count enforcement".to_string(),
                    Severity::Medium,
                    "Enforce minimum: require(guardianCount - 1 >= MIN_GUARDIANS, \"Cannot go below minimum\");".to_string()
                ));
            }

            // Check for duplicate guardian prevention
            let has_duplicate_check =
                source_lower.contains("!isguardian") || source_lower.contains("require(!guardian");

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
            let has_rate_limit = source_lower.contains("lastrecovery")
                || (source_lower.contains("timestamp") && source_lower.contains("cooldown"));

            if !has_rate_limit {
                issues.push((
                    "No rate limiting on recovery attempts (spam risk)".to_string(),
                    Severity::Medium,
                    "Add cooldown: require(block.timestamp >= lastRecoveryAttempt + COOLDOWN_PERIOD, \"Cooldown active\");".to_string()
                ));
            }

            // Check for notification/event emission
            let has_event = source_lower.contains("emit") && source_lower.contains("recovery");

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

        if !self.is_social_recovery_contract(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection for comprehensive social recovery

        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check for comprehensive social recovery protection
        let has_recovery_timelock =
            source.contains("RECOVERY_TIMELOCK") || source.contains("RECOVERY_DELAY");
        let has_min_guardians = source.contains("MIN_GUARDIANS")
            || source_lower.contains("minimum") && source_lower.contains("guardian");
        let has_threshold = source_lower.contains("threshold") && source_lower.contains(">=");
        let has_approval_tracking =
            source_lower.contains("approval") || source_lower.contains("approvalcount");
        let has_executed_flag = source_lower.contains("executed") && source_lower.contains("bool");

        // If contract has comprehensive social recovery protections, return early
        if has_recovery_timelock
            && has_min_guardians
            && has_threshold
            && has_approval_tracking
            && has_executed_flag
        {
            // Comprehensive social recovery with timelock + guardian threshold + replay protection
            return Ok(findings);
        }

        // Also check for timelock + multisig pattern (alternative protection)
        if access_control_patterns::has_timelock_pattern(ctx)
            && access_control_patterns::has_multisig_pattern(ctx)
        {
            // Timelock + multisig provides strong protection for account recovery
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
