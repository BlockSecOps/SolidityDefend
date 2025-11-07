//! AA Session Key Vulnerabilities Detector
//!
//! Detects insecure session key implementations:
//! 1. Unlimited permissions (session key = full account access)
//! 2. No expiration time (indefinite access)
//! 3. Missing target/function restrictions
//! 4. No spending limits
//! 5. No emergency pause mechanism

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AASessionKeyVulnerabilitiesDetector {
    base: BaseDetector,
}

impl AASessionKeyVulnerabilitiesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-session-key-vulnerabilities".to_string()),
                "AA Session Key Vulnerabilities".to_string(),
                "Detects insecure session key implementations with unlimited permissions or missing restrictions".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for AASessionKeyVulnerabilitiesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AASessionKeyVulnerabilitiesDetector {
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

        if !has_session_keys(ctx) {
            return Ok(findings);
        }

        // Check 1: Unrestricted session keys
        if !has_session_key_restrictions(ctx) {
            findings.push(self.base.create_finding_with_severity(
                ctx,
                "Session keys have unlimited permissions - same as owner".to_string(),
                1, 0, 20,
                Severity::Critical,
            ).with_fix_suggestion("Add SessionKeyData struct with validUntil, allowedTargets, spendingLimit fields".to_string()));
        }

        // Check 2: No expiration
        if !has_session_expiration(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "Session keys never expire - indefinite access".to_string(),
                        1,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion(
                        "Add validUntil field and time validation in validateUserOp".to_string(),
                    ),
            );
        }

        // Check 3: No target restrictions
        if !has_target_restrictions(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "Session keys can call any contract - should restrict targets".to_string(),
                        1,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion("Add allowedTargets array and validation".to_string()),
            );
        }

        // Check 4: No function selector restrictions
        if !has_selector_restrictions(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "Session keys can call any function - should restrict selectors"
                            .to_string(),
                        1,
                        0,
                        20,
                        Severity::Medium,
                    )
                    .with_fix_suggestion(
                        "Add allowedSelectors array (bytes4[]) and validation".to_string(),
                    ),
            );
        }

        // Check 5: No period-based spending limits
        if !has_period_based_limits(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "Spending limit doesn't reset - should be per-period (daily/weekly)"
                            .to_string(),
                        1,
                        0,
                        20,
                        Severity::Low,
                    )
                    .with_fix_suggestion(
                        "Add periodDuration and periodStart for resetting limits".to_string(),
                    ),
            );
        }

        // Check 6: No emergency pause
        if !has_emergency_pause(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "No emergency pause for compromised session keys".to_string(),
                        1,
                        0,
                        20,
                        Severity::Medium,
                    )
                    .with_fix_suggestion(
                        "Add paused field and pauseSessionKey function".to_string(),
                    ),
            );
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
