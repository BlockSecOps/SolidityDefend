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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        if !has_session_keys(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Consolidate all sub-check failures into 1 finding per contract
        let mut sub_issues: Vec<String> = Vec::new();

        if !has_session_key_restrictions(ctx) {
            sub_issues.push("unlimited permissions (same as owner)".to_string());
        }
        if !has_session_expiration(ctx) {
            sub_issues.push("no expiration (indefinite access)".to_string());
        }
        if !has_target_restrictions(ctx) {
            sub_issues.push("no target contract restrictions".to_string());
        }
        if !has_selector_restrictions(ctx) {
            sub_issues.push("no function selector restrictions".to_string());
        }
        if !has_period_based_limits(ctx) {
            sub_issues.push("spending limits don't reset per-period".to_string());
        }
        if !has_emergency_pause(ctx) {
            sub_issues.push("no emergency pause mechanism".to_string());
        }

        if !sub_issues.is_empty() {
            let consolidated_msg = format!(
                "Session key vulnerabilities in '{}': {}",
                ctx.contract.name.name,
                sub_issues.join("; ")
            );
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        consolidated_msg,
                        1,
                        0,
                        20,
                        Severity::Critical,
                    )
                    .with_fix_suggestion(
                        "Add SessionKeyData struct with validUntil, allowedTargets, \
                         allowedSelectors, spendingLimit fields, and pauseSessionKey function"
                            .to_string(),
                    ),
            );
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
