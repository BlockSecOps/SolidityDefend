//! AA Social Recovery Detector
//!
//! Detects vulnerabilities in social recovery mechanisms:
//! 1. No recovery delay (instant takeover)
//! 2. Insufficient guardian threshold (1-of-N)
//! 3. No recovery cancellation

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::aa::classification::*;

pub struct AASocialRecoveryDetector {
    base: BaseDetector,
}

impl AASocialRecoveryDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-social-recovery".to_string()),
                "AA Social Recovery Vulnerabilities".to_string(),
                "Detects vulnerabilities in social recovery mechanisms".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for AASocialRecoveryDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AASocialRecoveryDetector {
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

        if !has_social_recovery(ctx) {
            return Ok(findings);
        }

        // Check 1: Recovery delay
        if !has_recovery_delay(ctx) {
            findings.push(self.base.create_finding_with_severity(
                ctx,
                "No recovery delay - instant account takeover possible".to_string(),
                1, 0, 20,
                Severity::High,
            ).with_fix_suggestion("Add 24-48 hour delay between initiateRecovery and executeRecovery".to_string()));
        }

        // Check 2: Guardian threshold
        if !has_sufficient_threshold(ctx) {
            findings.push(self.base.create_finding_with_severity(
                ctx,
                "Weak guardian threshold - 1-of-N or too low".to_string(),
                1, 0, 20,
                Severity::Medium,
            ).with_fix_suggestion("Use threshold >= 50% of guardians (e.g., 3-of-5)".to_string()));
        }

        // Check 3: Recovery cancellation
        if !has_recovery_cancellation(ctx) {
            findings.push(self.base.create_finding_with_severity(
                ctx,
                "No recovery cancellation - owner can't abort malicious recovery".to_string(),
                1, 0, 20,
                Severity::Medium,
            ).with_fix_suggestion("Add cancelRecovery function callable by current owner".to_string()));
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
