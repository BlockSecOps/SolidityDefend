//! AA Social Recovery Detector
//!
//! Detects vulnerabilities in social recovery mechanisms:
//! 1. No recovery delay (instant takeover)
//! 2. Insufficient guardian threshold (1-of-N)
//! 3. No recovery cancellation

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        if !has_social_recovery(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Consolidate all sub-check failures into single finding per contract
        let mut sub_issues: Vec<String> = Vec::new();

        if !has_recovery_delay(ctx) {
            sub_issues.push("no recovery delay (instant account takeover possible)".to_string());
        }
        if !has_sufficient_threshold(ctx) {
            sub_issues.push("weak guardian threshold (1-of-N or too low)".to_string());
        }
        if !has_recovery_cancellation(ctx) {
            sub_issues.push(
                "no recovery cancellation (owner can't abort malicious recovery)".to_string(),
            );
        }

        if !sub_issues.is_empty() {
            let consolidated_msg = format!(
                "Social recovery in '{}' has {} issues: {}",
                ctx.contract.name.name,
                sub_issues.len(),
                sub_issues.join("; ")
            );
            findings.push(
                self.base
                    .create_finding_with_severity(ctx, consolidated_msg, 1, 0, 20, Severity::High)
                    .with_fix_suggestion(
                        "Add 24-48 hour recovery delay, use threshold >= 50% of guardians, \
                         and add cancelRecovery function callable by current owner"
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
