//! Time-Locked Admin Bypass Detector
//!
//! Detects timelock circumvention patterns and missing delay enforcement on critical
//! admin functions. Prevents instant rug pulls despite timelock promises.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TimeLockedAdminBypassDetector {
    base: BaseDetector,
}

impl TimeLockedAdminBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("time-locked-admin-bypass".to_string()),
                "Time-Locked Admin Bypass".to_string(),
                "Detects timelock circumvention and missing delay enforcement on critical admin functions".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Default for TimeLockedAdminBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TimeLockedAdminBypassDetector {
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
        let lower = ctx.source_code.to_lowercase();

        // Check if contract mentions timelock
        let mentions_timelock = lower.contains("timelock")
            || lower.contains("timelocked")
            || lower.contains("delay");

        if !mentions_timelock {
            return Ok(findings);
        }

        // Pattern 1: Admin functions not going through timelock
        let has_admin_functions = lower.contains("function upgradeto")
            || lower.contains("function setparameter")
            || lower.contains("function changeconfig")
            || lower.contains("onlyowner");

        if has_admin_functions && mentions_timelock {
            let has_timelock_check = lower.contains("timelock.execute")
                || lower.contains("executeproposal")
                || lower.contains("require(block.timestamp >=");

            if !has_timelock_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Admin functions exist but don't enforce timelock delay - timelock may be bypassable".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Route all admin functions through timelock contract with schedule→execute pattern".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Missing delay check in upgrade functions
        let has_upgrade = lower.contains("upgradeto") || lower.contains("upgradeimplementation");
        if has_upgrade {
            let has_delay = lower.contains("upgradedelay")
                || lower.contains("delay")
                || lower.contains("block.timestamp >=")
                || lower.contains("timelockcontroller");

            if !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Upgrade function lacks timelock delay - instant upgrades possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum delay period before upgrade execution (e.g., 2-7 days)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Direct state changes bypassing proposed→queued→executed flow
        let has_queue = lower.contains("queue") || lower.contains("schedule");
        let has_execute = lower.contains("execute") || lower.contains("executeproposal");

        if mentions_timelock && (!has_queue || !has_execute) {
            let finding = self.base.create_finding(
                ctx,
                "Timelock implementation incomplete - missing queue/schedule or execute functions".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Implement complete timelock flow: propose→queue→wait(delay)→execute".to_string()
            );

            findings.push(finding);
        }

        // Pattern 4: Emergency functions bypassing timelock
        let has_emergency = lower.contains("emergency")
            || lower.contains("urgent")
            || lower.contains("immediate");

        if has_emergency && mentions_timelock {
            let has_multisig = lower.contains("multisig")
                || lower.contains("threshold")
                || lower.contains("requiresignatures");

            if !has_multisig {
                let finding = self.base.create_finding(
                    ctx,
                    "Emergency functions bypass timelock without multisig protection".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require multisig approval for emergency functions that bypass timelock".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
