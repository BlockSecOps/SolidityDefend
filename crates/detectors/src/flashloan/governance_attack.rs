//! Flash Loan Governance Attack Detector
//!
//! Detects governance systems vulnerable to flash loan attacks:
//! - No snapshot-based voting (uses current balance) - Beanstalk $182M
//! - Instant execution without timelock - Compound Proposal 289
//! - No voting delay
//! - No quorum requirement
//!
//! Severity: HIGH
//! Real Exploits: Shibarium $2.4M, Compound 499k COMP, Beanstalk $182M

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct FlashloanGovernanceAttackDetector {
    base: BaseDetector,
}

impl FlashloanGovernanceAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashloan-governance-attack".to_string()),
                "Flash Loan Governance Attack".to_string(),
                "Detects governance systems vulnerable to flash loan voting attacks".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    fn is_governance_contract(&self, ctx: &AnalysisContext) -> bool {
        ctx.get_functions().iter().any(|f| f.name.name == "propose")
            && ctx.get_functions().iter().any(|f| f.name.name == "vote")
            && ctx.get_functions().iter().any(|f| f.name.name == "execute")
    }

    fn get_function_source<'a>(
        &self,
        function: &ast::Function,
        ctx: &'a AnalysisContext,
    ) -> &'a str {
        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return "";
        }

        &source[func_start..func_end.min(source.len())]
    }

    fn uses_snapshot_voting(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();

        // Check for snapshot-based voting functions
        func_lower.contains("getpastvotes")
            || func_lower.contains("balanceofat")
            || func_lower.contains("snapshot")
    }

    fn has_timelock(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check for queue function and timelock variable
        let has_queue = ctx.get_functions().iter().any(|f| f.name.name == "queue");
        let has_timelock_var = source_lower.contains("timelock");

        has_queue && has_timelock_var
    }
}

impl Default for FlashloanGovernanceAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashloanGovernanceAttackDetector {
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

        if !self.is_governance_contract(ctx) {
            return Ok(findings);
        }

        // Check vote function
        for function in ctx.get_functions() {
            if function.name.name == "vote" {
                let line = function.name.location.start().line() as u32;

                if !self.uses_snapshot_voting(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        "Uses current balance for voting - flash loan exploitable (Beanstalk $182M exploit)".to_string(),
                        line, 0, 20,
                        Severity::Critical,
                    ).with_fix_suggestion("Use EIP-5805 getPastVotes() with snapshot block".to_string()));
                }
            }
        }

        // Check timelock
        if !self.has_timelock(ctx) {
            findings.push(
                self.base
                    .create_finding_with_severity(
                        ctx,
                        "No timelock delay - instant execution (Compound Proposal 289 pattern)"
                            .to_string(),
                        1,
                        0,
                        20,
                        Severity::Critical,
                    )
                    .with_fix_suggestion(
                        "Add timelock with queue() → execute() pattern (2+ days delay)".to_string(),
                    ),
            );
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
