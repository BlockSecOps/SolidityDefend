//! MEV Backrun Opportunities Detector
//!
//! Detects backrunnable state changes that create MEV opportunities.
//! State changes that affect prices or balances can be exploited via backrunning.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MEVBackrunOpportunitiesDetector {
    base: BaseDetector,
}

impl MEVBackrunOpportunitiesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-backrun-opportunities".to_string()),
                "MEV Backrun Opportunities".to_string(),
                "Detects backrunnable state changes creating MEV opportunities".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for MEVBackrunOpportunitiesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVBackrunOpportunitiesDetector {
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

        // Check for state-changing operations
        let has_state_change = lower.contains("function")
            && (lower.contains("external") || lower.contains("public"));

        if !has_state_change {
            return Ok(findings);
        }

        // Pattern 1: Reserve updates without delay
        let updates_reserves = lower.contains("reserves")
            || lower.contains("updatereserves")
            || lower.contains("sync()");

        if updates_reserves {
            let has_delay = lower.contains("blocknumber")
                || lower.contains("timestamp")
                || lower.contains("lastupdate");

            if !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Reserve updates without block delay - backrunnable for instant arbitrage".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add delay or use commit-reveal: lastUpdate = block.number; require(block.number > lastUpdate)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Oracle price updates triggering actions
        let updates_price = lower.contains("updateprice")
            || lower.contains("setprice")
            || lower.contains("refreshprice");

        if updates_price {
            let emits_event = lower.contains("emit");
            if emits_event {
                let finding = self.base.create_finding(
                    ctx,
                    "Price update emits event - MEV bots can backrun with arbitrage before others see update".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use private mempool or implement delay for critical price updates".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Liquidation triggers without protection
        let has_liquidation = lower.contains("liquidate")
            || lower.contains("canbeliquidated");

        if has_liquidation {
            let has_backrun_protection = lower.contains("liquidationdelay")
                || lower.contains("graceperiod");

            if !has_backrun_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation without delay - MEV bots can frontrun health factor checks and backrun liquidations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add grace period before liquidation to reduce MEV opportunity".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Rebalancing operations
        let has_rebalance = lower.contains("rebalance")
            || lower.contains("reweight")
            || lower.contains("adjust");

        if has_rebalance {
            let finding = self.base.create_finding(
                ctx,
                "Rebalancing function present - creates predictable MEV opportunity for backrunners".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Use batch auctions or time-weighted execution to reduce MEV extraction".to_string()
            );

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
