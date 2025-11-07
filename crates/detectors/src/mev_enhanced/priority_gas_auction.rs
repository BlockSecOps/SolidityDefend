//! MEV Priority Gas Auction Detector
//!
//! Detects PGA (Priority Gas Auction) vulnerable functions.
//! Gas wars occur when multiple parties compete for same opportunity.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MEVPriorityGasAuctionDetector {
    base: BaseDetector,
}

impl MEVPriorityGasAuctionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-priority-gas-auction".to_string()),
                "MEV Priority Gas Auction".to_string(),
                "Detects PGA-vulnerable functions causing gas wars".to_string(),
                vec![DetectorCategory::MEV],
                Severity::Medium,
            ),
        }
    }
}

impl Default for MEVPriorityGasAuctionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVPriorityGasAuctionDetector {
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

        // Pattern 1: First-come-first-served minting
        let has_mint = lower.contains("function mint") || lower.contains("function claim");

        if has_mint {
            let is_fcfs = lower.contains("while (supply")
                || lower.contains("if (available")
                || lower.contains("totalsupply");

            let has_queue = lower.contains("queue")
                || lower.contains("whitelist")
                || lower.contains("allowlist");

            if is_fcfs && !has_queue {
                let finding = self.base.create_finding(
                    ctx,
                    "First-come-first-served mint - creates PGA where users bid up gas to mint first".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use commit-reveal, whitelist, or fair launch mechanism instead of FCFS".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Liquidation rewards to caller
        let has_liquidation = lower.contains("liquidate");
        if has_liquidation {
            let rewards_caller = lower.contains("msg.sender")
                && (lower.contains("reward")
                    || lower.contains("bonus")
                    || lower.contains("incentive"));

            if rewards_caller {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation rewards go to caller - creates PGA where bots compete with gas price".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use Dutch auction for liquidation bonus or distribute rewards over time".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Arbitrage opportunities for anyone
        let has_arbitrage = lower.contains("arbitrage")
            || lower.contains("rebalance")
            || (lower.contains("buy") && lower.contains("sell"));

        if has_arbitrage {
            let is_public = lower.contains("external") || lower.contains("public");

            if is_public {
                let finding = self.base.create_finding(
                    ctx,
                    "Public arbitrage function - creates PGA as bots compete for profit".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Capture MEV for protocol via auction mechanism or restrict to specific keepers".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Time-sensitive operations
        let has_time_sensitive =
            lower.contains("deadline") || lower.contains("expires") || lower.contains("validuntil");

        if has_time_sensitive {
            let is_first_wins =
                lower.contains("require(!executed") || lower.contains("require(!claimed");

            if is_first_wins {
                let finding = self.base.create_finding(
                    ctx,
                    "Time-sensitive first-winner operation - creates PGA as users race before deadline".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use commit-reveal or randomized selection instead of first-wins pattern".to_string()
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
