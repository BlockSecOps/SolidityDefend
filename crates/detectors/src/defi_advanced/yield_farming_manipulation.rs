//! Yield Farming Reward Manipulation Detector
//!
//! Detects vulnerabilities in yield farming reward calculations that can be exploited:
//! 1. TVL (Total Value Locked) manipulation to inflate rewards
//! 2. Reward rate gaming through flash loans or quick deposits
//! 3. Unprotected reward calculation that doesn't account for time-weighted positions
//! 4. Missing checks for minimum staking duration
//!
//! These vulnerabilities allow attackers to claim disproportionate rewards without
//! providing long-term liquidity to the protocol.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct YieldFarmingManipulationDetector {
    base: BaseDetector,
}

impl YieldFarmingManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("yield-farming-manipulation".to_string()),
                "Yield Farming Reward Manipulation".to_string(),
                "Detects vulnerabilities in yield farming reward calculations that allow attackers to manipulate TVL or claim disproportionate rewards".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }
}

impl Default for YieldFarmingManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for YieldFarmingManipulationDetector {
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

        // Check for reward calculation based on TVL without time-weighting
        let has_reward_calculation = lower.contains("reward")
            || lower.contains("accruereward")
            || lower.contains("claimreward")
            || lower.contains("harvest");

        if has_reward_calculation {
            let uses_tvl = lower.contains("totalvaluelocked")
                || lower.contains("tvl")
                || lower.contains("totalstaked")
                || lower.contains("totaldeposit");

            if uses_tvl {
                // Check for time-weighted calculations
                let has_timeweighting = lower.contains("timeweighted")
                    || lower.contains("averagebalance")
                    || lower.contains("stakeduration")
                    || lower.contains("block.timestamp -");

                if !has_timeweighting {
                    let finding = self.base.create_finding(
                        ctx,
                        "Reward calculation uses TVL without time-weighting - vulnerable to flash deposit attacks".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Implement time-weighted reward distribution based on staking duration, not just current TVL".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Check for missing minimum staking duration
        let has_staking = lower.contains("stake")
            || lower.contains("deposit")
            || lower.contains("addliquidity");

        if has_staking && has_reward_calculation {
            let has_min_duration = lower.contains("minstaketime")
                || lower.contains("minimumstake")
                || lower.contains("lockperiod")
                || lower.contains("require(block.timestamp");

            if !has_min_duration {
                let finding = self.base.create_finding(
                    ctx,
                    "No minimum staking duration enforced - allows instant reward farming".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum staking duration requirement before allowing reward claims".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for reward rate manipulation via share price
        let has_share_based_rewards = lower.contains("accrewardpershare")
            || lower.contains("rewardpershare")
            || lower.contains("sharevalue");

        if has_share_based_rewards {
            let has_share_inflation_protection = lower.contains("minimumshares")
                || lower.contains("initial_shares")
                || lower.contains("dead_shares")
                || lower.contains("require(totalshares");

            if !has_share_inflation_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Share-based reward calculation without inflation protection - first depositor can manipulate reward rate".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Initialize pool with minimum shares or dead shares to prevent first-depositor manipulation".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for unprotected reward update
        let has_reward_update = lower.contains("updatereward")
            || lower.contains("updatepool")
            || lower.contains("accrue");

        if has_reward_update {
            let has_update_protection = lower.contains("onlyowner")
                || lower.contains("onlyadmin")
                || lower.contains("require(msg.sender")
                || lower.contains("internal");

            if !has_update_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Reward update function lacks access control - anyone can trigger reward accrual at arbitrary times".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add access control or make reward update function internal with automatic triggers".to_string()
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
