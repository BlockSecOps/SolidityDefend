//! JIT Liquidity Sandwich Attack Detector
//!
//! Detects vulnerability to just-in-time (JIT) liquidity attacks where an attacker:
//! 1. Adds large liquidity immediately before a user's swap
//! 2. Captures a significant portion of the trading fees
//! 3. Removes liquidity immediately after
//!
//! This is a sophisticated MEV strategy that exploits protocols without time-locks
//! on liquidity provision/removal.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct JitLiquiditySandwichDetector {
    base: BaseDetector,
}

impl JitLiquiditySandwichDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("jit-liquidity-sandwich".to_string()),
                "JIT Liquidity Sandwich".to_string(),
                "Detects vulnerability to just-in-time liquidity attacks where attackers add liquidity before swaps and remove immediately after to capture fees".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Default for JitLiquiditySandwichDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for JitLiquiditySandwichDetector {
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

        // Skip standard AMM implementations (Uniswap V2/V3, Curve, Balancer)
        // These protocols intentionally allow instant liquidity provision/removal
        // JIT attacks are a known design tradeoff for capital efficiency
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Skip lending protocols - JIT attacks target AMM pools, not lending protocols
        // Lending protocols (Compound, Aave, MakerDAO) have deposit/withdraw for user funds,
        // not liquidity provision. Users should be able to withdraw their deposits anytime.
        // JIT liquidity sandwich attacks are specific to AMM fee capture, not lending.
        if utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        // Check for liquidity removal functions without time-locks
        let has_remove_liquidity = lower.contains("removeliquidity")
            || lower.contains("withdraw")
            || lower.contains("burn");

        if has_remove_liquidity {
            // Check for time-lock protection
            let has_timelock = lower.contains("minlocktime")
                || lower.contains("lockuntil")
                || lower.contains("lockeduntil")
                || lower.contains("block.timestamp >=")
                || lower.contains("require(block.timestamp");

            // Check for liquidity epoch/cooldown
            let has_epoch_protection = lower.contains("epoch")
                || lower.contains("cooldown")
                || lower.contains("lastdeposit")
                || lower.contains("deposittime");

            if !has_timelock && !has_epoch_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidity removal without time-lock protection - vulnerable to JIT attacks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add a minimum lock time for liquidity positions (e.g., 1 block or epoch-based system) to prevent JIT liquidity attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for instant liquidity activation
        let has_add_liquidity = lower.contains("addliquidity")
            || lower.contains("deposit")
            || lower.contains("mint");

        if has_add_liquidity {
            let has_activation_delay = lower.contains("activationdelay")
                || lower.contains("nextepoch")
                || lower.contains("pendingdeposit");

            if !has_activation_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidity becomes active immediately - may enable JIT sandwich attacks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Consider delaying liquidity activation to the next epoch or block to mitigate JIT attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for time-weighted fee distribution
        let has_fee_distribution = lower.contains("distributefee")
            || lower.contains("accruefee")
            || lower.contains("claimfee");

        if has_fee_distribution {
            let has_timeweighted_fees = lower.contains("timeweighted")
                || lower.contains("averageliquidity")
                || lower.contains("liquidityduration");

            if !has_timeweighted_fees {
                let finding = self.base.create_finding(
                    ctx,
                    "Fee distribution not time-weighted - JIT liquidity providers get disproportionate rewards".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement time-weighted fee distribution to reward longer-term liquidity providers".to_string()
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
