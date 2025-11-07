//! MEV Toxic Flow Detector
//!
//! Detects AMM toxic flow risks where informed traders extract value.
//! Adversarial order flow causes LPs to lose money to informed traders.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct MEVToxicFlowDetector {
    base: BaseDetector,
}

impl MEVToxicFlowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-toxic-flow-exposure".to_string()),
                "MEV Toxic Flow Exposure".to_string(),
                "Detects AMM toxic flow risks from informed order flow".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for MEVToxicFlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVToxicFlowDetector {
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
        // These protocols intentionally don't have dynamic fees or toxic flow protection
        // and operate with known MEV risks as part of their design
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        // Check for AMM/DEX functionality
        let is_amm = lower.contains("swap")
            || lower.contains("getreserves")
            || lower.contains("addliquidity");

        if !is_amm {
            return Ok(findings);
        }

        // Pattern 1: No fee tier for toxic flow
        if is_amm {
            let has_dynamic_fees = lower.contains("dynamicfee")
                || lower.contains("adjustfee")
                || lower.contains("volatilityfee");

            if !has_dynamic_fees {
                let finding = self.base.create_finding(
                    ctx,
                    "Static fees on AMM - no protection against toxic flow from informed traders".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement dynamic fees that increase with volatility or trade size to discourage toxic flow".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No trade size limits
        if lower.contains("swap") {
            let has_size_limit = lower.contains("maxtradesize")
                || lower.contains("amountlimit")
                || lower.contains("require(amount <");

            if !has_size_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "No trade size limits - large informed trades can extract maximum value from LPs".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add maximum trade size as percentage of reserves: require(amountIn < reserves * maxBps / 10000)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Instant arbitrage possible
        if is_amm {
            let allows_instant_arb = lower.contains("sync()") || lower.contains("update");

            let has_delay = lower.contains("blocknumber") || lower.contains("lastupdate");

            if allows_instant_arb && !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Instant arbitrage possible - informed traders can extract value with zero risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add block delay or use time-weighted pricing to reduce instant arbitrage opportunities".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: No JIT liquidity protection
        if lower.contains("addliquidity") {
            let has_jit_protection = lower.contains("lockperiod")
                || lower.contains("minimumhold")
                || lower.contains("withdrawdelay");

            if !has_jit_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "No JIT liquidity protection - attackers can add liquidity, extract fees, and withdraw immediately".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum holding period for LP tokens: mapping(address => uint256) public depositTime".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Oracle price not checked
        if lower.contains("swap") {
            let checks_oracle =
                lower.contains("oracle") || lower.contains("twap") || lower.contains("chainlink");

            if !checks_oracle {
                let finding = self.base.create_finding(
                    ctx,
                    "Swaps don't check oracle price - no protection against informed traders exploiting price deviations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Compare swap price against TWAP oracle; reject if deviation exceeds threshold".to_string()
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
