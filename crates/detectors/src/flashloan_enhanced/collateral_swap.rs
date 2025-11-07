//! Flash Loan Collateral Swap Detector
//!
//! Detects flash loan manipulation of collateral ratios to trigger unfair
//! liquidations or create bad debt via collateral manipulation.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct FlashLoanCollateralSwapDetector {
    base: BaseDetector,
}

impl FlashLoanCollateralSwapDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flash-loan-collateral-swap".to_string()),
                "Flash Loan Collateral Swap".to_string(),
                "Detects flash loan manipulation of collateral ratios".to_string(),
                vec![DetectorCategory::FlashLoan, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for FlashLoanCollateralSwapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashLoanCollateralSwapDetector {
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

        // Skip known lending protocols - they have audited collateral management
        // Compound, Aave, MakerDAO manage risk through:
        // - Compound: Collateral factors via Comptroller
        // - Aave: Isolation mode, LTV ratios, health factor monitoring
        // - MakerDAO: Ilk-based collateral types with separate debt ceilings
        // These protocols don't use "isolation mode" keyword but have equivalent safeguards.
        // This detector should focus on CUSTOM lending implementations without proper risk management.
        if utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        // Check for lending/collateral functionality
        let is_lending = lower.contains("collateral")
            || lower.contains("borrow")
            || lower.contains("healthfactor")
            || lower.contains("ltv")
            || lower.contains("liquidate");

        if !is_lending {
            return Ok(findings);
        }

        // Pattern 1: Collateral value based on spot price
        let has_collateral_valuation = lower.contains("collateralvalue")
            || lower.contains("getaccountliquidity")
            || lower.contains("healthfactor");

        if has_collateral_valuation {
            let uses_spot_price = (lower.contains("getreserves") || lower.contains("balanceof"))
                && (lower.contains("price") || lower.contains("value"));

            let has_twap = lower.contains("twap")
                || lower.contains("timeweighted")
                || lower.contains("average");

            if uses_spot_price && !has_twap {
                let finding = self.base.create_finding(
                    ctx,
                    "Collateral value based on spot price - flash loan can manipulate to trigger liquidations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use time-weighted average price (TWAP) with 30+ minute window for collateral valuation".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Collateral swap without delay
        let has_collateral_change = lower.contains("depositcollateral")
            || lower.contains("withdrawcollateral")
            || lower.contains("swapcollateral");

        if has_collateral_change {
            let has_delay = lower.contains("unlocktime")
                || lower.contains("cooldown")
                || lower.contains("withdrawaldelay")
                || lower.contains("block.timestamp + delay");

            if !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Collateral can be swapped without delay - flash loan attack to manipulate health factor".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum delay (e.g., 1 hour) between collateral changes and borrowing/liquidation".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Liquidation based on single-block health factor
        let has_liquidation = lower.contains("liquidate") || lower.contains("liquidationthreshold");

        if has_liquidation {
            let checks_health = lower.contains("healthfactor")
                || lower.contains("collateralratio")
                || lower.contains("ltv");

            let has_multi_block_check = lower.contains("blocknumber")
                || lower.contains("lastupdate")
                || lower.contains("checkpoint");

            if checks_health && !has_multi_block_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation based on single-block health check - flash loan can temporarily drop health factor".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require health factor violation to persist for multiple blocks before allowing liquidation".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Multiple collateral types without isolation
        if is_lending {
            let collateral_count = lower.matches("collateral").count();
            if collateral_count > 3 {
                let has_isolation_mode = lower.contains("isolationmode")
                    || lower.contains("isolatedcollateral")
                    || lower.contains("borrowcap");

                if !has_isolation_mode {
                    let finding = self.base.create_finding(
                        ctx,
                        "Multiple collateral types without isolation - cross-collateral flash loan manipulation".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Implement isolation mode or borrow caps per collateral type to limit cross-contamination".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 5: Oracle price can be manipulated within transaction
        if has_collateral_valuation || has_liquidation {
            let has_oracle = lower.contains("oracle")
                || lower.contains("pricefeed")
                || lower.contains("getprice");

            if has_oracle {
                let has_staleness_check = lower.contains("updatedAt")
                    || lower.contains("timestamp")
                    || lower.contains("stale")
                    || lower.contains("heartbeat");

                if !has_staleness_check {
                    let finding = self.base.create_finding(
                        ctx,
                        "Oracle price used without staleness check - flash loan can exploit stale prices".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Check oracle updatedAt timestamp; reject prices older than maximum staleness period".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 6: Liquidation bonus too high
        if has_liquidation {
            // Check for liquidation bonus/incentive
            let mentions_bonus = lower.contains("liquidationbonus")
                || lower.contains("liquidationincentive")
                || lower.contains("discount");

            if mentions_bonus {
                // This is a good sign, but we warn if it seems excessive
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation bonus present - verify it's not excessive (typically 5-10%) to prevent flash loan liquidation attacks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Cap liquidation bonus at reasonable level (5-10%) to reduce incentive for flash loan manipulation".to_string()
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
