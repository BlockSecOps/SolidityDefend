//! Flash Loan Price Manipulation Advanced Detector
//!
//! Detects multi-protocol price manipulation chains using flash loans.
//! Addresses cascading liquidations and oracle manipulation across multiple pools.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct FlashLoanPriceManipulationAdvancedDetector {
    base: BaseDetector,
}

impl FlashLoanPriceManipulationAdvancedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flash-loan-price-manipulation-advanced".to_string()),
                "Flash Loan Price Manipulation Advanced".to_string(),
                "Detects multi-protocol price manipulation using flash loans".to_string(),
                vec![DetectorCategory::FlashLoan, DetectorCategory::Oracle],
                Severity::Critical,
            ),
        }
    }
}

impl Default for FlashLoanPriceManipulationAdvancedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashLoanPriceManipulationAdvancedDetector {
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

        // Check for flash loan callback
        let is_flash_loan = lower.contains("flashloan")
            || lower.contains("flash")
            || lower.contains("onflashloan")
            || lower.contains("erc3156");

        if !is_flash_loan {
            return Ok(findings);
        }

        // Pattern 1: Price fetched from single DEX during flash loan
        let has_flash_callback = lower.contains("onflashloan")
            || lower.contains("receivetokens")
            || lower.contains("flashloan")
            || lower.contains("executeOperation");

        let has_price_fetch = lower.contains("getamountout")
            || lower.contains("getreserves")
            || lower.contains("price")
            || lower.contains("quote");

        if has_flash_callback {
            let has_multi_oracle = lower.contains("chainlink")
                || lower.contains("twap")
                || lower.contains("getlatestprice")
                || lower.contains("median");

            if has_price_fetch && !has_multi_oracle {
                let finding = self.base.create_finding(
                    ctx,
                    "Price fetched from single DEX during flash loan - susceptible to manipulation via large swaps".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use multi-source price oracle (Chainlink + TWAP) or disable price-sensitive operations during flash loans".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Multiple swaps in flash loan callback
        let swap_count = lower.matches("swap(").count()
            + lower.matches("swapexacttokensfortokens").count()
            + lower.matches("swaptokensforexacttokens").count();

        if has_flash_callback && swap_count > 2 {
            let finding = self.base.create_finding(
                ctx,
                format!(
                    "Multiple swaps ({}) detected in flash loan callback - multi-protocol price manipulation pattern",
                    swap_count
                ),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Limit number of swaps per transaction or use MEV-resistant execution (Flashbots, private mempool)".to_string()
            );

            findings.push(finding);
        }

        // Pattern 3: Liquidation triggered based on manipulated price
        if is_flash_loan {
            let has_liquidation = lower.contains("liquidate")
                || lower.contains("liquidationthreshold")
                || lower.contains("healthfactor");

            let uses_spot_price = lower.contains("getreserves")
                || lower.contains("balanceof")
                && (lower.contains("price") || lower.contains("ratio"));

            if has_liquidation && uses_spot_price {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation based on spot price - vulnerable to flash loan price manipulation".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use time-weighted average price (TWAP) with minimum period (e.g., 30 minutes) for liquidation checks".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Cross-protocol price dependency
        if is_flash_loan {
            let protocol_count = (if lower.contains("uniswap") { 1 } else { 0 })
                + (if lower.contains("sushiswap") { 1 } else { 0 })
                + (if lower.contains("curve") { 1 } else { 0 })
                + (if lower.contains("balancer") { 1 } else { 0 })
                + (if lower.contains("pancakeswap") { 1 } else { 0 });

            if protocol_count > 1 && has_price_fetch {
                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Price data sourced from {} protocols - cross-protocol manipulation risk",
                        protocol_count
                    ),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement circuit breaker for abnormal price deviations across protocols (e.g., >10% difference)".to_string()
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
