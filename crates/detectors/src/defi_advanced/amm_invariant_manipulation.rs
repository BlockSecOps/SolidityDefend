//! AMM Invariant Manipulation Detector
//!
//! Detects vulnerabilities in Automated Market Maker (AMM) invariant enforcement:
//! 1. Missing K invariant checks (x * y = k for constant product AMMs)
//! 2. Unprotected reserve updates that bypass invariant validation
//! 3. Price oracle manipulation via flash swaps
//! 4. Missing TWAP (Time-Weighted Average Price) implementation
//! 5. Reserve synchronization issues
//!
//! The constant product formula (x * y = k) is fundamental to AMM security.
//! Any operation that bypasses or manipulates this invariant can lead to fund loss.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct AmmInvariantManipulationDetector {
    base: BaseDetector,
}

impl AmmInvariantManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("amm-invariant-manipulation".to_string()),
                "AMM Invariant Manipulation".to_string(),
                "Detects vulnerabilities in AMM invariant enforcement including K invariant violations, missing TWAP, and reserve manipulation".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for AmmInvariantManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AmmInvariantManipulationDetector {
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

        // Skip standard AMM implementations (UniswapV2/V3, Curve, Balancer)
        // These are battle-tested implementations with proper invariant checks
        // This detector should focus on custom AMM implementations
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        // Check for AMM swap functionality
        let is_amm = lower.contains("swap")
            || lower.contains("getamountout")
            || lower.contains("getamountin");

        if !is_amm {
            return Ok(findings);
        }

        // Check for K invariant enforcement
        let has_reserves =
            lower.contains("reserve0") || lower.contains("reserve1") || lower.contains("_reserve");

        if has_reserves {
            let has_k_check = lower.contains("k =")
                || lower.contains("invariant")
                || lower.contains("require(")
                || lower.contains("assert(");

            let has_k_enforcement = lower.contains("* reserve1")
                || lower.contains("* reserve0")
                || lower.contains("product");

            if !has_k_check || !has_k_enforcement {
                let finding = self.base.create_finding(
                    ctx,
                    "AMM swap lacks K invariant validation - reserves can be manipulated without proper checks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Enforce K invariant (reserve0 * reserve1 >= k) after every swap to prevent reserve manipulation".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for reserve update protection
        let has_reserve_update =
            lower.contains("_update") || lower.contains("sync") || lower.contains("updatereserves");

        if has_reserve_update {
            let has_update_protection = lower.contains("private")
                || lower.contains("internal")
                || lower.contains("onlypair")
                || lower.contains("locked");

            if !has_update_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Reserve update function lacks access control - reserves can be manipulated directly".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Make reserve update functions internal/private and only callable through validated swap paths".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for TWAP implementation
        let has_price_oracle =
            lower.contains("price") || lower.contains("getprice") || lower.contains("oracle");

        if has_price_oracle {
            let has_twap = lower.contains("twap")
                || lower.contains("timeweighted")
                || lower.contains("cumulativeprice")
                || lower.contains("blockTimestampLast");

            if !has_twap {
                let finding = self.base.create_finding(
                    ctx,
                    "Price oracle uses spot price without TWAP - vulnerable to flash loan price manipulation".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement time-weighted average price (TWAP) using cumulative price observations to resist manipulation".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for flash swap protection
        let has_swap = lower.contains("function swap") || lower.contains("swapexacttoken");

        if has_swap {
            let has_flash_protection = lower.contains("callback")
                || lower.contains("flashswap")
                || lower.contains("require(balance");

            let has_reentrancy_guard = lower.contains("nonreentrant")
                || lower.contains("locked")
                || lower.contains("reentrancyguard");

            if has_flash_protection && !has_reentrancy_guard {
                let finding = self.base.create_finding(
                    ctx,
                    "Swap function supports callbacks without reentrancy guard - vulnerable to reentrancy via flash swaps".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add reentrancy guard to swap function or validate invariants before and after callback execution".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for slippage protection
        if has_swap {
            let has_slippage = lower.contains("minamountout")
                || lower.contains("amountoutmin")
                || lower.contains("deadline")
                || lower.contains("slippage");

            if !has_slippage {
                let finding = self.base.create_finding(
                    ctx,
                    "Swap lacks slippage protection - users vulnerable to sandwich attacks and price manipulation".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum output amount and deadline parameters to protect users from excessive slippage".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for fee-on-transfer token support
        let has_transfer = lower.contains("transferfrom") || lower.contains("safetransferfrom");

        if has_transfer && has_reserves {
            let checks_balance = lower.contains("balanceof")
                || lower.contains("actualamount")
                || lower.contains("received");

            if !checks_balance {
                let finding = self.base.create_finding(
                    ctx,
                    "AMM assumes transfer amounts equal input amounts - incompatible with fee-on-transfer tokens".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Check actual received amounts via balanceOf() before and after transfer to support fee-on-transfer tokens".to_string()
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
