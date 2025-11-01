//! MEV Sandwich Vulnerable Swaps Detector
//!
//! Detects unprotected DEX swaps vulnerable to sandwich attacks.
//! Missing slippage protection allows MEV bots to profit at user expense.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct MEVSandwichVulnerableDetector {
    base: BaseDetector,
}

impl MEVSandwichVulnerableDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-sandwich-vulnerable-swaps".to_string()),
                "MEV Sandwich Vulnerable Swaps".to_string(),
                "Detects unprotected DEX swaps vulnerable to sandwich attacks".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for MEVSandwichVulnerableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVSandwichVulnerableDetector {
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

        // Skip AMM pool contracts - sandwich attacks on AMM swaps are expected/intentional
        // AMMs provide liquidity and price discovery through arbitrage (which includes sandwiches)
        // This detector should focus on contracts that CONSUME AMM data without slippage protection
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        // Check for DEX swap operations
        let has_swap = lower.contains("swap")
            || lower.contains("swapexacttokensfortokens")
            || lower.contains("swaptokensforexacttokens")
            || lower.contains("exactinput");

        if !has_swap {
            return Ok(findings);
        }

        // Pattern 1: Swap with zero or no minimum output
        if lower.contains("swap") {
            let has_zero_min = lower.contains("minamountout: 0")
                || lower.contains("amountoutmin: 0")
                || lower.contains("amountoutminimum: 0");

            if has_zero_min {
                let finding = self.base.create_finding(
                    ctx,
                    "Swap with zero minimum output - 100% vulnerable to sandwich attacks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Set minimum output: uint256 minOut = quote * (10000 - slippageBps) / 10000; swap(..., minOut)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No slippage parameter in swap function
        let has_swap_function = lower.contains("function swap")
            || lower.contains("function execute");

        if has_swap_function {
            let has_slippage_param = lower.contains("slippage")
                || lower.contains("minout")
                || lower.contains("minamount");

            if !has_slippage_param {
                let finding = self.base.create_finding(
                    ctx,
                    "Swap function lacks slippage parameter - users cannot protect against MEV".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add slippage protection parameter: function swap(..., uint256 minAmountOut)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Large swaps without MEV protection
        if has_swap {
            let has_large_amount = lower.contains("balanceof(address(this))")
                || lower.contains("totalassets")
                || lower.contains("reserves");

            let uses_flashbots = lower.contains("flashbots")
                || lower.contains("private")
                || lower.contains("mev");

            if has_large_amount && !uses_flashbots {
                let finding = self.base.create_finding(
                    ctx,
                    "Large swaps without MEV protection (Flashbots/private mempool) - high sandwich risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use Flashbots/MEV-Share for large swaps or implement private transaction submission".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Deadline too far in future
        if has_swap {
            let has_deadline = lower.contains("deadline");
            if has_deadline {
                let has_long_deadline = lower.contains("type(uint256).max")
                    || lower.contains("deadline: max");

                if has_long_deadline {
                    let finding = self.base.create_finding(
                        ctx,
                        "Swap deadline set to max - transaction can be held and executed at worst price".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Use short deadline: uint256 deadline = block.timestamp + 300; // 5 minutes".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
