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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // File-wide source for flash loan prerequisite (TPs may have keywords in sibling contracts)
        let file_lower = ctx.source_code.to_lowercase();
        // Contract-specific source for pattern detection (reduces cross-contract FPs)
        let contract_lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // FP Reduction: Skip known lending protocols (Aave, Compound, MakerDAO)
        // They have audited flash loan handling
        if crate::utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts that have flash-loan or price-related
        // functions in their own AST. This prevents cross-contract false positives
        // in multi-contract files where flash loan keywords appear in sibling contracts.
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();

        let contract_has_flash_fn = contract_func_names.iter().any(|n| {
            n.contains("flashloan")
                || n.contains("flash")
                || n.contains("onflashloan")
                || n.contains("executeoperation")
                || n.contains("receivetokens")
        });
        let contract_has_price_fn = contract_func_names.iter().any(|n| {
            n.contains("price")
                || n.contains("oracle")
                || n.contains("liquidat")
                || n.contains("collateral")
                || n.contains("swap")
                || n.contains("borrow")
                || n.contains("reserve")
                || n.contains("getamount")
        });
        let contract_name_relevant = contract_name_lower.contains("flash")
            || contract_name_lower.contains("oracle")
            || contract_name_lower.contains("price")
            || contract_name_lower.contains("liquidat")
            || contract_name_lower.contains("lending")
            || contract_name_lower.contains("swap")
            || contract_name_lower.contains("arbitrage");

        // Skip contracts that have no relevant functions AND no relevant name
        if !contract_has_flash_fn && !contract_has_price_fn && !contract_name_relevant {
            return Ok(findings);
        }

        // Require flash loan implementation patterns OR price manipulation context
        // Use FILE source for prerequisite (flash loan keywords may be in sibling contracts)
        let has_flash_loan_impl = file_lower.contains("onflashloan")
            || file_lower.contains("erc3156")
            || file_lower.contains("flashmint")
            || file_lower.contains("executeoperation")
            || file_lower.contains("function flashloan")
            || file_lower.contains("receivetokens")
            || file_lower.contains("flashloansimple");

        // Flash loan USAGE (calling flash loan on external contract)
        let has_flash_loan_usage =
            file_lower.contains(".flashloan(") || file_lower.contains(".flashloansimple(");

        // Price manipulation context: contract has flash-related function AND price operations
        let has_flash_price_context = (file_lower.contains("function flashswap")
            || file_lower.contains("function flashborrow"))
            && (file_lower.contains("getamountout")
                || file_lower.contains("getreserves(")
                || file_lower.contains("getprice(")
                || file_lower.contains("latestrounddata("));

        let is_flash_loan = has_flash_loan_impl || has_flash_loan_usage || has_flash_price_context;

        if !is_flash_loan {
            return Ok(findings);
        }

        // Pattern 1: Price fetched from single DEX during flash loan
        // Use FILE source for flash callback detection (may be in sibling contracts)
        let has_flash_callback = file_lower.contains("onflashloan")
            || file_lower.contains("receivetokens")
            || file_lower.contains("function flashloan")
            || file_lower.contains("executeoperation");

        // FP Reduction: Use CONTRACT source for price fetch detection (must be in THIS contract)
        let has_price_fetch = contract_lower.contains("getamountout")
            || contract_lower.contains("getreserves(")
            || contract_lower.contains(".price(")
            || contract_lower.contains("getprice(")
            || contract_lower.contains("quote(")
            || contract_lower.contains("latestrounddata(");

        if has_flash_callback {
            // Check for actual multi-oracle usage — use CONTRACT source
            let has_multi_oracle = contract_lower.contains("chainlinkfeed")
                || contract_lower.contains("aggregatorv3interface(")
                || contract_lower.contains("twaporacle")
                || contract_lower.contains("twap(")
                || contract_lower.contains("= getlatestprice")
                || contract_lower.contains(".latestround")
                || contract_lower.contains("median(");

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

        // Pattern 2: Multiple swaps in flash loan callback — use FILE source for swap count
        // (interface declarations containing swap signatures are part of the deployment context)
        let swap_count = file_lower.matches("swap(").count()
            + file_lower.matches("swapexacttokensfortokens").count()
            + file_lower.matches("swaptokensforexacttokens").count();

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

        // Pattern 3: Liquidation triggered based on manipulated price — use CONTRACT source
        if is_flash_loan {
            let has_liquidation = contract_lower.contains("liquidate")
                || contract_lower.contains("liquidationthreshold")
                || contract_lower.contains("healthfactor");

            let uses_spot_price = contract_lower.contains("getreserves(")
                || (contract_lower.contains("balanceof")
                    && (contract_lower.contains("price") || contract_lower.contains("ratio")));

            // FP Reduction: Skip if contract uses TWAP, Chainlink, or multi-oracle
            let has_oracle_protection = contract_lower.contains("twaporacle")
                || contract_lower.contains("twap(")
                || contract_lower.contains("twap_period")
                || contract_lower.contains("chainlinkfeed")
                || contract_lower.contains("aggregatorv3interface(")
                || contract_lower.contains("= getlatestprice")
                || contract_lower.contains(".latestround")
                || contract_lower.contains("pricefeed(")
                || contract_lower.contains("timeweighted(")
                || contract_lower.contains("median(")
                || contract_lower.contains("maxdeviation")
                || contract_lower.contains("deviationthreshold")
                || contract_lower.contains("pricedeviation")
                || contract_lower.contains("maxheartbeat")
                || contract_lower.contains("heartbeatperiod");

            if has_liquidation && uses_spot_price && !has_oracle_protection {
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

        // Pattern 4: Cross-protocol price dependency — use CONTRACT source
        if is_flash_loan {
            let protocol_count = (if contract_lower.contains("uniswap") {
                1
            } else {
                0
            }) + (if contract_lower.contains("sushiswap") {
                1
            } else {
                0
            }) + (if contract_lower.contains("curve") {
                1
            } else {
                0
            }) + (if contract_lower.contains("balancer") {
                1
            } else {
                0
            }) + (if contract_lower.contains("pancakeswap") {
                1
            } else {
                0
            });

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
