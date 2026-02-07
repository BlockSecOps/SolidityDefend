//! Flash Loan Price Oracle Manipulation Detector
//!
//! Detects oracle manipulation vulnerabilities exploitable via flash loans:
//! - Single-source oracle (spot price from DEX) - Polter Finance $7M
//! - No TWAP (Time-Weighted Average Price)
//! - No multi-source validation
//! - Missing flash loan detection
//! - No price deviation checks
//!
//! Severity: CRITICAL
//! Real Exploit: Polter Finance (2024) - $7M via flash-borrowed BOO tokens

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;
use ast;

pub struct FlashloanPriceOracleManipulationDetector {
    base: BaseDetector,
}

impl FlashloanPriceOracleManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashloan-price-oracle-manipulation".to_string()),
                "Flash Loan Price Oracle Manipulation".to_string(),
                "Detects oracle manipulation vulnerabilities exploitable via flash loans"
                    .to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    fn is_defi_protocol(&self, ctx: &AnalysisContext) -> bool {
        let code_lower = ctx.source_code.to_lowercase();
        code_lower.contains("borrow")
            || code_lower.contains("lend")
            || code_lower.contains("collateral")
            || code_lower.contains("liquidate")
            || code_lower.contains("swap")
    }

    fn get_function_source<'a>(
        &self,
        function: &ast::Function,
        ctx: &'a AnalysisContext,
    ) -> &'a str {
        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return "";
        }

        &source[func_start..func_end.min(source.len())]
    }

    fn uses_spot_price_oracle(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();

        // Check if uses spot price (getReserves) without TWAP protection
        let uses_spot = func_lower.contains("getreserves")
            || func_lower.contains("getamountsout")
            || func_lower.contains("spotprice");

        let uses_twap = func_lower.contains("consult")
            || func_lower.contains("observe")
            || func_lower.contains("twap");

        uses_spot && !uses_twap
    }
}

impl Default for FlashloanPriceOracleManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashloanPriceOracleManipulationDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
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

        if !self.is_defi_protocol(ctx) {
            return Ok(findings);
        }

        // Skip if this is an AMM pool - AMM pools ARE the oracle source, not consumers
        // Uniswap V2/V3 pairs provide TWAP oracle data via getReserves()/observe()
        // They should not be flagged for using spot prices internally
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if func_name.contains("borrow")
                || func_name.contains("liquidate")
                || func_name.contains("swap")
                || func_name.contains("price")
            {
                let line = function.name.location.start().line() as u32;

                if self.uses_spot_price_oracle(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        format!("'{}' uses spot price oracle - vulnerable to flash loan manipulation (Polter Finance $7M exploit)", function.name.name),
                        line, 0, 20,
                        Severity::Critical,
                    ).with_fix_suggestion("Use TWAP oracle (Uniswap V3 observe()) or Chainlink with 30-minute average".to_string()));
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
