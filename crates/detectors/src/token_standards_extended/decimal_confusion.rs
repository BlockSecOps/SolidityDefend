//! Token Decimal Confusion Detector
//!
//! Detects decimal mismatch errors that can lead to loss of funds.
//! Different tokens have different decimals (6, 8, 18) causing calculation errors.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TokenDecimalConfusionDetector {
    base: BaseDetector,
}

impl TokenDecimalConfusionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-decimal-confusion".to_string()),
                "Token Decimal Confusion".to_string(),
                "Detects decimal mismatch errors in multi-token systems".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for TokenDecimalConfusionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TokenDecimalConfusionDetector {
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

        // Context gating: Skip contracts that don't need decimal analysis
        if !self.is_decimal_sensitive_contract(&lower) {
            return Ok(findings);
        }

        // Skip if contract already handles decimals properly
        if self.handles_decimals_properly(&lower) {
            return Ok(findings);
        }

        // Pattern 1: Multi-token swap/exchange with hardcoded 1e18
        // Only flag if there's actual cross-token arithmetic
        if self.has_cross_token_arithmetic(&lower) {
            let has_hardcoded_decimals = lower.contains("1e18")
                || lower.contains("10**18")
                || lower.contains("1000000000000000000");

            let calls_decimals = lower.contains(".decimals()");

            if has_hardcoded_decimals && !calls_decimals {
                let finding = self.base.create_finding(
                    ctx,
                    "Cross-token arithmetic with hardcoded 18 decimals - incompatible with USDC (6), WBTC (8)".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Call token.decimals() for each token and normalize calculations".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Price oracle integration without decimal handling
        // Require actual oracle pattern, not just "price" keyword
        if self.has_price_oracle_pattern(&lower) && !self.normalizes_oracle_decimals(&lower) {
            let finding = self.base.create_finding(
                ctx,
                "Price oracle integration without decimal normalization".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Normalize oracle price with token decimals: price * 10**tokenDecimals / 10**oracleDecimals".to_string()
            );

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TokenDecimalConfusionDetector {
    /// Check if contract is a decimal-sensitive DeFi contract
    fn is_decimal_sensitive_contract(&self, source: &str) -> bool {
        // Must have actual multi-token infrastructure
        let token_indicators = [
            "ierc20(",        // Token interface usage
            "ierc20 ",        // Token interface declaration
            ".transfer(",     // Token transfer
            ".transferfrom(", // Token transferFrom
            ".balanceof(",    // Token balance check
        ];

        let token_count = token_indicators
            .iter()
            .filter(|p| source.contains(*p))
            .count();
        if token_count < 2 {
            return false;
        }

        // Must have arithmetic operations between token amounts
        let arithmetic_indicators = [
            " / ",      // Division
            " * ",      // Multiplication
            ".div(",    // SafeMath div
            ".mul(",    // SafeMath mul
            "amount *", // Amount calculation
            "* amount", // Amount calculation
            "amount /", // Amount calculation
            "/ amount", // Amount calculation
        ];

        arithmetic_indicators.iter().any(|p| source.contains(p))
    }

    /// Check if contract already handles decimals properly
    fn handles_decimals_properly(&self, source: &str) -> bool {
        // Explicit decimal handling patterns
        let proper_handling = [
            ".decimals()",    // Calls decimals()
            "tokendecimals",  // Decimal tracking variable
            "decimals[",      // Decimal mapping
            "10**decimals",   // Dynamic decimal scaling
            "10 ** decimals", // Dynamic decimal scaling
            "scalefactor",    // Scale factor pattern
            "_decimals",      // Stored decimals
            "decimals1",      // Multi-token decimal tracking
            "decimals2",      // Multi-token decimal tracking
            "normalizeto18",  // Explicit normalization
            "scaleto18",      // Scale function
        ];

        proper_handling.iter().any(|p| source.contains(p))
    }

    /// Check for actual cross-token arithmetic (not just transfers)
    fn has_cross_token_arithmetic(&self, source: &str) -> bool {
        // Must have multiple different token references in calculations
        let swap_patterns = [
            "tokenin",
            "tokenout",
            "tokena",
            "tokenb",
            "token0",
            "token1",
            "fromtoken",
            "totoken",
            "srctoken",
            "dsttoken",
        ];

        let swap_count = swap_patterns.iter().filter(|p| source.contains(*p)).count();
        if swap_count >= 2 {
            return true;
        }

        // Or has swap/exchange function with amount calculations
        let has_exchange =
            source.contains("swap(") || source.contains("exchange(") || source.contains("convert(");

        let has_amount_calc = source.contains("amountin")
            || source.contains("amountout")
            || source.contains("getamount");

        has_exchange && has_amount_calc
    }

    /// Check for price oracle integration pattern
    fn has_price_oracle_pattern(&self, source: &str) -> bool {
        // Must have actual oracle infrastructure
        let oracle_patterns = [
            "pricefeed",
            "aggregatorv3",
            "latestanswer",
            "latestrounddata",
            "chainlink",
            "getprice(",
            "oracle.get",
        ];

        let oracle_count = oracle_patterns
            .iter()
            .filter(|p| source.contains(*p))
            .count();

        // Require at least 2 oracle indicators (not just "price" keyword)
        oracle_count >= 2
    }

    /// Check if oracle decimals are normalized
    fn normalizes_oracle_decimals(&self, source: &str) -> bool {
        let normalization_patterns = [
            "oracle.decimals()",
            "feeddecimals",
            "pricedecimals",
            "10**8", // Chainlink standard 8 decimals
            "1e8",   // Chainlink standard
            "oracledecimals",
        ];

        normalization_patterns.iter().any(|p| source.contains(p))
    }
}
