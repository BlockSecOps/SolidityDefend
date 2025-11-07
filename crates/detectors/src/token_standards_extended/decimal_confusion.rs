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

        // Check for multi-token operations
        let has_tokens =
            lower.contains("ierc20") || lower.contains("token") || lower.contains("decimals()");

        if !has_tokens {
            return Ok(findings);
        }

        // Pattern 1: Hardcoded decimal assumption (1e18)
        let has_hardcoded_decimals = lower.contains("1e18")
            || lower.contains("10**18")
            || lower.contains("1000000000000000000");

        if has_hardcoded_decimals {
            let calls_decimals = lower.contains(".decimals()") || lower.contains("decimals()");

            if !calls_decimals {
                let finding = self.base.create_finding(
                    ctx,
                    "Hardcoded decimal assumption (18) - incompatible with USDC (6), WBTC (8), etc.".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Call token.decimals() and normalize: uint256 decimals = token.decimals(); amount * 10**decimals".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Price calculation without decimal normalization
        let has_price_calc =
            lower.contains("price") || lower.contains("exchange") || lower.contains("convert");

        if has_price_calc && has_tokens {
            let normalizes_decimals = lower.contains("10**decimals")
                || lower.contains("10 ** decimals")
                || lower.contains("decimals1")
                || lower.contains("decimals2");

            if !normalizes_decimals {
                let finding = self.base.create_finding(
                    ctx,
                    "Token price/exchange calculation without decimal normalization - incorrect conversions".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Normalize decimals: amount * 10**token1.decimals() / 10**token2.decimals()".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Multiple tokens without decimal tracking
        let token_count = lower.matches("ierc20").count();
        if token_count > 1 {
            let tracks_decimals = lower.contains("decimals[")
                || lower.contains("tokendecimals")
                || lower.contains("mapping(address => uint8) decimals");

            if !tracks_decimals {
                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Multiple tokens ({}) without decimal tracking - calculation errors likely",
                        token_count
                    ),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Store decimals per token: mapping(address => uint8) public tokenDecimals".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Decimal-sensitive operations without validation
        if has_tokens {
            let has_sensitive_ops =
                lower.contains("div") || lower.contains("mul") || lower.contains("ratio");

            let validates_decimals =
                lower.contains("require(decimals") || lower.contains("assert(decimals");

            if has_sensitive_ops && !validates_decimals {
                let finding = self.base.create_finding(
                    ctx,
                    "Decimal-sensitive math operations without validation - verify decimal assumptions".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate expected decimals: require(token.decimals() == EXPECTED_DECIMALS)".to_string()
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
