use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::oracle_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for lending protocol liquidation abuse vulnerabilities
pub struct LendingLiquidationAbuseDetector {
    base: BaseDetector,
}

impl Default for LendingLiquidationAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LendingLiquidationAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("lending-liquidation-abuse".to_string()),
                "Lending Liquidation Abuse".to_string(),
                "Detects unfair liquidation mechanics in lending protocols that can be exploited for profit or griefing".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for LendingLiquidationAbuseDetector {
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


        // Early exit for contracts with comprehensive oracle safety
        // These contracts use manipulation-resistant price feeds
        if oracle_patterns::has_comprehensive_oracle_safety(ctx) {
            return Ok(findings);
        }

        // Check for specific safe oracle patterns that reduce liquidation abuse risk
        let has_twap = oracle_patterns::has_twap_oracle(ctx);
        let has_multi_oracle = oracle_patterns::has_multi_oracle_validation(ctx);
        let has_staleness = oracle_patterns::has_staleness_check(ctx);
        let has_deviation = oracle_patterns::has_deviation_bounds(ctx);

        // Skip if using TWAP (time-weighted, resistant to flash loan manipulation)
        if has_twap {
            return Ok(findings);
        }

        // Skip if using multi-oracle validation (cross-validates prices)
        if has_multi_oracle {
            return Ok(findings);
        }

        // Track partial safety for severity reduction
        let has_partial_oracle_safety = has_staleness || has_deviation;

        for function in ctx.get_functions() {
            if let Some(liquidation_issue) =
                self.check_liquidation_abuse(function, ctx, has_partial_oracle_safety)
            {
                // Reduce severity if contract has some oracle safety measures
                let severity = if has_partial_oracle_safety {
                    Severity::Medium
                } else {
                    Severity::Critical
                };

                let message = format!(
                    "Function '{}' has liquidation abuse vulnerability. {} \
                    Unfair liquidation mechanics can be exploited to profit from borrowers \
                    or manipulated to prevent legitimate liquidations.",
                    function.name.name, liquidation_issue
                );

                let mut finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(1339) // CWE-1339: Insufficient Precision or Accuracy
                    .with_fix_suggestion(format!(
                        "Fix liquidation mechanism in '{}'. \
                    Use TWAP oracles for health factor calculations, implement liquidation cooldown periods, \
                    add liquidation incentive caps, validate collateral prices from multiple sources, \
                    and implement partial liquidation limits.",
                        function.name.name
                    ));

                finding.severity = severity;
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

impl LendingLiquidationAbuseDetector {
    /// Check for liquidation abuse vulnerabilities
    fn check_liquidation_abuse(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        has_partial_oracle_safety: bool,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Identify liquidation functions
        let is_liquidation_function = func_source.contains("liquidate")
            || function.name.name.to_lowercase().contains("liquidate")
            || func_source.contains("seize")
            || func_source.contains("liquidationCall");

        if !is_liquidation_function {
            return None;
        }

        // Pattern 1: Spot price used for health factor calculation
        // Skip this check if contract has some oracle safety (staleness/deviation checks)
        let uses_spot_price = (func_source.contains("getPrice")
            || func_source.contains("latestAnswer")
            || func_source.contains("price()"))
            && !func_source.contains("TWAP")
            && !func_source.contains("timeWeighted")
            && !func_source.contains("cumulative");

        // Only flag spot price if no partial oracle safety exists
        if uses_spot_price && !has_partial_oracle_safety {
            return Some(
                "Liquidation uses spot price for health factor calculation, \
                enabling price manipulation to trigger unfair liquidations"
                    .to_string(),
            );
        }

        // Pattern 2: No liquidation cooldown or front-running protection
        let lacks_cooldown = !func_source.contains("lastLiquidation")
            && !func_source.contains("liquidationDelay")
            && !func_source.contains("cooldown")
            && !func_source.contains("block.timestamp");

        if lacks_cooldown {
            return Some(
                "No liquidation cooldown period, allowing instant repeated liquidations \
                and front-running of user's repayment transactions"
                    .to_string(),
            );
        }

        // Pattern 3: Excessive liquidation bonus/incentive
        let has_bonus = func_source.contains("liquidationBonus")
            || func_source.contains("liquidationIncentive")
            || func_source.contains("bonus")
            || func_source.contains("incentive");

        let lacks_bonus_cap = has_bonus
            && !func_source.contains("MAX_")
            && !func_source.contains("require(")
            && !func_source.contains("<");

        if lacks_bonus_cap {
            return Some(
                "Liquidation bonus lacks maximum cap, potentially allowing \
                liquidators to seize excessive collateral from borrowers"
                    .to_string(),
            );
        }

        // Pattern 4: Full liquidation without partial option
        let has_full_liquidation = func_source.contains("seizeCollateral")
            || func_source.contains("totalDebt")
            || func_source.contains("borrowBalance");

        let lacks_partial_liquidation = has_full_liquidation
            && !func_source.contains("repayAmount")
            && !func_source.contains("partialLiquidation")
            && !func_source.contains("closeFactorMantissa")
            && !func_source.contains("maxClose");

        if lacks_partial_liquidation {
            return Some(
                "Only allows full liquidation without partial liquidation option, \
                forcing unnecessary loss for borrowers barely under collateral ratio"
                    .to_string(),
            );
        }

        // Pattern 5: Health factor not properly validated
        let calculates_health = func_source.contains("healthFactor")
            || func_source.contains("collateralRatio")
            || func_source.contains("LTV");

        let lacks_health_validation = calculates_health
            && !func_source.contains("require(healthFactor")
            && !func_source.contains("require(collateralRatio")
            && !func_source.contains("if (")
            && !func_source.contains("1e18");

        if lacks_health_validation {
            return Some(
                "Health factor calculation lacks proper threshold validation, \
                allowing liquidations when users are still adequately collateralized"
                    .to_string(),
            );
        }

        // Pattern 6: Missing oracle staleness check
        // Skip if contract already has staleness checks detected at contract level
        if !has_partial_oracle_safety {
            let uses_oracle = func_source.contains("oracle")
                || func_source.contains("getPrice")
                || func_source.contains("latestAnswer");

            let lacks_staleness_check = uses_oracle
                && !func_source.contains("updatedAt")
                && !func_source.contains("timestamp")
                && !func_source.contains("stale");

            if lacks_staleness_check {
                return Some(
                    "Uses price oracle without checking for stale data, \
                    enabling liquidations based on outdated prices"
                        .to_string(),
                );
            }
        }

        // Pattern 7: No minimum collateral protection
        let seizes_collateral = func_source.contains("seize")
            || func_source.contains("transfer")
            || func_source.contains("liquidatorShare");

        let lacks_min_protection = seizes_collateral
            && !func_source.contains("minCollateral")
            && !func_source.contains("dustThreshold")
            && !func_source.contains("require(amount");

        if lacks_min_protection {
            return Some(
                "Collateral seizure lacks minimum amount protection, \
                allowing griefing attacks through dust liquidations"
                    .to_string(),
            );
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("liquidation")
                || func_source.contains("unfair")
                || func_source.contains("abuse"))
        {
            return Some("Liquidation abuse vulnerability marker detected".to_string());
        }

        None
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = LendingLiquidationAbuseDetector::new();
        assert_eq!(detector.name(), "Lending Liquidation Abuse");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
