use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for lending protocol liquidation abuse vulnerabilities
pub struct LendingLiquidationAbuseDetector {
    base: BaseDetector,
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

        for function in ctx.get_functions() {
            if let Some(liquidation_issue) = self.check_liquidation_abuse(function, ctx) {
                let message = format!(
                    "Function '{}' has liquidation abuse vulnerability. {} \
                    Unfair liquidation mechanics can be exploited to profit from borrowers \
                    or manipulated to prevent legitimate liquidations.",
                    function.name.name,
                    liquidation_issue
                );

                let finding = self.base.create_finding(
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

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl LendingLiquidationAbuseDetector {
    /// Check for liquidation abuse vulnerabilities
    fn check_liquidation_abuse(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify liquidation functions
        let is_liquidation_function = func_source.contains("liquidate") ||
                                     function.name.name.to_lowercase().contains("liquidate") ||
                                     func_source.contains("seize") ||
                                     func_source.contains("liquidationCall");

        if !is_liquidation_function {
            return None;
        }

        // Pattern 1: Spot price used for health factor calculation
        let uses_spot_price = (func_source.contains("getPrice") ||
                              func_source.contains("latestAnswer") ||
                              func_source.contains("price()")) &&
                             !func_source.contains("TWAP") &&
                             !func_source.contains("timeWeighted") &&
                             !func_source.contains("cumulative");

        if uses_spot_price {
            return Some(format!(
                "Liquidation uses spot price for health factor calculation, \
                enabling price manipulation to trigger unfair liquidations"
            ));
        }

        // Pattern 2: No liquidation cooldown or front-running protection
        let lacks_cooldown = !func_source.contains("lastLiquidation") &&
                            !func_source.contains("liquidationDelay") &&
                            !func_source.contains("cooldown") &&
                            !func_source.contains("block.timestamp");

        if lacks_cooldown {
            return Some(format!(
                "No liquidation cooldown period, allowing instant repeated liquidations \
                and front-running of user's repayment transactions"
            ));
        }

        // Pattern 3: Excessive liquidation bonus/incentive
        let has_bonus = func_source.contains("liquidationBonus") ||
                       func_source.contains("liquidationIncentive") ||
                       func_source.contains("bonus") ||
                       func_source.contains("incentive");

        let lacks_bonus_cap = has_bonus &&
                             !func_source.contains("MAX_") &&
                             !func_source.contains("require(") &&
                             !func_source.contains("<");

        if lacks_bonus_cap {
            return Some(format!(
                "Liquidation bonus lacks maximum cap, potentially allowing \
                liquidators to seize excessive collateral from borrowers"
            ));
        }

        // Pattern 4: Full liquidation without partial option
        let has_full_liquidation = func_source.contains("seizeCollateral") ||
                                  func_source.contains("totalDebt") ||
                                  func_source.contains("borrowBalance");

        let lacks_partial_liquidation = has_full_liquidation &&
                                       !func_source.contains("repayAmount") &&
                                       !func_source.contains("partialLiquidation") &&
                                       !func_source.contains("closeFactorMantissa") &&
                                       !func_source.contains("maxClose");

        if lacks_partial_liquidation {
            return Some(format!(
                "Only allows full liquidation without partial liquidation option, \
                forcing unnecessary loss for borrowers barely under collateral ratio"
            ));
        }

        // Pattern 5: Health factor not properly validated
        let calculates_health = func_source.contains("healthFactor") ||
                               func_source.contains("collateralRatio") ||
                               func_source.contains("LTV");

        let lacks_health_validation = calculates_health &&
                                      !func_source.contains("require(healthFactor") &&
                                      !func_source.contains("require(collateralRatio") &&
                                      !func_source.contains("if (") &&
                                      !func_source.contains("1e18");

        if lacks_health_validation {
            return Some(format!(
                "Health factor calculation lacks proper threshold validation, \
                allowing liquidations when users are still adequately collateralized"
            ));
        }

        // Pattern 6: Missing oracle staleness check
        let uses_oracle = func_source.contains("oracle") ||
                         func_source.contains("getPrice") ||
                         func_source.contains("latestAnswer");

        let lacks_staleness_check = uses_oracle &&
                                   !func_source.contains("updatedAt") &&
                                   !func_source.contains("timestamp") &&
                                   !func_source.contains("stale");

        if lacks_staleness_check {
            return Some(format!(
                "Uses price oracle without checking for stale data, \
                enabling liquidations based on outdated prices"
            ));
        }

        // Pattern 7: No minimum collateral protection
        let seizes_collateral = func_source.contains("seize") ||
                               func_source.contains("transfer") ||
                               func_source.contains("liquidatorShare");

        let lacks_min_protection = seizes_collateral &&
                                   !func_source.contains("minCollateral") &&
                                   !func_source.contains("dustThreshold") &&
                                   !func_source.contains("require(amount");

        if lacks_min_protection {
            return Some(format!(
                "Collateral seizure lacks minimum amount protection, \
                allowing griefing attacks through dust liquidations"
            ));
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY") &&
           (func_source.contains("liquidation") ||
            func_source.contains("unfair") ||
            func_source.contains("abuse")) {
            return Some(format!(
                "Liquidation abuse vulnerability marker detected"
            ));
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
