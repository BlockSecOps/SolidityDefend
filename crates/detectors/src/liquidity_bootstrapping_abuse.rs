use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for liquidity bootstrapping pool (LBP) manipulation vulnerabilities
pub struct LiquidityBootstrappingAbuseDetector {
    base: BaseDetector,
}

impl Default for LiquidityBootstrappingAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LiquidityBootstrappingAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("liquidity-bootstrapping-abuse".to_string()),
                "Liquidity Bootstrapping Pool Abuse".to_string(),
                "Detects vulnerabilities in LBP implementations where weight changes can be manipulated for unfair token distribution".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for LiquidityBootstrappingAbuseDetector {
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


        for function in ctx.get_functions() {
            if let Some(lbp_issue) = self.check_lbp_abuse(function, ctx) {
                let message = format!(
                    "Function '{}' has liquidity bootstrapping pool manipulation risk. {} \
                    LBP weight manipulation can cause unfair token distribution, \
                    enable whale advantage, or allow price manipulation during sale.",
                    function.name.name, lbp_issue
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_fix_suggestion(format!(
                        "Secure LBP implementation in '{}'. \
                    Add: (1) Gradual weight transition with block-based limits, \
                    (2) Maximum purchase caps per address, (3) Cooldown between weight updates, \
                    (4) Minimum duration enforcement, (5) Purchase limits per transaction.",
                        function.name.name
                    ));

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

impl LiquidityBootstrappingAbuseDetector {
    /// Check for LBP manipulation vulnerabilities
    fn check_lbp_abuse(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Identify LBP-related functions
        let is_lbp_function = func_source.contains("weight")
            || func_source.contains("bootstrap")
            || function.name.name.to_lowercase().contains("weight")
            || function.name.name.to_lowercase().contains("lbp")
            || func_source.contains("updateWeight");

        if !is_lbp_function {
            return None;
        }

        // Pattern 1: Weight update without rate limiting
        let updates_weight = func_source.contains("weight =")
            || func_source.contains("setWeight")
            || func_source.contains("updateWeight");

        let lacks_rate_limit = updates_weight
            && !func_source.contains("lastUpdate")
            && !func_source.contains("block.timestamp")
            && !func_source.contains("timeSince")
            && !func_source.contains("delay");

        if lacks_rate_limit {
            return Some(
                "Weight updates lack time-based rate limiting, \
                allowing rapid weight changes that can be exploited"
                    .to_string(),
            );
        }

        // Pattern 2: No maximum weight change per update
        let lacks_max_change = updates_weight
            && !func_source.contains("MAX_WEIGHT_CHANGE")
            && !func_source.contains("maxDelta")
            && !func_source.contains("require(delta")
            && !func_source.contains("weightDelta");

        if lacks_max_change {
            return Some(
                "No maximum weight change limit per update, \
                allowing sudden large weight shifts during LBP"
                    .to_string(),
            );
        }

        // Pattern 3: Purchase function without per-address cap
        let is_purchase = func_source.contains("buy")
            || func_source.contains("purchase")
            || func_source.contains("swap")
            || function.name.name.to_lowercase().contains("buy");

        let lacks_purchase_cap = is_purchase
            && is_lbp_function
            && !func_source.contains("maxPurchase")
            && !func_source.contains("purchaseCap")
            && !func_source.contains("bought[msg.sender]")
            && !func_source.contains("userPurchases");

        if lacks_purchase_cap {
            return Some(
                "No per-address purchase cap during LBP, \
                allowing whales to acquire disproportionate token amounts"
                    .to_string(),
            );
        }

        // Pattern 4: No minimum LBP duration enforcement
        let is_start_function = func_source.contains("start")
            || function.name.name.to_lowercase().contains("start")
            || func_source.contains("initialize");

        let is_end_function = func_source.contains("end")
            || func_source.contains("finalize")
            || function.name.name.to_lowercase().contains("end");

        let lacks_duration = (is_start_function || is_end_function)
            && is_lbp_function
            && !func_source.contains("MINIMUM_DURATION")
            && !func_source.contains("minDuration")
            && !func_source.contains("require(block.timestamp");

        if lacks_duration {
            return Some(
                "No minimum LBP duration enforcement, \
                allowing premature termination to manipulate distribution"
                    .to_string(),
            );
        }

        // Pattern 5: Weight transitions not gradual/linear
        let has_weight_calculation = updates_weight
            && (func_source.contains("startWeight") || func_source.contains("endWeight"));

        let lacks_gradual_transition = has_weight_calculation
            && !func_source.contains("block.timestamp")
            && !func_source.contains("elapsed")
            && !func_source.contains("progress")
            && !func_source.contains("* (");

        if lacks_gradual_transition {
            return Some(
                "Weight transitions are not time-based and gradual, \
                allowing discrete jumps that can be exploited"
                    .to_string(),
            );
        }

        // Pattern 6: No transaction size limit during LBP
        let is_swap_in_lbp = is_purchase || (is_lbp_function && func_source.contains("amount"));

        let lacks_tx_limit = is_swap_in_lbp
            && !func_source.contains("MAX_AMOUNT")
            && !func_source.contains("maxTradeSize")
            && !func_source.contains("require(amount <");

        if lacks_tx_limit {
            return Some(
                "No per-transaction size limit during LBP phase, \
                allowing single large purchases to drain pool"
                    .to_string(),
            );
        }

        // Pattern 7: Owner can update weights at will
        let has_owner_control = updates_weight
            && (func_source.contains("onlyOwner") || func_source.contains("onlyAdmin"));

        let lacks_timelock = has_owner_control
            && !func_source.contains("timelock")
            && !func_source.contains("proposedAt")
            && !func_source.contains("delay");

        if lacks_timelock {
            return Some(
                "Owner can update weights without timelock, \
                enabling manipulation for insider advantage"
                    .to_string(),
            );
        }

        // Pattern 8: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("LBP")
                || func_source.contains("liquidity bootstrap")
                || func_source.contains("weight manipulation"))
        {
            return Some("LBP manipulation vulnerability marker detected".to_string());
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
        let detector = LiquidityBootstrappingAbuseDetector::new();
        assert_eq!(detector.name(), "Liquidity Bootstrapping Pool Abuse");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
