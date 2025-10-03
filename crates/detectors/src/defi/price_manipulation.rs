use crate::types::{DetectorResult, AnalysisContext, Severity, Finding, DetectorId, Confidence, SourceLocation};
use ast::Function;
use crate::defi::{DeFiDetector, DeFiPatterns};

/// Detector for price manipulation vulnerabilities
pub struct PriceManipulationDetector;

impl DeFiDetector for PriceManipulationDetector {
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Only analyze contracts with oracle dependencies or pricing logic
        if !DeFiPatterns::has_oracle_dependencies(ctx) {
            return results;
        }

        results.extend(self.detect_single_oracle_dependency(ctx));
        results.extend(self.detect_spot_price_usage(ctx));
        results.extend(self.detect_insufficient_price_validation(ctx));
        results.extend(self.detect_oracle_manipulation_risks(ctx));
        results.extend(self.detect_price_staleness_issues(ctx));
        results.extend(self.detect_decimal_precision_issues(ctx));

        results
    }

    fn name(&self) -> &'static str {
        "price-manipulation-detector"
    }

    fn description(&self) -> &'static str {
        "Detects vulnerabilities related to price manipulation and oracle usage"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool {
        DeFiPatterns::has_oracle_dependencies(ctx) || self.has_pricing_logic(ctx)
    }
}

impl PriceManipulationDetector {
    /// Detect contracts relying on a single oracle
    fn detect_single_oracle_dependency(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.uses_single_oracle(ctx, func) && !self.has_oracle_redundancy(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::High,
                    format!(
                        "Function '{}' relies on a single price oracle without redundancy. \
                        This creates a single point of failure that could be exploited \
                        through oracle manipulation or failure.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(20);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Multiple oracle calls increase gas costs".to_string())
                    .with_suggested_fix(
                        "Implement multiple oracle sources with price aggregation and deviation checks".to_string()
                    ));
            }
        }

        results
    }

    /// Detect usage of spot prices instead of time-weighted averages
    fn detect_spot_price_usage(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.uses_spot_price(ctx, func) && !self.has_twap_protection(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::High,
                    format!(
                        "Function '{}' uses spot prices which can be manipulated within a single transaction. \
                        This allows attackers to temporarily manipulate prices for profit.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - TWAP calculations require additional storage and computation".to_string())
                    .with_suggested_fix(
                        "Use Time-Weighted Average Price (TWAP) or other manipulation-resistant pricing mechanisms".to_string()
                    ));
            }
        }

        results
    }

    /// Detect insufficient price validation
    fn detect_insufficient_price_validation(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.uses_price_data(ctx, func) {
                let mut validation_issues = Vec::new();

                if !self.validates_price_bounds(ctx, func) {
                    validation_issues.push("Missing price bounds validation");
                }

                if !self.validates_price_freshness(ctx, func) {
                    validation_issues.push("Missing price freshness validation");
                }

                if !self.handles_oracle_failures(ctx, func) {
                    validation_issues.push("Missing oracle failure handling");
                }

                if !validation_issues.is_empty() {
                    let finding = Finding::new(
                        DetectorId::new(self.name()),
                        Severity::Medium,
                        Confidence::Medium,
                        format!(
                            "Function '{}' has insufficient price validation: {}",
                            func.name.as_str(),
                            validation_issues.join(", ")
                        ),
                        SourceLocation::new(
                            ctx.file_path.clone(),
                            func.location.start().line() as u32,
                            0,
                            func.name.as_str().len() as u32,
                        ),
                    ).with_cwe(20);

                    results.push(DetectorResult::new(finding)
                        .with_gas_impact("Low - Validation checks are gas-efficient".to_string())
                        .with_suggested_fix(
                            "Add comprehensive price validation including bounds checking, \
                            freshness validation, and oracle failure handling".to_string()
                        ));
                }
            }
        }

        results
    }

    /// Detect oracle manipulation risks
    fn detect_oracle_manipulation_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_vulnerable_to_oracle_manipulation(ctx, func) {
                let manipulation_type = self.classify_manipulation_risk(ctx, func);

                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' is vulnerable to oracle manipulation. {}",
                        func.name.as_str(),
                        self.get_manipulation_description(&manipulation_type)
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Variable - Depends on manipulation complexity".to_string())
                    .with_suggested_fix(self.get_manipulation_mitigation(&manipulation_type)));
            }
        }

        results
    }

    /// Detect price staleness issues
    fn detect_price_staleness_issues(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.uses_potentially_stale_prices(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' may use stale price data without proper freshness checks. \
                        This could lead to incorrect pricing decisions during oracle outages.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(20);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Low - Timestamp checks are gas-efficient".to_string())
                    .with_suggested_fix(
                        "Implement timestamp-based freshness checks and fallback mechanisms \
                        for stale price data".to_string()
                    ));
            }
        }

        results
    }

    /// Detect decimal precision issues in price calculations
    fn detect_decimal_precision_issues(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.has_decimal_precision_risks(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' performs price calculations that may suffer from \
                        precision loss or decimal mismatches between different tokens/oracles.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(681);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Low - Precision handling is computationally efficient".to_string())
                    .with_suggested_fix(
                        "Normalize decimal places, use fixed-point arithmetic, or implement \
                        proper scaling for price calculations".to_string()
                    ));
            }
        }

        results
    }

    // Helper methods for price manipulation detection

    fn has_pricing_logic(&self, ctx: &AnalysisContext) -> bool {
        let pricing_indicators = [
            "price", "rate", "exchange", "oracle", "feed", "aggregator"
        ];
        pricing_indicators.iter().any(|&indicator|
            ctx.source.to_lowercase().contains(indicator)
        )
    }

    fn uses_single_oracle(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let oracle_patterns = [
            "getPrice", "latestRoundData", "latestAnswer", "aggregator"
        ];
        oracle_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn has_oracle_redundancy(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let redundancy_patterns = [
            "oracle1", "oracle2", "primaryOracle", "secondaryOracle",
            "median", "average", "aggregate", "multiple"
        ];
        redundancy_patterns.iter().any(|&pattern|
            ctx.source.to_lowercase().contains(pattern)
        )
    }

    fn uses_spot_price(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let spot_price_patterns = [
            "getReserves", "balanceOf", "currentPrice", "spotPrice"
        ];
        spot_price_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn has_twap_protection(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let twap_patterns = [
            "TWAP", "timeWeighted", "average", "period", "window"
        ];
        twap_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn uses_price_data(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let price_usage_patterns = [
            "price", "rate", "latestRoundData", "getPrice"
        ];
        price_usage_patterns.iter().any(|&pattern|
            func.name.as_str().contains(pattern) || ctx.source.contains(pattern)
        )
    }

    fn validates_price_bounds(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let bounds_patterns = [
            "require(price >", "require(price <", "minPrice", "maxPrice",
            "bounds", "range", "sanity"
        ];
        bounds_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn validates_price_freshness(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let freshness_patterns = [
            "updatedAt", "timestamp", "stale", "fresh", "timeout"
        ];
        freshness_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn handles_oracle_failures(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let failure_handling_patterns = [
            "try", "catch", "fallback", "emergency", "paused"
        ];
        failure_handling_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }

    fn is_vulnerable_to_oracle_manipulation(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        self.uses_price_data(ctx, func) &&
        (self.uses_spot_price(ctx, func) || !self.has_oracle_redundancy(ctx, func))
    }

    fn classify_manipulation_risk(&self, ctx: &AnalysisContext, func: &Function) -> String {
        if self.uses_spot_price(ctx, func) {
            "Flash loan price manipulation".to_string()
        } else if !self.has_oracle_redundancy(ctx, func) {
            "Single oracle manipulation".to_string()
        } else {
            "General price manipulation".to_string()
        }
    }

    fn get_manipulation_description(&self, manipulation_type: &str) -> String {
        match manipulation_type {
            "Flash loan price manipulation" =>
                "Spot prices can be manipulated within a single transaction using flash loans".to_string(),
            "Single oracle manipulation" =>
                "Reliance on a single oracle creates vulnerability to oracle attacks".to_string(),
            _ =>
                "Price data can be manipulated to exploit the contract".to_string(),
        }
    }

    fn get_manipulation_mitigation(&self, manipulation_type: &str) -> String {
        match manipulation_type {
            "Flash loan price manipulation" =>
                "Use TWAP or other time-weighted pricing mechanisms".to_string(),
            "Single oracle manipulation" =>
                "Implement multiple oracle sources with price aggregation".to_string(),
            _ =>
                "Implement robust price validation and manipulation resistance".to_string(),
        }
    }

    fn uses_potentially_stale_prices(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        self.uses_price_data(ctx, func) && !self.validates_price_freshness(ctx, func)
    }

    fn has_decimal_precision_risks(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let precision_risk_patterns = [
            "decimals", "mul", "div", "/", "*", "scale", "precision"
        ];
        self.uses_price_data(ctx, func) &&
        precision_risk_patterns.iter().any(|&pattern|
            ctx.source.contains(pattern)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Contract, Function};
    use std::collections::HashMap;

    fn create_mock_context() -> AnalysisContext<'static> {
        AnalysisContext {
            contract: &Contract {
                name: "TestContract".to_string(),
                functions: Vec::new(),
                state_variables: Vec::new(),
                events: Vec::new(),
                modifiers: Vec::new(),
            },
            symbols: HashMap::new(),
            source_code: "".to_string(),
            file_path: "test.sol".to_string(),
        }
    }

    #[test]
    fn test_single_oracle_detection() {
        let detector = PriceManipulationDetector;

        let mut ctx = create_mock_context();
        ctx.source = "function getPrice() { return oracle.latestAnswer(); }".to_string();

        let func = Function {
            name: "getPrice".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.uses_single_oracle(&ctx, &func));
        assert!(!detector.has_oracle_redundancy(&ctx, &func));
    }

    #[test]
    fn test_spot_price_detection() {
        let detector = PriceManipulationDetector;

        let mut ctx = create_mock_context();
        ctx.source = "function swap() { (uint112 reserve0, uint112 reserve1,) = pair.getReserves(); }".to_string();

        let func = Function {
            name: "swap".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.uses_spot_price(&ctx, &func));
        assert!(!detector.has_twap_protection(&ctx, &func));
    }

    #[test]
    fn test_detector_properties() {
        let detector = PriceManipulationDetector;
        assert_eq!(detector.name(), "price-manipulation-detector");
        assert_eq!(detector.severity(), Severity::High);
        assert!(!detector.description().is_empty());
    }

    #[test]
    fn test_price_validation_detection() {
        let detector = PriceManipulationDetector;

        let mut ctx = create_mock_context();
        ctx.source = "function trade() { uint price = oracle.getPrice(); }".to_string();

        let func = Function {
            name: "trade".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.uses_price_data(&ctx, &func));
        assert!(!detector.validates_price_bounds(&ctx, &func));
        assert!(!detector.validates_price_freshness(&ctx, &func));
    }
}