use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for stale oracle price data vulnerabilities
pub struct PriceOracleStaleDetector {
    base: BaseDetector,
}

impl Default for PriceOracleStaleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceOracleStaleDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("price-oracle-stale".to_string()),
                "Stale Price Oracle Data".to_string(),
                "Detects missing staleness checks on oracle price feeds that could lead to using outdated price data".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for PriceOracleStaleDetector {
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
            if let Some(oracle_issue) = self.check_stale_oracle(function, ctx) {
                let message = format!(
                    "Function '{}' uses oracle price data without staleness validation. {} \
                    Using stale oracle data can lead to incorrect liquidations, price manipulations, and financial losses.",
                    function.name.name, oracle_issue
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
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(672) // CWE-672: Operation on a Resource after Expiration or Release
                    .with_fix_suggestion(format!(
                        "Add staleness checks in '{}'. \
                    Implement: (1) Check oracle updatedAt timestamp, \
                    (2) Verify data freshness with block.timestamp comparison, \
                    (3) Add HEARTBEAT_THRESHOLD constant (e.g., 3600 seconds), \
                    (4) Revert if price is too old, \
                    (5) Consider Chainlink's latestRoundData() with timestamp validation.",
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

impl PriceOracleStaleDetector {
    fn check_stale_oracle(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Oracle call without timestamp/staleness check
        let has_oracle_call = func_source.contains("getPrice")
            || func_source.contains("latestAnswer")
            || func_source.contains("latestRoundData");

        let has_staleness_check = func_source.contains("updatedAt")
            || func_source.contains("timestamp")
            || func_source.contains("HEARTBEAT")
            || func_source.contains("MAX_AGE")
            || func_source.contains("STALE");

        if has_oracle_call && !has_staleness_check {
            return Some(
                "Oracle price fetch without staleness validation. \
                Missing checks for updatedAt timestamp, price age, or heartbeat threshold"
                    .to_string(),
            );
        }

        // Pattern 2: Using stored price without checking lastUpdate
        let uses_stored_price = func_source.contains("lastPrice")
            || func_source.contains("cachedPrice")
            || func_source.contains("storedPrice");

        let checks_last_update = func_source.contains("lastUpdate")
            && (func_source.contains("block.timestamp") || func_source.contains("require"));

        if uses_stored_price && !checks_last_update {
            return Some(
                "Uses stored oracle price without verifying lastUpdate timestamp. \
                Price may be stale and cause incorrect calculations"
                    .to_string(),
            );
        }

        // Pattern 3: getPrice() without latestRoundData() timestamp validation
        if func_source.contains("getPrice()")
            && !func_source.contains("latestRoundData")
            && !func_source.contains("updatedAt")
        {
            return Some(
                "Uses simplified getPrice() without fetching round metadata. \
                Should use latestRoundData() to access updatedAt timestamp"
                    .to_string(),
            );
        }

        None
    }

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
        let detector = PriceOracleStaleDetector::new();
        assert_eq!(detector.name(), "Stale Price Oracle Data");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
