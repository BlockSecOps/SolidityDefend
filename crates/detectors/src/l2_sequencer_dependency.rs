use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for L2 sequencer dependency vulnerabilities
///
/// Detects contracts that use Chainlink price feeds on L2 without checking
/// sequencer uptime. During sequencer downtime, stale prices can be exploited.
///
/// Vulnerable pattern:
/// ```solidity
/// function getPrice() external view returns (uint256) {
///     (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
///     // Missing: Check if sequencer is up
///     return uint256(price);
/// }
/// ```
pub struct L2SequencerDependencyDetector {
    base: BaseDetector,
}

impl Default for L2SequencerDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2SequencerDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-sequencer-dependency"),
                "L2 Sequencer Dependency".to_string(),
                "Detects Chainlink price feed usage on L2s without sequencer uptime checks. \
                 During sequencer downtime, stale prices can be exploited for arbitrage or \
                 liquidations at incorrect prices."
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract uses Chainlink feeds
    fn uses_chainlink(&self, source: &str) -> bool {
        source.contains("latestRoundData")
            || source.contains("AggregatorV3Interface")
            || source.contains("AggregatorV2V3Interface")
            || source.contains("priceFeed")
    }

    /// Find oracle usage without sequencer check
    fn find_oracle_without_sequencer_check(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for latestRoundData call
            if trimmed.contains("latestRoundData()") {
                // Get surrounding context
                let context_start = if line_num > 20 { line_num - 20 } else { 0 };
                let context_end = std::cmp::min(line_num + 20, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Check for sequencer uptime check
                let has_sequencer_check = context.contains("sequencerUptimeFeed")
                    || context.contains("sequencer")
                    || context.contains("SEQUENCER")
                    || context.contains("isSequencerUp")
                    || context.contains("SequencerUptime")
                    || context.contains("L2_SEQUENCER");

                // Also check for staleness check
                let has_staleness_check = context.contains("updatedAt")
                    && (context.contains("block.timestamp") || context.contains("stale"));

                if !has_sequencer_check {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find L2-specific patterns without sequencer awareness
    fn find_l2_patterns(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        // Check for L2 indicators
        let l2_indicators = [
            "Arbitrum",
            "Optimism",
            "arbitrum",
            "optimism",
            "L2",
            "l2",
            "rollup",
            "0x4200", // Optimism system addresses
        ];

        let mut is_l2 = false;
        for line in &lines {
            for indicator in &l2_indicators {
                if line.contains(indicator) {
                    is_l2 = true;
                    break;
                }
            }
        }

        if !is_l2 {
            return None;
        }

        // Check if uses oracle without sequencer check
        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("latestRoundData") {
                let context: String = lines.join("\n");
                if !context.contains("sequencer") && !context.contains("SEQUENCER") {
                    return Some(line_num as u32 + 1);
                }
            }
        }

        None
    }

    /// Check for grace period implementation
    fn has_grace_period(&self, source: &str) -> bool {
        source.contains("GRACE_PERIOD")
            || source.contains("gracePeriod")
            || source.contains("grace_period")
            || source.contains("startedAt")
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for L2SequencerDependencyDetector {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check contracts using Chainlink
        if !self.uses_chainlink(source) {
            return Ok(findings);
        }

        // Check for oracle usage without sequencer check
        let oracle_usages = self.find_oracle_without_sequencer_check(source);
        for (line, func_name) in &oracle_usages {
            let message = format!(
                "Function '{}' in contract '{}' uses Chainlink oracle without checking L2 \
                 sequencer uptime. During sequencer downtime, the price feed continues returning \
                 stale prices, allowing exploitation through arbitrage or unfair liquidations.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 30)
                .with_cwe(662) // CWE-662: Improper Synchronization
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add sequencer uptime check for L2 deployments:\n\n\
                     // Sequencer uptime feed (Arbitrum/Optimism specific)\n\
                     AggregatorV3Interface public sequencerUptimeFeed;\n\n\
                     function getPrice() public view returns (uint256) {\n\
                         // Check sequencer is up\n\
                         (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();\n\
                         bool isSequencerUp = answer == 0;\n\
                         require(isSequencerUp, \"Sequencer is down\");\n\n\
                         // Check grace period after sequencer restart\n\
                         uint256 timeSinceUp = block.timestamp - startedAt;\n\
                         require(timeSinceUp > GRACE_PERIOD_TIME, \"Grace period not over\");\n\n\
                         // Now get price\n\
                         (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();\n\
                         require(block.timestamp - updatedAt < STALENESS_THRESHOLD, \"Stale price\");\n\
                         return uint256(price);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for L2-specific patterns
        if let Some(line) = self.find_l2_patterns(source) {
            // Only add if not already reported
            if !oracle_usages.iter().any(|(l, _)| *l == line) {
                let message = format!(
                    "Contract '{}' appears to be designed for L2 but doesn't implement \
                     sequencer uptime checks. L2 sequencers can go offline, causing price \
                     feed staleness issues.",
                    contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 30)
                    .with_cwe(662) // CWE-662: Improper Synchronization
                    .with_confidence(Confidence::Low)
                    .with_fix_suggestion(
                        "Implement L2 sequencer uptime feed check before using oracle data."
                            .to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = L2SequencerDependencyDetector::new();
        assert_eq!(detector.name(), "L2 Sequencer Dependency");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_uses_chainlink() {
        let detector = L2SequencerDependencyDetector::new();

        assert!(detector.uses_chainlink("priceFeed.latestRoundData()"));
        assert!(detector.uses_chainlink("AggregatorV3Interface priceFeed;"));
        assert!(!detector.uses_chainlink("contract Simple {}"));
    }

    #[test]
    fn test_missing_sequencer_check() {
        let detector = L2SequencerDependencyDetector::new();

        let vulnerable = r#"
            contract PriceOracle {
                AggregatorV3Interface public priceFeed;

                function getPrice() public view returns (uint256) {
                    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
                    require(block.timestamp - updatedAt < 3600, "Stale");
                    return uint256(price);
                }
            }
        "#;
        let findings = detector.find_oracle_without_sequencer_check(vulnerable);
        assert!(!findings.is_empty());

        let safe = r#"
            contract PriceOracle {
                AggregatorV3Interface public priceFeed;
                AggregatorV3Interface public sequencerUptimeFeed;

                function getPrice() public view returns (uint256) {
                    (, int256 answer, , , ) = sequencerUptimeFeed.latestRoundData();
                    require(answer == 0, "Sequencer down");
                    (, int256 price, , , ) = priceFeed.latestRoundData();
                    return uint256(price);
                }
            }
        "#;
        let findings = detector.find_oracle_without_sequencer_check(safe);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_has_grace_period() {
        let detector = L2SequencerDependencyDetector::new();

        assert!(detector.has_grace_period("uint256 constant GRACE_PERIOD = 3600;"));
        assert!(detector.has_grace_period("require(timeSinceUp > gracePeriod);"));
        assert!(!detector.has_grace_period("contract Simple {}"));
    }
}
