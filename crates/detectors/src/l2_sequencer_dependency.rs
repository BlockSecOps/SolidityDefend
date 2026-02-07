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
///
/// False positive reduction (v1.10.15):
/// - Skip contracts with no L2 indicators (not deployed on L2)
/// - Detect contract-level sequencer uptime feed declarations
/// - Recognize comprehensive oracle validation patterns (staleness + answer + round checks)
/// - Skip internal/private helper functions that delegate to protected callers
/// - Detect grace period patterns after sequencer restart
/// - Use full contract scope for sequencer check detection instead of narrow window
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

    /// Check if the contract has any L2-specific indicators.
    /// Contracts without L2 indicators are general-purpose and should not be
    /// flagged for missing sequencer uptime checks.
    fn has_l2_indicators(&self, source: &str) -> bool {
        let l2_indicators = [
            "Arbitrum",
            "Optimism",
            "arbitrum",
            "optimism",
            "L2",
            "l2",
            "rollup",
            "sequencer",
            "SEQUENCER",
            "sequencerUptimeFeed",
            "isSequencerUp",
            "SequencerUptime",
            "L2_SEQUENCER",
            "0x4200",                                     // Optimism system addresses
            "0xFdB631F5EE196F0ed6FAa767959853A9F217697D", // Arbitrum sequencer feed
        ];

        for indicator in &l2_indicators {
            if source.contains(indicator) {
                return true;
            }
        }
        false
    }

    /// Check if the contract already has a sequencer uptime check anywhere.
    /// Uses full contract scope rather than a narrow window around each call.
    fn has_sequencer_uptime_check(&self, source: &str) -> bool {
        source.contains("sequencerUptimeFeed")
            || source.contains("isSequencerUp")
            || source.contains("SequencerUptime")
            || source.contains("L2_SEQUENCER")
            || source.contains("sequencer_uptime")
            || (source.contains("sequencer") && source.contains("latestRoundData"))
    }

    /// Check if the contract implements comprehensive Chainlink best-practice
    /// validation. Contracts that validate staleness, answer positivity, and
    /// round completeness are well-protected consumers and are less likely to
    /// be exploited even without an explicit sequencer check.
    fn has_comprehensive_oracle_validation(&self, source: &str) -> bool {
        // Check for staleness validation
        let has_staleness = (source.contains("updatedAt")
            && (source.contains("block.timestamp") || source.contains("stale")))
            || source.contains("StalePrice")
            || source.contains("STALENESS")
            || source.contains("MAX_STALENESS");

        // Check for answer positivity validation
        let has_answer_validation = source.contains("answer <= 0")
            || source.contains("answer < 0")
            || source.contains("price <= 0")
            || source.contains("price < 0")
            || source.contains("InvalidPrice")
            || source.contains("answer > 0")
            || source.contains("price > 0");

        // Check for round completeness validation
        let has_round_check = source.contains("answeredInRound")
            || source.contains("InvalidRound")
            || source.contains("roundId");

        // All three checks present = comprehensive validation
        has_staleness && has_answer_validation && has_round_check
    }

    /// Check if the function containing the oracle call is internal or private.
    /// Internal/private functions cannot be called externally and typically
    /// delegate to a protected public entry point.
    fn is_internal_or_private_function(&self, lines: &[&str], line_num: usize) -> bool {
        let func_start = self.find_function_start_line(lines, line_num);
        if func_start.is_none() {
            return false;
        }
        let func_start = func_start.unwrap();

        // Gather function signature (may span multiple lines until opening brace)
        let header_end = std::cmp::min(func_start + 8, lines.len());
        let mut header = String::new();
        for line in &lines[func_start..header_end] {
            header.push_str(line);
            header.push(' ');
            if line.contains('{') {
                break;
            }
        }

        let header_lower = header.to_lowercase();
        header_lower.contains(" internal ")
            || header_lower.contains(" internal\n")
            || header_lower.contains(" private ")
            || header_lower.contains(" private\n")
    }

    /// Check if the function containing the oracle call is a view or pure function.
    /// While view/pure functions can still return stale data, flagging them is
    /// lower priority since they do not modify state.
    fn is_view_or_pure_function(&self, lines: &[&str], line_num: usize) -> bool {
        let func_start = self.find_function_start_line(lines, line_num);
        if func_start.is_none() {
            return false;
        }
        let func_start = func_start.unwrap();

        // Gather function signature (may span multiple lines until opening brace)
        let header_end = std::cmp::min(func_start + 8, lines.len());
        let mut header = String::new();
        for line in &lines[func_start..header_end] {
            header.push_str(line);
            header.push(' ');
            if line.contains('{') {
                break;
            }
        }

        header.contains(" view ") || header.contains(" pure ")
    }

    /// Find oracle usage without sequencer check.
    /// Only flags contracts with L2 indicators that lack sequencer uptime checks.
    fn find_oracle_without_sequencer_check(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Phase 1: If the contract has no L2 indicators at all, it is a general-
        // purpose Chainlink consumer. Do not flag -- L2 sequencer checks are only
        // relevant for contracts deployed on L2 networks.
        if !self.has_l2_indicators(source) {
            return findings;
        }

        // Phase 2: If the contract already has a sequencer uptime check at the
        // contract level, all oracle calls are protected.
        if self.has_sequencer_uptime_check(source) {
            return findings;
        }

        // Phase 3: If the contract has comprehensive oracle validation (staleness +
        // answer + round checks) AND a grace period, the developer is clearly
        // security-aware. Skip to avoid noisy FPs on well-audited code.
        if self.has_comprehensive_oracle_validation(source) && self.has_grace_period(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for latestRoundData call
            if trimmed.contains("latestRoundData()") {
                // Phase 4: Skip internal/private helper functions -- they cannot
                // be called externally and rely on their public caller for checks.
                if self.is_internal_or_private_function(&lines, line_num) {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find L2-specific patterns without sequencer awareness
    fn find_l2_patterns(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        // Check for L2 indicators (strict set -- excludes "sequencer" since if
        // the contract mentions "sequencer" it likely already has the check)
        let l2_indicators = [
            "Arbitrum", "Optimism", "arbitrum", "optimism", "L2", "l2", "rollup",
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

        // If the contract already has a sequencer uptime check, skip
        if self.has_sequencer_uptime_check(source) {
            return None;
        }

        // If comprehensive oracle validation is present, skip
        if self.has_comprehensive_oracle_validation(source) {
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

    /// Check for grace period implementation after sequencer restart
    fn has_grace_period(&self, source: &str) -> bool {
        source.contains("GRACE_PERIOD")
            || source.contains("gracePeriod")
            || source.contains("grace_period")
            || source.contains("startedAt")
    }

    /// Find the line number where the containing function declaration starts
    fn find_function_start_line(&self, lines: &[&str], line_num: usize) -> Option<usize> {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return Some(i);
            }
            // Stop searching if we hit a contract/library/interface boundary
            if trimmed.starts_with("contract ")
                || trimmed.starts_with("library ")
                || trimmed.starts_with("interface ")
            {
                return None;
            }
        }
        None
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check contracts using Chainlink
        if !self.uses_chainlink(source) {
            return Ok(findings);
        }

        // Early exit: contracts with no L2 indicators are general-purpose
        // Chainlink consumers and should not be flagged.
        if !self.has_l2_indicators(source) {
            return Ok(findings);
        }

        // Early exit: contract already has sequencer uptime check
        if self.has_sequencer_uptime_check(source) {
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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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

        // Vulnerable: L2 contract without sequencer check
        let vulnerable = r#"
            // Arbitrum price oracle
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

        // Safe: has sequencer uptime feed check
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
    fn test_no_l2_indicators_skipped() {
        let detector = L2SequencerDependencyDetector::new();

        // General-purpose Chainlink consumer with no L2 indicators should NOT be flagged
        let general_consumer = r#"
            contract SafeChainlinkConsumer {
                AggregatorV3Interface public primaryOracle;
                uint256 public constant MAX_STALENESS = 3600;

                function getPrimaryPrice() public view returns (uint256) {
                    (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = primaryOracle.latestRoundData();
                    if (block.timestamp - updatedAt > MAX_STALENESS) { revert StalePrice(); }
                    if (answer <= 0) { revert InvalidPrice(); }
                    if (answeredInRound < roundId) { revert InvalidRound(); }
                    return uint256(answer);
                }
            }
        "#;
        let findings = detector.find_oracle_without_sequencer_check(general_consumer);
        assert!(
            findings.is_empty(),
            "Should not flag general-purpose Chainlink consumers without L2 indicators"
        );
    }

    #[test]
    fn test_comprehensive_validation_with_grace_period_skipped() {
        let detector = L2SequencerDependencyDetector::new();

        // L2 contract with comprehensive oracle validation + grace period
        let well_validated = r#"
            // Optimism oracle with full validation
            contract L2PriceOracle {
                AggregatorV3Interface public priceFeed;
                uint256 public constant GRACE_PERIOD = 3600;
                uint256 public constant MAX_STALENESS = 3600;

                function getPrice() public view returns (uint256) {
                    (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
                    if (block.timestamp - updatedAt > MAX_STALENESS) { revert StalePrice(); }
                    if (answer <= 0) { revert InvalidPrice(); }
                    if (answeredInRound < roundId) { revert InvalidRound(); }
                    return uint256(answer);
                }
            }
        "#;
        let findings = detector.find_oracle_without_sequencer_check(well_validated);
        assert!(
            findings.is_empty(),
            "Should not flag L2 contracts with comprehensive oracle validation and grace period"
        );
    }

    #[test]
    fn test_internal_function_skipped() {
        let detector = L2SequencerDependencyDetector::new();

        // L2 contract where oracle call is in an internal function
        let internal_helper = r#"
            // Arbitrum internal helper
            contract L2PriceOracle {
                AggregatorV3Interface public priceFeed;

                function _getPrice() internal view returns (uint256) {
                    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
                    require(block.timestamp - updatedAt < 3600, "Stale");
                    return uint256(price);
                }
            }
        "#;
        let findings = detector.find_oracle_without_sequencer_check(internal_helper);
        assert!(findings.is_empty(), "Should not flag internal functions");
    }

    #[test]
    fn test_has_l2_indicators() {
        let detector = L2SequencerDependencyDetector::new();

        assert!(detector.has_l2_indicators("// Deployed on Arbitrum"));
        assert!(detector.has_l2_indicators("// Optimism oracle"));
        assert!(detector.has_l2_indicators("// L2 deployment"));
        assert!(detector.has_l2_indicators("sequencerUptimeFeed"));
        assert!(!detector.has_l2_indicators("contract SimpleOracle {}"));
    }

    #[test]
    fn test_has_grace_period() {
        let detector = L2SequencerDependencyDetector::new();

        assert!(detector.has_grace_period("uint256 constant GRACE_PERIOD = 3600;"));
        assert!(detector.has_grace_period("require(timeSinceUp > gracePeriod);"));
        assert!(!detector.has_grace_period("contract Simple {}"));
    }

    #[test]
    fn test_has_comprehensive_oracle_validation() {
        let detector = L2SequencerDependencyDetector::new();

        // Has all three: staleness, answer validation, round check
        let comprehensive = r#"
            if (block.timestamp - updatedAt > MAX_STALENESS) { revert StalePrice(); }
            if (answer <= 0) { revert InvalidPrice(); }
            if (answeredInRound < roundId) { revert InvalidRound(); }
        "#;
        assert!(detector.has_comprehensive_oracle_validation(comprehensive));

        // Missing round check
        let partial = r#"
            if (block.timestamp - updatedAt > MAX_STALENESS) { revert StalePrice(); }
            if (answer <= 0) { revert InvalidPrice(); }
        "#;
        assert!(!detector.has_comprehensive_oracle_validation(partial));

        // No validation at all
        assert!(!detector.has_comprehensive_oracle_validation("contract Simple {}"));
    }
}
