use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::oracle_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

// ---------------------------------------------------------------------------
// 1. ChainlinkStalePriceDetector
// ---------------------------------------------------------------------------

/// Detector for Chainlink `latestRoundData()` calls without staleness checks.
///
/// Stale price data from Chainlink can cause incorrect valuations, enabling
/// exploits in lending, trading, and liquidation functions. Contracts must
/// compare `updatedAt` against `block.timestamp` or verify `answeredInRound`.
pub struct ChainlinkStalePriceDetector {
    base: BaseDetector,
}

impl Default for ChainlinkStalePriceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainlinkStalePriceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("chainlink-stale-price"),
                "Chainlink Stale Price Data".to_string(),
                "Detects Chainlink latestRoundData() calls without staleness \
                 checks, which can return outdated prices and lead to incorrect \
                 valuations or exploitable arbitrage."
                    .to_string(),
                vec![DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }

    /// Scan the full source for `latestRoundData()` usage without staleness
    /// validation.  Returns a list of (1-based line number, description).
    fn find_stale_price_issues(&self, source: &str) -> Vec<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let lower_source = source.to_lowercase();

        // If the source does not contain latestRoundData at all, nothing to do.
        if !lower_source.contains("latestrounddata") {
            return Vec::new();
        }

        // Check whether the contract already has a staleness check anywhere.
        // We consider the following patterns as adequate:
        //   - block.timestamp - updatedAt  (or block.timestamp.sub(updatedAt))
        //   - updatedAt + <something>  (heartbeat comparison)
        //   - answeredInRound >= roundId   (round-completeness check)
        //   - stalePrice / STALENESS / HEARTBEAT / heartbeat / maxDelay
        let has_staleness_check = lower_source.contains("block.timestamp - updatedat")
            || lower_source.contains("block.timestamp.sub(updatedat")
            || lower_source.contains("updatedat +")
            || lower_source.contains("updatedat >=")
            || lower_source.contains("answeredinround >= roundid")
            || lower_source.contains("answeredinround == roundid")
            || lower_source.contains("staleprice")
            || lower_source.contains("staleness")
            || lower_source.contains("heartbeat")
            || lower_source.contains("maxdelay")
            || lower_source.contains("max_delay")
            || lower_source.contains("price_staleness")
            || lower_source.contains("stale_threshold");

        if has_staleness_check {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            if trimmed.contains("latestRoundData") {
                findings.push((
                    (idx + 1) as u32,
                    format!(
                        "latestRoundData() called without staleness check on line {}. \
                         The returned price may be stale if the Chainlink feed has not \
                         been updated recently.",
                        idx + 1
                    ),
                ));
            }
        }

        findings
    }
}

impl Detector for ChainlinkStalePriceDetector {
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

        // FP Reduction: Skip interface and test contracts
        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        for (line, description) in self.find_stale_price_issues(source) {
            let finding = self
                .base
                .create_finding(ctx, description, line, 1, 50)
                .with_cwe(754) // CWE-754: Improper Check for Unusual or Exceptional Conditions
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add a staleness check after calling latestRoundData():\n\n\
                     (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = \
                     priceFeed.latestRoundData();\n\
                     require(answer > 0, \"Negative price\");\n\
                     require(updatedAt > 0, \"Round incomplete\");\n\
                     require(block.timestamp - updatedAt <= MAX_STALENESS, \"Stale price\");\n\
                     require(answeredInRound >= roundId, \"Stale round\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 2. ChainlinkSequencerCheckDetector
// ---------------------------------------------------------------------------

/// Detector for L2 Chainlink usage without Sequencer Uptime Feed check.
///
/// On L2 networks (Arbitrum, Optimism), the sequencer can go offline, causing
/// Chainlink price feeds to return stale data. Contracts must check the
/// sequencer uptime feed before relying on price data.
pub struct ChainlinkSequencerCheckDetector {
    base: BaseDetector,
}

impl Default for ChainlinkSequencerCheckDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainlinkSequencerCheckDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("chainlink-sequencer-check"),
                "Missing Chainlink L2 Sequencer Check".to_string(),
                "Detects Chainlink oracle usage on L2 networks without \
                 Sequencer Uptime Feed validation. When the sequencer is down, \
                 prices may be stale and exploitable."
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::L2],
                Severity::Medium,
            ),
        }
    }

    /// Detect L2 Chainlink usage without sequencer uptime check.
    fn find_missing_sequencer_checks(&self, source: &str) -> Vec<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let lower_source = source.to_lowercase();

        // Must use latestRoundData to be relevant
        if !lower_source.contains("latestrounddata") {
            return Vec::new();
        }

        // Must reference L2-related terms
        let l2_terms = [
            "arbitrum",
            "optimism",
            "l2",
            "layer2",
            "layer 2",
            "sequencer",
            "l2_",
        ];
        let has_l2_context = l2_terms.iter().any(|term| lower_source.contains(term));
        if !has_l2_context {
            return Vec::new();
        }

        // Check if contract already validates sequencer uptime
        let has_sequencer_check = lower_source.contains("sequenceruptimefeed")
            || lower_source.contains("sequencer_uptime_feed")
            || lower_source.contains("issequencerup")
            || lower_source.contains("is_sequencer_up")
            || lower_source.contains("sequenceruptime")
            || lower_source.contains("sequencer_uptime")
            || lower_source.contains("sequencerfeed");

        if has_sequencer_check {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            if trimmed.contains("latestRoundData") {
                findings.push((
                    (idx + 1) as u32,
                    format!(
                        "latestRoundData() called in an L2-aware contract on line {} \
                         without Sequencer Uptime Feed validation. If the L2 sequencer \
                         goes offline, Chainlink feeds may serve stale prices.",
                        idx + 1
                    ),
                ));
            }
        }

        findings
    }
}

impl Detector for ChainlinkSequencerCheckDetector {
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

        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        for (line, description) in self.find_missing_sequencer_checks(source) {
            let finding = self
                .base
                .create_finding(ctx, description, line, 1, 50)
                .with_cwe(754) // CWE-754: Improper Check for Unusual or Exceptional Conditions
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add a Sequencer Uptime Feed check before using Chainlink on L2:\n\n\
                     (, int256 answer, , uint256 startedAt, ) = \
                     sequencerUptimeFeed.latestRoundData();\n\
                     bool isSequencerUp = answer == 0;\n\
                     require(isSequencerUp, \"Sequencer is down\");\n\
                     require(block.timestamp - startedAt > GRACE_PERIOD, \"Grace period not over\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 3. OracleSingleSourceDetector
// ---------------------------------------------------------------------------

/// Detector for price reliance on a single oracle without fallback.
///
/// Relying on a single oracle introduces a single point of failure. If the
/// oracle goes offline or is compromised, the contract has no backup. Best
/// practice is to use multiple oracles with fallback logic or try/catch.
pub struct OracleSingleSourceDetector {
    base: BaseDetector,
}

impl Default for OracleSingleSourceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleSingleSourceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("oracle-single-source"),
                "Single Oracle Source Without Fallback".to_string(),
                "Detects reliance on a single price oracle without fallback \
                 logic. A single oracle failure or compromise can halt or \
                 exploit the protocol."
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Detect oracle usage that lacks fallback mechanisms.
    fn find_single_source_issues(&self, source: &str) -> Vec<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let lower_source = source.to_lowercase();

        // Must use some kind of price oracle call
        let oracle_call_patterns = [
            "getprice",
            "latestanswer",
            "latestrounddata",
            "getlatestprice",
            "fetchprice",
            "consultoracle",
        ];

        let has_oracle_call = oracle_call_patterns
            .iter()
            .any(|pat| lower_source.contains(pat));

        if !has_oracle_call {
            return Vec::new();
        }

        // Gate 1: Require actual oracle infrastructure — plain getPrice() function
        // names alone are not enough evidence of oracle dependency. Require
        // well-known oracle interfaces or Chainlink-specific call patterns.
        let oracle_infra = [
            "aggregatorv3interface",
            "aggregatorinterface",
            "ipricefeed",
            "ioracle",
            "ichainlinkoracle",
            "chainlinkfeed",
            "priceconsumer",
            "latestrounddata",
            "latestanswer",
        ];

        let has_infra = oracle_infra.iter().any(|pat| lower_source.contains(pat));
        if !has_infra {
            return Vec::new();
        }

        // Gate 3: Check whether the contract has fallback / redundancy patterns (expanded)
        let fallback_indicators = [
            "fallback",
            "fallbackoracle",
            "fallback_oracle",
            "secondary",
            "secondaryoracle",
            "secondary_oracle",
            "backup",
            "backuporacle",
            "backup_oracle",
            "try {",
            "try{",
            "catch (",
            "catch(",
            "primaryoracle",
            "primary_oracle",
            "oraclefallback",
            "oracle_fallback",
            // Configurable oracle patterns (can add fallback later)
            "oracleaddress",
            "priceoracle",
            "setoracle",
            "updateoracle",
            "setoraclesource",
            // Array-based multi-source patterns
            "pricefeeds[",
            "oracles[",
        ];

        let has_fallback = fallback_indicators
            .iter()
            .any(|pat| lower_source.contains(pat));

        if has_fallback {
            return Vec::new();
        }

        // Chainlink + staleness validation is safe enough
        if (lower_source.contains("chainlink") || lower_source.contains("aggregatorv3"))
            && (lower_source.contains("staleness")
                || lower_source.contains("heartbeat")
                || lower_source.contains("updatedat")
                || lower_source.contains("stale"))
        {
            return Vec::new();
        }

        // Deviation bounds near oracle/price = safety check
        if lower_source.contains("deviation")
            && (lower_source.contains("oracle") || lower_source.contains("price"))
        {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Find actual oracle call lines
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            let lower_line = trimmed.to_lowercase();
            let has_call = oracle_call_patterns
                .iter()
                .any(|pat| lower_line.contains(pat));

            if has_call {
                // Skip function declarations — we want actual call sites, not definitions
                if lower_line.contains("function ") {
                    continue;
                }

                // Gate 4: Skip oracle calls in view/pure functions (read-only = no exploit path)
                if Self::is_in_view_or_pure_function(&lines, idx) {
                    continue;
                }

                findings.push((
                    (idx + 1) as u32,
                    format!(
                        "Oracle price query on line {} uses a single source without \
                         fallback logic. If this oracle becomes unavailable or returns \
                         incorrect data, the contract has no recovery path.",
                        idx + 1
                    ),
                ));
            }
        }

        findings
    }

    /// Check if a given line is inside a view or pure function.
    fn is_in_view_or_pure_function(lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                // Check the function signature lines for view/pure modifiers
                let end = (i + 5).min(lines.len()).min(line_num + 1);
                for j in i..end {
                    let lower_line = lines[j].to_lowercase();
                    if lower_line.contains(" view")
                        || lower_line.contains(" pure")
                        || lower_line.contains(")view")
                        || lower_line.contains(")pure")
                    {
                        return true;
                    }
                    // Stop at function body start (but not on the same line as function keyword)
                    if j > i && lines[j].contains('{') {
                        break;
                    }
                }
                return false;
            }
            // Stop at contract/interface boundary
            if trimmed.starts_with("contract ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("library ")
            {
                break;
            }
        }
        false
    }
}

impl Detector for OracleSingleSourceDetector {
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

        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Gate 2: Use safe_patterns library — skip if contract already has safe oracle patterns
        if oracle_patterns::has_multi_oracle_validation(ctx) {
            return Ok(findings);
        }
        if oracle_patterns::is_safe_oracle_consumer(ctx) {
            return Ok(findings);
        }
        if oracle_patterns::has_twap_oracle(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        for (line, description) in self.find_single_source_issues(source) {
            let finding = self
                .base
                .create_finding(ctx, description, line, 1, 50)
                .with_cwe(754) // CWE-754: Improper Check for Unusual or Exceptional Conditions
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Implement oracle fallback logic with multiple price sources:\n\n\
                     function getPrice() internal view returns (uint256) {\n\
                         try primaryOracle.latestRoundData() returns (\n\
                             uint80, int256 price, , uint256 updatedAt, uint80\n\
                         ) {\n\
                             if (block.timestamp - updatedAt <= MAX_STALENESS) {\n\
                                 return uint256(price);\n\
                             }\n\
                         } catch {}\n\
                         // Fallback to secondary oracle\n\
                         return secondaryOracle.getPrice();\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 4. TwapManipulationWindowDetector
// ---------------------------------------------------------------------------

/// Detector for TWAP oracles with short observation windows.
///
/// A TWAP (Time-Weighted Average Price) oracle with a short observation
/// window (< 30 minutes) can be manipulated by an attacker who sustains a
/// price deviation for the duration of the window. Longer windows make
/// attacks significantly more expensive.
pub struct TwapManipulationWindowDetector {
    base: BaseDetector,
}

impl Default for TwapManipulationWindowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TwapManipulationWindowDetector {
    /// Minimum safe TWAP window in seconds (30 minutes).
    const MIN_SAFE_WINDOW_SECONDS: u64 = 1800;

    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("twap-manipulation-window"),
                "TWAP Oracle Short Observation Window".to_string(),
                "Detects TWAP oracle configurations with observation windows \
                 shorter than 30 minutes, making price manipulation economically \
                 feasible for well-funded attackers."
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Check whether the source references TWAP and has a suspiciously short
    /// observation window.
    fn find_short_twap_windows(&self, source: &str) -> Vec<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let lower_source = source.to_lowercase();

        // Must reference TWAP in some form
        if !lower_source.contains("twap") && !lower_source.contains("time-weighted") {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // TWAP-related constant/variable name patterns (case-insensitive)
        let twap_var_patterns = [
            "twap_period",
            "twapperiod",
            "twap_window",
            "twapwindow",
            "twap_interval",
            "twapinterval",
            "observation_window",
            "observationwindow",
            "secondsago",
            "seconds_ago",
            "twap_duration",
            "twapduration",
            "oracle_period",
            "oracleperiod",
        ];

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            let lower_line = trimmed.to_lowercase();

            // Check if this line defines a TWAP-related variable/constant
            let is_twap_definition = twap_var_patterns.iter().any(|pat| lower_line.contains(pat));

            if !is_twap_definition {
                continue;
            }

            // Try to extract a numeric value from the line
            if let Some(value) = self.extract_numeric_value(trimmed) {
                if value > 0 && value < Self::MIN_SAFE_WINDOW_SECONDS {
                    findings.push((
                        (idx + 1) as u32,
                        format!(
                            "TWAP observation window of {} seconds on line {} is below \
                             the recommended minimum of {} seconds (30 minutes). A short \
                             window makes price manipulation economically viable.",
                            value,
                            idx + 1,
                            Self::MIN_SAFE_WINDOW_SECONDS,
                        ),
                    ));
                }
            }
        }

        findings
    }

    /// Try to extract a numeric value from an assignment or constant definition.
    /// Handles patterns like:
    ///   - `uint256 constant TWAP_PERIOD = 600;`
    ///   - `secondsAgo = 300;`
    ///   - `uint32[] memory secondsAgos = new uint32[](2); secondsAgos[0] = 900;`
    fn extract_numeric_value(&self, line: &str) -> Option<u64> {
        // Look for `= <number>` at the end of the line (before semicolon)
        let cleaned = line.trim().trim_end_matches(';').trim();

        // Find the last `=` sign and parse what comes after it
        if let Some(eq_pos) = cleaned.rfind('=') {
            let after_eq = cleaned[eq_pos + 1..].trim();
            // Strip any trailing comments and semicolons
            let value_str = if let Some(comment_pos) = after_eq.find("//") {
                after_eq[..comment_pos].trim().trim_end_matches(';').trim()
            } else {
                after_eq.trim_end_matches(';').trim()
            };

            // Try parsing as a plain integer
            if let Ok(val) = value_str.parse::<u64>() {
                return Some(val);
            }

            // Handle patterns like `uint32(600)` or `uint256(900)`
            if let Some(paren_start) = value_str.find('(') {
                if let Some(paren_end) = value_str.find(')') {
                    let inner = value_str[paren_start + 1..paren_end].trim();
                    if let Ok(val) = inner.parse::<u64>() {
                        return Some(val);
                    }
                }
            }
        }

        None
    }
}

impl Detector for TwapManipulationWindowDetector {
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

        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        for (line, description) in self.find_short_twap_windows(source) {
            let finding = self
                .base
                .create_finding(ctx, description, line, 1, 50)
                .with_cwe(330) // CWE-330: Use of Insufficiently Random Values (price predictability)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Increase the TWAP observation window to at least 30 minutes (1800 seconds) \
                     to make price manipulation prohibitively expensive:\n\n\
                     uint256 constant TWAP_PERIOD = 1800; // 30 minutes minimum\n\n\
                     For high-value protocols, consider 1-4 hour windows. Longer windows \
                     increase the cost of sustained manipulation but reduce price responsiveness."
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 5. OracleDecimalMismatchDetector
// ---------------------------------------------------------------------------

/// Detector for price feed usage without `decimals()` normalization.
///
/// Chainlink price feeds return prices with different decimal precisions
/// (e.g., 8 decimals for USD feeds, 18 for ETH feeds). Using these values
/// in arithmetic without calling `.decimals()` and normalizing can cause
/// orders-of-magnitude errors in calculations.
pub struct OracleDecimalMismatchDetector {
    base: BaseDetector,
}

impl Default for OracleDecimalMismatchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleDecimalMismatchDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("oracle-decimal-mismatch"),
                "Oracle Decimal Mismatch".to_string(),
                "Detects price feed usage without decimals() normalization. \
                 Different feeds return prices with varying decimal precisions, \
                 and failing to normalize can cause catastrophic calculation errors."
                    .to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Detect oracle price usage without decimal normalization.
    fn find_decimal_mismatch_issues(&self, source: &str) -> Vec<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let lower_source = source.to_lowercase();

        // Must use some Chainlink price feed call
        let has_price_feed =
            lower_source.contains("latestrounddata") || lower_source.contains("latestanswer");

        if !has_price_feed {
            return Vec::new();
        }

        // Check if the contract calls .decimals() anywhere -- this indicates
        // awareness of decimal normalization.
        let has_decimals_call = lower_source.contains(".decimals()")
            || lower_source.contains("pricefeeddecimals")
            || lower_source.contains("price_feed_decimals")
            || lower_source.contains("oracledecimals")
            || lower_source.contains("oracle_decimals")
            || lower_source.contains("feeddecimals")
            || lower_source.contains("feed_decimals")
            || lower_source.contains("10 ** 8")  // Common Chainlink USD feed normalization
            || lower_source.contains("10**8")
            || lower_source.contains("1e8")
            || lower_source.contains("10 ** 18")
            || lower_source.contains("10**18")
            || lower_source.contains("1e18");

        if has_decimals_call {
            return Vec::new();
        }

        // Check if the answer from latestRoundData is used in arithmetic
        // (multiplication, division, comparison with token amounts).
        let arithmetic_indicators = [
            "price *",
            "price*",
            "* price",
            "*price",
            "price /",
            "price/",
            "/ price",
            "/price",
            "answer *",
            "answer*",
            "* answer",
            "*answer",
            "answer /",
            "answer/",
            "/ answer",
            "/answer",
            "uint256(answer)",
            "uint256(price)",
        ];

        let has_arithmetic = arithmetic_indicators
            .iter()
            .any(|pat| lower_source.contains(pat));

        if !has_arithmetic {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            if trimmed.contains("latestRoundData") || trimmed.contains("latestAnswer") {
                findings.push((
                    (idx + 1) as u32,
                    format!(
                        "Price feed query on line {} returns data that is used in \
                         arithmetic without calling .decimals() for normalization. \
                         Different Chainlink feeds use different decimal precisions \
                         (e.g., 8 for USD, 18 for ETH), which can cause \
                         orders-of-magnitude errors.",
                        idx + 1
                    ),
                ));
            }
        }

        findings
    }
}

impl Detector for OracleDecimalMismatchDetector {
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

        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        for (line, description) in self.find_decimal_mismatch_issues(source) {
            let finding = self
                .base
                .create_finding(ctx, description, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Normalize oracle price data by querying the feed's decimals:\n\n\
                     uint8 feedDecimals = priceFeed.decimals();\n\
                     (, int256 answer, , , ) = priceFeed.latestRoundData();\n\
                     uint256 price = uint256(answer);\n\n\
                     // Normalize to 18 decimals\n\
                     if (feedDecimals < 18) {\n\
                         price = price * 10 ** (18 - feedDecimals);\n\
                     } else if (feedDecimals > 18) {\n\
                         price = price / 10 ** (feedDecimals - 18);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- ChainlinkStalePriceDetector --

    #[test]
    fn test_chainlink_stale_price_properties() {
        let detector = ChainlinkStalePriceDetector::new();
        assert_eq!(detector.id().0, "chainlink-stale-price");
        assert_eq!(detector.name(), "Chainlink Stale Price Data");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::Oracle));
    }

    #[test]
    fn test_chainlink_stale_price_detects_missing_check() {
        let detector = ChainlinkStalePriceDetector::new();
        let source = r#"
contract PriceConsumer {
    function getPrice() public view returns (int256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return answer;
    }
}
"#;
        let issues = detector.find_stale_price_issues(source);
        assert!(
            !issues.is_empty(),
            "Should flag latestRoundData without staleness check"
        );
    }

    #[test]
    fn test_chainlink_stale_price_skips_with_check() {
        let detector = ChainlinkStalePriceDetector::new();
        let source = r#"
contract SafePriceConsumer {
    function getPrice() public view returns (int256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale price");
        require(answeredInRound >= roundId, "Stale round");
        return answer;
    }
}
"#;
        let issues = detector.find_stale_price_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag when staleness check is present"
        );
    }

    // -- ChainlinkSequencerCheckDetector --

    #[test]
    fn test_chainlink_sequencer_check_properties() {
        let detector = ChainlinkSequencerCheckDetector::new();
        assert_eq!(detector.id().0, "chainlink-sequencer-check");
        assert_eq!(detector.name(), "Missing Chainlink L2 Sequencer Check");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::Oracle));
        assert!(detector.categories().contains(&DetectorCategory::L2));
    }

    #[test]
    fn test_chainlink_sequencer_detects_missing_check() {
        let detector = ChainlinkSequencerCheckDetector::new();
        let source = r#"
// Deployed on Arbitrum L2
contract ArbitrumPriceConsumer {
    function getPrice() public view returns (int256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return answer;
    }
}
"#;
        let issues = detector.find_missing_sequencer_checks(source);
        assert!(
            !issues.is_empty(),
            "Should flag L2 usage without sequencer check"
        );
    }

    #[test]
    fn test_chainlink_sequencer_skips_with_check() {
        let detector = ChainlinkSequencerCheckDetector::new();
        let source = r#"
// Deployed on Arbitrum L2
contract SafeArbitrumConsumer {
    AggregatorV3Interface public sequencerUptimeFeed;

    function getPrice() public view returns (int256) {
        (, int256 seqAnswer, , , ) = sequencerUptimeFeed.latestRoundData();
        require(seqAnswer == 0, "Sequencer down");
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return answer;
    }
}
"#;
        let issues = detector.find_missing_sequencer_checks(source);
        assert!(
            issues.is_empty(),
            "Should not flag when sequencer check is present"
        );
    }

    // -- OracleSingleSourceDetector --

    #[test]
    fn test_oracle_single_source_properties() {
        let detector = OracleSingleSourceDetector::new();
        assert_eq!(detector.id().0, "oracle-single-source");
        assert_eq!(detector.name(), "Single Oracle Source Without Fallback");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::Oracle));
    }

    #[test]
    fn test_oracle_single_source_detects_no_fallback() {
        let detector = OracleSingleSourceDetector::new();
        let source = r#"
contract Vault {
    AggregatorV3Interface internal priceFeed;
    function getValue(uint256 amount) public returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return uint256(answer) * amount / 1e18;
    }
}
"#;
        let issues = detector.find_single_source_issues(source);
        assert!(
            !issues.is_empty(),
            "Should flag single oracle without fallback"
        );
    }

    #[test]
    fn test_oracle_single_source_skips_view_only() {
        let detector = OracleSingleSourceDetector::new();
        let source = r#"
contract Vault {
    AggregatorV3Interface internal priceFeed;
    function getPrice() public view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return uint256(answer);
    }
}
"#;
        let issues = detector.find_single_source_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag oracle calls in view-only functions"
        );
    }

    #[test]
    fn test_oracle_single_source_skips_no_infra() {
        let detector = OracleSingleSourceDetector::new();
        let source = r#"
contract Token {
    function getPrice() public returns (uint256) {
        return _calculatePrice();
    }
}
"#;
        let issues = detector.find_single_source_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag contracts without oracle infrastructure"
        );
    }

    #[test]
    fn test_oracle_single_source_skips_with_staleness() {
        let detector = OracleSingleSourceDetector::new();
        let source = r#"
contract Vault {
    AggregatorV3Interface internal priceFeed;
    // Uses Chainlink with staleness check
    function getValue(uint256 amount) public returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        return uint256(answer) * amount / 1e18;
    }
}
"#;
        let issues = detector.find_single_source_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag Chainlink with staleness validation"
        );
    }

    #[test]
    fn test_oracle_single_source_skips_with_fallback() {
        let detector = OracleSingleSourceDetector::new();
        let source = r#"
contract RobustVault {
    function getValue() public view returns (uint256) {
        try primaryOracle.getPrice(token) returns (int256 price) {
            return uint256(price) * amount / 1e18;
        } catch {
            return fallbackOracle.getPrice(token) * amount / 1e18;
        }
    }
}
"#;
        let issues = detector.find_single_source_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag when fallback logic is present"
        );
    }

    // -- TwapManipulationWindowDetector --

    #[test]
    fn test_twap_manipulation_window_properties() {
        let detector = TwapManipulationWindowDetector::new();
        assert_eq!(detector.id().0, "twap-manipulation-window");
        assert_eq!(detector.name(), "TWAP Oracle Short Observation Window");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::Oracle));
    }

    #[test]
    fn test_twap_detects_short_window() {
        let detector = TwapManipulationWindowDetector::new();
        let source = r#"
contract TwapOracle {
    uint256 constant TWAP_PERIOD = 600; // 10 minutes - too short!

    function getTwapPrice() public view returns (uint256) {
        return computeTWAP(TWAP_PERIOD);
    }
}
"#;
        let issues = detector.find_short_twap_windows(source);
        assert!(!issues.is_empty(), "Should flag TWAP period of 600 seconds");
    }

    #[test]
    fn test_twap_skips_safe_window() {
        let detector = TwapManipulationWindowDetector::new();
        let source = r#"
contract SafeTwapOracle {
    uint256 constant TWAP_PERIOD = 3600; // 1 hour - safe

    function getTwapPrice() public view returns (uint256) {
        return computeTWAP(TWAP_PERIOD);
    }
}
"#;
        let issues = detector.find_short_twap_windows(source);
        assert!(
            issues.is_empty(),
            "Should not flag TWAP period of 3600 seconds"
        );
    }

    #[test]
    fn test_twap_extract_numeric_value() {
        let detector = TwapManipulationWindowDetector::new();
        assert_eq!(
            detector.extract_numeric_value("uint256 constant TWAP_PERIOD = 600;"),
            Some(600)
        );
        assert_eq!(
            detector.extract_numeric_value("secondsAgo = uint32(300);"),
            Some(300)
        );
        assert_eq!(
            detector.extract_numeric_value("uint256 x = 1800;"),
            Some(1800)
        );
    }

    // -- OracleDecimalMismatchDetector --

    #[test]
    fn test_oracle_decimal_mismatch_properties() {
        let detector = OracleDecimalMismatchDetector::new();
        assert_eq!(detector.id().0, "oracle-decimal-mismatch");
        assert_eq!(detector.name(), "Oracle Decimal Mismatch");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert!(detector.categories().contains(&DetectorCategory::Oracle));
    }

    #[test]
    fn test_oracle_decimal_detects_missing_normalization() {
        let detector = OracleDecimalMismatchDetector::new();
        let source = r#"
contract Vault {
    function getCollateralValue(uint256 amount) public view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        uint256 price = uint256(answer);
        return price * amount;
    }
}
"#;
        let issues = detector.find_decimal_mismatch_issues(source);
        assert!(
            !issues.is_empty(),
            "Should flag price arithmetic without decimals()"
        );
    }

    #[test]
    fn test_oracle_decimal_skips_with_normalization() {
        let detector = OracleDecimalMismatchDetector::new();
        let source = r#"
contract SafeVault {
    function getCollateralValue(uint256 amount) public view returns (uint256) {
        uint8 feedDecimals = priceFeed.decimals();
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        uint256 price = uint256(answer) * 10 ** (18 - feedDecimals);
        return price * amount / 1e18;
    }
}
"#;
        let issues = detector.find_decimal_mismatch_issues(source);
        assert!(
            issues.is_empty(),
            "Should not flag when .decimals() is used"
        );
    }
}
