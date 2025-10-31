//! Oracle Staleness Heartbeat Detector (OWASP 2025)
//!
//! Detects missing Chainlink heartbeat validation.
//! Stale price usage can lead to incorrect valuations.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct OracleStalenesDetector {
    base: BaseDetector,
}

impl OracleStalenesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("oracle-staleness-heartbeat".to_string()),
                "Oracle Staleness Heartbeat".to_string(),
                "Detects missing Chainlink heartbeat and staleness checks".to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }
}

impl Default for OracleStalenesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for OracleStalenesDetector {
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
        let source = &ctx.source_code;

        // Check for Chainlink usage
        let has_chainlink = source.contains("chainlink") || source.contains("Chainlink")
            || source.contains("AggregatorV3") || source.contains("aggregator");

        let has_latest_round = source.contains("latestRoundData") || source.contains("getRoundData");

        let has_staleness_check = source.contains("updatedAt")
            && (source.contains("block.timestamp") || source.contains("timestamp"));

        let has_heartbeat = source.contains("heartbeat") || source.contains("HEARTBEAT")
            || source.contains("maxDelay") || source.contains("MAX_DELAY");

        // Chainlink without staleness check
        if has_chainlink && has_latest_round && !has_staleness_check {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Chainlink oracle without staleness check - stale prices can be used".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            ).with_fix_suggestion(
                "❌ MISSING STALENESS CHECK (OWASP 2025):\n\
                 (,int256 price,,,) = priceFeed.latestRoundData();\n\
                 // What if this price is hours old?\n\
                 \n\
                 ✅ CORRECT - Check updatedAt:\n\
                 (\n\
                     uint80 roundId,\n\
                     int256 price,\n\
                     uint256 startedAt,\n\
                     uint256 updatedAt,\n\
                     uint80 answeredInRound\n\
                 ) = priceFeed.latestRoundData();\n\
                 \n\
                 // 1. Check price is not stale (heartbeat + buffer)\n\
                 uint256 HEARTBEAT = 3600;  // 1 hour for most feeds\n\
                 uint256 BUFFER = 300;      // 5 min buffer\n\
                 require(block.timestamp - updatedAt <= HEARTBEAT + BUFFER, \"Stale price\");\n\
                 \n\
                 // 2. Check round is complete\n\
                 require(answeredInRound >= roundId, \"Incomplete round\");\n\
                 \n\
                 // 3. Check price is positive\n\
                 require(price > 0, \"Invalid price\");\n\
                 \n\
                 ✅ BEST - Use helper function:\n\
                 function getChainlinkPrice() internal view returns (uint256) {\n\
                     (uint80 roundId, int256 price,, uint256 updatedAt, uint80 answeredInRound) = \n\
                         priceFeed.latestRoundData();\n\
                     \n\
                     require(price > 0, \"Invalid price\");\n\
                     require(answeredInRound >= roundId, \"Stale round\");\n\
                     require(block.timestamp - updatedAt <= HEARTBEAT + BUFFER, \"Stale price\");\n\
                     \n\
                     return uint256(price);\n\
                 }".to_string()
            );
            findings.push(finding);
        }

        // Chainlink without heartbeat constant
        if has_chainlink && has_latest_round && !has_heartbeat {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Chainlink oracle without heartbeat configuration - define max price age".to_string(),
                1,
                0,
                20,
                Severity::Low,
            ).with_fix_suggestion(
                "Each Chainlink feed has a specific heartbeat interval.\n\
                 Define these constants based on the feed:\n\
                 \n\
                 Common Chainlink heartbeats:\n\
                 - ETH/USD: 1 hour (3600 seconds)\n\
                 - BTC/USD: 1 hour (3600 seconds)\n\
                 - Stable pairs: 24 hours (86400 seconds)\n\
                 - Volatile pairs: 1 hour or less\n\
                 \n\
                 ✅ Define heartbeat constants:\n\
                 uint256 private constant ETH_USD_HEARTBEAT = 3600;\n\
                 uint256 private constant BTC_USD_HEARTBEAT = 3600;\n\
                 uint256 private constant USDC_USD_HEARTBEAT = 86400;\n\
                 uint256 private constant STALENESS_BUFFER = 300;  // 5 min\n\
                 \n\
                 function validatePrice(\n\
                     uint256 updatedAt,\n\
                     uint256 heartbeat\n\
                 ) internal view {\n\
                     require(\n\
                         block.timestamp - updatedAt <= heartbeat + STALENESS_BUFFER,\n\
                         \"Price too stale\"\n\
                     );\n\
                 }\n\
                 \n\
                 Check feed documentation: https://data.chain.link/".to_string()
            );
            findings.push(finding);
        }

        // Using latestRoundData without all checks
        if has_latest_round {
            let has_round_check = source.contains("answeredInRound") && source.contains("roundId");
            let has_price_check = source.contains("price > 0") || source.contains("price >= 0");

            if !has_round_check || !has_price_check {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    "Incomplete Chainlink validation - missing round or price checks".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                ).with_fix_suggestion(
                    "Complete Chainlink validation checklist:\n\
                     \n\
                     ✅ All required checks:\n\
                     (uint80 roundId, int256 price,, uint256 updatedAt, uint80 answeredInRound) = \n\
                         priceFeed.latestRoundData();\n\
                     \n\
                     // Check 1: Price is valid (non-zero)\n\
                     require(price > 0, \"Invalid price\");\n\
                     \n\
                     // Check 2: Round is complete (answered)\n\
                     require(answeredInRound >= roundId, \"Stale round\");\n\
                     \n\
                     // Check 3: Price is not stale (within heartbeat)\n\
                     require(\n\
                         block.timestamp - updatedAt <= HEARTBEAT + BUFFER,\n\
                         \"Stale price\"\n\
                     );\n\
                     \n\
                     // Check 4: No oracle circuit breaker (optional)\n\
                     uint256 minPrice = 1000e8;  // Min expected price\n\
                     uint256 maxPrice = 10000e8; // Max expected price\n\
                     require(price >= int256(minPrice) && price <= int256(maxPrice), \"Price out of bounds\");\n\
                     \n\
                     Why each check matters:\n\
                     - price > 0: Prevents using zero/negative prices\n\
                     - answeredInRound: Ensures round is finalized\n\
                     - updatedAt: Prevents stale data usage\n\
                     - Circuit breaker: Catches oracle failures".to_string()
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
