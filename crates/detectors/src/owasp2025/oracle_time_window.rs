//! Oracle Time Window Attack Detector (OWASP 2025)
//!
//! Detects oracle price manipulation via time-window attacks.
//! Missing TWAP (Time-Weighted Average Price) implementation.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct OracleTimeWindowAttackDetector {
    base: BaseDetector,
}

impl OracleTimeWindowAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("oracle-time-window-attack".to_string()),
                "Oracle Time Window Attack".to_string(),
                "Detects spot price usage without TWAP protection".to_string(),
                vec![DetectorCategory::Oracle, DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }
}

impl Default for OracleTimeWindowAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for OracleTimeWindowAttackDetector {
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

        // Skip AMM pool contracts - they ARE the oracle/price source, not consumers
        // UniswapV2/V3 pools provide TWAP data via cumulative price tracking
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        // Check for oracle usage
        let has_oracle = source.contains("oracle") || source.contains("Oracle")
            || source.contains("price") || source.contains("Price");

        let has_uniswap = source.contains("uniswap") || source.contains("Uniswap")
            || source.contains("IUniswap");

        let has_twap = source.contains("twap") || source.contains("TWAP")
            || source.contains("TimeWeighted") || source.contains("observe");

        // Uniswap without TWAP is dangerous
        if has_uniswap && !has_twap {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Uniswap price oracle without TWAP - vulnerable to time-window manipulation".to_string(),
                1,
                0,
                20,
                Severity::High,
            ).with_fix_suggestion(
                "❌ VULNERABLE - Spot price manipulation:\n\
                 IUniswapV2Pair pair = IUniswapV2Pair(pairAddress);\n\
                 (uint112 reserve0, uint112 reserve1,) = pair.getReserves();\n\
                 uint256 price = reserve1 / reserve0;  // Manipulable!\n\
                 \n\
                 ✅ SECURE - Use Uniswap V3 TWAP:\n\
                 uint32[] memory secondsAgos = new uint32[](2);\n\
                 secondsAgos[0] = 1800;  // 30 min ago\n\
                 secondsAgos[1] = 0;     // now\n\
                 \n\
                 (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);\n\
                 int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0];\n\
                 int24 avgTick = int24(tickCumulativeDelta / 1800);\n\
                 uint256 twapPrice = OracleLibrary.getQuoteAtTick(avgTick, ...);\n\
                 \n\
                 ✅ BEST - Use multiple TWAPs with different windows:\n\
                 uint256 twap10min = getTWAP(600);   // 10 min\n\
                 uint256 twap30min = getTWAP(1800);  // 30 min\n\
                 uint256 twap1hour = getTWAP(3600);  // 1 hour\n\
                 \n\
                 // Reject if deviation > threshold\n\
                 require(abs(twap10min - twap30min) < maxDeviation);\n\
                 \n\
                 Attack vector: Flash loan → Manipulate spot price → Exploit → Repay".to_string()
            );
            findings.push(finding);
        }

        // General oracle without time-averaging
        if has_oracle && !has_twap && !source.contains("chainlink") && !source.contains("Chainlink") {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Oracle price usage without time-weighted average - consider TWAP".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            ).with_fix_suggestion(
                "Single-block price oracles are manipulable:\n\
                 \n\
                 ❌ Vulnerable patterns:\n\
                 - Using spot price from DEX\n\
                 - Single block price snapshot\n\
                 - No time-weighting\n\
                 - No price deviation checks\n\
                 \n\
                 ✅ Recommended solutions:\n\
                 \n\
                 1. Use Uniswap V3 TWAP (30+ minute window)\n\
                 2. Use Chainlink Price Feeds (aggregated off-chain)\n\
                 3. Combine multiple oracle sources\n\
                 4. Implement price deviation bounds:\n\
                    require(abs(newPrice - lastPrice) < maxDelta);\n\
                 5. Use time-weighted moving average:\n\
                    priceSum += currentPrice;\n\
                    priceCount++;\n\
                    avgPrice = priceSum / priceCount;\n\
                 \n\
                 Minimum TWAP window: 30 minutes (longer is better)\n\
                 Maximum price deviation: 2-5% from last update".to_string()
            );
            findings.push(finding);
        }

        // Check for getReserves() which is spot price
        if source.contains("getReserves") {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Using getReserves() for pricing - this is a spot price, not time-weighted".to_string(),
                1,
                0,
                20,
                Severity::High,
            ).with_fix_suggestion(
                "getReserves() returns SPOT price - manipulable in single block!\n\
                 \n\
                 Attack: Flash loan → Swap large amount → getReserves() → Exploit → Unwind\n\
                 \n\
                 ❌ INSECURE:\n\
                 (uint112 reserve0, uint112 reserve1,) = pair.getReserves();\n\
                 price = reserve1 * 1e18 / reserve0;  // Spot price!\n\
                 \n\
                 ✅ SECURE - Use TWAP instead:\n\
                 // For Uniswap V2:\n\
                 uint256 price0CumulativeLast = pair.price0CumulativeLast();\n\
                 uint32 blockTimestamp = uint32(block.timestamp % 2**32);\n\
                 uint32 timeElapsed = blockTimestamp - blockTimestampLast;\n\
                 \n\
                 // Calculate TWAP\n\
                 FixedPoint.uq112x112 memory price0Avg = FixedPoint.uq112x112(\n\
                     uint224((price0Cumulative - price0CumulativeLast) / timeElapsed)\n\
                 );\n\
                 \n\
                 // For Uniswap V3: Use observe() as shown above".to_string()
            );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
