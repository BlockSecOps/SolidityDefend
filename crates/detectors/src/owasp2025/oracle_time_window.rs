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

    /// Check if the contract has actual oracle infrastructure usage.
    /// This requires real oracle interface patterns (function calls to oracle contracts,
    /// price feed interfaces, Chainlink aggregators, etc.), not just the word "price"
    /// appearing in comments or variable names.
    fn has_oracle_infrastructure(&self, source: &str) -> bool {
        // Oracle interface patterns: actual oracle contract usage
        let has_oracle_interface = source.contains("IOracle")
            || source.contains("IPriceOracle")
            || source.contains("IPriceFeed")
            || source.contains("AggregatorV3Interface")
            || source.contains("AggregatorV2V3Interface")
            || source.contains("IChainlinkOracle");

        // Oracle function call patterns: calling oracle methods
        let has_oracle_call = source.contains(".getPrice(")
            || source.contains(".latestRoundData(")
            || source.contains(".latestAnswer(")
            || source.contains(".getRoundData(")
            || source.contains(".consult(")
            || source.contains(".getTWAP(");

        // Uniswap price oracle usage (actual interface, not just a comment)
        let has_uniswap_oracle =
            source.contains("IUniswap") || source.contains("uniswap") || source.contains("Uniswap");

        // DEX price feed patterns (actual on-chain price data retrieval)
        let has_dex_price = source.contains("getReserves")
            || source.contains("price0CumulativeLast")
            || source.contains("price1CumulativeLast");

        has_oracle_interface || has_oracle_call || has_uniswap_oracle || has_dex_price
    }

    /// Check if the contract makes actual oracle function calls to retrieve prices.
    /// More strict than has_oracle_infrastructure -- requires actual price retrieval calls.
    fn has_oracle_call_pattern(&self, source: &str) -> bool {
        source.contains(".getPrice(")
            || source.contains(".latestRoundData(")
            || source.contains(".latestAnswer(")
            || source.contains(".getRoundData(")
            || source.contains(".consult(")
            || source.contains("IOracle(")
            || source.contains("IPriceOracle(")
            || source.contains("IPriceFeed(")
            || source.contains("AggregatorV3Interface(")
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Skip AMM pool contracts - they ARE the oracle/price source, not consumers
        // UniswapV2/V3 pools provide TWAP data via cumulative price tracking
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;

        // FP Reduction: Require actual oracle infrastructure usage, not just the word "price"
        // in comments or variable names. Contracts that mention "share price" or "price impact"
        // in comments are not oracle consumers.
        let has_oracle_interface = self.has_oracle_infrastructure(source);

        // If the contract does not use any oracle infrastructure, skip entirely.
        // This prevents FPs on vault contracts, ZK contracts, bridge contracts, etc.
        // that happen to mention "price" in comments or non-oracle contexts.
        if !has_oracle_interface {
            return Ok(findings);
        }

        let has_uniswap =
            source.contains("uniswap") || source.contains("Uniswap") || source.contains("IUniswap");

        let has_twap = source.contains("twap")
            || source.contains("TWAP")
            || source.contains("TimeWeighted")
            || source.contains("observe");

        // Uniswap without TWAP is dangerous
        if has_uniswap && !has_twap {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Uniswap price oracle without TWAP - vulnerable to time-window manipulation"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
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
                 Attack vector: Flash loan → Manipulate spot price → Exploit → Repay"
                        .to_string(),
                );
            findings.push(finding);
        }

        // General oracle without time-averaging
        // Only flag if contract has actual oracle call patterns (interface calls, price feeds)
        let has_oracle_call = self.has_oracle_call_pattern(source);
        if has_oracle_call
            && !has_twap
            && !source.contains("chainlink")
            && !source.contains("Chainlink")
        {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Oracle price usage without time-weighted average - consider TWAP".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
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
                 Maximum price deviation: 2-5% from last update"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for getReserves() which is spot price
        if source.contains("getReserves") {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Using getReserves() for pricing - this is a spot price, not time-weighted"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
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
                 // For Uniswap V3: Use observe() as shown above"
                        .to_string(),
                );
            findings.push(finding);
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
    use crate::types::test_utils::create_mock_ast_contract;

    fn make_context(source: &str) -> AnalysisContext<'static> {
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let contract = Box::leak(Box::new(create_mock_ast_contract(
            arena,
            "TestContract",
            vec![],
        )));
        AnalysisContext::new(
            contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        )
    }

    #[test]
    fn test_detector_properties() {
        let detector = OracleTimeWindowAttackDetector::new();
        assert_eq!(detector.name(), "Oracle Time Window Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_no_fp_on_vault_contract_with_price_in_comments() {
        let detector = OracleTimeWindowAttackDetector::new();
        // This vault contract mentions "share price" in comments but does NOT use oracles
        let source = r#"
contract VulnerableVault {
    // VULNERABILITY: Share price can be manipulated
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function deposit(uint256 assets) public returns (uint256 shares) {
        shares = totalSupply == 0 ? assets : (assets * totalSupply) / totalAssets();
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
    }

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }
}
"#;
        assert!(
            !detector.has_oracle_infrastructure(source),
            "Vault contract with 'price' only in comments should not be detected as oracle user"
        );
    }

    #[test]
    fn test_no_fp_on_zk_contract() {
        let detector = OracleTimeWindowAttackDetector::new();
        // ZK contract that does not use oracles
        let source = r#"
contract ZKVerifier {
    function verify(uint256[8] calldata proof, uint256 amount) external pure returns (bool) {
        return proof[0] != 0 && amount > 0;
    }
}
"#;
        assert!(
            !detector.has_oracle_infrastructure(source),
            "ZK contract should not be detected as oracle user"
        );
    }

    #[test]
    fn test_no_fp_on_bridge_contract() {
        let detector = OracleTimeWindowAttackDetector::new();
        // Bridge contract that mentions "price" in comments but no oracle usage
        let source = r#"
contract BridgeVault {
    // Time-based oracle manipulation mentioned in docs
    mapping(bytes32 => bool) public processedRequests;
    function bridge(uint256 amount) external {
        processedRequests[keccak256(abi.encode(msg.sender, amount))] = true;
    }
}
"#;
        assert!(
            !detector.has_oracle_infrastructure(source),
            "Bridge contract without oracle calls should not be detected"
        );
    }

    #[test]
    fn test_detects_actual_oracle_consumer() {
        let detector = OracleTimeWindowAttackDetector::new();
        // Contract that actually uses an oracle
        let source = r#"
interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

contract OracleConsumer {
    IOracle public priceOracle;

    function getTokenPrice(address token) external view returns (uint256) {
        return priceOracle.getPrice(token);
    }
}
"#;
        assert!(
            detector.has_oracle_infrastructure(source),
            "Contract with IOracle interface and .getPrice() should be detected as oracle user"
        );
        assert!(
            detector.has_oracle_call_pattern(source),
            "Contract with .getPrice() should match oracle call pattern"
        );
    }

    #[test]
    fn test_detects_uniswap_price_consumer() {
        let detector = OracleTimeWindowAttackDetector::new();
        // Contract that uses Uniswap for pricing
        let source = r#"
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract AMMConsumer {
    function getSpotPrice(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }
}
"#;
        assert!(
            detector.has_oracle_infrastructure(source),
            "Contract using IUniswapV2Pair.getReserves() should be detected as oracle user"
        );
    }

    #[test]
    fn test_detects_chainlink_consumer() {
        let detector = OracleTimeWindowAttackDetector::new();
        let source = r#"
interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkConsumer {
    AggregatorV3Interface public priceFeed;

    function getLatestPrice() external view returns (int256) {
        (, int256 price,,,) = priceFeed.latestRoundData();
        return price;
    }
}
"#;
        assert!(
            detector.has_oracle_infrastructure(source),
            "Contract using Chainlink AggregatorV3Interface should be detected as oracle user"
        );
    }

    #[test]
    fn test_no_fp_on_simple_yield_farm() {
        let detector = OracleTimeWindowAttackDetector::new();
        // Yield farm without oracle usage
        let source = r#"
contract SimpleYieldFarm {
    uint256 public rewardPerBlock;
    mapping(address => uint256) public staked;

    function stake(uint256 amount) external {
        staked[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(staked[msg.sender] >= amount);
        staked[msg.sender] -= amount;
    }
}
"#;
        assert!(
            !detector.has_oracle_infrastructure(source),
            "Simple yield farm without oracle usage should not be detected"
        );
    }

    #[test]
    fn test_no_fp_on_curve_pool_without_oracle() {
        let detector = OracleTimeWindowAttackDetector::new();
        // Curve-style pool that has "price" in function names but no external oracle usage
        let source = r#"
contract CurvePool {
    uint256 public totalSupply;
    uint256 public token0Balance;
    uint256 public token1Balance;

    function get_virtual_price() external view returns (uint256) {
        if (totalSupply == 0) return 0;
        uint256 value = token0Balance + token1Balance;
        return (value * 1e18) / totalSupply;
    }

    function removeLiquidity(uint256 shares) external {
        uint256 amount0 = (shares * token0Balance) / totalSupply;
        (bool success, ) = msg.sender.call{value: amount0}("");
        require(success);
    }
}
"#;
        assert!(
            !detector.has_oracle_infrastructure(source),
            "Curve pool without external oracle calls should not be detected"
        );
    }
}
