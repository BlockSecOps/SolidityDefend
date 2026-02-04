//! Oracle Safe Patterns Module
//!
//! This module provides functions to detect safe oracle implementations
//! that reduce false positive rates for oracle-related vulnerability detectors.
//!
//! Safe patterns include:
//! - Chainlink AggregatorV3Interface usage with proper validation
//! - TWAP (Time-Weighted Average Price) oracle implementations
//! - Multi-oracle validation with fallback mechanisms
//! - Staleness checks on price data
//! - Deviation bounds validation

use crate::types::AnalysisContext;

/// Detect Chainlink oracle integration with proper validation
///
/// Checks for AggregatorV3Interface usage and proper round data validation.
///
/// Patterns detected:
/// - AggregatorV3Interface import/usage
/// - latestRoundData() calls with answer validation
/// - getRoundData() calls with timestamp checks
/// - decimals() usage for proper scaling
pub fn has_chainlink_oracle(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: AggregatorV3Interface usage
    let has_aggregator = source.contains("AggregatorV3Interface")
        || source.contains("AggregatorInterface")
        || source.contains("@chainlink/contracts");

    // Pattern 2: latestRoundData() call
    let has_latest_round = source_lower.contains("latestrounddata");

    // Pattern 3: Proper answer validation
    let has_answer_check = source_lower.contains("answer >")
        || source_lower.contains("answer >=")
        || source_lower.contains("answer !=")
        || source.contains("require(answer");

    // Strong indicator: AggregatorV3Interface + latestRoundData + validation
    if has_aggregator && has_latest_round && has_answer_check {
        return true;
    }

    // Medium indicator: AggregatorV3Interface + latestRoundData
    if has_aggregator && has_latest_round {
        return true;
    }

    // Pattern 4: priceFeed variable with proper interface
    if source_lower.contains("pricefeed") && has_aggregator {
        return true;
    }

    false
}

/// Detect TWAP (Time-Weighted Average Price) oracle implementation
///
/// TWAP oracles are more resistant to manipulation as they use historical data.
///
/// Patterns detected:
/// - observe() function calls (Uniswap V3 style)
/// - observations[] array access
/// - cumulative price calculations
/// - timeWeighted prefix/suffix
pub fn has_twap_oracle(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: Uniswap V3 style observe()
    if source_lower.contains(".observe(") || source_lower.contains("ipool.observe") {
        return true;
    }

    // Pattern 2: observations array (Uniswap V3)
    if source_lower.contains("observations[") || source_lower.contains("observation[") {
        return true;
    }

    // Pattern 3: Cumulative price patterns
    if source_lower.contains("cumulativeprice")
        || source_lower.contains("pricecumulative")
        || source_lower.contains("price0cumulative")
        || source_lower.contains("price1cumulative")
    {
        return true;
    }

    // Pattern 4: Time-weighted naming
    if source_lower.contains("timeweighted")
        || source_lower.contains("time_weighted")
        || source_lower.contains("twap")
    {
        return true;
    }

    // Pattern 5: Sliding window/period calculations
    if (source_lower.contains("window") || source_lower.contains("period"))
        && source_lower.contains("price")
    {
        // Check for time-based calculations
        if source_lower.contains("block.timestamp") || source_lower.contains("granularity") {
            return true;
        }
    }

    // Pattern 6: Oracle.consult() pattern (common in TWAP implementations)
    if source_lower.contains(".consult(") && source_lower.contains("oracle") {
        return true;
    }

    false
}

/// Detect multi-oracle validation with fallback mechanisms
///
/// Multi-oracle setups use multiple price sources to validate accuracy.
///
/// Patterns detected:
/// - Multiple oracle/priceFeed variables (oracle1, oracle2, etc.)
/// - Fallback oracle patterns
/// - Price deviation comparisons between oracles
/// - Primary/secondary oracle logic
pub fn has_multi_oracle_validation(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: Multiple named oracles
    let has_oracle1 = source_lower.contains("oracle1")
        || source_lower.contains("oracle_1")
        || source_lower.contains("primaryoracle");
    let has_oracle2 = source_lower.contains("oracle2")
        || source_lower.contains("oracle_2")
        || source_lower.contains("secondaryoracle");

    if has_oracle1 && has_oracle2 {
        return true;
    }

    // Pattern 2: Fallback oracle pattern
    if (source_lower.contains("fallbackoracle") || source_lower.contains("fallback_oracle"))
        && source_lower.contains("pricefeed")
    {
        return true;
    }

    // Pattern 3: Multiple price feeds array
    if source_lower.contains("pricefeeds[") || source_lower.contains("oracles[") {
        return true;
    }

    // Pattern 4: Price comparison between sources
    if source_lower.contains("deviation")
        && (source_lower.contains("oracle") || source_lower.contains("price"))
    {
        return true;
    }

    // Pattern 5: Chainlink + TWAP combination
    let has_chainlink = source.contains("AggregatorV3Interface");
    let has_twap = source_lower.contains("twap") || source_lower.contains("observe(");
    if has_chainlink && has_twap {
        return true;
    }

    // Pattern 6: "primary" and "secondary" price source pattern
    if source_lower.contains("primaryprice") && source_lower.contains("secondaryprice") {
        return true;
    }

    false
}

/// Detect staleness checks on price data
///
/// Staleness checks ensure price data is recent enough to be trusted.
///
/// Patterns detected:
/// - updatedAt timestamp validation
/// - block.timestamp - timestamp comparisons
/// - Heartbeat/staleness threshold checks
/// - answeredInRound validation (Chainlink specific)
pub fn has_staleness_check(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: updatedAt from latestRoundData
    let has_updated_at = source_lower.contains("updatedat")
        || source_lower.contains("updated_at")
        || source_lower.contains("lastupdated");

    // Pattern 2: Timestamp comparison with block.timestamp
    let has_timestamp_check = source_lower.contains("block.timestamp -")
        || source_lower.contains("block.timestamp-")
        || source.contains("block.timestamp <")
        || source.contains("block.timestamp >");

    if has_updated_at && has_timestamp_check {
        return true;
    }

    // Pattern 3: Staleness threshold/heartbeat
    if source_lower.contains("staleness")
        || source_lower.contains("stale")
        || source_lower.contains("heartbeat")
    {
        if has_timestamp_check {
            return true;
        }
    }

    // Pattern 4: answeredInRound validation (Chainlink specific)
    if source_lower.contains("answeredinround") {
        if source.contains("require(answeredInRound") || source.contains("if (answeredInRound") {
            return true;
        }
    }

    // Pattern 5: roundId validation
    if source_lower.contains("roundid") && source.contains("require(") {
        return true;
    }

    // Pattern 6: MAX_DELAY or PRICE_EXPIRY pattern
    if source.contains("MAX_DELAY")
        || source.contains("PRICE_EXPIRY")
        || source.contains("MAX_STALENESS")
    {
        return true;
    }

    // Pattern 7: Age check pattern
    if source_lower.contains("age") && source_lower.contains("price") && has_timestamp_check {
        return true;
    }

    false
}

/// Detect deviation bounds validation
///
/// Deviation bounds ensure price changes are within acceptable ranges.
///
/// Patterns detected:
/// - MAX_DEVIATION or similar constants
/// - Percentage deviation calculations
/// - Price band/range checks
/// - Circuit breaker patterns
pub fn has_deviation_bounds(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: MAX_DEVIATION constant
    if source.contains("MAX_DEVIATION")
        || source.contains("DEVIATION_THRESHOLD")
        || source.contains("MAX_PRICE_DEVIATION")
    {
        return true;
    }

    // Pattern 2: Percentage deviation calculation
    if source_lower.contains("deviation") && source.contains("%") {
        return true;
    }

    // Pattern 3: Price band checks
    if source_lower.contains("priceband")
        || source_lower.contains("price_band")
        || source_lower.contains("upperbound")
        || source_lower.contains("lowerbound")
    {
        return true;
    }

    // Pattern 4: Circuit breaker pattern
    if source_lower.contains("circuitbreaker") || source_lower.contains("circuit_breaker") {
        return true;
    }

    // Pattern 5: Price tolerance check
    if source_lower.contains("tolerance") && source_lower.contains("price") {
        return true;
    }

    // Pattern 6: Min/Max price bounds
    if (source.contains("minPrice") || source.contains("MIN_PRICE"))
        && (source.contains("maxPrice") || source.contains("MAX_PRICE"))
    {
        return true;
    }

    // Pattern 7: Deviation percentage calculation
    // e.g., abs(price1 - price2) * 100 / price1
    if source_lower.contains("abs(") && source_lower.contains("price") && source.contains("100") {
        return true;
    }

    // Pattern 8: require with deviation logic
    if source.contains("require(") && source_lower.contains("deviation") {
        return true;
    }

    false
}

/// Check if contract has comprehensive oracle safety measures
///
/// Returns true if the contract implements multiple oracle safety patterns,
/// indicating a well-protected oracle integration.
pub fn has_comprehensive_oracle_safety(ctx: &AnalysisContext) -> bool {
    let chainlink = has_chainlink_oracle(ctx);
    let twap = has_twap_oracle(ctx);
    let multi_oracle = has_multi_oracle_validation(ctx);
    let staleness = has_staleness_check(ctx);
    let deviation = has_deviation_bounds(ctx);

    // Count safety measures
    let safety_count = [chainlink, twap, multi_oracle, staleness, deviation]
        .iter()
        .filter(|&&x| x)
        .count();

    // Comprehensive if 3+ patterns or (staleness + deviation) or multi-oracle
    safety_count >= 3 || (staleness && deviation) || multi_oracle
}

/// Detect safe oracle consumer patterns
///
/// Checks if the contract appears to be a safe consumer of oracle data
/// with proper error handling and validation.
pub fn is_safe_oracle_consumer(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Must use some oracle
    if !source_lower.contains("oracle")
        && !source_lower.contains("pricefeed")
        && !source.contains("AggregatorV3Interface")
    {
        return false;
    }

    // Check for try/catch on oracle calls (defensive pattern)
    let has_try_catch = source.contains("try ") && source_lower.contains("oracle");

    // Check for zero price validation
    let has_zero_check = source.contains("require(price > 0")
        || source.contains("require(answer > 0")
        || source.contains("if (price == 0")
        || source.contains("if (answer == 0");

    // Check for staleness
    let has_staleness = has_staleness_check(ctx);

    // Safe if: (try/catch + zero check) or (zero check + staleness)
    (has_try_catch && has_zero_check) || (has_zero_check && has_staleness)
}

// NOTE: Unit tests for oracle patterns are in tests/fp_regression_tests.rs
// The tests below require AnalysisContext which needs AST parsing.
// Pattern detection tests are covered by source-level tests in the FP regression suite.
