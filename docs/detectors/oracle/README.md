# Oracle Security Detectors

**Total:** 9 detectors

---

## Safe Pattern Detection

Oracle detectors use the **Safe Patterns Library** to reduce false positives. Contracts implementing proper oracle safety measures are automatically skipped or receive reduced severity.

### Recognized Safe Patterns

| Pattern | Detection Function | Effect |
|---------|-------------------|--------|
| Chainlink AggregatorV3Interface | `has_chainlink_oracle()` | Reduces FPs for standard Chainlink usage |
| TWAP Oracle (Uniswap V3 style) | `has_twap_oracle()` | Skips contracts using time-weighted prices |
| Multi-Oracle Validation | `has_multi_oracle_validation()` | Skips contracts with fallback oracles |
| Staleness Check | `has_staleness_check()` | Reduces severity when updatedAt is validated |
| Deviation Bounds | `has_deviation_bounds()` | Reduces severity when price bands are enforced |

### Example Safe Implementation

```solidity
// This contract will NOT trigger oracle manipulation findings
contract SafeChainlinkConsumer {
    AggregatorV3Interface public primaryOracle;
    AggregatorV3Interface public secondaryOracle;
    uint256 public constant MAX_STALENESS = 3600;
    uint256 public constant MAX_DEVIATION = 500; // 5%

    function getValidatedPrice() external view returns (uint256) {
        (, int256 answer,, uint256 updatedAt,) = primaryOracle.latestRoundData();
        require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale");
        require(answer > 0, "Invalid");
        // Multi-oracle deviation check...
        return uint256(answer);
    }
}
```

---

## AI Agent Decision Manipulation

**ID:** `ai-agent-decision-manipulation`  
**Severity:** High  
**Categories:** Oracle  

### Description

Detects AI decision manipulation via oracle/input poisoning

### Remediation

- Add multi-oracle consensus: require(consensusReached(oracleData, threshold))

### Source

`ai_agent/decision_manipulation.rs`

---

## Autonomous Contract Oracle Dependency

**ID:** `autonomous-contract-oracle-dependency`  
**Severity:** Medium  
**Categories:** Oracle  

### Description

Detects oracle dependency creating single point of failure

### Remediation

- Add fallback oracle: if (primaryOracle.isDown()) use backupOracle

### Source

`ai_agent/oracle_dependency.rs`

---

## Missing Price Validation

**ID:** `missing-price-validation`  
**Severity:** Medium  
**Categories:** Oracle  
**CWE:** CWE-20  

### Description

Oracle price data is used without proper validation

### Source

`src/oracle.rs`

---

## Oracle Price Manipulation

**ID:** `oracle-manipulation`  
**Severity:** Critical  
**Categories:** Oracle, FlashLoanAttacks  
**CWE:** CWE-20, CWE-682  

### Description

Detects oracle price queries vulnerable to flash loan manipulation attacks

### Source

`src/oracle_manipulation.rs`

---

## Oracle Staleness Heartbeat

**ID:** `oracle-staleness-heartbeat`  
**Severity:** Medium  
**Categories:** Oracle, Oracle  

### Description

Detects missing Chainlink heartbeat and staleness checks

### Remediation

- ❌ MISSING STALENESS CHECK (OWASP 2025): \
     (,int256 price,,,) = priceFeed.latestRoundData(); \
     // What if this price is hours old? \
     \
     ✅ CORRECT - Check updatedAt: \
     ( \
      uint80 roundId, \
      int256 price, \
      uint256 startedAt, \
      uint256 updatedAt, \
      uint80 answeredInRound \
     ) = priceFeed.latestRoundData(); \
     \
     // 1. Check price is not stale (heartbeat + buffer) \
     uint256 HEARTBEAT = 3600; // 1 hour for most feeds \
     uint256 BUFFER = 300;  // 5 min buffer \
     require(block.timestamp - updatedAt <= HEARTBEAT + BUFFER, \

### Source

`owasp2025/oracle_staleness.rs`

---

## Oracle Time Window Attack

**ID:** `oracle-time-window-attack`  
**Severity:** High  
**Categories:** Oracle, Oracle  

### Description

Detects spot price usage without TWAP protection

### Remediation

- ❌ VULNERABLE - Spot price manipulation: \
     IUniswapV2Pair pair = IUniswapV2Pair(pairAddress); \
     (uint112 reserve0, uint112 reserve1,) = pair.getReserves(); \
     uint256 price = reserve1 / reserve0; // Manipulable! \
     \
     ✅ SECURE - Use Uniswap V3 TWAP: \
     uint32[] memory secondsAgos = new uint32[](2); \
     secondsAgos[0] = 1800; // 30 min ago \
     secondsAgos[1] = 0;  // now \
     \
     (int56[] memory tickCumulatives,) = pool.observe(secondsAgos); \
     int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0]; \
     int24 avgTick = int24(tickCumulativeDelta / 1800); \
     uint256 twapPrice = OracleLibrary.getQuoteAtTick(avgTick, ...); \
     \
     ✅ BEST - Use multiple TWAPs with different windows: \
     uint256 twap10min = getTWAP(600); // 10 min \
     uint256 twap30min = getTWAP(1800); // 30 min \
     uint256 twap1hour = getTWAP(3600); // 1 hour \
     \
     // Reject if deviation > threshold \
     require(abs(twap10min - twap30min) < maxDeviation); \
     \
     Attack vector: Flash loan → Manipulate spot price → Exploit → Repay

### Source

`owasp2025/oracle_time_window.rs`

---

## Price Impact Manipulation

**ID:** `price-impact-manipulation`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description

Detects swap functions that don't protect against large trades causing excessive price impact and slippage

### Vulnerable Patterns

- No maximum trade size limit
- No price impact calculation
- Missing minimum output validation

### Source

`src/price_impact_manipulation.rs`

---

## Stale Price Oracle Data

**ID:** `price-oracle-stale`  
**Severity:** Critical  
**Categories:** Oracle  
**CWE:** CWE-672, CWE-829  

### Description

Detects missing staleness checks on oracle price feeds that could lead to using outdated price data

### Vulnerable Patterns

- Oracle call without timestamp/staleness check
- Using stored price without checking lastUpdate
- getPrice() without latestRoundData() timestamp validation

### Source

`src/price_oracle_stale.rs`

---

## Single Oracle Source

**ID:** `single-oracle-source`  
**Severity:** High  
**Categories:** Oracle  
**CWE:** CWE-693  

### Description

Contract relies on a single oracle source for critical price data

### Source

`src/oracle.rs`

---

