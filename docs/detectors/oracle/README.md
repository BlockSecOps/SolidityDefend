# Oracle Detectors

**Total:** 10 detectors

---

## Oracle Manipulation

**ID:** `oracle-manipulation`  
**Severity:** Critical  
**Categories:** Oracle, FlashLoanAttacks  
**CWE:** CWE-20, CWE-682  

### Description



### Source

`crates/detectors/src/oracle_manipulation.rs`

---

## Price Oracle Stale

**ID:** `price-oracle-stale`  
**Severity:** Critical  
**Categories:** Oracle  
**CWE:** CWE-829, CWE-672  

### Description



### Source

`crates/detectors/src/price_oracle_stale.rs`

---

## Oracle Time Window Attack

**ID:** `oracle-time-window-attack`  
**Severity:** High  
**Categories:** Oracle, Oracle  

### Description



### Details

Oracle Time Window Attack Detector (OWASP 2025)

Detects oracle price manipulation via time-window attacks.
Missing TWAP (Time-Weighted Average Price) implementation.

### Source

`crates/detectors/src/owasp2025/oracle_time_window.rs`

---

## Price Impact Manipulation

**ID:** `price-impact-manipulation`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description



### Details

Check for price impact manipulation vulnerabilities

### Source

`crates/detectors/src/price_impact_manipulation.rs`

---

## Single Oracle Source

**ID:** `single-oracle-source`  
**Severity:** High  
**Categories:** Oracle, Oracle  
**CWE:** CWE-693, CWE-20  

### Description



### Source

`crates/detectors/src/oracle.rs`

---

## Single Oracle Source

**ID:** `single-oracle-source`  
**Severity:** High  
**Categories:** Oracle, Oracle  
**CWE:** CWE-693, CWE-20  

### Description



### Source

`crates/detectors/src/oracle.rs`

---

## Autonomous Contract Oracle Dependency

**ID:** `autonomous-contract-oracle-dependency`  
**Severity:** Medium  
**Categories:** Oracle  

### Description



### Details

Autonomous Contract Oracle Dependency Detector

### Source

`crates/detectors/src/ai_agent/oracle_dependency.rs`

---

## Gas Price Manipulation

**ID:** `gas-price-manipulation`  
**Severity:** Medium  
**Categories:** MEV, DeFi  
**CWE:** CWE-693, CWE-358  

### Description



### Details

Check if function has gas price bypass vulnerability

### Remediation

- Replace gas price checks in function '{}' with robust MEV protection. \
                    Example: Use commit-reveal schemes with sufficient delays, implement \
                    order batching, or use decentralized sequencers.

### Source

`crates/detectors/src/gas_price_manipulation.rs`

---

## Oracle Staleness Heartbeat

**ID:** `oracle-staleness-heartbeat`  
**Severity:** Medium  
**Categories:** Oracle, Oracle  

### Description



### Details

Oracle Staleness Heartbeat Detector (OWASP 2025)

Detects missing Chainlink heartbeat validation.
Stale price usage can lead to incorrect valuations.

### Source

`crates/detectors/src/owasp2025/oracle_staleness.rs`

---

## Missing Price Validation

**ID:** `missing-price-validation`
**Severity:** Medium
**Categories:** Oracle

### Description

Oracle price data is used without proper validation.

### Details

Using oracle price data without proper validation is a critical vulnerability that can lead to financial losses, incorrect protocol decisions, and manipulation attacks. Price oracles provide external data that should never be trusted blindly.

**Common Oracle Price Validation Issues:**

1. **No Price Range Checks:** Accepting prices that are unreasonably high or low
2. **Missing Staleness Checks:** Using outdated price data
3. **No Sanity Checks:** Not validating that price is non-zero or within expected bounds
4. **Ignoring Update Timestamps:** Not checking when the price was last updated
5. **No Circuit Breakers:** No mechanism to pause when prices are anomalous
6. **Single Oracle Dependency:** Not comparing multiple oracle sources

**Why This Matters:**

Price oracles can fail or be manipulated through:
- Flash loan attacks on price sources
- Oracle failures or downtime
- Network congestion preventing updates
- Compromised oracle operators
- Calculation errors in price feeds
- Market manipulation of underlying sources

**Example Vulnerable Code:**

```solidity
contract VulnerableLendingProtocol {
    IPriceOracle public oracle;

    // ❌ No validation - accepts any price from oracle
    function calculateCollateralValue(address token, uint amount) public view returns (uint) {
        uint price = oracle.getPrice(token);
        // No checks on price validity, range, or freshness!
        return amount * price / 1e18;
    }

    function liquidate(address borrower) external {
        uint collateralValue = calculateCollateralValue(collateral, borrowerCollateral);
        uint debtValue = calculateDebtValue(borrower);

        // ❌ Decision based on unvalidated price
        if (collateralValue < debtValue) {
            _liquidate(borrower);
        }
    }
}
```

**Attack Scenarios:**

1. **Flash Loan Price Manipulation:**
   - Attacker manipulates spot price using flash loan
   - Oracle reads manipulated price
   - Protocol uses invalid price for liquidations/collateral calculations
   - Attacker profits from incorrect valuations

2. **Stale Price Exploitation:**
   - Oracle stops updating due to network issues
   - Price remains stale while market price changes significantly
   - Attacker exploits the price difference
   - Protocol suffers losses due to outdated pricing

3. **Zero Price Attack:**
   - Oracle returns zero price due to error
   - Protocol treats asset as worthless
   - Attacker drains collateral or manipulates positions

### Remediation

**1. Implement Comprehensive Price Validation:**

```solidity
contract SecureLendingProtocol {
    IPriceOracle public oracle;

    // Price bounds (example: for ETH, reasonable bounds might be $500-$50,000)
    mapping(address => uint) public minPrice;
    mapping(address => uint) public maxPrice;

    // Maximum acceptable age for price data
    uint public constant MAX_PRICE_AGE = 1 hours;

    // ✅ Comprehensive price validation
    function calculateCollateralValue(address token, uint amount) public view returns (uint) {
        (uint price, uint timestamp) = oracle.getPriceWithTimestamp(token);

        // Validate price is not zero
        require(price > 0, "Invalid price: zero");

        // Validate price is within reasonable bounds
        require(price >= minPrice[token], "Price too low");
        require(price <= maxPrice[token], "Price too high");

        // Validate price is fresh
        require(block.timestamp - timestamp <= MAX_PRICE_AGE, "Stale price");

        return amount * price / 1e18;
    }
}
```

**2. Use Multiple Oracle Sources:**

```solidity
contract MultiOracleValidation {
    IPriceOracle public primaryOracle;
    IPriceOracle public secondaryOracle;

    uint public constant MAX_PRICE_DEVIATION = 5; // 5% max deviation

    // ✅ Compare multiple oracle sources
    function getValidatedPrice(address token) public view returns (uint) {
        uint price1 = primaryOracle.getPrice(token);
        uint price2 = secondaryOracle.getPrice(token);

        // Validate both prices are non-zero
        require(price1 > 0 && price2 > 0, "Invalid oracle price");

        // Calculate percentage difference
        uint diff = price1 > price2 ? price1 - price2 : price2 - price1;
        uint deviation = (diff * 100) / ((price1 + price2) / 2);

        // Require prices agree within threshold
        require(deviation <= MAX_PRICE_DEVIATION, "Oracle price mismatch");

        // Return average of both prices
        return (price1 + price2) / 2;
    }
}
```

**3. Implement Circuit Breakers:**

```solidity
contract CircuitBreakerOracle {
    bool public paused;
    uint public lastPrice;
    uint public constant MAX_PRICE_CHANGE = 20; // 20% max change

    // ✅ Circuit breaker for abnormal price movements
    function updatePrice(uint newPrice) external {
        require(!paused, "Circuit breaker active");

        if (lastPrice > 0) {
            uint priceChange = newPrice > lastPrice ? newPrice - lastPrice : lastPrice - newPrice;
            uint percentChange = (priceChange * 100) / lastPrice;

            // Pause if price change is too dramatic
            if (percentChange > MAX_PRICE_CHANGE) {
                paused = true;
                emit CircuitBreakerTriggered(lastPrice, newPrice);
                return;
            }
        }

        lastPrice = newPrice;
        emit PriceUpdated(newPrice);
    }
}
```

**4. Use Chainlink's Built-in Validations:**

```solidity
contract ChainlinkValidation {
    AggregatorV3Interface public priceFeed;

    // ✅ Use Chainlink's validation features
    function getValidatedPrice() public view returns (uint) {
        (
            uint80 roundId,
            int256 price,
            uint startedAt,
            uint updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Validate round is complete
        require(answeredInRound >= roundId, "Stale round");

        // Validate price is positive
        require(price > 0, "Invalid price");

        // Validate price is fresh
        require(updatedAt > 0, "Round not complete");
        require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Stale price");

        return uint(price);
    }
}
```

**5. Add Time-Weighted Average Price (TWAP):**

```solidity
contract TWAPOracle {
    struct PriceObservation {
        uint timestamp;
        uint price;
    }

    PriceObservation[] public observations;
    uint public constant TWAP_PERIOD = 30 minutes;

    // ✅ Use TWAP to resist manipulation
    function getTWAP() public view returns (uint) {
        uint cutoff = block.timestamp - TWAP_PERIOD;
        uint priceSum = 0;
        uint count = 0;

        for (uint i = observations.length; i > 0; i--) {
            if (observations[i-1].timestamp < cutoff) break;
            priceSum += observations[i-1].price;
            count++;
        }

        require(count > 0, "No observations in TWAP period");
        return priceSum / count;
    }
}
```

### Best Practices

- Always validate oracle prices are non-zero
- Implement reasonable minimum and maximum price bounds
- Check price freshness using timestamps
- Use multiple oracle sources when possible
- Implement circuit breakers for abnormal price movements
- Consider using TWAP or other manipulation-resistant price mechanisms
- Monitor oracle uptime and have fallback mechanisms
- Include governance controls for updating price bounds

### Source

`crates/detectors/src/oracle.rs`

---

