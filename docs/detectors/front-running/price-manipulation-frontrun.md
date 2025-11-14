# Price Manipulation Front-Running Detector

**Detector ID:** `price-manipulation-frontrun`
**Severity:** High
**Category:** MEV, Logic, DeFi
**CWE:** CWE-362 (Concurrent Execution), CWE-841 (Improper Enforcement of Behavioral Workflow)

## Description

The Price Manipulation Front-Running detector identifies vulnerabilities where contracts rely on manipulable price sources without proper validation. These vulnerabilities enable flash loan attacks, sandwich attacks, and MEV extraction through price oracle manipulation.

Price manipulation vulnerabilities occur when smart contracts:
- Use spot prices from AMMs (Uniswap, SushiSwap) without TWAP protection
- Calculate prices using token balances that can be manipulated via flash loans
- Query external oracles without validating price staleness or freshness
- Accept prices without deviation bounds or circuit breakers
- Perform large operations without checking price impact

## Vulnerability Details

### Root Cause

Modern DeFi protocols rely heavily on price oracles to determine asset values for:
- Lending/borrowing collateralization ratios
- DEX swap calculations
- Liquidation triggers
- Token minting/burning rates
- Yield farming rewards

When these price sources can be manipulated (even temporarily), attackers can:
1. **Flash loan manipulation:** Borrow large amounts → manipulate price → profit → repay loan (all in one transaction)
2. **Sandwich attacks:** Front-run victim's transaction → manipulate price → victim executes at bad price → back-run to restore price
3. **Oracle manipulation:** Exploit time gaps, staleness, or single-source oracles
4. **MEV extraction:** Monitor mempool for price-dependent transactions and extract value

### Attack Scenarios

#### Scenario 1: Flash Loan Price Manipulation

```solidity
// VULNERABLE
function borrow(uint256 collateralAmount) external {
    IUniswapV2Pair pair = IUniswapV2Pair(uniswapPool);
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();

    // Spot price - easily manipulated!
    uint256 price = uint256(reserve1) / uint256(reserve0);

    uint256 borrowAmount = collateralAmount * price * 80 / 100;
    // ...
}
```

**Attack:**
1. Attacker takes flash loan of token0
2. Swaps large amount on Uniswap → inflates reserve0, reduces reserve1
3. Calls `borrow()` → gets favorable collateral valuation due to manipulated price
4. Unwinds position and repays flash loan
5. Profit from over-collateralization

**Loss:** Protocol lends more than collateral is worth → bad debt

#### Scenario 2: Stale Oracle Exploitation

```solidity
// VULNERABLE
function liquidate(address user) external {
    // No staleness check!
    int256 price = oracle.latestAnswer();

    uint256 collateralValue = getUserCollateral(user) * uint256(price);
    uint256 debt = getUserDebt(user);

    if (collateralValue < debt) {
        // Liquidate based on stale price
    }
}
```

**Attack:**
1. Oracle price becomes stale (hasn't updated in hours)
2. Real market price moves significantly
3. Attacker liquidates users unfairly OR
4. Attacker avoids liquidation when they should be liquidated

**Loss:** Unfair liquidations or bad debt accumulation

#### Scenario 3: BalanceOf Price Calculation

```solidity
// VULNERABLE
function exchange(uint256 amountIn) external {
    uint256 poolBalanceA = tokenA.balanceOf(pool);
    uint256 poolBalanceB = tokenB.balanceOf(pool);

    // Price from balances - manipulable!
    uint256 price = poolBalanceB * 1e18 / poolBalanceA;
    uint256 amountOut = amountIn * price / 1e18;

    tokenA.transferFrom(msg.sender, address(this), amountIn);
    tokenB.transfer(msg.sender, amountOut);
}
```

**Attack:**
1. Flash loan tokenA
2. Deposit to pool → increases poolBalanceA
3. Call `exchange()` → get favorable rate
4. Withdraw and repay flash loan

**Loss:** User receives more tokens than they should

#### Scenario 4: No Price Deviation Bounds

```solidity
// VULNERABLE
function updatePrice() external {
    uint256 newPrice = oracle.getPrice(address(token));

    // No bounds checking - accepts 10x price changes!
    lastPrice = newPrice;
}
```

**Attack:**
1. Oracle is compromised or has bug
2. Reports price 10x higher than real value
3. Protocol operates on incorrect price
4. Attacker extracts value before correction

**Loss:** Systemic losses across all protocol operations

## Detection Strategy

The detector identifies price manipulation vulnerabilities through multiple pattern checks:

### Pattern 1: Spot Price from AMM

**Checks for:**
- `getAmountOut()` calls
- `getReserves()` usage with division
- Direct reserve ratio calculations
- Spot price queries

**Without:**
- TWAP (Time-Weighted Average Price) calculation
- `observe()` function (Uniswap V3)
- `cumulativePrice` or `tickCumulative` usage
- Time-weighted averaging

### Pattern 2: BalanceOf for Pricing

**Checks for:**
- `balanceOf()` calls
- Combined with arithmetic operations (`*`, `/`, `mul`, `div`)
- Used in price/value calculations

**Without:**
- Price validation checks
- Require statements validating bounds

### Pattern 3: External Oracle Without Staleness

**Checks for:**
- Oracle calls: `getPrice()`, `latestAnswer()`, `latestRoundData()`
- Price feed queries

**Without:**
- Timestamp validation
- `block.timestamp - updatedAt <= MAX_DELAY` checks
- Staleness validation

### Pattern 4: No Price Deviation Bounds

**Checks for:**
- Price updates or queries

**Without:**
- `maxDeviation` or `MAX_DEVIATION` constants
- Deviation calculation and validation
- Min/max price bounds

### Pattern 5: Large Operations Without Impact Checks

**Checks for:**
- Liquidation functions
- Flash loan/swap functions
- Large value operations

**Without:**
- Before/after price comparison
- Price impact validation
- Slippage checks

## Vulnerable Code Examples

### Example 1: DEX Spot Price

```solidity
// VULNERABLE: Uses spot reserves
contract VulnerableDEX {
    function swap(uint256 amountIn, bool aToB) external {
        // VULNERABLE: Spot price from reserves
        uint256 amountOut = amountIn * reserveB / reserveA;

        reserveA += amountIn;
        reserveB -= amountOut;

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
    }
}
```

**Issue:** Flash loans can manipulate reserves, causing users to receive unfair exchange rates.

### Example 2: Lending Without Staleness Check

```solidity
// VULNERABLE: No staleness validation
contract VulnerableLending {
    function borrow(uint256 collateralAmount) external {
        // VULNERABLE: Could be hours old
        int256 price = oracle.latestAnswer();
        require(price > 0, "Invalid price");

        uint256 borrowAmount = collateralAmount * uint256(price) * 80 / 100;
        // ...
    }
}
```

**Issue:** Stale prices allow borrowing when collateral is actually worth less.

### Example 3: No Deviation Bounds

```solidity
// VULNERABLE: Accepts any price change
contract VulnerableProtocol {
    function updatePrice() external {
        uint256 newPrice = oracle.getPrice(address(token));

        // VULNERABLE: No check if price changed 1000%
        lastPrice = newPrice;
    }
}
```

**Issue:** Oracle bugs or manipulation can cause extreme price acceptance.

## Secure Code Examples

### Example 1: TWAP Protection

```solidity
// SECURE: Uses Uniswap V3 TWAP
contract SecureTWAP {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 1800; // 30 minutes

    function getTWAP() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        // SECURE: Time-weighted price, not spot
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(TWAP_PERIOD)));

        return getPriceFromTick(arithmeticMeanTick);
    }

    function swap(uint256 amountIn) external returns (uint256) {
        // SECURE: Cannot be manipulated by flash loans
        uint256 twapPrice = getTWAP();
        return amountIn * twapPrice / 1e18;
    }
}
```

**Protection:** TWAP averages price over 30 minutes, making flash loan manipulation impossible.

### Example 2: Staleness Validation

```solidity
// SECURE: Validates price freshness
contract SecureOracle {
    uint256 public constant MAX_DELAY = 3600; // 1 hour

    function getValidPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        // SECURE: Reject stale prices
        require(block.timestamp - updatedAt <= MAX_DELAY, "Stale price");
        require(answer > 0, "Invalid price");
        require(answeredInRound >= roundId, "Stale round");

        return uint256(answer);
    }
}
```

**Protection:** Only accepts prices updated within the last hour.

### Example 3: Price Deviation Bounds

```solidity
// SECURE: Validates deviation
contract SecureDeviation {
    uint256 public constant MAX_DEVIATION = 10; // 10%
    uint256 public lastPrice;

    function updatePrice() external {
        uint256 newPrice = oracle.getPrice(address(token));

        // SECURE: Reject extreme changes
        uint256 deviation = newPrice > lastPrice ?
            (newPrice - lastPrice) * 100 / lastPrice :
            (lastPrice - newPrice) * 100 / lastPrice;

        require(deviation <= MAX_DEVIATION, "Price deviation too large");

        lastPrice = newPrice;
    }
}
```

**Protection:** Rejects price changes greater than 10%.

### Example 4: Multiple Oracle Sources

```solidity
// SECURE: Uses median of multiple oracles
contract SecureMultiOracle {
    IOracle[] public oracles;

    function getMedianPrice() public view returns (uint256) {
        uint256[] memory prices = new uint256[](oracles.length);

        for (uint256 i = 0; i < oracles.length; i++) {
            (,int256 answer,, uint256 updatedAt,) = oracles[i].latestRoundData();

            // Validate staleness for each
            require(block.timestamp - updatedAt <= MAX_DELAY, "Stale");
            prices[i] = uint256(answer);
        }

        // SECURE: Single oracle manipulation cannot affect result
        return median(prices);
    }
}
```

**Protection:** Requires compromising majority of oracles.

### Example 5: Price Impact Validation

```solidity
// SECURE: Validates price didn't move too much
contract SecureLiquidation {
    uint256 public constant MAX_IMPACT = 1; // 1%

    function liquidate(address user, uint256 amount) external {
        uint256 priceBefore = getCurrentPrice();

        // Perform liquidation
        _liquidate(user, amount);

        // SECURE: Ensure price stable
        uint256 priceAfter = getCurrentPrice();
        uint256 impact = priceAfter > priceBefore ?
            (priceAfter - priceBefore) * 100 / priceBefore :
            (priceBefore - priceAfter) * 100 / priceBefore;

        require(impact <= MAX_IMPACT, "Price impact too large");
    }
}
```

**Protection:** Prevents liquidations that significantly move the market.

## Best Practices

### 1. Use TWAP for AMM Prices

**Why:** Time-weighted averages are resistant to flash loan manipulation
**How:** Use Uniswap V3's `observe()` function with 15-30 minute windows
**Cost:** Higher gas for oracle queries

### 2. Validate Oracle Staleness

**Why:** Prevents using outdated prices
**How:** Check `block.timestamp - updatedAt <= MAX_DELAY`
**Typical:** 1-4 hour maximum delay depending on asset volatility

### 3. Implement Price Deviation Bounds

**Why:** Protects against oracle failures and extreme volatility
**How:** Limit price changes to 5-20% per update
**Balance:** Too tight → legitimate moves rejected, too loose → manipulation possible

### 4. Use Multiple Oracle Sources

**Why:** Single oracle failure or manipulation doesn't affect system
**How:** Query 3-5 oracles, use median price
**Examples:** Chainlink, Band Protocol, API3, Uniswap TWAP, custom oracles

### 5. Implement Circuit Breakers

**Why:** Pause operations during extreme market events
**How:** Automatically pause if price moves >50% in short period
**Recovery:** Manual admin intervention to resume

### 6. Add Slippage Protection

**Why:** Users protected from price manipulation
**How:** Require `minAmountOut` parameter in swaps/trades
**UX:** Calculate expected output with tolerance

### 7. Validate Price Impact

**Why:** Prevents single transaction from manipulating price
**How:** Compare price before/after large operations
**Threshold:** Typically 1-5% maximum impact

### 8. Consider Commit-Reveal

**Why:** Hides trade intent from front-runners
**How:** User commits hash of params → wait delay → reveal and execute
**Tradeoff:** Poor UX (requires two transactions)

### 9. Use Private Transaction Pools

**Why:** Transactions not visible in public mempool
**How:** Flashbots Protect, Eden Network, etc.
**Limitation:** Not all users/chains have access

### 10. Regular Oracle Health Checks

**Why:** Detect oracle issues before exploitation
**How:** Monitor deviation, staleness, response times
**Alert:** Set up monitoring and alerting systems

## Real-World Examples

### Case Study 1: Harvest Finance (October 2020)

**Loss:** $34 million

**Attack Vector:**
- Attacker used flash loans from Uniswap and Curve
- Manipulated prices between stablecoin pools (USDC/USDT)
- Protocol relied on spot prices without TWAP
- Executed arbitrage exploiting price manipulation

**Lesson:** Always use TWAP for AMM price queries

### Case Study 2: Cream Finance (Multiple Attacks 2021)

**Loss:** $130+ million total

**Attack Vector:**
- Flash loan price manipulation of collateral assets
- Protocol used spot prices for collateralization
- Attacker inflated collateral value temporarily
- Borrowed more than collateral was worth

**Lesson:** Combine TWAP with multiple oracle sources

### Case Study 3: Inverse Finance (April 2022)

**Loss:** $15.6 million

**Attack Vector:**
- Manipulation of Chainlink oracle for $INV token
- Low liquidity allowed easy price manipulation
- Protocol accepted manipulated oracle price
- Attacker borrowed against inflated collateral

**Lesson:** Implement price deviation bounds and circuit breakers

## Testing Recommendations

### Unit Tests

```solidity
function testRejectStalePrice() public {
    // Arrange: Price older than MAX_DELAY
    vm.warp(block.timestamp + 2 hours);

    // Act & Assert: Should revert
    vm.expectRevert("Stale price");
    protocol.getValidPrice();
}

function testRejectExtremeDeviation() public {
    // Arrange: Set reasonable initial price
    protocol.updatePrice(); // $1000

    // Simulate 100% price increase
    oracle.setPrice(2000e18);

    // Act & Assert: Should revert with 10% max deviation
    vm.expectRevert("Price deviation too large");
    protocol.updatePrice();
}

function testTWAPResistsFlashLoan() public {
    // Arrange: Record initial TWAP
    uint256 initialTWAP = protocol.getTWAP();

    // Act: Flash loan manipulation
    flashLoan(1000000e18);
    uniswap.swap(/* manipulate reserves */);

    // Assert: TWAP should be unchanged
    assertEq(protocol.getTWAP(), initialTWAP);
}
```

### Integration Tests

1. **Flash Loan Attack Simulation**
   - Take flash loan
   - Attempt price manipulation
   - Verify protections prevent exploitation

2. **Stale Oracle Scenario**
   - Mock oracle with stale timestamp
   - Attempt operations
   - Verify rejections

3. **Multi-Oracle Divergence**
   - Set different prices on oracles
   - Verify median calculation
   - Test with one oracle compromised

### Fuzzing Recommendations

```solidity
function testFuzz_PriceDeviation(uint256 newPrice) public {
    vm.assume(newPrice > 0 && newPrice < type(uint128).max);

    uint256 oldPrice = protocol.lastPrice();
    oracle.setPrice(newPrice);

    uint256 deviation = newPrice > oldPrice ?
        (newPrice - oldPrice) * 100 / oldPrice :
        (oldPrice - newPrice) * 100 / oldPrice;

    if (deviation > MAX_DEVIATION) {
        vm.expectRevert();
    }

    protocol.updatePrice();
}
```

## Gas Cost Analysis

| Protection | Gas Cost | Worth It? |
|-----------|----------|-----------|
| TWAP (30 min) | +50-100k | ✅ Yes - Critical |
| Staleness check | +5-10k | ✅ Yes - Cheap |
| Deviation validation | +10-15k | ✅ Yes - Important |
| Multi-oracle (3) | +100-200k | ⚠️ Depends - High value only |
| Price impact check | +20-40k | ✅ Yes - For large ops |

## References

- [SWC-114: Transaction Order Dependence](https://swcregistry.io/docs/SWC-114)
- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [Uniswap V3 Oracle Documentation](https://docs.uniswap.org/contracts/v3/guides/oracle/oracle)
- [Chainlink Price Feeds Best Practices](https://docs.chain.link/data-feeds/using-data-feeds)
- [Flash Boys 2.0: Frontrunning in Decentralized Exchanges](https://arxiv.org/abs/1904.05234)
- [Trail of Bits: Price Oracle Security](https://blog.trailofbits.com/2020/08/05/accidentally-stepping-on-a-defi-lego/)
- [Consensys Diligence: Oracle Manipulation](https://consensys.net/diligence/blog/2019/09/real-world-contract-security-9-oracle-manipulation/)
- [Rekt News: Harvest Finance](https://rekt.news/harvest-finance-rekt/)
- [Rekt News: Cream Finance](https://rekt.news/cream-rekt-2/)

## Related Detectors

- `token-transfer-frontrun` - Detects transferFrom without slippage protection
- `missing-transaction-deadline` - Detects operations without deadline parameters
- `erc20-approve-race` - Detects approve race conditions

## Version History

- **v1.3.5** (2025-11-13): Initial implementation as part of Phase 2 Week 2
