# Missing Transaction Deadline Detector

**Detector ID:** `missing-transaction-deadline`
**Severity:** Medium
**Category:** MEV, Logic, DeFi
**CWE:** CWE-682 (Incorrect Calculation), CWE-362 (Concurrent Execution)

## Description

The Missing Transaction Deadline detector identifies time-sensitive operations (swaps, trades, orders) that lack deadline parameters or expiration validation. These vulnerabilities allow transactions to be executed at unfavorable times, enabling MEV extraction, stale execution, and user fund loss.

Without deadline protection, transactions can sit in the mempool indefinitely and execute when:
- Market conditions have significantly changed
- Prices have moved against the user
- The original intent is no longer valid
- MEV bots can profit from delayed execution

## Vulnerability Details

### Root Cause

Time-sensitive DeFi operations require temporal constraints to ensure execution happens within acceptable timeframes. Without deadlines:

1. **Transaction Staling**: Submitted transactions can execute hours or days later
2. **MEV Timing Attacks**: Miners/validators can delay execution for profit
3. **Price Movement Risk**: Prices change between submission and execution
4. **Expired Conditions**: Operations execute when preconditions no longer hold
5. **User Intent Violation**: Execution doesn't match user's original intent

### Attack Scenarios

#### Scenario 1: Swap Timing Attack

```solidity
// VULNERABLE: No deadline parameter
function swap(uint256 amountIn, uint256 minAmountOut) external {
    // No deadline check!
    uint256 amountOut = calculateSwap(amountIn);
    require(amountOut >= minAmountOut, "Slippage");

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

**Attack:**
1. User submits swap transaction with gas price slightly below market
2. MEV bot sees transaction in mempool
3. Bot front-runs with higher gas to move price
4. User's transaction executes hours later at worse price
5. Bot back-runs to profit from price movement

**Loss:** User receives significantly less output than expected

#### Scenario 2: Stale Order Execution

```solidity
// VULNERABLE: No expiration check
function executeOrder(uint256 orderId) external {
    Order memory order = orders[orderId];
    // No expiration validation!

    token.transferFrom(order.trader, msg.sender, order.amount);
}
```

**Attack:**
1. User creates limit order 6 months ago
2. Market conditions have completely changed
3. Malicious executor fills ancient order at terrible price
4. User loses funds due to stale order

**Loss:** Execution at prices user never intended

#### Scenario 3: Liquidation Timing

```solidity
// VULNERABLE: No deadline on liquidation
function liquidate(address user, uint256 amount) external {
    // No deadline!
    require(isLiquidatable(user), "Not liquidatable");

    // Execute liquidation
}
```

**Attack:**
1. Liquidator submits transaction with low gas
2. Holds transaction until collateral value drops further
3. Executes liquidation at maximum profit
4. Protocol loses more than necessary

**Loss:** Excessive liquidation penalties

#### Scenario 4: Cross-Chain Bridge Delay

```solidity
// VULNERABLE: No timeout
function bridgeTransfer(
    address recipient,
    uint256 amount,
    uint256 destinationChain
) external {
    // No timeout!
    token.transferFrom(msg.sender, address(this), amount);
    emit BridgeInitiated(recipient, amount, destinationChain);
}
```

**Attack:**
1. User initiates bridge transfer
2. Transaction delayed by relayer
3. Executes on destination chain when price unfavorable
4. User receives less value than intended

**Loss:** Cross-chain value loss due to timing

## Detection Strategy

The detector identifies missing deadline vulnerabilities through:

### Step 1: Identify Time-Sensitive Operations

**Function names indicating time-sensitivity:**
- swap, trade, exchange
- buy, sell
- execute, fill
- withdraw, redeem
- liquidate
- claim

**Source code patterns:**
- Contains `transferFrom()`
- Contains swap/trade operations
- Performs value transfers

### Step 2: Check for Deadline Protection

**Parameter-based deadlines:**
```solidity
function swap(..., uint256 deadline) external
```

**Source code validation:**
```solidity
require(block.timestamp <= deadline, "Expired");
```

**Order expiration:**
```solidity
require(block.timestamp <= order.expiration, "Order expired");
```

### Step 3: Report if Missing

If time-sensitive operation has no deadline parameter AND no expiration validation in source → Flag as vulnerable

## Vulnerable Code Examples

### Example 1: Swap Without Deadline

```solidity
// VULNERABLE: Missing deadline
function swap(
    uint256 amountIn,
    uint256 minAmountOut
) external {
    // Has slippage protection but no deadline!
    uint256 amountOut = calculateSwap(amountIn);
    require(amountOut >= minAmountOut, "Slippage");

    executeSwap(amountIn, amountOut);
}
```

**Issue:** Transaction can execute hours later when slippage bounds no longer protective.

### Example 2: Order Execution Without Expiration

```solidity
// VULNERABLE: Orders never expire
function executeOrder(uint256 orderId) external {
    Order storage order = orders[orderId];
    require(!order.filled, "Already filled");
    // No expiration check!

    order.filled = true;
    token.transferFrom(order.trader, msg.sender, order.amount);
}
```

**Issue:** Orders from months/years ago can still execute.

### Example 3: Liquidation Without Deadline

```solidity
// VULNERABLE: Liquidation timing attack
function liquidate(address user) external {
    require(isLiquidatable(user), "Not liquidatable");
    // No deadline - liquidator can time for max profit

    executeLiquidation(user);
}
```

**Issue:** Liquidators can delay execution for maximum profit extraction.

### Example 4: Batch Operations Without Timeout

```solidity
// VULNERABLE: Batch without deadline
function batchSwap(
    uint256[] calldata amounts,
    address[] calldata recipients
) external {
    // No deadline for batch!
    for (uint256 i = 0; i < amounts.length; i++) {
        executeSwap(amounts[i], recipients[i]);
    }
}
```

**Issue:** Entire batch can execute at unfavorable time.

## Secure Code Examples

### Example 1: Swap With Deadline (Uniswap Pattern)

```solidity
// SECURE: Following Uniswap V2/V3 pattern
function swap(
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 deadline  // ✅ Deadline parameter
) external {
    // SECURE: Validate deadline first
    require(block.timestamp <= deadline, "Transaction expired");

    uint256 amountOut = calculateSwap(amountIn);
    require(amountOut >= minAmountOut, "Slippage");

    executeSwap(amountIn, amountOut);
}
```

**Protection:** Transaction reverts if not mined by deadline.

**Frontend usage:**
```javascript
const deadline = Math.floor(Date.now() / 1000) + 60 * 15; // 15 minutes
await contract.swap(amountIn, minAmountOut, deadline);
```

### Example 2: Order With Expiration

```solidity
// SECURE: Orders have expiration
struct Order {
    address trader;
    uint256 amount;
    uint256 price;
    uint256 expiration;  // ✅ Expiration timestamp
    bool filled;
}

function createOrder(
    uint256 amount,
    uint256 price,
    uint256 expiration
) external {
    require(expiration > block.timestamp, "Invalid expiration");

    orders.push(Order({
        trader: msg.sender,
        amount: amount,
        price: price,
        expiration: expiration,
        filled: false
    }));
}

function executeOrder(uint256 orderId) external {
    Order storage order = orders[orderId];
    require(!order.filled, "Already filled");

    // SECURE: Check expiration
    require(block.timestamp <= order.expiration, "Order expired");

    order.filled = true;
    token.transferFrom(order.trader, msg.sender, order.amount);
}
```

**Protection:** Orders automatically expire, preventing stale execution.

### Example 3: Liquidation With Deadline

```solidity
// SECURE: Liquidation must execute promptly
function liquidate(
    address user,
    uint256 amount,
    uint256 deadline  // ✅ Deadline parameter
) external {
    // SECURE: Validate deadline
    require(block.timestamp <= deadline, "Liquidation expired");
    require(isLiquidatable(user), "Not liquidatable");

    executeLiquidation(user, amount);
}
```

**Protection:** Prevents holding liquidation for timing advantage.

### Example 4: Batch With Deadline

```solidity
// SECURE: Batch operations have deadline
function batchSwap(
    uint256[] calldata amounts,
    address[] calldata recipients,
    uint256 deadline  // ✅ Deadline for entire batch
) external {
    // SECURE: Validate deadline
    require(block.timestamp <= deadline, "Batch expired");

    for (uint256 i = 0; i < amounts.length; i++) {
        executeSwap(amounts[i], recipients[i]);
    }
}
```

**Protection:** Entire batch must execute by deadline or reverts.

### Example 5: Bridge With Timeout

```solidity
// SECURE: Cross-chain transfers have timeout
function bridgeTransfer(
    address recipient,
    uint256 amount,
    uint256 destinationChain,
    uint256 timeout  // ✅ Timeout parameter
) external {
    // SECURE: Validate timeout
    require(block.timestamp <= timeout, "Bridge transfer timeout");

    token.transferFrom(msg.sender, address(this), amount);
    emit BridgeInitiated(recipient, amount, destinationChain, timeout);
}
```

**Protection:** Bridge transfers must complete within timeout or can be refunded.

## Best Practices

### 1. Always Include Deadline Parameters

**For all time-sensitive operations:**
```solidity
function timeOperation(..., uint256 deadline) external {
    require(block.timestamp <= deadline, "Expired");
    // ... operation
}
```

**Operations requiring deadlines:**
- Swaps and trades
- Liquidity additions/removals
- Order executions
- Withdrawals and redemptions
- Liquidations
- Claims and harvests
- Cross-chain operations
- Batch operations

### 2. Use Reasonable Default Deadlines

**Frontend implementation:**
```javascript
// Short-term operations: 15 minutes
const deadline = currentTimestamp + 60 * 15;

// Medium-term operations: 1 hour
const deadline = currentTimestamp + 60 * 60;

// Long-term orders: days/weeks (with expiration)
const expiration = currentTimestamp + 60 * 60 * 24 * 30;
```

**Contract defaults (if frontend doesn't provide):**
```solidity
uint256 constant DEFAULT_DEADLINE = 15 minutes;

function swap(uint256 amount) external {
    _swapWithDeadline(amount, block.timestamp + DEFAULT_DEADLINE);
}
```

### 3. Store Expiration for Orders

**Order structures should include expiration:**
```solidity
struct Order {
    // ... other fields
    uint256 expiration;  // ✅ Always include
}
```

**Validate on execution:**
```solidity
require(block.timestamp <= order.expiration, "Order expired");
```

### 4. Batch Operations Need Deadlines

**Apply deadline to entire batch:**
```solidity
function batchOperation(
    uint256[] calldata data,
    uint256 deadline
) external {
    require(block.timestamp <= deadline, "Batch expired");

    for (uint256 i = 0; i < data.length; i++) {
        // Process each item
    }
}
```

### 5. Cross-Chain Operations Need Timeouts

**Bridge transfers:**
```solidity
struct BridgeRequest {
    address recipient;
    uint256 amount;
    uint256 timeout;
}

function initiateBridge(..., uint256 timeout) external {
    require(timeout > block.timestamp + MIN_TIMEOUT, "Timeout too short");
    // ... bridge logic
}
```

**Timeout should allow for:**
- Network congestion
- Relayer delays
- Destination chain confirmation
- Reasonable safety margin

### 6. Document Deadline Behavior

**In function comments:**
```solidity
/**
 * @param deadline Unix timestamp after which transaction reverts
 * @notice Transaction will revert if not mined by deadline
 * @dev Recommended: block.timestamp + 15 minutes
 */
function swap(
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 deadline
) external;
```

### 7. Consider Deadline Granularity

**Block-based vs timestamp-based:**
```solidity
// Timestamp-based (more common)
require(block.timestamp <= deadline, "Expired");

// Block-based (for specific use cases)
require(block.number <= deadlineBlock, "Expired");
```

**Timestamp-based is preferred** for most DeFi operations.

### 8. Emergency Operations May Skip Deadline

**Critical operations that must execute:**
```solidity
function emergencyWithdraw() external onlyOwner {
    // No deadline needed for emergency functions
    // that must execute regardless of timing
}
```

**Use sparingly** - only for true emergencies.

### 9. View Functions Don't Need Deadlines

**Read-only operations:**
```solidity
function getPrice() external view returns (uint256) {
    // No deadline needed for view functions
}
```

### 10. Gas Price Considerations

**Deadline doesn't prevent low gas issues:**
```solidity
// User still needs reasonable gas price
// Deadline only prevents indefinite delays
```

**Best practice:** Use reasonable gas + deadline together.

## Real-World Examples

### Case Study 1: Uniswap V2

**Implementation:**
```solidity
function swapExactTokensForTokens(
    uint amountIn,
    uint amountOutMin,
    address[] calldata path,
    address to,
    uint deadline  // ✅ Deadline parameter
) external returns (uint[] memory amounts) {
    require(block.timestamp <= deadline, 'UniswapV2Router: EXPIRED');
    // ... swap logic
}
```

**Benefit:** Prevents stale swaps from executing at unfavorable prices.

### Case Study 2: SushiSwap

**Consistent pattern across all operations:**
- All swaps have deadline
- All liquidity operations have deadline
- All remove liquidity operations have deadline

**Result:** Users protected from timing attacks.

### Case Study 3: Curve Finance

**Some pools lacked deadlines in early versions:**
- Users suffered from delayed execution
- Later versions added deadline parameters
- Improved user protection

**Lesson:** Always include deadlines from initial deployment.

## Testing Recommendations

### Unit Tests

```solidity
function testSwapRevertsAfterDeadline() public {
    uint256 deadline = block.timestamp + 1 hours;

    // Fast forward past deadline
    vm.warp(deadline + 1);

    // Should revert
    vm.expectRevert("Transaction expired");
    dex.swap(amountIn, minAmountOut, deadline);
}

function testSwapExecutesBeforeDeadline() public {
    uint256 deadline = block.timestamp + 1 hours;

    // Execute before deadline
    dex.swap(amountIn, minAmountOut, deadline);

    // Should succeed
    assertEq(token.balanceOf(user), expectedAmount);
}

function testOrderExpiresCorrectly() public {
    uint256 expiration = block.timestamp + 1 days;
    dex.createOrder(amount, price, expiration);

    // Fast forward past expiration
    vm.warp(expiration + 1);

    // Execution should revert
    vm.expectRevert("Order expired");
    dex.executeOrder(0);
}
```

### Integration Tests

1. **Deadline Boundary Testing**
   - Execute exactly at deadline
   - Execute 1 second before deadline
   - Execute 1 second after deadline

2. **Order Lifecycle**
   - Create order with expiration
   - Execute before expiration (success)
   - Attempt execution after expiration (fail)

3. **Batch Operation Timing**
   - Submit batch with deadline
   - Ensure entire batch respects deadline

### Fuzzing

```solidity
function testFuzz_DeadlineValidation(uint256 deadline) public {
    vm.assume(deadline > 0);

    if (deadline < block.timestamp) {
        vm.expectRevert("Transaction expired");
    }

    dex.swap(amountIn, minAmountOut, deadline);
}
```

## Gas Cost Analysis

| Protection | Gas Cost | Worth It? |
|-----------|----------|-----------|
| Deadline parameter | +2-5k | ✅ Yes - Essential |
| Deadline validation | +5k | ✅ Yes - Critical |
| Order expiration check | +5-10k | ✅ Yes - Important |
| Batch deadline | +5k | ✅ Yes - Protects all |

**Conclusion:** Deadline protection is cheap and essential.

## Common Pitfalls

### Pitfall 1: Deadline Too Far in Future

```solidity
// BAD: 1 year deadline
uint256 deadline = block.timestamp + 365 days;
```

**Issue:** Defeats purpose of deadline protection.

**Solution:** Use reasonable timeframes (15 minutes to 1 hour).

### Pitfall 2: No Frontend Integration

```solidity
// Contract has deadline parameter but frontend doesn't use it
function swap(..., uint256 deadline) external;

// Frontend calls without deadline
await contract.swap(amount, minOut, 0);  // BAD
```

**Solution:** Frontend must calculate and pass deadline.

### Pitfall 3: Inconsistent Deadline Usage

```solidity
// Some functions have deadline, others don't
function swapA(..., uint256 deadline) external;  // ✅
function swapB(...) external;  // ❌
```

**Solution:** Apply deadline consistently across all time-sensitive operations.

## References

- [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)
- [CWE-362: Concurrent Execution using Shared Resource](https://cwe.mitre.org/data/definitions/362.html)
- [Uniswap V2 Router](https://github.com/Uniswap/v2-periphery/blob/master/contracts/UniswapV2Router02.sol)
- [Uniswap V3 Router](https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol)
- [SushiSwap Router](https://github.com/sushiswap/sushiswap/blob/master/contracts/uniswapv2/UniswapV2Router02.sol)
- [MEV and Transaction Ordering](https://ethereum.org/en/developers/docs/mev/)

## Related Detectors

- `price-manipulation-frontrun` - Detects price oracle manipulation vulnerabilities
- `token-transfer-frontrun` - Detects transferFrom without slippage protection
- `erc20-approve-race` - Detects approve race conditions

## Version History

- **v1.3.5** (2025-11-13): Initial implementation as part of Phase 2 Week 2
