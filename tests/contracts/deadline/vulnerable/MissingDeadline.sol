// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MissingDeadline - Vulnerable Patterns
 * @notice VULNERABLE: Operations without transaction deadlines
 * @dev This contract demonstrates patterns where time-sensitive operations
 *      lack deadline parameters, allowing MEV extraction and stale execution.
 *
 * Vulnerabilities Demonstrated:
 * 1. Swap without deadline
 * 2. Trade execution without expiration
 * 3. Order filling without timeout
 * 4. Batch operations without deadline
 * 5. Withdrawals without time limit
 * 6. Liquidations without deadline
 * 7. Claims without expiration
 * 8. Cross-chain operations without timeout
 *
 * Attack Vectors:
 * - MEV bots delaying execution
 * - Stale price execution
 * - Sandwich attacks with timing
 * - Expired conditions executing
 *
 * Reference: Uniswap, SushiSwap best practices
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice VULNERABLE Pattern 1: Swap without deadline
 * @dev Transaction can sit in mempool and execute at any time
 */
contract VulnerableSwapNoDeadline {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice VULNERABLE: No deadline parameter
     * @dev MEV bot can delay this transaction until price is unfavorable
     */
    function swap(uint256 amountIn, uint256 minAmountOut) external {
        // VULNERABLE: No deadline check
        // Transaction could execute hours later

        uint256 amountOut = amountIn * reserveB / reserveA;
        require(amountOut >= minAmountOut, "Slippage");

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);

        reserveA += amountIn;
        reserveB -= amountOut;
    }

    /**
     * @notice VULNERABLE: Swap with only slippage, no deadline
     */
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external {
        // VULNERABLE: Has slippage protection but no deadline
        // Can still be held and executed at bad time

        uint256 amountOut = calculateSwap(amountIn, path);
        require(amountOut >= amountOutMin, "Insufficient output");

        // Execute swap
        tokenA.transferFrom(msg.sender, address(this), amountIn);
    }

    function calculateSwap(uint256, address[] calldata) internal pure returns (uint256) {
        return 1000; // Simplified
    }
}

/**
 * @notice VULNERABLE Pattern 2: Trade execution without expiration
 * @dev Order can be filled at any time, regardless of market conditions
 */
contract VulnerableTradeExecution {
    struct Order {
        address trader;
        uint256 amount;
        uint256 price;
        bool filled;
    }

    Order[] public orders;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function createOrder(uint256 amount, uint256 price) external {
        orders.push(Order({
            trader: msg.sender,
            amount: amount,
            price: price,
            filled: false
        }));
    }

    /**
     * @notice VULNERABLE: No expiration check
     * @dev Order created months ago can still be executed
     */
    function executeOrder(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(!order.filled, "Already filled");

        // VULNERABLE: No expiration validation
        // Order from 6 months ago could execute now

        order.filled = true;
        token.transferFrom(order.trader, msg.sender, order.amount);
    }

    /**
     * @notice VULNERABLE: Batch execution without deadline
     */
    function executeBatchOrders(uint256[] calldata orderIds) external {
        // VULNERABLE: No deadline for batch
        for (uint256 i = 0; i < orderIds.length; i++) {
            Order storage order = orders[orderIds[i]];
            if (!order.filled) {
                order.filled = true;
                token.transferFrom(order.trader, msg.sender, order.amount);
            }
        }
    }
}

/**
 * @notice VULNERABLE Pattern 3: DEX operations without deadline
 * @dev All critical operations lack time constraints
 */
contract VulnerableDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice VULNERABLE: Buy without deadline
     */
    function buy(uint256 amount) external payable {
        // VULNERABLE: No deadline
        uint256 price = getPrice();
        uint256 cost = amount * price;
        require(msg.value >= cost, "Insufficient payment");

        tokenA.transfer(msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: Sell without deadline
     */
    function sell(uint256 amount) external {
        // VULNERABLE: No deadline
        uint256 price = getPrice();
        uint256 payout = amount * price;

        tokenA.transferFrom(msg.sender, address(this), amount);
        payable(msg.sender).transfer(payout);
    }

    /**
     * @notice VULNERABLE: Add liquidity without deadline
     */
    function addLiquidity(uint256 amountA, uint256 amountB) external {
        // VULNERABLE: No deadline
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
    }

    /**
     * @notice VULNERABLE: Remove liquidity without deadline
     */
    function removeLiquidity(uint256 liquidity) external {
        // VULNERABLE: No deadline
        uint256 amountA = liquidity / 2;
        uint256 amountB = liquidity / 2;

        tokenA.transfer(msg.sender, amountA);
        tokenB.transfer(msg.sender, amountB);
    }

    function getPrice() public pure returns (uint256) {
        return 1e18;
    }
}

/**
 * @notice VULNERABLE Pattern 4: Withdrawal without time limit
 * @dev Allows withdrawals at any time without considering market conditions
 */
contract VulnerableWithdrawal {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    /**
     * @notice VULNERABLE: Withdraw without deadline
     * @dev User's transaction could execute at bad exchange rate
     */
    function withdraw(uint256 amount) external {
        // VULNERABLE: No deadline
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: Redeem shares without deadline
     */
    function redeemShares(uint256 shares) external {
        // VULNERABLE: No deadline
        uint256 tokenAmount = calculateRedemption(shares);
        token.transfer(msg.sender, tokenAmount);
    }

    function calculateRedemption(uint256 shares) internal pure returns (uint256) {
        return shares * 2;
    }
}

/**
 * @notice VULNERABLE Pattern 5: Liquidation without deadline
 * @dev Can be held until most profitable for liquidator
 */
contract VulnerableLiquidation {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _collateral, address _debt) {
        collateralToken = IERC20(_collateral);
        debtToken = IERC20(_debt);
    }

    /**
     * @notice VULNERABLE: Liquidate without deadline
     * @dev MEV bot can hold transaction until max profit
     */
    function liquidate(address user, uint256 amount) external {
        // VULNERABLE: No deadline
        require(isLiquidatable(user), "Not liquidatable");

        uint256 collateralAmount = amount * 110 / 100; // 10% bonus

        debt[user] -= amount;
        collateral[user] -= collateralAmount;

        debtToken.transferFrom(msg.sender, address(this), amount);
        collateralToken.transfer(msg.sender, collateralAmount);
    }

    function isLiquidatable(address) internal pure returns (bool) {
        return true; // Simplified
    }
}

/**
 * @notice VULNERABLE Pattern 6: Claim without expiration
 * @dev Rewards can be claimed at any time
 */
contract VulnerableClaim {
    IERC20 public rewardToken;
    mapping(address => uint256) public rewards;

    constructor(address _reward) {
        rewardToken = IERC20(_reward);
    }

    /**
     * @notice VULNERABLE: Claim rewards without deadline
     * @dev User transaction could execute when token price is low
     */
    function claimRewards() external {
        // VULNERABLE: No deadline
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No rewards");

        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: Compound without deadline
     */
    function compound() external {
        // VULNERABLE: No deadline
        uint256 amount = rewards[msg.sender];
        rewards[msg.sender] = 0;
        // Reinvest at current rate (could be unfavorable)
    }
}

/**
 * @notice VULNERABLE Pattern 7: Batch operations without deadline
 * @dev Multiple operations without time constraints
 */
contract VulnerableBatchOperations {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Batch swap without deadline
     */
    function batchSwap(
        uint256[] calldata amountsIn,
        address[] calldata recipients
    ) external {
        // VULNERABLE: No deadline for entire batch
        require(amountsIn.length == recipients.length, "Length mismatch");

        for (uint256 i = 0; i < amountsIn.length; i++) {
            token.transferFrom(msg.sender, recipients[i], amountsIn[i]);
        }
    }

    /**
     * @notice VULNERABLE: Multi-hop swap without deadline
     */
    function multiHopSwap(
        uint256 amountIn,
        address[] calldata path
    ) external {
        // VULNERABLE: No deadline across multiple hops
        uint256 amountOut = amountIn;
        for (uint256 i = 0; i < path.length - 1; i++) {
            // Perform swaps
            amountOut = amountOut * 99 / 100; // Fee
        }

        token.transfer(msg.sender, amountOut);
    }
}

/**
 * @notice VULNERABLE Pattern 8: Cross-chain operations without timeout
 * @dev Bridge operations without time limits
 */
contract VulnerableBridge {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Bridge transfer without timeout
     * @dev Cross-chain tx could execute hours later
     */
    function bridgeTransfer(
        address recipient,
        uint256 amount,
        uint256 destinationChain
    ) external {
        // VULNERABLE: No timeout
        // Cross-chain message could be delayed significantly

        token.transferFrom(msg.sender, address(this), amount);
        // Emit event for relayer
        emit BridgeInitiated(recipient, amount, destinationChain);
    }

    event BridgeInitiated(address indexed recipient, uint256 amount, uint256 destinationChain);
}

/**
 * @notice VULNERABLE Pattern 9: Limit order without expiration
 * @dev Orders never expire
 */
contract VulnerableLimitOrder {
    struct LimitOrder {
        address trader;
        uint256 amount;
        uint256 limitPrice;
        bool executed;
    }

    LimitOrder[] public orders;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function createLimitOrder(uint256 amount, uint256 limitPrice) external {
        orders.push(LimitOrder({
            trader: msg.sender,
            amount: amount,
            limitPrice: limitPrice,
            executed: false
        }));
    }

    /**
     * @notice VULNERABLE: Execute limit order without checking expiration
     */
    function executeLimitOrder(uint256 orderId) external {
        LimitOrder storage order = orders[orderId];
        require(!order.executed, "Already executed");

        // VULNERABLE: No expiration check
        // Order from 2 years ago could execute

        uint256 currentPrice = getCurrentPrice();
        require(currentPrice <= order.limitPrice, "Price too high");

        order.executed = true;
        token.transferFrom(order.trader, msg.sender, order.amount);
    }

    function getCurrentPrice() public pure returns (uint256) {
        return 1000;
    }
}

/**
 * @notice VULNERABLE Pattern 10: Flash swap without deadline
 * @dev Arbitrage operations without time limits
 */
contract VulnerableFlashSwap {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Flash swap without deadline
     * @dev Arbitrage could execute when opportunity is gone
     */
    function flashSwap(
        uint256 amount,
        address[] calldata path
    ) external {
        // VULNERABLE: No deadline
        // Arbitrage opportunity could be gone by execution time

        token.transfer(msg.sender, amount);
        // Execute arbitrage across path
        // Expect repayment
        token.transferFrom(msg.sender, address(this), amount);
    }
}
