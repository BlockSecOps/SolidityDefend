// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MissingDeadlineSafe - Secure Patterns
 * @notice SECURE: Operations with proper deadline protection
 * @dev This contract demonstrates secure patterns for time-sensitive operations
 *      with deadline parameters and expiration validation.
 *
 * Security Features:
 * - Deadline parameters in all time-sensitive functions
 * - block.timestamp validation
 * - Order expiration checks
 * - Reasonable default deadlines
 * - Batch operation timeouts
 *
 * Reference: Uniswap V2/V3, SushiSwap
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice SECURE: Swap with deadline parameter
 * @dev Following Uniswap V2 pattern
 */
contract SecureSwapWithDeadline {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice SECURE: Swap with deadline parameter
     * @dev Transaction must execute before deadline
     */
    function swap(
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline
    ) external {
        // SECURE: Deadline validation
        require(block.timestamp <= deadline, "Transaction expired");

        uint256 amountOut = amountIn * reserveB / reserveA;
        require(amountOut >= minAmountOut, "Slippage");

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);

        reserveA += amountIn;
        reserveB -= amountOut;
    }

    /**
     * @notice SECURE: Multi-parameter swap with deadline
     */
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        uint256 deadline
    ) external {
        // SECURE: Validate deadline first
        require(block.timestamp <= deadline, "Expired");

        uint256 amountOut = calculateSwap(amountIn, path);
        require(amountOut >= amountOutMin, "Insufficient output");

        tokenA.transferFrom(msg.sender, address(this), amountIn);
    }

    function calculateSwap(uint256, address[] calldata) internal pure returns (uint256) {
        return 1000;
    }
}

/**
 * @notice SECURE: Orders with expiration
 * @dev Orders expire after specified time
 */
contract SecureOrderWithExpiration {
    struct Order {
        address trader;
        uint256 amount;
        uint256 price;
        uint256 expiration;
        bool filled;
    }

    Order[] public orders;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Create order with expiration
     */
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

    /**
     * @notice SECURE: Execute order with expiration check
     * @dev Validates order hasn't expired
     */
    function executeOrder(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(!order.filled, "Already filled");

        // SECURE: Expiration validation
        require(block.timestamp <= order.expiration, "Order expired");

        order.filled = true;
        token.transferFrom(order.trader, msg.sender, order.amount);
    }

    /**
     * @notice SECURE: Batch with expiration
     */
    function executeBatchOrders(
        uint256[] calldata orderIds,
        uint256 deadline
    ) external {
        // SECURE: Deadline for entire batch
        require(block.timestamp <= deadline, "Batch expired");

        for (uint256 i = 0; i < orderIds.length; i++) {
            Order storage order = orders[orderIds[i]];
            if (!order.filled && block.timestamp <= order.expiration) {
                order.filled = true;
                token.transferFrom(order.trader, msg.sender, order.amount);
            }
        }
    }
}

/**
 * @notice SECURE: DEX with deadline on all operations
 * @dev All time-sensitive functions require deadline
 */
contract SecureDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice SECURE: Buy with deadline
     */
    function buy(uint256 amount, uint256 deadline) external payable {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Expired");

        uint256 price = getPrice();
        uint256 cost = amount * price;
        require(msg.value >= cost, "Insufficient payment");

        tokenA.transfer(msg.sender, amount);
    }

    /**
     * @notice SECURE: Sell with deadline
     */
    function sell(uint256 amount, uint256 deadline) external {
        // SECURE: Deadline validation
        require(block.timestamp <= deadline, "Expired");

        uint256 price = getPrice();
        uint256 payout = amount * price;

        tokenA.transferFrom(msg.sender, address(this), amount);
        payable(msg.sender).transfer(payout);
    }

    /**
     * @notice SECURE: Add liquidity with deadline
     */
    function addLiquidity(
        uint256 amountA,
        uint256 amountB,
        uint256 deadline
    ) external {
        require(block.timestamp <= deadline, "Expired");

        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
    }

    /**
     * @notice SECURE: Remove liquidity with deadline
     */
    function removeLiquidity(
        uint256 liquidity,
        uint256 deadline
    ) external {
        require(block.timestamp <= deadline, "Expired");

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
 * @notice SECURE: Withdrawal with deadline
 * @dev User can specify deadline for withdrawal
 */
contract SecureWithdrawal {
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
     * @notice SECURE: Withdraw with deadline
     */
    function withdraw(uint256 amount, uint256 deadline) external {
        // SECURE: Deadline validation
        require(block.timestamp <= deadline, "Expired");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    /**
     * @notice SECURE: Redeem with deadline
     */
    function redeemShares(uint256 shares, uint256 deadline) external {
        require(block.timestamp <= deadline, "Expired");

        uint256 tokenAmount = calculateRedemption(shares);
        token.transfer(msg.sender, tokenAmount);
    }

    function calculateRedemption(uint256 shares) internal pure returns (uint256) {
        return shares * 2;
    }
}

/**
 * @notice SECURE: Liquidation with deadline
 * @dev Prevents holding liquidation for max profit
 */
contract SecureLiquidation {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _collateral, address _debt) {
        collateralToken = IERC20(_collateral);
        debtToken = IERC20(_debt);
    }

    /**
     * @notice SECURE: Liquidate with deadline
     */
    function liquidate(
        address user,
        uint256 amount,
        uint256 deadline
    ) external {
        // SECURE: Deadline prevents MEV timing
        require(block.timestamp <= deadline, "Expired");
        require(isLiquidatable(user), "Not liquidatable");

        uint256 collateralAmount = amount * 110 / 100;

        debt[user] -= amount;
        collateral[user] -= collateralAmount;

        debtToken.transferFrom(msg.sender, address(this), amount);
        collateralToken.transfer(msg.sender, collateralAmount);
    }

    function isLiquidatable(address) internal pure returns (bool) {
        return true;
    }
}

/**
 * @notice SECURE: Claim with deadline
 * @dev Users specify when they want claim to execute by
 */
contract SecureClaim {
    IERC20 public rewardToken;
    mapping(address => uint256) public rewards;

    constructor(address _reward) {
        rewardToken = IERC20(_reward);
    }

    /**
     * @notice SECURE: Claim with deadline
     */
    function claimRewards(uint256 deadline) external {
        // SECURE: Deadline validation
        require(block.timestamp <= deadline, "Expired");

        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No rewards");

        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, amount);
    }

    /**
     * @notice SECURE: Compound with deadline
     */
    function compound(uint256 deadline) external {
        require(block.timestamp <= deadline, "Expired");

        uint256 amount = rewards[msg.sender];
        rewards[msg.sender] = 0;
    }
}

/**
 * @notice SECURE: Batch operations with deadline
 * @dev Entire batch must execute by deadline
 */
contract SecureBatchOperations {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Batch swap with deadline
     */
    function batchSwap(
        uint256[] calldata amountsIn,
        address[] calldata recipients,
        uint256 deadline
    ) external {
        // SECURE: Deadline for batch
        require(block.timestamp <= deadline, "Batch expired");
        require(amountsIn.length == recipients.length, "Length mismatch");

        for (uint256 i = 0; i < amountsIn.length; i++) {
            token.transferFrom(msg.sender, recipients[i], amountsIn[i]);
        }
    }

    /**
     * @notice SECURE: Multi-hop with deadline
     */
    function multiHopSwap(
        uint256 amountIn,
        address[] calldata path,
        uint256 deadline
    ) external {
        // SECURE: Deadline across all hops
        require(block.timestamp <= deadline, "Expired");

        uint256 amountOut = amountIn;
        for (uint256 i = 0; i < path.length - 1; i++) {
            amountOut = amountOut * 99 / 100;
        }

        token.transfer(msg.sender, amountOut);
    }
}

/**
 * @notice SECURE: Bridge with timeout
 * @dev Cross-chain operations have timeout
 */
contract SecureBridge {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Bridge with timeout
     */
    function bridgeTransfer(
        address recipient,
        uint256 amount,
        uint256 destinationChain,
        uint256 timeout
    ) external {
        // SECURE: Timeout for cross-chain
        require(block.timestamp <= timeout, "Transfer timeout");

        token.transferFrom(msg.sender, address(this), amount);
        emit BridgeInitiated(recipient, amount, destinationChain, timeout);
    }

    event BridgeInitiated(
        address indexed recipient,
        uint256 amount,
        uint256 destinationChain,
        uint256 timeout
    );
}

/**
 * @notice SECURE: Limit order with expiration
 * @dev Orders auto-expire
 */
contract SecureLimitOrder {
    struct LimitOrder {
        address trader;
        uint256 amount;
        uint256 limitPrice;
        uint256 expiration;
        bool executed;
    }

    LimitOrder[] public orders;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Create order with expiration
     */
    function createLimitOrder(
        uint256 amount,
        uint256 limitPrice,
        uint256 expiration
    ) external {
        require(expiration > block.timestamp, "Invalid expiration");

        orders.push(LimitOrder({
            trader: msg.sender,
            amount: amount,
            limitPrice: limitPrice,
            expiration: expiration,
            executed: false
        }));
    }

    /**
     * @notice SECURE: Execute with expiration check
     */
    function executeLimitOrder(uint256 orderId) external {
        LimitOrder storage order = orders[orderId];
        require(!order.executed, "Already executed");

        // SECURE: Expiration validation
        require(block.timestamp <= order.expiration, "Order expired");

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
 * @notice SECURE: Flash swap with deadline
 * @dev Arbitrage must complete by deadline
 */
contract SecureFlashSwap {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Flash swap with deadline
     */
    function flashSwap(
        uint256 amount,
        address[] calldata path,
        uint256 deadline
    ) external {
        // SECURE: Deadline for flash swap
        require(block.timestamp <= deadline, "Flash swap expired");

        token.transfer(msg.sender, amount);
        // Execute arbitrage
        token.transferFrom(msg.sender, address(this), amount);
    }
}

/**
 * @notice SECURE: Alternative pattern with stored expiration
 * @dev Expiration checked in source code
 */
contract SecureStoredExpiration {
    struct Position {
        uint256 amount;
        uint256 expiresAt;
    }

    mapping(address => Position) public positions;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Close position with expiration check in code
     */
    function closePosition() external {
        Position storage pos = positions[msg.sender];

        // SECURE: Expiration validated in source
        require(block.timestamp <= pos.expiresAt, "Position expired");

        uint256 amount = pos.amount;
        pos.amount = 0;

        token.transfer(msg.sender, amount);
    }
}
