// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TokenTransferFrontrun
 * @notice VULNERABLE: Token transfer operations without slippage protection
 * @dev This contract demonstrates transferFrom vulnerabilities in price-dependent
 *      contexts that lack slippage protection or deadline checks.
 *
 * Vulnerability: CWE-362 (Concurrent Execution using Shared Resource)
 * Severity: MEDIUM
 * Impact: MEV extraction, sandwich attacks, price manipulation
 *
 * Common attack scenario (Sandwich Attack):
 * 1. User submits buyTokens(1 ETH) expecting ~1000 tokens at current price
 * 2. Attacker monitors mempool, sees user's transaction
 * 3. Attacker front-runs by buying tokens first, increasing price
 * 4. User's transaction executes at higher price, gets fewer tokens
 * 5. Attacker back-runs by selling tokens at profit
 *
 * Real-world impact:
 * - $1B+ extracted via MEV in DeFi (2023)
 * - Sandwich attacks account for 20%+ of MEV
 * - Users lose 1-5% on average per trade
 */

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice VULNERABLE: Token purchase without slippage protection
 */
contract VulnerableTokenPurchase {
    IERC20 public token;
    uint256 public price = 1000; // 1000 tokens per ETH

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: buyTokens without minimum output amount
     * @dev Price can change between tx submission and execution
     */
    function buyTokens() external payable {
        // VULNERABLE: No slippage protection
        // Attacker can front-run and manipulate price
        uint256 amount = msg.value * price;

        // User expects certain amount but has no guarantee
        token.transferFrom(address(this), msg.sender, amount);
    }

    // Admin can change price anytime (front-running vector)
    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}

/**
 * @notice VULNERABLE: NFT minting without price lock
 */
contract VulnerableNFTMint {
    IERC20 public paymentToken;
    uint256 public mintPrice = 100 * 10**18; // 100 tokens

    constructor(address _paymentToken) {
        paymentToken = IERC20(_paymentToken);
    }

    /**
     * @notice VULNERABLE: mint without deadline or price lock
     * @dev Price can be front-run changed before user's tx executes
     */
    function mint() external {
        // VULNERABLE: Price read from storage (can be front-run changed)
        // No deadline - tx could execute hours later at different price
        paymentToken.transferFrom(msg.sender, address(this), mintPrice);

        // Mint NFT...
    }

    // Owner can front-run user's mint by increasing price
    function setMintPrice(uint256 newPrice) external {
        mintPrice = newPrice;
    }
}

/**
 * @notice VULNERABLE: DEX swap without slippage limits
 */
contract VulnerableDEXSwap {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice VULNERABLE: swap without minAmountOut
     * @dev Classic sandwich attack target
     */
    function swap(uint256 amountIn) external {
        // VULNERABLE: No minimum output amount specified
        // Attacker can:
        // 1. Front-run: Buy tokenB (increases price)
        // 2. User's swap executes at worse price
        // 3. Back-run: Sell tokenB at profit

        uint256 amountOut = getAmountOut(amountIn);

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
    }

    function getAmountOut(uint256 amountIn) public view returns (uint256) {
        // Simplified AMM formula (vulnerable to manipulation)
        return amountIn * 95 / 100; // Assumes 5% fee
    }
}

/**
 * @notice VULNERABLE: Token sale without deadline
 */
contract VulnerableTokenSale {
    IERC20 public token;
    uint256 public price;

    constructor(address _token, uint256 _price) {
        token = IERC20(_token);
        price = _price;
    }

    /**
     * @notice VULNERABLE: purchase without deadline parameter
     * @dev Transaction could execute hours/days later at different market conditions
     */
    function purchase(uint256 amount) external payable {
        // VULNERABLE: No deadline check
        // User's tx might be pending for long time
        // Market conditions change significantly

        require(msg.value >= amount * price, "Insufficient payment");

        token.transferFrom(address(this), msg.sender, amount);
    }
}

/**
 * @notice VULNERABLE: Auction bid without commit-reveal
 */
contract VulnerableAuction {
    IERC20 public paymentToken;
    mapping(address => uint256) public bids;

    constructor(address _paymentToken) {
        paymentToken = IERC20(_paymentToken);
    }

    /**
     * @notice VULNERABLE: Transparent bidding allows front-running
     * @dev Attacker can see bid in mempool and outbid
     */
    function bid(uint256 amount) external {
        // VULNERABLE: Bid visible in mempool before execution
        // Attacker can front-run with higher bid

        paymentToken.transferFrom(msg.sender, address(this), amount);
        bids[msg.sender] = amount;
    }
}

/**
 * @notice VULNERABLE: Liquidity provision without price bounds
 */
contract VulnerableLiquidityPool {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice VULNERABLE: addLiquidity without price bounds
     * @dev Attacker can manipulate pool before user's tx executes
     */
    function addLiquidity(uint256 amountA, uint256 amountB) external {
        // VULNERABLE: No price bounds (minAmountA/B given other amount)
        // Attacker can manipulate pool ratio before this executes
        // User provides liquidity at unfavorable ratio

        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);

        // Mint LP tokens...
    }
}

/**
 * @notice VULNERABLE: Flash loan arbitrage without protection
 */
contract VulnerableArbitrage {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: executeArbitrage without slippage limits
     * @dev Price differences might disappear or reverse before execution
     */
    function executeArbitrage(uint256 amount) external {
        // VULNERABLE: No minimum profit guarantee
        // Price difference might disappear due to front-running
        // Or attacker front-runs to steal the arbitrage opportunity

        uint256 expectedProfit = calculateProfit(amount);

        token.transferFrom(msg.sender, address(this), amount);

        // Execute arbitrage trades...
        // Actual profit might be much less or negative
    }

    function calculateProfit(uint256) internal pure returns (uint256) {
        return 100; // Simplified
    }
}

/**
 * @notice VULNERABLE: Batch purchase without individual limits
 */
contract VulnerableBatchPurchase {
    IERC20 public token;
    uint256 public pricePerUnit;

    constructor(address _token, uint256 _price) {
        token = IERC20(_token);
        pricePerUnit = _price;
    }

    /**
     * @notice VULNERABLE: batchBuy without price protection per item
     * @dev Price can be manipulated between items in batch
     */
    function batchBuy(uint256[] calldata amounts) external payable {
        // VULNERABLE: No aggregate slippage limit
        // Price could spike mid-batch execution

        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 cost = amounts[i] * getCurrentPrice();
            token.transferFrom(address(this), msg.sender, amounts[i]);
        }
    }

    function getCurrentPrice() public view returns (uint256) {
        return pricePerUnit;
    }
}

/**
 * @notice VULNERABLE: Limit order without expiration
 */
contract VulnerableLimitOrder {
    IERC20 public token;

    struct Order {
        address trader;
        uint256 amount;
        uint256 targetPrice;
    }

    Order[] public orders;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: createOrder without expiration time
     * @dev Order could execute far in future at unfavorable conditions
     */
    function createOrder(uint256 amount, uint256 targetPrice) external {
        // VULNERABLE: No expiration/deadline
        // Order might execute weeks later when trader no longer wants it

        orders.push(Order({
            trader: msg.sender,
            amount: amount,
            targetPrice: targetPrice
        }));
    }

    function executeOrder(uint256 orderId) external {
        Order memory order = orders[orderId];
        require(getCurrentPrice() <= order.targetPrice, "Price too high");

        // VULNERABLE: No deadline check
        token.transferFrom(order.trader, address(this), order.amount);
    }

    function getCurrentPrice() public pure returns (uint256) {
        return 1000;
    }
}

/**
 * @notice VULNERABLE: Price oracle relying on spot price
 */
contract VulnerableOracleDependent {
    IERC20 public token;
    IPriceOracle public oracle;

    constructor(address _token, address _oracle) {
        token = IERC20(_token);
        oracle = IPriceOracle(_oracle);
    }

    /**
     * @notice VULNERABLE: Uses spot price without TWAP
     * @dev Spot price can be manipulated via flash loans
     */
    function trade(uint256 amountIn) external {
        // VULNERABLE: Spot price oracle (can be flash-loan manipulated)
        // No TWAP or minimum output amount

        uint256 price = oracle.getPrice();
        uint256 amountOut = amountIn * price;

        token.transferFrom(msg.sender, address(this), amountIn);
        // Transfer based on manipulatable price...
    }
}

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

/**
 * @notice VULNERABLE: Staking reward claim without protection
 */
contract VulnerableStaking {
    IERC20 public rewardToken;
    mapping(address => uint256) public rewards;

    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
    }

    /**
     * @notice VULNERABLE: claimRewards without minimum amount
     * @dev Reward calculation could be manipulated before claim
     */
    function claimRewards() external {
        // VULNERABLE: Reward amount not locked at claim initiation
        // Attacker could manipulate reward calculation before this executes

        uint256 reward = calculateReward(msg.sender);

        rewardToken.transferFrom(address(this), msg.sender, reward);
        rewards[msg.sender] = 0;
    }

    function calculateReward(address) internal pure returns (uint256) {
        return 1000; // Simplified
    }
}
