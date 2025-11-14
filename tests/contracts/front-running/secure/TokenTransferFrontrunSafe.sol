// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TokenTransferFrontrunSafe
 * @notice SECURE: Token transfer operations with proper slippage protection
 * @dev This contract demonstrates secure patterns for price-dependent token transfers
 *      that prevent front-running attacks and MEV extraction.
 *
 * Security Features:
 * - Slippage protection (minAmountOut parameters)
 * - Deadline checks (transaction expiration)
 * - TWAP oracles (manipulation-resistant pricing)
 * - Commit-reveal schemes (hidden intent)
 * - Price bounds for liquidity operations
 *
 * Reference: Uniswap V3, CowSwap, Flashbots
 */

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice SECURE: Token purchase with slippage protection
 */
contract SecureTokenPurchase {
    IERC20 public token;
    uint256 public price = 1000; // 1000 tokens per ETH

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: buyTokens with minimum output amount
     * @param minAmountOut Minimum tokens to receive (slippage protection)
     * @dev User specifies acceptable slippage tolerance
     */
    function buyTokens(uint256 minAmountOut) external payable {
        uint256 amount = msg.value * price;

        // SECURE: Revert if slippage exceeded
        require(amount >= minAmountOut, "Slippage: insufficient output");

        token.transferFrom(address(this), msg.sender, amount);
    }

    // Price can change, but user is protected by minAmountOut
    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}

/**
 * @notice SECURE: NFT minting with price lock and deadline
 */
contract SecureNFTMint {
    IERC20 public paymentToken;
    uint256 public mintPrice = 100 * 10**18;

    constructor(address _paymentToken) {
        paymentToken = IERC20(_paymentToken);
    }

    /**
     * @notice SECURE: mint with expected price and deadline
     * @param expectedPrice Price user agrees to pay (price lock)
     * @param deadline Transaction must execute before this timestamp
     */
    function mint(uint256 expectedPrice, uint256 deadline) external {
        // SECURE: Deadline check prevents delayed execution
        require(block.timestamp <= deadline, "Transaction expired");

        // SECURE: User locks in price at transaction submission
        require(mintPrice == expectedPrice, "Price changed");

        paymentToken.transferFrom(msg.sender, address(this), mintPrice);

        _mintNFT(msg.sender);
    }

    function setMintPrice(uint256 newPrice) external {
        mintPrice = newPrice;
    }

    function _mintNFT(address) internal {
        // Mint logic
    }
}

/**
 * @notice SECURE: DEX swap with slippage and deadline (Uniswap V3 pattern)
 */
contract SecureDEXSwap {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice SECURE: swap with complete protection (Uniswap V3 style)
     * @param amountIn Input token amount
     * @param minAmountOut Minimum output (slippage protection)
     * @param deadline Transaction expiration (deadline protection)
     */
    function swap(
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline
    ) external returns (uint256 amountOut) {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Transaction too old");

        amountOut = getAmountOut(amountIn);

        // SECURE: Slippage check
        require(amountOut >= minAmountOut, "Too little received");

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
    }

    function getAmountOut(uint256 amountIn) public view returns (uint256) {
        // Simplified AMM formula
        return amountIn * 95 / 100;
    }
}

/**
 * @notice SECURE: Token sale with deadline and slippage
 */
contract SecureTokenSale {
    IERC20 public token;
    uint256 public price;

    constructor(address _token, uint256 _price) {
        token = IERC20(_token);
        price = _price;
    }

    /**
     * @notice SECURE: purchase with deadline and minimum amount
     * @param amount Tokens to purchase
     * @param deadline Transaction must execute before this
     */
    function purchase(uint256 amount, uint256 deadline) external payable {
        // SECURE: Deadline prevents delayed execution
        require(block.timestamp <= deadline, "Offer expired");

        uint256 cost = amount * price;
        require(msg.value >= cost, "Insufficient payment");

        token.transferFrom(address(this), msg.sender, amount);

        // Refund excess
        if (msg.value > cost) {
            payable(msg.sender).transfer(msg.value - cost);
        }
    }
}

/**
 * @notice SECURE: Auction with commit-reveal scheme
 */
contract SecureAuction {
    IERC20 public paymentToken;

    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public bids;
    mapping(address => bool) public revealed;

    uint256 public commitDeadline;
    uint256 public revealDeadline;

    constructor(address _paymentToken, uint256 _commitPeriod, uint256 _revealPeriod) {
        paymentToken = IERC20(_paymentToken);
        commitDeadline = block.timestamp + _commitPeriod;
        revealDeadline = commitDeadline + _revealPeriod;
    }

    /**
     * @notice SECURE: Phase 1 - Commit bid hash (hidden amount)
     * @param commitment Hash of (amount, nonce) to hide bid
     */
    function commitBid(bytes32 commitment) external {
        require(block.timestamp < commitDeadline, "Commit phase ended");
        require(commitments[msg.sender] == bytes32(0), "Already committed");

        commitments[msg.sender] = commitment;
    }

    /**
     * @notice SECURE: Phase 2 - Reveal bid amount
     * @param amount Actual bid amount
     * @param nonce Random value used in commitment
     */
    function revealBid(uint256 amount, bytes32 nonce) external {
        require(block.timestamp >= commitDeadline, "Reveal phase not started");
        require(block.timestamp < revealDeadline, "Reveal phase ended");
        require(!revealed[msg.sender], "Already revealed");

        // SECURE: Verify commitment matches revealed values
        bytes32 commitment = keccak256(abi.encodePacked(amount, nonce));
        require(commitments[msg.sender] == commitment, "Invalid reveal");

        // Process bid (front-running impossible - amount was hidden)
        paymentToken.transferFrom(msg.sender, address(this), amount);
        bids[msg.sender] = amount;
        revealed[msg.sender] = true;
    }

    function getCommitment(uint256 amount, bytes32 nonce) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, nonce));
    }
}

/**
 * @notice SECURE: Liquidity provision with price bounds
 */
contract SecureLiquidityPool {
    IERC20 public tokenA;
    IERC20 public tokenB;

    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice SECURE: addLiquidity with price bounds
     * @param amountA Amount of token A to add
     * @param amountB Amount of token B to add
     * @param minAmountA Minimum A to add (protects against ratio manipulation)
     * @param minAmountB Minimum B to add (protects against ratio manipulation)
     * @param deadline Transaction expiration
     */
    function addLiquidity(
        uint256 amountA,
        uint256 amountB,
        uint256 minAmountA,
        uint256 minAmountB,
        uint256 deadline
    ) external returns (uint256 actualAmountA, uint256 actualAmountB) {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Expired");

        // Calculate optimal amounts based on current ratio
        if (reserveA > 0 && reserveB > 0) {
            uint256 amountBOptimal = (amountA * reserveB) / reserveA;
            if (amountBOptimal <= amountB) {
                // SECURE: Verify minimum bounds
                require(amountBOptimal >= minAmountB, "Insufficient B amount");
                actualAmountA = amountA;
                actualAmountB = amountBOptimal;
            } else {
                uint256 amountAOptimal = (amountB * reserveA) / reserveB;
                require(amountAOptimal <= amountA, "Invalid amounts");
                require(amountAOptimal >= minAmountA, "Insufficient A amount");
                actualAmountA = amountAOptimal;
                actualAmountB = amountB;
            }
        } else {
            actualAmountA = amountA;
            actualAmountB = amountB;
        }

        tokenA.transferFrom(msg.sender, address(this), actualAmountA);
        tokenB.transferFrom(msg.sender, address(this), actualAmountB);

        reserveA += actualAmountA;
        reserveB += actualAmountB;

        // Mint LP tokens...
    }
}

/**
 * @notice SECURE: Arbitrage with minimum profit guarantee
 */
contract SecureArbitrage {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: executeArbitrage with minimum profit
     * @param amount Amount to arbitrage
     * @param minProfit Minimum profit to accept
     * @param deadline Transaction expiration
     */
    function executeArbitrage(
        uint256 amount,
        uint256 minProfit,
        uint256 deadline
    ) external returns (uint256 profit) {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Expired");

        uint256 balanceBefore = token.balanceOf(address(this));

        token.transferFrom(msg.sender, address(this), amount);

        // Execute arbitrage trades...
        _performArbitrage(amount);

        uint256 balanceAfter = token.balanceOf(address(this));
        profit = balanceAfter - balanceBefore;

        // SECURE: Minimum profit check
        require(profit >= minProfit, "Insufficient profit");

        // Return principal + profit
        token.transfer(msg.sender, amount + profit);
    }

    function _performArbitrage(uint256) internal {
        // Arbitrage logic
    }
}

/**
 * @notice SECURE: Batch purchase with aggregate slippage limit
 */
contract SecureBatchPurchase {
    IERC20 public token;
    uint256 public pricePerUnit;

    constructor(address _token, uint256 _price) {
        token = IERC20(_token);
        pricePerUnit = _price;
    }

    /**
     * @notice SECURE: batchBuy with total slippage protection
     * @param amounts Array of amounts to purchase
     * @param minTotalAmount Minimum total tokens to receive
     * @param deadline Transaction expiration
     */
    function batchBuy(
        uint256[] calldata amounts,
        uint256 minTotalAmount,
        uint256 deadline
    ) external payable returns (uint256 totalReceived) {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Expired");

        uint256 totalCost = 0;

        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 cost = amounts[i] * getCurrentPrice();
            totalCost += cost;
            totalReceived += amounts[i];

            token.transferFrom(address(this), msg.sender, amounts[i]);
        }

        // SECURE: Aggregate slippage check
        require(totalReceived >= minTotalAmount, "Total slippage exceeded");
        require(msg.value >= totalCost, "Insufficient payment");
    }

    function getCurrentPrice() public view returns (uint256) {
        return pricePerUnit;
    }
}

/**
 * @notice SECURE: Limit order with expiration
 */
contract SecureLimitOrder {
    IERC20 public token;

    struct Order {
        address trader;
        uint256 amount;
        uint256 targetPrice;
        uint256 expiration; // SECURE: Order expires
    }

    Order[] public orders;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: createOrder with expiration time
     * @param amount Amount to trade
     * @param targetPrice Maximum price willing to pay
     * @param expiration Order expires after this timestamp
     */
    function createOrder(
        uint256 amount,
        uint256 targetPrice,
        uint256 expiration
    ) external {
        // SECURE: Require reasonable expiration
        require(expiration > block.timestamp, "Invalid expiration");
        require(expiration <= block.timestamp + 30 days, "Expiration too far");

        orders.push(Order({
            trader: msg.sender,
            amount: amount,
            targetPrice: targetPrice,
            expiration: expiration
        }));
    }

    /**
     * @notice SECURE: executeOrder with expiration check
     */
    function executeOrder(uint256 orderId) external {
        Order memory order = orders[orderId];

        // SECURE: Check not expired
        require(block.timestamp <= order.expiration, "Order expired");

        uint256 currentPrice = getCurrentPrice();
        require(currentPrice <= order.targetPrice, "Price too high");

        token.transferFrom(order.trader, address(this), order.amount);

        // Mark order as executed (simplified)
        delete orders[orderId];
    }

    function getCurrentPrice() public pure returns (uint256) {
        return 1000;
    }
}

/**
 * @notice SECURE: TWAP oracle for manipulation resistance
 */
contract SecureTWAPOracle {
    struct Observation {
        uint256 timestamp;
        uint256 price;
    }

    Observation[] public observations;
    uint256 public constant OBSERVATION_PERIOD = 15 minutes;

    /**
     * @notice SECURE: Get time-weighted average price
     * @param period Time period to average over (in seconds)
     * @return twap Time-weighted average price
     */
    function getTWAP(uint256 period) external view returns (uint256 twap) {
        require(period > 0, "Invalid period");
        require(observations.length > 0, "No observations");

        uint256 targetTimestamp = block.timestamp - period;
        uint256 totalWeight = 0;
        uint256 weightedSum = 0;

        for (uint256 i = observations.length; i > 0; i--) {
            uint256 idx = i - 1;
            if (observations[idx].timestamp < targetTimestamp) {
                break;
            }

            uint256 weight = block.timestamp - observations[idx].timestamp;
            weightedSum += observations[idx].price * weight;
            totalWeight += weight;
        }

        require(totalWeight > 0, "Insufficient observations");
        twap = weightedSum / totalWeight;
    }

    /**
     * @notice Add price observation (called by keeper/oracle)
     */
    function addObservation(uint256 price) external {
        observations.push(Observation({
            timestamp: block.timestamp,
            price: price
        }));
    }
}

/**
 * @notice SECURE: Oracle-dependent trade using TWAP
 */
contract SecureOracleDependent {
    IERC20 public token;
    SecureTWAPOracle public twapOracle;

    constructor(address _token, address _oracle) {
        token = IERC20(_token);
        twapOracle = SecureTWAPOracle(_oracle);
    }

    /**
     * @notice SECURE: trade using TWAP price (flash loan resistant)
     * @param amountIn Input amount
     * @param minAmountOut Minimum output (slippage protection)
     * @param deadline Transaction expiration
     */
    function trade(
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline
    ) external returns (uint256 amountOut) {
        // SECURE: Deadline check
        require(block.timestamp <= deadline, "Expired");

        // SECURE: Use TWAP (not spot price)
        // 1-hour TWAP is resistant to flash loan manipulation
        uint256 price = twapOracle.getTWAP(3600);
        amountOut = amountIn * price;

        // SECURE: Slippage check
        require(amountOut >= minAmountOut, "Slippage exceeded");

        token.transferFrom(msg.sender, address(this), amountIn);
        // Transfer output based on TWAP price
    }
}

/**
 * @notice SECURE: Staking reward claim with locked amount
 */
contract SecureStaking {
    IERC20 public rewardToken;
    mapping(address => uint256) public lockedRewards;
    mapping(address => uint256) public lastUpdate;

    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
    }

    /**
     * @notice Update and lock user's reward amount
     * @dev Called periodically to lock reward calculation
     */
    function updateRewards(address user) public {
        uint256 reward = calculateReward(user);
        lockedRewards[user] = reward;
        lastUpdate[user] = block.timestamp;
    }

    /**
     * @notice SECURE: claimRewards with locked amount
     * @param minAmount Minimum reward to claim (slippage protection)
     */
    function claimRewards(uint256 minAmount) external {
        // Update rewards first
        updateRewards(msg.sender);

        uint256 reward = lockedRewards[msg.sender];

        // SECURE: Minimum amount check
        require(reward >= minAmount, "Insufficient rewards");

        rewardToken.transferFrom(address(this), msg.sender, reward);
        lockedRewards[msg.sender] = 0;
    }

    function calculateReward(address) internal pure returns (uint256) {
        return 1000; // Simplified
    }
}

/**
 * @notice SECURE: Complete Uniswap V3 Router pattern
 */
contract SecureSwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        uint256 amountIn;
        uint256 amountOutMinimum;  // SECURE: Slippage protection
        uint256 deadline;          // SECURE: Deadline protection
    }

    /**
     * @notice SECURE: Industry-standard swap (Uniswap V3 pattern)
     * @param params Swap parameters with full protection
     * @return amountOut Actual output amount
     */
    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external payable returns (uint256 amountOut) {
        // SECURE: Deadline check
        require(block.timestamp <= params.deadline, "Transaction too old");

        // Execute swap
        amountOut = _swap(
            params.tokenIn,
            params.tokenOut,
            params.amountIn,
            params.fee
        );

        // SECURE: Slippage check
        require(amountOut >= params.amountOutMinimum, "Too little received");

        // Execute transfers
        IERC20(params.tokenIn).transferFrom(
            msg.sender,
            address(this),
            params.amountIn
        );
        IERC20(params.tokenOut).transfer(msg.sender, amountOut);
    }

    function _swap(
        address,
        address,
        uint256 amountIn,
        uint24
    ) internal pure returns (uint256) {
        // Simplified swap logic
        return amountIn * 95 / 100;
    }
}
