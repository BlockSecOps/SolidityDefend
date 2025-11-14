// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title PriceManipulation - Vulnerable Patterns
 * @notice VULNERABLE: Various price manipulation and oracle attack patterns
 * @dev This contract demonstrates vulnerable price oracle usage patterns
 *      that enable flash loan attacks, sandwich attacks, and MEV extraction.
 *
 * Vulnerabilities Demonstrated:
 * 1. Spot price from AMM without TWAP
 * 2. BalanceOf for pricing without validation
 * 3. External oracle without staleness check
 * 4. No price deviation bounds
 * 5. Large operations without price impact checks
 * 6. Multiple oracle issues combined
 *
 * Attack Vectors:
 * - Flash loan price manipulation
 * - Sandwich attacks
 * - Oracle manipulation
 * - Stale price exploitation
 * - Price impact attacks
 *
 * Reference: Trail of Bits, Consensys Diligence, Rekt News
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IUniswapV2Router {
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

/**
 * @notice VULNERABLE Pattern 1: Spot price from AMM without TWAP
 * @dev Uses getAmountOut which returns spot price, easily manipulated via flash loans
 */
contract VulnerableSpotPriceSwap {
    IUniswapV2Router public router;
    IERC20 public token;

    constructor(address _router, address _token) {
        router = IUniswapV2Router(_router);
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Uses spot price for swap calculation
     * @dev Attacker can manipulate price with flash loan before user's transaction
     */
    function swap(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) external {
        // VULNERABLE: getAmountOut returns spot price (no TWAP)
        uint256 amountOut = router.getAmountOut(amountIn, reserveIn, reserveOut);

        token.transferFrom(msg.sender, address(this), amountIn);
        // Perform swap using manipulated spot price
    }

    /**
     * @notice VULNERABLE: Direct reserve ratio for pricing
     * @dev Can be manipulated via large trades or flash loans
     */
    function trade(address pair, uint256 amount) external {
        IUniswapV2Pair uniPair = IUniswapV2Pair(pair);

        // VULNERABLE: Uses spot reserves without TWAP
        (uint112 reserve0, uint112 reserve1,) = uniPair.getReserves();
        uint256 spotPrice = uint256(reserve1) / uint256(reserve0);

        uint256 amountOut = amount * spotPrice;
        token.transferFrom(msg.sender, address(this), amount);
    }
}

/**
 * @notice VULNERABLE Pattern 2: BalanceOf for pricing
 * @dev Token balances can be manipulated via flash loans
 */
contract VulnerableBalancePricing {
    IERC20 public tokenA;
    IERC20 public tokenB;
    address public pool;

    constructor(address _tokenA, address _tokenB, address _pool) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
        pool = _pool;
    }

    /**
     * @notice VULNERABLE: Price based on pool balances
     * @dev Flash loan can manipulate balances to get favorable rate
     */
    function exchange(uint256 amountIn) external {
        // VULNERABLE: Uses balanceOf for price calculation
        uint256 balanceA = tokenA.balanceOf(pool);
        uint256 balanceB = tokenB.balanceOf(pool);

        uint256 price = balanceB * 1e18 / balanceA;
        uint256 amountOut = amountIn * price / 1e18;

        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
    }

    /**
     * @notice VULNERABLE: Liquidity ratio for minting
     * @dev Can be manipulated to mint at unfair rate
     */
    function mintShares(uint256 amount) external returns (uint256 shares) {
        uint256 balance = tokenA.balanceOf(pool);

        // VULNERABLE: Share calculation based on manipulable balance
        shares = amount * 1000 / balance;

        tokenA.transferFrom(msg.sender, pool, amount);
    }
}

/**
 * @notice VULNERABLE Pattern 3: Oracle without staleness check
 * @dev Stale prices enable arbitrage and unfair liquidations
 */
contract VulnerableStaleOracle {
    IPriceOracle public oracle;
    IERC20 public token;

    constructor(address _oracle, address _token) {
        oracle = IPriceOracle(_oracle);
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: No staleness check on oracle price
     * @dev Stale prices allow arbitrage when market price diverges
     */
    function borrow(uint256 collateralAmount) external returns (uint256 borrowAmount) {
        // VULNERABLE: No check if price is recent
        uint256 collateralPrice = oracle.getPrice(address(token));

        borrowAmount = collateralAmount * collateralPrice * 80 / 100;
        token.transferFrom(msg.sender, address(this), collateralAmount);
    }

    /**
     * @notice VULNERABLE: Liquidation with stale price
     * @dev Users can be unfairly liquidated with outdated prices
     */
    function liquidate(address user, uint256 debtAmount) external {
        // VULNERABLE: latestAnswer doesn't validate timestamp
        int256 price = oracle.latestAnswer();
        require(price > 0, "Invalid price");

        uint256 collateralValue = debtAmount * uint256(price);
        // Liquidate using potentially stale price
    }
}

/**
 * @notice VULNERABLE Pattern 4: No price deviation bounds
 * @dev Accepts extreme prices without validation
 */
contract VulnerableNoDeviation {
    IPriceOracle public oracle;
    uint256 public lastPrice;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
        lastPrice = 1000e18;
    }

    /**
     * @notice VULNERABLE: No bounds on price changes
     * @dev Accepts any price, even 10x changes
     */
    function updatePrice() external {
        // VULNERABLE: No deviation check from lastPrice
        uint256 newPrice = oracle.getPrice(address(this));
        lastPrice = newPrice;

        // Price could have changed 1000% - no validation
    }

    /**
     * @notice VULNERABLE: Trade accepts any oracle price
     * @dev No min/max bounds enable price manipulation
     */
    function trade(uint256 amount) external {
        uint256 price = oracle.getPrice(address(this));

        // VULNERABLE: No require(price >= minPrice && price <= maxPrice)
        uint256 value = amount * price / 1e18;
    }
}

/**
 * @notice VULNERABLE Pattern 5: Large operation without price impact check
 * @dev Flash loan can manipulate price during execution
 */
contract VulnerableLargeOperation {
    IUniswapV2Pair public pair;
    IERC20 public token;
    IPriceOracle public oracle;

    constructor(address _pair, address _token, address _oracle) {
        pair = IUniswapV2Pair(_pair);
        token = IERC20(_token);
        oracle = IPriceOracle(_oracle);
    }

    /**
     * @notice VULNERABLE: Liquidation without price impact validation
     * @dev Large liquidation can move market, no validation of final price
     */
    function liquidate(address user, uint256 amount) external {
        uint256 price = oracle.getPrice(address(token));

        // VULNERABLE: No before/after price check
        // Large liquidation can impact market price significantly
        uint256 collateralValue = amount * price;

        token.transferFrom(user, msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: Flash swap without impact check
     * @dev No validation that price didn't move too much
     */
    function flashSwap(uint256 amount) external {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 priceBefore = uint256(reserve1) / uint256(reserve0);

        // Perform flash swap
        // VULNERABLE: No price impact validation

        // Should check: require(priceAfter <= priceBefore * 1.01)
    }
}

/**
 * @notice VULNERABLE Pattern 6: Lending protocol with multiple issues
 * @dev Combines spot price, no staleness check, and no deviation bounds
 */
contract VulnerableLendingProtocol {
    IPriceOracle public oracle;
    IUniswapV2Pair public pair;
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    constructor(
        address _oracle,
        address _pair,
        address _collateralToken,
        address _borrowToken
    ) {
        oracle = IPriceOracle(_oracle);
        pair = IUniswapV2Pair(_pair);
        collateralToken = IERC20(_collateralToken);
        borrowToken = IERC20(_borrowToken);
    }

    /**
     * @notice VULNERABLE: Multiple oracle issues
     * @dev Uses spot price, no staleness, no bounds
     */
    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        // VULNERABLE 1: Spot price from reserves
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 spotPrice = uint256(reserve1) / uint256(reserve0);

        // VULNERABLE 2: No staleness check on oracle
        uint256 oraclePrice = oracle.getPrice(address(collateralToken));

        // VULNERABLE 3: No deviation bounds between prices
        uint256 price = (spotPrice + oraclePrice) / 2;

        uint256 collateralValue = collateralAmount * price;
        require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");

        deposits[msg.sender] += collateralAmount;
        borrows[msg.sender] += borrowAmount;

        collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
        borrowToken.transfer(msg.sender, borrowAmount);
    }

    /**
     * @notice VULNERABLE: Repay with manipulated price
     * @dev User can profit from favorable price manipulation
     */
    function repay(uint256 amount) external {
        // Get current price (manipulable)
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 price = uint256(reserve1) / uint256(reserve0);

        uint256 collateralReturn = amount * price / 1e18;

        borrows[msg.sender] -= amount;
        deposits[msg.sender] -= collateralReturn;

        borrowToken.transferFrom(msg.sender, address(this), amount);
        collateralToken.transfer(msg.sender, collateralReturn);
    }
}

/**
 * @notice VULNERABLE Pattern 7: DEX with spot price calculation
 * @dev All swaps use manipulable spot prices
 */
contract VulnerableDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice VULNERABLE: Swap using spot reserves
     * @dev Classic AMM vulnerable to flash loan sandwich
     */
    function swap(uint256 amountIn, bool aToB) external {
        uint256 amountOut;

        if (aToB) {
            // VULNERABLE: Spot price calculation
            amountOut = amountIn * reserveB / reserveA;
            reserveA += amountIn;
            reserveB -= amountOut;

            tokenA.transferFrom(msg.sender, address(this), amountIn);
            tokenB.transfer(msg.sender, amountOut);
        } else {
            amountOut = amountIn * reserveA / reserveB;
            reserveB += amountIn;
            reserveA -= amountOut;

            tokenB.transferFrom(msg.sender, address(this), amountIn);
            tokenA.transfer(msg.sender, amountOut);
        }
    }
}

/**
 * @notice VULNERABLE Pattern 8: NFT pricing from floor price
 * @dev Floor price can be manipulated via wash trading
 */
contract VulnerableNFTPricing {
    IPriceOracle public floorPriceOracle;

    constructor(address _oracle) {
        floorPriceOracle = IPriceOracle(_oracle);
    }

    /**
     * @notice VULNERABLE: Lending based on manipulable floor
     * @dev Flash loans can manipulate NFT floor prices
     */
    function borrowAgainstNFT(uint256 nftId) external returns (uint256) {
        // VULNERABLE: Floor price easily manipulated
        uint256 floorPrice = floorPriceOracle.getPrice(address(this));

        // Lend 50% of floor price
        uint256 loanAmount = floorPrice * 50 / 100;

        return loanAmount;
    }
}

/**
 * @notice VULNERABLE Pattern 9: Yield farming with spot rate
 * @dev APY calculation uses manipulable prices
 */
contract VulnerableYieldFarm {
    IERC20 public rewardToken;
    IERC20 public stakingToken;
    IUniswapV2Pair public pair;

    constructor(address _reward, address _staking, address _pair) {
        rewardToken = IERC20(_reward);
        stakingToken = IERC20(_staking);
        pair = IUniswapV2Pair(_pair);
    }

    /**
     * @notice VULNERABLE: Reward calculation with spot price
     * @dev Can be gamed by manipulating price temporarily
     */
    function claimRewards() external returns (uint256) {
        // VULNERABLE: Uses spot reserves for valuation
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 rewardPrice = uint256(reserve1) / uint256(reserve0);

        uint256 stakingValue = stakingToken.balanceOf(address(this));
        uint256 rewardAmount = stakingValue * rewardPrice / 1e18;

        rewardToken.transfer(msg.sender, rewardAmount);
        return rewardAmount;
    }
}

/**
 * @notice VULNERABLE Pattern 10: Options pricing
 * @dev Strike price validation uses manipulable oracle
 */
contract VulnerableOptions {
    IPriceOracle public oracle;

    struct Option {
        uint256 strike;
        uint256 expiry;
        bool isCall;
    }

    mapping(uint256 => Option) public options;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    /**
     * @notice VULNERABLE: Exercise with no price validation
     * @dev Oracle can be manipulated at exercise time
     */
    function exercise(uint256 optionId) external {
        Option memory option = options[optionId];
        require(block.timestamp <= option.expiry, "Expired");

        // VULNERABLE: No bounds on oracle price
        uint256 currentPrice = oracle.getPrice(address(this));

        if (option.isCall) {
            require(currentPrice > option.strike, "Out of money");
        } else {
            require(currentPrice < option.strike, "Out of money");
        }

        // Exercise option using potentially manipulated price
    }
}
