// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title PriceManipulationSafe - Secure Patterns
 * @notice SECURE: Proper price oracle usage with protections
 * @dev This contract demonstrates secure patterns for price oracles
 *      that prevent flash loan attacks, sandwich attacks, and MEV extraction.
 *
 * Security Features:
 * - TWAP (Time-Weighted Average Price) instead of spot prices
 * - Staleness validation for oracle prices
 * - Price deviation bounds and circuit breakers
 * - Price impact checks for large operations
 * - Multiple oracle sources with median calculation
 * - Commit-reveal for price-sensitive operations
 *
 * Reference: Uniswap V3, Chainlink, Compound
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

interface IChainlinkOracle {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

/**
 * @notice SECURE: TWAP price oracle
 * @dev Uses time-weighted average prices, not spot prices
 */
contract SecureTWAPOracle {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 1800; // 30 minutes

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    /**
     * @notice SECURE: Calculate TWAP price
     * @dev Uses cumulative ticks over time period, resistant to manipulation
     */
    function getTWAP() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        // SECURE: Get time-weighted average, not spot
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(TWAP_PERIOD)));

        // Convert tick to price
        uint256 price = getPriceFromTick(arithmeticMeanTick);
        return price;
    }

    function getPriceFromTick(int24 tick) internal pure returns (uint256) {
        // Simplified - real implementation uses TickMath
        return uint256(uint24(tick)) * 1e18 / 1000000;
    }

    /**
     * @notice SECURE: Swap using TWAP price
     * @dev Cannot be manipulated by flash loans
     */
    function swap(uint256 amountIn) external returns (uint256) {
        // SECURE: Uses TWAP, not spot price
        uint256 twapPrice = getTWAP();

        uint256 amountOut = amountIn * twapPrice / 1e18;
        return amountOut;
    }
}

/**
 * @notice SECURE: Oracle with staleness checks
 * @dev Validates price timestamp before use
 */
contract SecureStaleCheck {
    IChainlinkOracle public oracle;
    uint256 public constant MAX_DELAY = 3600; // 1 hour
    IERC20 public token;

    constructor(address _oracle, address _token) {
        oracle = IChainlinkOracle(_oracle);
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Get price with staleness validation
     * @dev Reverts if price is too old
     */
    function getValidPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        // SECURE: Validate price is recent
        require(block.timestamp - updatedAt <= MAX_DELAY, "Stale price");
        require(answer > 0, "Invalid price");
        require(answeredInRound >= roundId, "Stale round");

        return uint256(answer);
    }

    /**
     * @notice SECURE: Borrow with fresh price check
     * @dev Only uses recently updated prices
     */
    function borrow(uint256 collateralAmount) external returns (uint256) {
        // SECURE: Validates staleness
        uint256 collateralPrice = getValidPrice();

        uint256 borrowAmount = collateralAmount * collateralPrice * 80 / 100;
        token.transferFrom(msg.sender, address(this), collateralAmount);

        return borrowAmount;
    }
}

/**
 * @notice SECURE: Price deviation bounds
 * @dev Rejects extreme price changes
 */
contract SecureDeviationBounds {
    IChainlinkOracle public oracle;
    uint256 public lastPrice;
    uint256 public constant MAX_DEVIATION = 10; // 10% max change

    constructor(address _oracle) {
        oracle = IChainlinkOracle(_oracle);
        lastPrice = 1000e18;
    }

    /**
     * @notice SECURE: Update price with deviation check
     * @dev Rejects prices that changed more than 10%
     */
    function updatePrice() external {
        (,int256 answer,,,) = oracle.latestRoundData();
        uint256 newPrice = uint256(answer);

        // SECURE: Validate price didn't change too much
        uint256 deviation = newPrice > lastPrice ?
            (newPrice - lastPrice) * 100 / lastPrice :
            (lastPrice - newPrice) * 100 / lastPrice;

        require(deviation <= MAX_DEVIATION, "Price deviation too large");

        lastPrice = newPrice;
    }

    /**
     * @notice SECURE: Trade with min/max price bounds
     * @dev Validates price is within acceptable range
     */
    function trade(uint256 amount, uint256 minPrice, uint256 maxPrice) external {
        (,int256 answer,,,) = oracle.latestRoundData();
        uint256 price = uint256(answer);

        // SECURE: Price must be within bounds
        require(price >= minPrice && price <= maxPrice, "Price out of bounds");

        uint256 value = amount * price / 1e18;
    }
}

/**
 * @notice SECURE: Multiple oracle sources with median
 * @dev Uses median of multiple oracles, resistant to single oracle manipulation
 */
contract SecureMultiOracle {
    IChainlinkOracle[] public oracles;
    uint256 public constant MIN_ORACLES = 3;

    constructor(address[] memory _oracles) {
        require(_oracles.length >= MIN_ORACLES, "Need at least 3 oracles");
        for (uint256 i = 0; i < _oracles.length; i++) {
            oracles.push(IChainlinkOracle(_oracles[i]));
        }
    }

    /**
     * @notice SECURE: Get median price from multiple oracles
     * @dev Single oracle manipulation cannot affect result
     */
    function getMedianPrice() public view returns (uint256) {
        uint256[] memory prices = new uint256[](oracles.length);

        // Collect prices from all oracles
        for (uint256 i = 0; i < oracles.length; i++) {
            (,int256 answer,,,) = oracles[i].latestRoundData();
            prices[i] = uint256(answer);
        }

        // SECURE: Return median, not average
        return median(prices);
    }

    function median(uint256[] memory data) internal pure returns (uint256) {
        // Sort and return middle value
        sort(data);
        return data[data.length / 2];
    }

    function sort(uint256[] memory data) internal pure {
        // Simple bubble sort (use better algo in production)
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = i + 1; j < data.length; j++) {
                if (data[i] > data[j]) {
                    (data[i], data[j]) = (data[j], data[i]);
                }
            }
        }
    }

    /**
     * @notice SECURE: Trade using median price
     * @dev Cannot be manipulated via single oracle
     */
    function trade(uint256 amount) external returns (uint256) {
        // SECURE: Uses median of multiple oracles
        uint256 price = getMedianPrice();
        return amount * price / 1e18;
    }
}

/**
 * @notice SECURE: Price impact validation
 * @dev Checks price before and after large operations
 */
contract SecurePriceImpact {
    IUniswapV3Pool public pool;
    uint256 public constant MAX_IMPACT = 1; // 1% max price impact

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    /**
     * @notice SECURE: Liquidation with price impact check
     * @dev Validates price didn't move too much during operation
     */
    function liquidate(address user, uint256 amount) external {
        // Get price before
        uint256 priceBefore = getCurrentPrice();

        // Perform liquidation
        // ... liquidation logic ...

        // SECURE: Validate price after
        uint256 priceAfter = getCurrentPrice();
        uint256 impact = priceAfter > priceBefore ?
            (priceAfter - priceBefore) * 100 / priceBefore :
            (priceBefore - priceAfter) * 100 / priceBefore;

        require(impact <= MAX_IMPACT, "Price impact too large");
    }

    function getCurrentPrice() internal view returns (uint256) {
        // Simplified - real implementation uses pool observations
        return 1000e18;
    }
}

/**
 * @notice SECURE: Lending with comprehensive protections
 * @dev Combines TWAP, staleness, deviation, and multiple oracles
 */
contract SecureLendingProtocol {
    IChainlinkOracle public chainlinkOracle;
    IUniswapV3Pool public uniswapPool;
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    uint256 public constant MAX_DELAY = 3600;
    uint256 public constant MAX_DEVIATION = 10;
    uint256 public constant TWAP_PERIOD = 1800;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    constructor(
        address _chainlink,
        address _uniswap,
        address _collateral,
        address _borrow
    ) {
        chainlinkOracle = IChainlinkOracle(_chainlink);
        uniswapPool = IUniswapV3Pool(_uniswap);
        collateralToken = IERC20(_collateral);
        borrowToken = IERC20(_borrow);
    }

    /**
     * @notice SECURE: Get validated price
     * @dev Uses Chainlink with staleness check and Uniswap TWAP for comparison
     */
    function getValidatedPrice() public view returns (uint256) {
        // Get Chainlink price with staleness check
        (,int256 chainlinkPrice,, uint256 updatedAt,) = chainlinkOracle.latestRoundData();
        require(block.timestamp - updatedAt <= MAX_DELAY, "Stale Chainlink price");

        uint256 clPrice = uint256(chainlinkPrice);

        // Get Uniswap TWAP for comparison
        uint256 twapPrice = getTWAP();

        // SECURE: Validate prices are close to each other
        uint256 deviation = clPrice > twapPrice ?
            (clPrice - twapPrice) * 100 / twapPrice :
            (twapPrice - clPrice) * 100 / clPrice;

        require(deviation <= MAX_DEVIATION, "Oracle price deviation too large");

        // Return average of both
        return (clPrice + twapPrice) / 2;
    }

    function getTWAP() internal view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = uniswapPool.observe(secondsAgos);
        // Calculate TWAP (simplified)
        return 1000e18;
    }

    /**
     * @notice SECURE: Borrow with comprehensive price validation
     * @dev All price checks pass before allowing borrow
     */
    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        // SECURE: Get validated price from multiple sources
        uint256 price = getValidatedPrice();

        uint256 collateralValue = collateralAmount * price;
        require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");

        deposits[msg.sender] += collateralAmount;
        borrows[msg.sender] += borrowAmount;

        collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
        borrowToken.transfer(msg.sender, borrowAmount);
    }
}

/**
 * @notice SECURE: DEX with slippage protection
 * @dev Users specify minimum output, protected from sandwich attacks
 */
contract SecureDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    /**
     * @notice SECURE: Swap with minAmountOut
     * @dev User protected from price manipulation
     */
    function swap(
        uint256 amountIn,
        uint256 minAmountOut,
        bool aToB
    ) external returns (uint256) {
        uint256 amountOut;

        if (aToB) {
            amountOut = amountIn * reserveB / reserveA;

            // SECURE: Validate minimum output
            require(amountOut >= minAmountOut, "Slippage too high");

            reserveA += amountIn;
            reserveB -= amountOut;

            tokenA.transferFrom(msg.sender, address(this), amountIn);
            tokenB.transfer(msg.sender, amountOut);
        } else {
            amountOut = amountIn * reserveA / reserveB;

            require(amountOut >= minAmountOut, "Slippage too high");

            reserveB += amountIn;
            reserveA -= amountOut;

            tokenB.transferFrom(msg.sender, address(this), amountIn);
            tokenA.transfer(msg.sender, amountOut);
        }

        return amountOut;
    }
}

/**
 * @notice SECURE: Circuit breaker for extreme moves
 * @dev Pauses operations if price moves too much
 */
contract SecureCircuitBreaker {
    IChainlinkOracle public oracle;
    uint256 public lastPrice;
    bool public circuitBreakerActive;
    uint256 public constant EXTREME_DEVIATION = 50; // 50%

    constructor(address _oracle) {
        oracle = IChainlinkOracle(_oracle);
        lastPrice = 1000e18;
    }

    /**
     * @notice SECURE: Check and activate circuit breaker if needed
     * @dev Stops trading if price moves more than 50%
     */
    function checkCircuitBreaker() public {
        (,int256 answer,,,) = oracle.latestRoundData();
        uint256 newPrice = uint256(answer);

        uint256 deviation = newPrice > lastPrice ?
            (newPrice - lastPrice) * 100 / lastPrice :
            (lastPrice - newPrice) * 100 / lastPrice;

        // SECURE: Activate circuit breaker on extreme moves
        if (deviation > EXTREME_DEVIATION) {
            circuitBreakerActive = true;
        }
    }

    /**
     * @notice SECURE: Trade only if circuit breaker inactive
     * @dev Prevents trading during extreme volatility
     */
    function trade(uint256 amount) external {
        checkCircuitBreaker();

        // SECURE: No trading during circuit breaker
        require(!circuitBreakerActive, "Circuit breaker active");

        (,int256 answer,,,) = oracle.latestRoundData();
        uint256 price = uint256(answer);
        uint256 value = amount * price / 1e18;
    }
}

/**
 * @notice SECURE: Commit-reveal for price-sensitive operations
 * @dev Hides intent until execution
 */
contract SecureCommitReveal {
    mapping(bytes32 => uint256) public commitments;
    mapping(bytes32 => uint256) public commitTimestamps;
    uint256 public constant REVEAL_DELAY = 600; // 10 minutes

    /**
     * @notice SECURE: Commit to trade parameters
     * @dev Hides trade details from front-runners
     */
    function commit(bytes32 commitment) external {
        commitments[commitment] = block.timestamp;
        commitTimestamps[commitment] = block.timestamp;
    }

    /**
     * @notice SECURE: Reveal and execute trade
     * @dev Can only execute after delay, prevents front-running
     */
    function reveal(
        uint256 amount,
        uint256 minPrice,
        uint256 salt
    ) external {
        bytes32 commitment = keccak256(abi.encodePacked(amount, minPrice, salt, msg.sender));

        // SECURE: Validate commitment exists and delay passed
        require(commitments[commitment] > 0, "No commitment");
        require(
            block.timestamp >= commitTimestamps[commitment] + REVEAL_DELAY,
            "Too early"
        );

        // Execute trade with committed parameters
        delete commitments[commitment];
    }
}

/**
 * @notice SECURE: NFT lending with multiple price sources
 * @dev Uses floor price from multiple marketplaces
 */
contract SecureNFTLending {
    IChainlinkOracle[] public floorPriceOracles;

    constructor(address[] memory _oracles) {
        require(_oracles.length >= 3, "Need multiple oracles");
        for (uint256 i = 0; i < _oracles.length; i++) {
            floorPriceOracles.push(IChainlinkOracle(_oracles[i]));
        }
    }

    /**
     * @notice SECURE: Get floor price from multiple sources
     * @dev Uses median to prevent manipulation
     */
    function getFloorPrice() public view returns (uint256) {
        uint256[] memory prices = new uint256[](floorPriceOracles.length);

        for (uint256 i = 0; i < floorPriceOracles.length; i++) {
            (,int256 answer,, uint256 updatedAt,) = floorPriceOracles[i].latestRoundData();

            // Validate staleness
            require(block.timestamp - updatedAt <= 3600, "Stale floor price");
            prices[i] = uint256(answer);
        }

        // Return median
        return median(prices);
    }

    function median(uint256[] memory data) internal pure returns (uint256) {
        // Sort and return middle value
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = i + 1; j < data.length; j++) {
                if (data[i] > data[j]) {
                    (data[i], data[j]) = (data[j], data[i]);
                }
            }
        }
        return data[data.length / 2];
    }

    /**
     * @notice SECURE: Borrow against NFT with validated floor
     * @dev Cannot be manipulated by wash trading
     */
    function borrowAgainstNFT(uint256 nftId) external returns (uint256) {
        // SECURE: Median of multiple sources
        uint256 floorPrice = getFloorPrice();

        // Conservative LTV
        uint256 loanAmount = floorPrice * 30 / 100;
        return loanAmount;
    }
}
