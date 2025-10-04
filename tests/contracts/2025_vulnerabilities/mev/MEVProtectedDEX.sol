// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IAggregatorV3 {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

/**
 * @title MEVProtectedDEX
 * @dev DEX with supposed MEV protection but multiple vulnerabilities
 *
 * VULNERABILITIES:
 * 1. Oracle manipulation through flash loans
 * 2. Commit-reveal scheme bypass
 * 3. Time-based MEV attacks
 * 4. Batch auction manipulation
 * 5. Private mempool front-running
 * 6. JIT liquidity attacks
 * 7. Sandwich attack vectors
 * 8. Cross-DEX arbitrage exploitation
 * 9. Gas price manipulation
 * 10. Block builder collusion vulnerability
 */
contract MEVProtectedDEX is Ownable, ReentrancyGuard {

    struct LiquidityPool {
        address tokenA;
        address tokenB;
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalShares;
        uint256 lastUpdate;
        bool isActive;
    }

    struct CommitOrder {
        address user;
        bytes32 commitment;
        uint256 commitTime;
        uint256 revealDeadline;
        bool revealed;
        bool executed;
    }

    struct RevealedOrder {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 nonce;
        uint256 gasPrice;
    }

    struct BatchAuction {
        uint256 batchId;
        uint256 startTime;
        uint256 endTime;
        uint256 settlementTime;
        mapping(address => uint256) tokenBalances;
        address[] tokens;
        bool settled;
    }

    // Pool management
    mapping(bytes32 => LiquidityPool) public pools;
    mapping(address => mapping(bytes32 => uint256)) public liquidityShares;
    bytes32[] public poolIds;

    // MEV Protection (flawed implementations)
    mapping(address => CommitOrder[]) public userCommitments;
    mapping(bytes32 => RevealedOrder) public revealedOrders;
    mapping(uint256 => BatchAuction) public batchAuctions;

    // Oracle system
    mapping(address => address) public tokenOracles;
    mapping(address => uint256) public lastOracleUpdate;

    // MEV protection parameters
    uint256 public commitRevealDelay = 1 minutes; // VULNERABILITY: Too short
    uint256 public batchDuration = 30 seconds; // VULNERABILITY: Predictable timing
    uint256 public maxGasPrice = 200 gwei;
    uint256 public oracleValidityPeriod = 5 minutes; // VULNERABILITY: Too long

    // Fee structure
    uint256 public tradingFee = 30; // 0.3%
    uint256 public protocolFee = 5; // 0.05%
    uint256 public mevProtectionFee = 10; // 0.1%

    uint256 private currentBatchId;
    uint256 private constant BASIS_POINTS = 10000;

    event PoolCreated(bytes32 indexed poolId, address tokenA, address tokenB);
    event OrderCommitted(address indexed user, bytes32 commitment, uint256 revealDeadline);
    event OrderRevealed(address indexed user, bytes32 indexed commitment);
    event BatchAuctionStarted(uint256 indexed batchId, uint256 endTime);
    event MEVDetected(address indexed user, uint256 gasPrice, uint256 blockNumber);

    modifier validPool(bytes32 poolId) {
        require(pools[poolId].isActive, "Pool not active");
        _;
    }

    modifier withinGasLimit() {
        // VULNERABILITY: Gas price check can be bypassed
        require(tx.gasprice <= maxGasPrice, "Gas price too high");
        _;
    }

    modifier oracleValid(address token) {
        require(
            block.timestamp - lastOracleUpdate[token] <= oracleValidityPeriod,
            "Oracle data stale"
        );
        _;
    }

    constructor() Ownable(msg.sender) {}

    /**
     * @dev Create liquidity pool
     */
    function createPool(
        address tokenA,
        address tokenB,
        address oracleA,
        address oracleB
    ) external onlyOwner returns (bytes32 poolId) {
        require(tokenA != tokenB, "Identical tokens");
        require(tokenA != address(0) && tokenB != address(0), "Zero address");

        // VULNERABILITY: Pool ID generation is predictable
        poolId = keccak256(abi.encodePacked(tokenA, tokenB, block.timestamp));

        pools[poolId] = LiquidityPool({
            tokenA: tokenA,
            tokenB: tokenB,
            reserveA: 0,
            reserveB: 0,
            totalShares: 0,
            lastUpdate: block.timestamp,
            isActive: true
        });

        poolIds.push(poolId);

        // Set oracles
        tokenOracles[tokenA] = oracleA;
        tokenOracles[tokenB] = oracleB;

        emit PoolCreated(poolId, tokenA, tokenB);
        return poolId;
    }

    /**
     * @dev Commit order for MEV protection - VULNERABLE implementation
     */
    function commitOrder(bytes32 commitment) external payable withinGasLimit {
        require(commitment != bytes32(0), "Invalid commitment");

        // VULNERABILITY: Commit-reveal delay is too short and predictable
        uint256 revealDeadline = block.timestamp + commitRevealDelay;

        CommitOrder memory newCommit = CommitOrder({
            user: msg.sender,
            commitment: commitment,
            commitTime: block.timestamp,
            revealDeadline: revealDeadline,
            revealed: false,
            executed: false
        });

        userCommitments[msg.sender].push(newCommit);

        // VULNERABILITY: MEV protection fee doesn't actually provide protection
        require(msg.value >= mevProtectionFee, "Insufficient MEV protection fee");

        emit OrderCommitted(msg.sender, commitment, revealDeadline);
    }

    /**
     * @dev Reveal committed order - VULNERABLE to manipulation
     */
    function revealOrder(
        uint256 commitIndex,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 nonce
    ) external oracleValid(tokenIn) oracleValid(tokenOut) {
        require(commitIndex < userCommitments[msg.sender].length, "Invalid commit index");

        CommitOrder storage commitment = userCommitments[msg.sender][commitIndex];
        require(!commitment.revealed, "Already revealed");
        require(block.timestamp >= commitment.revealDeadline, "Too early to reveal");
        require(block.timestamp <= commitment.revealDeadline + 1 minutes, "Reveal window expired");

        // VULNERABILITY: Commitment verification is weak
        bytes32 orderHash = keccak256(abi.encodePacked(
            tokenIn,
            tokenOut,
            amountIn,
            minAmountOut,
            nonce,
            msg.sender
        ));

        require(orderHash == commitment.commitment, "Invalid reveal");

        // VULNERABILITY: Oracle price check happens at reveal time, can be manipulated
        uint256 oraclePrice = getOraclePrice(tokenIn, tokenOut);
        uint256 currentPrice = getCurrentPrice(tokenIn, tokenOut);

        // VULNERABILITY: Price deviation check is insufficient
        uint256 priceDeviation = abs(oraclePrice, currentPrice) * BASIS_POINTS / oraclePrice;
        require(priceDeviation <= 500, "Price manipulation detected"); // 5% tolerance

        commitment.revealed = true;

        revealedOrders[commitment.commitment] = RevealedOrder({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            nonce: nonce,
            gasPrice: tx.gasprice
        });

        emit OrderRevealed(msg.sender, commitment.commitment);

        // VULNERABILITY: Immediate execution after reveal allows MEV
        _executeOrder(commitment.commitment);
    }

    /**
     * @dev Start batch auction - VULNERABLE to timing manipulation
     */
    function startBatchAuction() external {
        // VULNERABILITY: Anyone can start batch auction
        // VULNERABILITY: Predictable timing allows MEV bots to prepare

        currentBatchId++;
        uint256 endTime = block.timestamp + batchDuration;

        BatchAuction storage auction = batchAuctions[currentBatchId];
        auction.batchId = currentBatchId;
        auction.startTime = block.timestamp;
        auction.endTime = endTime;
        auction.settlementTime = endTime + 1 minutes;
        auction.settled = false;

        emit BatchAuctionStarted(currentBatchId, endTime);
    }

    /**
     * @dev Execute order with MEV protection - FLAWED implementation
     */
    function _executeOrder(bytes32 commitment) private nonReentrant {
        RevealedOrder memory order = revealedOrders[commitment];
        require(order.amountIn > 0, "Invalid order");

        bytes32 poolId = getPoolId(order.tokenIn, order.tokenOut);
        require(pools[poolId].isActive, "Pool not active");

        // VULNERABILITY: No slippage protection during execution
        uint256 amountOut = calculateAmountOut(order.tokenIn, order.tokenOut, order.amountIn);
        require(amountOut >= order.minAmountOut, "Insufficient output amount");

        // VULNERABILITY: External call before state update
        IERC20(order.tokenIn).transferFrom(msg.sender, address(this), order.amountIn);

        // Update pool reserves
        LiquidityPool storage pool = pools[poolId];
        if (pool.tokenA == order.tokenIn) {
            pool.reserveA += order.amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += order.amountIn;
            pool.reserveA -= amountOut;
        }

        pool.lastUpdate = block.timestamp;

        // Transfer output tokens
        IERC20(order.tokenOut).transfer(msg.sender, amountOut);

        // VULNERABILITY: MEV detection is ineffective
        if (tx.gasprice > maxGasPrice) {
            emit MEVDetected(msg.sender, tx.gasprice, block.number);
        }
    }

    /**
     * @dev Calculate output amount - VULNERABLE to manipulation
     */
    function calculateAmountOut(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) public view returns (uint256) {
        bytes32 poolId = getPoolId(tokenIn, tokenOut);
        LiquidityPool memory pool = pools[poolId];

        uint256 reserveIn;
        uint256 reserveOut;

        if (pool.tokenA == tokenIn) {
            reserveIn = pool.reserveA;
            reserveOut = pool.reserveB;
        } else {
            reserveIn = pool.reserveB;
            reserveOut = pool.reserveA;
        }

        // VULNERABILITY: Using constant product formula without protection
        // xy = k formula: (x + dx)(y - dy) = xy
        uint256 amountInWithFee = amountIn * (BASIS_POINTS - tradingFee) / BASIS_POINTS;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn + amountInWithFee;

        return numerator / denominator;
    }

    /**
     * @dev Get oracle price - VULNERABLE to manipulation
     */
    function getOraclePrice(address tokenA, address tokenB) public view returns (uint256) {
        require(tokenOracles[tokenA] != address(0), "No oracle for token A");
        require(tokenOracles[tokenB] != address(0), "No oracle for token B");

        // VULNERABILITY: Using latest price without TWAP
        (, int256 priceA,,,) = IAggregatorV3(tokenOracles[tokenA]).latestRoundData();
        (, int256 priceB,,,) = IAggregatorV3(tokenOracles[tokenB]).latestRoundData();

        require(priceA > 0 && priceB > 0, "Invalid oracle price");

        // VULNERABILITY: No staleness check for oracle data
        return uint256(priceA) * 1e18 / uint256(priceB);
    }

    /**
     * @dev Get current pool price - VULNERABLE to flash loan manipulation
     */
    function getCurrentPrice(address tokenA, address tokenB) public view returns (uint256) {
        bytes32 poolId = getPoolId(tokenA, tokenB);
        LiquidityPool memory pool = pools[poolId];

        if (pool.reserveA == 0 || pool.reserveB == 0) {
            return 0;
        }

        // VULNERABILITY: Spot price can be manipulated with large trades/flash loans
        if (pool.tokenA == tokenA) {
            return pool.reserveB * 1e18 / pool.reserveA;
        } else {
            return pool.reserveA * 1e18 / pool.reserveB;
        }
    }

    /**
     * @dev Add liquidity to pool
     */
    function addLiquidity(
        bytes32 poolId,
        uint256 amountA,
        uint256 amountB
    ) external validPool(poolId) nonReentrant returns (uint256 shares) {
        LiquidityPool storage pool = pools[poolId];

        IERC20(pool.tokenA).transferFrom(msg.sender, address(this), amountA);
        IERC20(pool.tokenB).transferFrom(msg.sender, address(this), amountB);

        if (pool.totalShares == 0) {
            shares = sqrt(amountA * amountB);
        } else {
            shares = min(
                amountA * pool.totalShares / pool.reserveA,
                amountB * pool.totalShares / pool.reserveB
            );
        }

        require(shares > 0, "Insufficient liquidity minted");

        pool.reserveA += amountA;
        pool.reserveB += amountB;
        pool.totalShares += shares;
        pool.lastUpdate = block.timestamp;

        liquidityShares[msg.sender][poolId] += shares;

        return shares;
    }

    /**
     * @dev Emergency pause - VULNERABLE to admin abuse
     */
    function emergencyPause(bytes32 poolId) external onlyOwner {
        // VULNERABILITY: No time lock or governance for emergency actions
        pools[poolId].isActive = false;
    }

    /**
     * @dev Update MEV protection parameters
     */
    function updateMEVParameters(
        uint256 _commitRevealDelay,
        uint256 _batchDuration,
        uint256 _maxGasPrice
    ) external onlyOwner {
        // VULNERABILITY: Parameters can be changed immediately
        commitRevealDelay = _commitRevealDelay;
        batchDuration = _batchDuration;
        maxGasPrice = _maxGasPrice;
    }

    /**
     * @dev Get pool ID
     */
    function getPoolId(address tokenA, address tokenB) public pure returns (bytes32) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return keccak256(abi.encodePacked(token0, token1));
    }

    /**
     * @dev Utility functions
     */
    function sqrt(uint256 y) private pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return a < b ? a : b;
    }

    function abs(uint256 a, uint256 b) private pure returns (uint256) {
        return a >= b ? a - b : b - a;
    }

    // VULNERABILITY: Direct ETH handling without protection
    receive() external payable {}
}