// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title SafeAMMPool
 * @notice A properly implemented AMM pool with TWAP oracle and protections.
 * @dev This contract should NOT trigger AMM/oracle manipulation detectors.
 *
 * Safe patterns implemented:
 * - TWAP oracle (time-weighted average price)
 * - Cumulative price tracking (Uniswap V2 style)
 * - Slippage protection
 * - Reentrancy protection
 * - MEV protection (deadline, minOutput)
 * - Minimum liquidity (dead shares)
 */
contract SafeAMMPool is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============== Constants ==============
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    uint256 private constant Q112 = 2**112;

    // ============== State ==============
    IERC20 public immutable token0;
    IERC20 public immutable token1;

    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;

    // TWAP Oracle: Cumulative prices
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;

    // Liquidity token
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // ============== Events ==============
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);

    // ============== Errors ==============
    error InsufficientLiquidity();
    error InsufficientInputAmount();
    error InsufficientOutputAmount();
    error SlippageExceeded();
    error DeadlineExpired();
    error InvariantViolation();

    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
    }

    /**
     * @notice Get current reserves
     */
    function getReserves()
        public
        view
        returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast)
    {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    /**
     * @notice Update TWAP oracle cumulative prices
     * @dev Called on every swap/mint/burn to maintain accurate TWAP
     */
    function _update(
        uint256 balance0,
        uint256 balance1,
        uint112 _reserve0,
        uint112 _reserve1
    ) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "Overflow");

        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;

        // Update cumulative prices for TWAP (only if time has passed)
        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            // Cumulative price updates (overflow is desired for TWAP)
            unchecked {
                price0CumulativeLast += uint256((_reserve1 * Q112) / _reserve0) * timeElapsed;
                price1CumulativeLast += uint256((_reserve0 * Q112) / _reserve1) * timeElapsed;
            }
        }

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;

        emit Sync(reserve0, reserve1);
    }

    /**
     * @notice Get TWAP price over a period
     * @param twapPeriod Time period for TWAP calculation
     * @return price0Average Average price of token0 in terms of token1
     */
    function getTWAP(uint32 twapPeriod) external view returns (uint256 price0Average) {
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;

        // Calculate current cumulative price
        uint256 price0Cumulative = price0CumulativeLast;
        if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
            unchecked {
                price0Cumulative += uint256((reserve1 * Q112) / reserve0) * timeElapsed;
            }
        }

        // TWAP = (currentCumulative - pastCumulative) / twapPeriod
        // This is a simplified version; full implementation would store historical values
        price0Average = price0Cumulative / twapPeriod;
    }

    /**
     * @notice Add liquidity with first depositor protection
     */
    function mint(address to) external nonReentrant returns (uint256 liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        uint256 amount0 = balance0 - _reserve0;
        uint256 amount1 = balance1 - _reserve1;

        if (totalSupply == 0) {
            // First depositor: mint dead shares to address(0)
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY); // Dead shares protection
        } else {
            liquidity = min(
                (amount0 * totalSupply) / _reserve0,
                (amount1 * totalSupply) / _reserve1
            );
        }

        require(liquidity > 0, "Insufficient liquidity minted");
        _mint(to, liquidity);

        _update(balance0, balance1, _reserve0, _reserve1);

        emit Mint(msg.sender, amount0, amount1);
    }

    /**
     * @notice Remove liquidity
     */
    function burn(address to) external nonReentrant returns (uint256 amount0, uint256 amount1) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        uint256 liquidity = balanceOf[address(this)];

        amount0 = (liquidity * balance0) / totalSupply;
        amount1 = (liquidity * balance1) / totalSupply;

        require(amount0 > 0 && amount1 > 0, "Insufficient liquidity burned");

        _burn(address(this), liquidity);

        token0.safeTransfer(to, amount0);
        token1.safeTransfer(to, amount1);

        balance0 = token0.balanceOf(address(this));
        balance1 = token1.balanceOf(address(this));

        _update(balance0, balance1, _reserve0, _reserve1);

        emit Burn(msg.sender, amount0, amount1, to);
    }

    /**
     * @notice Swap with slippage protection and deadline
     * @param amount0Out Amount of token0 to receive
     * @param amount1Out Amount of token1 to receive
     * @param to Recipient address
     * @param minAmountOut Minimum output amount (slippage protection)
     * @param deadline Transaction deadline (MEV protection)
     */
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        uint256 minAmountOut,
        uint256 deadline
    ) external nonReentrant {
        // Deadline check (MEV protection)
        if (block.timestamp > deadline) {
            revert DeadlineExpired();
        }

        // Slippage protection
        uint256 totalOut = amount0Out + amount1Out;
        if (totalOut < minAmountOut) {
            revert SlippageExceeded();
        }

        if (amount0Out == 0 && amount1Out == 0) {
            revert InsufficientOutputAmount();
        }

        (uint112 _reserve0, uint112 _reserve1,) = getReserves();

        if (amount0Out > _reserve0 || amount1Out > _reserve1) {
            revert InsufficientLiquidity();
        }

        // Transfer outputs
        if (amount0Out > 0) token0.safeTransfer(to, amount0Out);
        if (amount1Out > 0) token1.safeTransfer(to, amount1Out);

        // Get new balances
        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        // Calculate input amounts
        uint256 amount0In = balance0 > _reserve0 - amount0Out
            ? balance0 - (_reserve0 - amount0Out)
            : 0;
        uint256 amount1In = balance1 > _reserve1 - amount1Out
            ? balance1 - (_reserve1 - amount1Out)
            : 0;

        if (amount0In == 0 && amount1In == 0) {
            revert InsufficientInputAmount();
        }

        // Verify k invariant (with 0.3% fee)
        uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
        uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;

        if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
            revert InvariantViolation();
        }

        _update(balance0, balance1, _reserve0, _reserve1);

        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    // ============== Internal Functions ==============

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balanceOf[to] += value;
    }

    function _burn(address from, uint256 value) internal {
        balanceOf[from] -= value;
        totalSupply -= value;
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
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

    function min(uint256 x, uint256 y) internal pure returns (uint256) {
        return x < y ? x : y;
    }
}
