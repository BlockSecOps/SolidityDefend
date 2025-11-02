// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simplified Uniswap V2 Pair
 * @notice Representative implementation based on Uniswap V2 patterns
 * @dev Simplified for FP testing - focuses on core AMM patterns
 */

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

contract UniswapV2Pair {
    string public constant name = 'Uniswap V2';
    string public constant symbol = 'UNI-V2';
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    address public factory;
    address public token0;
    address public token1;

    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;

    // TWAP oracles - Uniswap V2 IS the oracle source
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;

    uint256 private unlocked = 1;

    modifier lock() {
        require(unlocked == 1, 'UniswapV2: LOCKED');
        unlocked = 0;
        _;
        unlocked = 1;
    }

    // Core AMM functions - should be detected by is_uniswap_v2_pair()

    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    function mint(address to) external lock returns (uint256 liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));
        uint256 amount0 = balance0 - _reserve0;
        uint256 amount1 = balance1 - _reserve1;

        if (totalSupply == 0) {
            liquidity = sqrt(amount0 * amount1);
        } else {
            liquidity = min(amount0 * totalSupply / _reserve0, amount1 * totalSupply / _reserve1);
        }

        require(liquidity > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED');
        balanceOf[to] += liquidity;
        totalSupply += liquidity;

        _update(balance0, balance1, _reserve0, _reserve1);
    }

    function burn(address to) external lock returns (uint256 amount0, uint256 amount1) {
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));
        uint256 liquidity = balanceOf[address(this)];

        amount0 = liquidity * balance0 / totalSupply;
        amount1 = liquidity * balance1 / totalSupply;

        require(amount0 > 0 && amount1 > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED');

        balanceOf[address(this)] -= liquidity;
        totalSupply -= liquidity;

        IERC20(token0).transfer(to, amount0);
        IERC20(token1).transfer(to, amount1);

        balance0 = IERC20(token0).balanceOf(address(this));
        balance1 = IERC20(token1).balanceOf(address(this));

        _update(balance0, balance1, reserve0, reserve1);
    }

    // Swap function - legitimate MEV target
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        require(amount0Out < _reserve0 && amount1Out < _reserve1, 'UniswapV2: INSUFFICIENT_LIQUIDITY');

        uint256 balance0;
        uint256 balance1;

        if (amount0Out > 0) IERC20(token0).transfer(to, amount0Out);
        if (amount1Out > 0) IERC20(token1).transfer(to, amount1Out);

        // Flash swap callback
        if (data.length > 0) {
            // This is a flash swap - legitimate pattern
            // Should NOT trigger flash loan vulnerabilities
        }

        balance0 = IERC20(token0).balanceOf(address(this));
        balance1 = IERC20(token1).balanceOf(address(this));

        uint256 amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;

        require(amount0In > 0 || amount1In > 0, 'UniswapV2: INSUFFICIENT_INPUT_AMOUNT');

        // Constant product formula check
        uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
        uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
        require(balance0Adjusted * balance1Adjusted >= uint256(_reserve0) * _reserve1 * 1000000, 'UniswapV2: K');

        _update(balance0, balance1, _reserve0, _reserve1);
    }

    // TWAP oracle update - this pool IS the oracle
    function _update(uint256 balance0, uint256 balance1, uint112 _reserve0, uint112 _reserve1) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, 'UniswapV2: OVERFLOW');
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;

        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            // Update cumulative prices for TWAP oracle
            price0CumulativeLast += uint256(_reserve1 / _reserve0) * timeElapsed;
            price1CumulativeLast += uint256(_reserve0 / _reserve1) * timeElapsed;
        }

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
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

    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x < y ? x : y;
    }
}
