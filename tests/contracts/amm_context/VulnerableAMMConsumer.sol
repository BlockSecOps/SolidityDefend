// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Vulnerable AMM Consumer Contract
/// This contract CONSUMES AMM data unsafely and should trigger:
/// - sandwich-resistant-swap (no slippage protection)
/// - slippage-protection (amountOutMin = 0)
/// - mev-extractable-value (MEV vulnerable swap)
contract VulnerableAMMConsumer {
    address public immutable router;
    address public immutable weth;

    constructor(address _router, address _weth) {
        router = _router;
        weth = _weth;
    }

    /// VULNERABILITY: Swap with no slippage protection
    /// Should be detected by: sandwich-resistant-swap, slippage-protection, mev-extractable-value
    function swapWithoutSlippage(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        // VULNERABILITY: No slippage protection!
        // amountOutMin = 0 means accept any output amount
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        // Transfer tokens from user
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // Approve router
        IERC20(tokenIn).approve(router, amountIn);

        // VULNERABILITY: Call swap with amountOutMin = 0
        // This is vulnerable to sandwich attacks
        uint[] memory amounts = IUniswapV2Router(router).swapExactTokensForTokens(
            amountIn,
            0,  // VULNERABILITY: No minimum output!
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    /// VULNERABILITY: Swap with no deadline
    /// Should be detected by: sandwich-resistant-swap
    function swapWithoutDeadline(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) external returns (uint256 amountOut) {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(router, amountIn);

        // VULNERABILITY: deadline = type(uint256).max means no deadline protection
        uint[] memory amounts = IUniswapV2Router(router).swapExactTokensForTokens(
            amountIn,
            amountOutMin,
            path,
            msg.sender,
            type(uint256).max  // VULNERABILITY: No deadline!
        );

        return amounts[amounts.length - 1];
    }

    /// VULNERABILITY: Using spot price without TWAP
    /// Should be detected by: sandwich-resistant-swap
    function swapUsingSpotPrice(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        // VULNERABILITY: Using getReserves (spot price) without TWAP
        (uint reserve0, uint reserve1,) = IUniswapV2Pair(getPair(tokenIn, tokenOut)).getReserves();

        // Calculate expected output using spot price
        uint amountInWithFee = amountIn * 997;
        uint numerator = amountInWithFee * reserve1;
        uint denominator = (reserve0 * 1000) + amountInWithFee;
        uint expectedOut = numerator / denominator;

        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(router, amountIn);

        // Even with minimum output, using spot price is vulnerable
        uint[] memory amounts = IUniswapV2Router(router).swapExactTokensForTokens(
            amountIn,
            expectedOut * 95 / 100,  // 5% slippage
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    function getPair(address tokenA, address tokenB) private pure returns (address) {
        // Simplified - would normally query factory
        return address(0);
    }
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
