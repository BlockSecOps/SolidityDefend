// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanProvider {
    function flashLoan(address asset, uint256 amount, bytes calldata data) external;
}

interface IDEXRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);

    function getAmountsOut(uint amountIn, address[] calldata path)
        external view returns (uint[] memory amounts);
}

/**
 * @title FlashLoanArbitrage
 * @dev Modern arbitrage contract with multiple 2025-era vulnerabilities
 *
 * VULNERABILITIES:
 * 1. MEV-vulnerable price calculation without protection
 * 2. Slippage manipulation via deadline manipulation
 * 3. Cross-DEX price oracle dependency without validation
 * 4. Flash loan callback reentrancy despite ReentrancyGuard
 * 5. Sandwich attack susceptibility
 * 6. Just-in-time (JIT) liquidity exploitation
 * 7. Missing access control on profit withdrawal
 * 8. Oracle price manipulation via large trades
 */
contract FlashLoanArbitrage is ReentrancyGuard, Ownable {

    struct ArbitrageParams {
        address tokenA;
        address tokenB;
        address dexA;
        address dexB;
        uint256 flashAmount;
        uint256 minProfit;
        uint256 deadline;
    }

    mapping(address => bool) public authorizedCallers;
    mapping(address => uint256) public profits;

    uint256 private constant MAX_SLIPPAGE = 300; // 3%
    uint256 private constant BASIS_POINTS = 10000;

    // VULNERABILITY: State variable that can be manipulated during flash loan execution
    uint256 public currentArbitrageAmount;
    bool private inFlashLoan;

    event ArbitrageExecuted(
        address indexed tokenA,
        address indexed tokenB,
        uint256 profit,
        address indexed executor
    );

    modifier onlyAuthorized() {
        require(authorizedCallers[msg.sender] || msg.sender == owner(), "Not authorized");
        _;
    }

    constructor() Ownable(msg.sender) {
        authorizedCallers[msg.sender] = true;
    }

    /**
     * @dev Execute flash loan arbitrage
     * VULNERABILITY: No MEV protection, susceptible to frontrunning
     */
    function executeArbitrage(ArbitrageParams calldata params) external onlyAuthorized {
        require(params.deadline > block.timestamp, "Deadline passed");
        require(params.minProfit > 0, "Invalid min profit");

        // VULNERABILITY: Price calculation happens before flash loan, can be manipulated
        uint256 expectedProfit = calculatePotentialProfit(params);
        require(expectedProfit >= params.minProfit, "Insufficient profit potential");

        // VULNERABILITY: State modification before external call
        currentArbitrageAmount = params.flashAmount;

        bytes memory data = abi.encode(params, msg.sender);
        IFlashLoanProvider(getFlashLoanProvider()).flashLoan(params.tokenA, params.flashAmount, data);
    }

    /**
     * @dev Flash loan callback - VULNERABLE to complex reentrancy
     */
    function onFlashLoan(
        address asset,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external nonReentrant returns (bool) {
        // VULNERABILITY: Missing validation of flash loan provider
        inFlashLoan = true;

        (ArbitrageParams memory params, address executor) = abi.decode(data, (ArbitrageParams, address));

        // VULNERABILITY: Price fetched during execution, can be manipulated by MEV bots
        uint256 priceA = getPriceFromDEX(params.dexA, params.tokenA, params.tokenB, amount);
        uint256 priceB = getPriceFromDEX(params.dexB, params.tokenB, params.tokenA, priceA);

        // Execute arbitrage trades
        _executeArbitrageTrades(params, amount);

        // VULNERABILITY: Profit calculation after trades, affected by slippage manipulation
        uint256 finalBalance = IERC20(asset).balanceOf(address(this));
        uint256 repayAmount = amount + fee;

        require(finalBalance >= repayAmount, "Arbitrage failed");

        uint256 profit = finalBalance - repayAmount;

        // VULNERABILITY: Profit stored in mapping, accessible by anyone
        profits[executor] += profit;

        // Repay flash loan
        IERC20(asset).transfer(msg.sender, repayAmount);

        inFlashLoan = false;
        emit ArbitrageExecuted(params.tokenA, params.tokenB, profit, executor);

        return true;
    }

    /**
     * @dev Calculate potential profit - VULNERABLE to manipulation
     */
    function calculatePotentialProfit(ArbitrageParams memory params) public view returns (uint256) {
        // VULNERABILITY: Using spot prices without TWAP or oracle validation
        uint256 priceA = getPriceFromDEX(params.dexA, params.tokenA, params.tokenB, params.flashAmount);
        uint256 priceB = getPriceFromDEX(params.dexB, params.tokenB, params.tokenA, priceA);

        // VULNERABILITY: No slippage calculation for large trades
        if (priceB > params.flashAmount) {
            return priceB - params.flashAmount;
        }
        return 0;
    }

    /**
     * @dev Execute trades on both DEXes
     */
    function _executeArbitrageTrades(ArbitrageParams memory params, uint256 amount) private {
        address[] memory pathA = new address[](2);
        pathA[0] = params.tokenA;
        pathA[1] = params.tokenB;

        address[] memory pathB = new address[](2);
        pathB[0] = params.tokenB;
        pathB[1] = params.tokenA;

        // VULNERABILITY: No slippage protection, using 0 as minimum
        IERC20(params.tokenA).approve(params.dexA, amount);
        uint256[] memory amountsA = IDEXRouter(params.dexA).swapExactTokensForTokens(
            amount,
            0, // VULNERABILITY: No minimum amount protection
            pathA,
            address(this),
            params.deadline
        );

        // VULNERABILITY: Using received amount directly without validation
        uint256 tokenBAmount = amountsA[1];

        IERC20(params.tokenB).approve(params.dexB, tokenBAmount);
        IDEXRouter(params.dexB).swapExactTokensForTokens(
            tokenBAmount,
            0, // VULNERABILITY: No minimum amount protection
            pathB,
            address(this),
            params.deadline
        );
    }

    /**
     * @dev Get price from DEX - VULNERABLE to manipulation
     */
    function getPriceFromDEX(
        address dex,
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) public view returns (uint256) {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        // VULNERABILITY: Using getAmountsOut which can be manipulated by large trades
        uint256[] memory amounts = IDEXRouter(dex).getAmountsOut(amountIn, path);
        return amounts[1];
    }

    /**
     * @dev Withdraw profits - VULNERABILITY: No access control
     */
    function withdrawProfits(address token) external {
        // VULNERABILITY: Anyone can withdraw anyone's profits
        uint256 profit = profits[msg.sender];
        require(profit > 0, "No profits");

        profits[msg.sender] = 0;
        IERC20(token).transfer(msg.sender, profit);
    }

    /**
     * @dev Emergency function - VULNERABILITY: Can be called during flash loan
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        // VULNERABILITY: No check if in flash loan, could steal flash loan funds
        IERC20(token).transfer(owner(), amount);
    }

    /**
     * @dev Set authorized caller
     */
    function setAuthorizedCaller(address caller, bool authorized) external onlyOwner {
        authorizedCallers[caller] = authorized;
    }

    /**
     * @dev Get flash loan provider - hardcoded for simplicity
     */
    function getFlashLoanProvider() public pure returns (address) {
        return 0x1234567890123456789012345678901234567890; // Mock address
    }

    /**
     * @dev Check if currently in flash loan
     */
    function isInFlashLoan() external view returns (bool) {
        return inFlashLoan;
    }

    // VULNERABILITY: Fallback function can receive Ether during flash loan
    receive() external payable {
        // This could be exploited if flash loan involves ETH
    }
}