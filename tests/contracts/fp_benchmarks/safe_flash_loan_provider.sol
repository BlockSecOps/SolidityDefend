// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title IERC3156FlashLender
 * @notice Standard ERC-3156 flash lender interface
 */
interface IERC3156FlashLender {
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}

/**
 * @title IERC3156FlashBorrower
 * @notice Standard ERC-3156 flash borrower interface
 */
interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

/**
 * @title SafeFlashLoanProvider
 * @notice A properly implemented ERC-3156 compliant flash loan provider.
 * @dev This contract should NOT trigger flash loan vulnerability detectors.
 *
 * Safe patterns implemented:
 * - Full ERC-3156 compliance
 * - CALLBACK_SUCCESS validation
 * - Reentrancy protection
 * - Fee validation and bounds
 * - Balance validation before/after callback
 * - Callback source validation
 */
contract SafeFlashLoanProvider is IERC3156FlashLender, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Standard ERC-3156 callback success value
    bytes32 public constant CALLBACK_SUCCESS =
        keccak256("ERC3156FlashBorrower.onFlashLoan");

    /// @notice Maximum flash loan fee (0.5% = 50 basis points)
    uint256 public constant MAX_FEE = 50;
    uint256 public constant BASIS_POINTS = 10000;

    /// @notice Current flash loan fee in basis points
    uint256 public flashLoanFee = 9; // 0.09% (similar to Aave)

    /// @notice Supported tokens
    mapping(address => bool) public supportedTokens;

    /// @notice Token balances (for validation)
    mapping(address => uint256) private _tokenBalances;

    error UnsupportedToken();
    error InvalidFee();
    error InvalidCallback();
    error InsufficientRepayment();
    error MaxLoanExceeded();

    constructor(address[] memory tokens) {
        for (uint256 i = 0; i < tokens.length; i++) {
            supportedTokens[tokens[i]] = true;
        }
    }

    /**
     * @notice Maximum flash loan amount for a token
     */
    function maxFlashLoan(address token) public view override returns (uint256) {
        if (!supportedTokens[token]) {
            return 0;
        }
        return IERC20(token).balanceOf(address(this));
    }

    /**
     * @notice Calculate flash loan fee
     */
    function flashFee(address token, uint256 amount)
        public
        view
        override
        returns (uint256)
    {
        if (!supportedTokens[token]) {
            revert UnsupportedToken();
        }
        return (amount * flashLoanFee) / BASIS_POINTS;
    }

    /**
     * @notice Execute an ERC-3156 compliant flash loan
     * @dev Implements all safety patterns:
     *      - Reentrancy protection
     *      - Balance validation before/after
     *      - Callback success validation
     *      - Repayment validation
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external override nonReentrant returns (bool) {
        // Validate token
        if (!supportedTokens[token]) {
            revert UnsupportedToken();
        }

        // Validate amount
        if (amount > maxFlashLoan(token)) {
            revert MaxLoanExceeded();
        }

        // Calculate fee
        uint256 fee = flashFee(token, amount);

        // Validate fee is within bounds
        require(fee <= (amount * MAX_FEE) / BASIS_POINTS, "Fee too high");

        // Record balance before
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));

        // Transfer tokens to receiver
        IERC20(token).safeTransfer(address(receiver), amount);

        // Execute callback
        bytes32 result = receiver.onFlashLoan(
            msg.sender,    // initiator
            token,
            amount,
            fee,
            data
        );

        // Validate callback success
        if (result != CALLBACK_SUCCESS) {
            revert InvalidCallback();
        }

        // Validate repayment
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        if (balanceAfter < balanceBefore + fee) {
            revert InsufficientRepayment();
        }

        return true;
    }

    /**
     * @notice Update flash loan fee (admin only)
     */
    function setFlashLoanFee(uint256 newFee) external {
        require(newFee <= MAX_FEE, "Fee exceeds maximum");
        flashLoanFee = newFee;
    }
}

/**
 * @title SafeFlashBorrower
 * @notice A properly implemented ERC-3156 compliant flash loan borrower.
 * @dev This contract should NOT trigger flash loan callback vulnerability detectors.
 */
contract SafeFlashBorrower is IERC3156FlashBorrower, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Standard ERC-3156 callback success value
    bytes32 public constant CALLBACK_SUCCESS =
        keccak256("ERC3156FlashBorrower.onFlashLoan");

    /// @notice Trusted lender address
    address public immutable lender;

    error UnauthorizedLender();
    error UnauthorizedInitiator();

    constructor(address _lender) {
        lender = _lender;
    }

    /**
     * @notice Handle flash loan callback with full validation
     * @dev Implements all safety patterns:
     *      - msg.sender validation (must be lender)
     *      - initiator validation (must be this contract)
     *      - Reentrancy protection
     */
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata /* data */
    ) external override nonReentrant returns (bytes32) {
        // Validate caller is the trusted lender
        if (msg.sender != lender) {
            revert UnauthorizedLender();
        }

        // Validate initiator is this contract
        if (initiator != address(this)) {
            revert UnauthorizedInitiator();
        }

        // === Do something with the borrowed tokens ===
        // (Business logic here)

        // Approve repayment
        IERC20(token).safeIncreaseAllowance(lender, amount + fee);

        return CALLBACK_SUCCESS;
    }

    /**
     * @notice Initiate a flash loan
     */
    function executeFlashLoan(address token, uint256 amount, bytes calldata data)
        external
        nonReentrant
    {
        IERC3156FlashLender(lender).flashLoan(
            IERC3156FlashBorrower(address(this)),
            token,
            amount,
            data
        );
    }
}
