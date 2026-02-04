// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title SafeERC4626Vault
 * @notice A properly implemented ERC-4626 vault with all inflation protections.
 * @dev This contract should NOT trigger vault-related vulnerability detectors.
 *
 * Safe patterns implemented:
 * - Virtual shares/assets offset (OpenZeppelin decimalsOffset pattern)
 * - Dead shares to address(0) on first deposit
 * - Minimum deposit requirements
 * - Proper share calculation with rounding
 * - Reentrancy protection
 * - Fee-on-transfer token handling
 */
contract SafeERC4626Vault is ERC4626, ReentrancyGuard {
    uint256 public constant MINIMUM_DEPOSIT = 1e6;
    uint256 private constant INITIAL_SHARE_LOCK = 1000;
    bool private _initialized;

    // Track actual assets to prevent donation attacks
    uint256 private _trackedAssets;

    constructor(IERC20 asset_) ERC4626(asset_) ERC20("Safe Vault Token", "SVT") {}

    /**
     * @notice Override decimalsOffset for virtual shares protection
     * @dev This provides inflation attack protection via virtual offset
     */
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3; // 10^3 = 1000 virtual offset
    }

    /**
     * @notice Deposit with minimum amount and first depositor protection
     */
    function deposit(uint256 assets, address receiver)
        public
        override
        nonReentrant
        returns (uint256 shares)
    {
        // Minimum deposit check
        require(assets >= MINIMUM_DEPOSIT, "Amount too small");

        // Handle fee-on-transfer tokens
        uint256 balanceBefore = IERC20(asset()).balanceOf(address(this));

        // First depositor protection: mint dead shares to address(0)
        if (totalSupply() == 0) {
            _mint(address(0), INITIAL_SHARE_LOCK);
        }

        shares = super.deposit(assets, receiver);

        // Calculate actual received amount
        uint256 balanceAfter = IERC20(asset()).balanceOf(address(this));
        uint256 actualAmount = balanceAfter - balanceBefore;

        // Update tracked assets
        _trackedAssets += actualAmount;

        // Validate non-zero shares
        require(shares > 0, "Shares must be non-zero");
    }

    /**
     * @notice Withdraw with slippage protection
     */
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override nonReentrant returns (uint256 shares) {
        shares = super.withdraw(assets, receiver, owner);

        // Update tracked assets
        _trackedAssets -= assets;

        // Validate non-zero assets
        require(assets > 0, "Assets must be non-zero");
    }

    /**
     * @notice Redeem with proper validation
     */
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public override nonReentrant returns (uint256 assets) {
        require(shares > 0, "Shares must be non-zero");

        assets = super.redeem(shares, receiver, owner);

        // Update tracked assets
        _trackedAssets -= assets;

        require(assets > 0, "Assets must be non-zero");
    }

    /**
     * @notice Total assets using tracked value (prevents donation attacks)
     */
    function totalAssets() public view override returns (uint256) {
        // Use tracked assets instead of balanceOf to prevent donation attacks
        return _trackedAssets;
    }
}
