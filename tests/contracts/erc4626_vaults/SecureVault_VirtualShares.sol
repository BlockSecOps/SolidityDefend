// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureVault_VirtualShares
 * @notice SECURE: ERC-4626 vault with virtual shares/assets protection
 *
 * MITIGATION: Virtual shares/assets offset (OpenZeppelin approach)
 * - Adds offset to share calculations to prevent first depositor manipulation
 * - Based on OpenZeppelin's ERC4626 implementation with _decimalsOffset()
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract SecureVault_VirtualShares {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // MITIGATION: Virtual shares/assets offset for inflation protection
    uint256 private constant VIRTUAL_SHARES_OFFSET = 10**3;
    uint256 private constant VIRTUAL_ASSETS_OFFSET = 1;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice SECURE: Deposit assets and receive shares
     * @dev Uses virtual shares/assets offset to prevent inflation attack
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // MITIGATION: Share calculation with virtual shares/assets protection
        // Prevents first depositor from setting arbitrary share/asset ratio
        shares = _convertToShares(assets);

        require(shares > 0, "Zero shares");

        balanceOf[receiver] += shares;
        totalSupply += shares;

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    /**
     * @notice Redeem shares for assets
     */
    function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        require(balanceOf[owner] >= shares, "Insufficient balance");

        assets = _convertToAssets(shares);

        balanceOf[owner] -= shares;
        totalSupply -= shares;

        require(asset.transfer(receiver, assets), "Transfer failed");

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    /**
     * @notice Total assets held by vault
     */
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /**
     * @notice SECURE: Convert assets to shares with virtual offset
     * @dev Implements virtual shares protection against inflation attack
     */
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        // MITIGATION: Virtual shares calculation
        // shares = (assets + VIRTUAL_ASSETS) * (totalSupply + VIRTUAL_SHARES) / (totalAssets + VIRTUAL_ASSETS)
        uint256 supply = totalSupply + VIRTUAL_SHARES_OFFSET;
        uint256 assetBalance = totalAssets() + VIRTUAL_ASSETS_OFFSET;

        return (assets * supply) / assetBalance;
    }

    /**
     * @notice SECURE: Convert shares to assets with virtual offset
     */
    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        uint256 supply = totalSupply + VIRTUAL_SHARES_OFFSET;
        uint256 assetBalance = totalAssets() + VIRTUAL_ASSETS_OFFSET;

        return (shares * assetBalance) / supply;
    }

    /**
     * @notice Preview deposit to calculate shares
     */
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets);
    }
}
