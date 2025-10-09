// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureVault_DeadShares
 * @notice SECURE: ERC-4626 vault with dead shares protection
 *
 * MITIGATION: Dead shares approach (Uniswap V2 style)
 * - Mints initial shares to address(0) on first deposit
 * - Makes it economically infeasible to manipulate share price
 * - Inspired by Uniswap V2's MINIMUM_LIQUIDITY mechanism
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SecureVault_DeadShares {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // MITIGATION: Minimum liquidity locked forever (dead shares)
    // Inspired by Uniswap V2, makes inflation attack economically infeasible
    uint256 private constant MINIMUM_LIQUIDITY = 10**3;

    bool private _initialized;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice SECURE: Deposit assets and receive shares
     * @dev First deposit mints dead shares to address(0)
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        if (totalSupply == 0) {
            // MITIGATION: First deposit - mint dead shares to address(0)
            // Prevents first depositor from setting arbitrary share/asset ratio
            shares = assets;

            // MITIGATION: Mint MINIMUM_LIQUIDITY to address(0) (dead shares)
            // These shares are locked forever, preventing manipulation
            balanceOf[address(0)] = MINIMUM_LIQUIDITY;
            totalSupply = MINIMUM_LIQUIDITY;

            // Give depositor remaining shares
            shares = assets - MINIMUM_LIQUIDITY;
            require(shares > 0, "Insufficient initial deposit");

            balanceOf[receiver] = shares;
            totalSupply += shares;

            _initialized = true;
        } else {
            // Standard deposit: calculate shares based on current ratio
            shares = (assets * totalSupply) / totalAssets();
            require(shares > 0, "Zero shares");

            balanceOf[receiver] += shares;
            totalSupply += shares;
        }

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    /**
     * @notice Redeem shares for assets
     */
    function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        require(balanceOf[owner] >= shares, "Insufficient balance");
        require(owner != address(0), "Cannot redeem dead shares");

        assets = (shares * totalAssets()) / totalSupply;

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
     * @notice Preview deposit to calculate shares
     */
    function previewDeposit(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) {
            return assets - MINIMUM_LIQUIDITY;
        }
        return (assets * totalSupply) / totalAssets();
    }
}
