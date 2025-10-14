// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureVault_MinimumDeposit
 * @notice SECURE: ERC-4626 vault with minimum deposit requirement
 *
 * MITIGATION: Minimum deposit enforcement
 * - Requires substantial minimum deposit (e.g., 1e6 tokens for USDC)
 * - Makes it expensive to execute inflation attack
 * - Prevents 1 wei deposit manipulation
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SecureVault_MinimumDeposit {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // MITIGATION: Minimum deposit requirement prevents 1 wei manipulation
    uint256 public constant MINIMUM_DEPOSIT = 1e6; // 1 USDC for USDC vault
    uint256 public constant MINIMUM_FIRST_DEPOSIT = 1e9; // 1000 USDC for first deposit

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice SECURE: Deposit assets and receive shares
     * @dev Enforces minimum deposit requirements to prevent manipulation
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // MITIGATION: Enforce minimum deposit amount
        if (totalSupply == 0) {
            // MITIGATION: First deposit requires higher minimum to prevent manipulation
            require(assets >= MINIMUM_FIRST_DEPOSIT, "First deposit below minimum");
            shares = assets;
        } else {
            // MITIGATION: Regular deposits enforce standard minimum
            require(assets >= MINIMUM_DEPOSIT, "Deposit below minimum");
            shares = (assets * totalSupply) / totalAssets();
        }

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
            return assets;
        }
        return (assets * totalSupply) / totalAssets();
    }
}
