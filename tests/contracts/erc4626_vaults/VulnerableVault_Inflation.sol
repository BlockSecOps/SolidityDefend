// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault_Inflation
 * @notice VULNERABLE: Classic ERC-4626 share inflation attack pattern
 *
 * VULNERABILITY: First depositor can manipulate share price
 *
 * Attack scenario:
 * 1. Attacker deposits 1 wei to get 1 share (totalSupply = 1, totalAssets = 1)
 * 2. Attacker directly transfers 10,000 tokens to vault (totalSupply = 1, totalAssets = 10,001)
 * 3. Victim deposits 20,000 tokens
 *    shares = 20,000 * 1 / 10,001 = 1.999... ≈ 1 share (rounds down)
 * 4. Attacker redeems 1 share, gets half of totalAssets
 * 5. Victim lost ~10,000 tokens to rounding
 *
 * Reference: Cetus DEX exploit (May 2025, $223M loss)
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault_Inflation {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice VULNERABLE: Deposit assets and receive shares
     * @dev Classic vulnerable share calculation without protection
     *
     * VULNERABILITY: Share inflation attack
     * - No minimum deposit requirement (allows 1 wei deposit)
     * - No virtual shares/assets offset
     * - No dead shares minted at deployment
     * - No totalSupply == 0 special case handling
     * - Uses balanceOf(address(this)) which can be manipulated by direct transfers
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // VULNERABILITY: Classic share calculation without protection
        // shares = assets * totalSupply / totalAssets
        if (totalSupply == 0) {
            shares = assets; // First deposit: 1:1 ratio
        } else {
            // VULNERABILITY: Uses token.balanceOf(address(this)) for share price calculation
            // without internal accounting, vulnerable to direct token transfer manipulation
            shares = (assets * totalSupply) / totalAssets();
        }

        // VULNERABILITY: No minimum deposit amount enforced, allowing 1 wei deposit
        // that can be used for share price manipulation
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
     * @notice VULNERABLE: Total assets calculation
     * @dev Uses balanceOf which can be manipulated by direct transfers
     */
    function totalAssets() public view returns (uint256) {
        // VULNERABILITY: Uses token.balanceOf(address(this)) for share price calculation
        // without internal accounting, vulnerable to direct token transfer manipulation
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
