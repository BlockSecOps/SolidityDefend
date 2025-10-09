// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault_Donation
 * @notice VULNERABLE: ERC-4626 vault susceptible to donation attacks
 *
 * VULNERABILITY: Direct token donations manipulate share price
 *
 * Attack scenario:
 * 1. Vault has 100 tokens and 100 shares (1:1 ratio)
 * 2. Attacker directly transfers 900 tokens to vault without depositing
 * 3. totalAssets() now returns 1000 (100 + 900 donation)
 * 4. Victim deposits 1000 tokens
 *    shares = 1000 * 100 / 1000 = 100 shares
 * 5. Victim should have received 1000 shares but only got 100
 * 6. Attacker profits from inflated share price
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault_Donation {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice VULNERABLE: Deposit function
     * @dev Share calculation uses balanceOf which can be manipulated by direct transfers
     *
     * VULNERABILITY: Donation attack
     * - Uses balanceOf(address(this)) for totalAssets calculation
     * - No internal accounting to track actual deposits
     * - Direct token transfers inflate totalAssets without issuing shares
     * - No validation for unexpected balance increases
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // VULNERABILITY: Share calculation depends on balanceOf which can be manipulated by donations
        shares = convertToShares(assets);

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

        assets = convertToAssets(shares);

        balanceOf[owner] -= shares;
        totalSupply -= shares;

        require(asset.transfer(receiver, assets), "Transfer failed");

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    /**
     * @notice VULNERABLE: Convert assets to shares
     * @dev Uses totalAssets() which depends on balanceOf
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }
        // VULNERABILITY: Share calculation depends on balanceOf which can be manipulated by donations
        return (assets * totalSupply) / totalAssets();
    }

    /**
     * @notice Convert shares to assets
     */
    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) {
            return shares;
        }
        return (shares * totalAssets()) / totalSupply;
    }

    /**
     * @notice VULNERABLE: Total assets calculation
     * @dev Uses balanceOf directly without internal accounting
     *
     * VULNERABILITY: Direct token donations inflate this value
     * - No internal balance tracking
     * - No donation guard or balance validation
     * - Any direct transfer will inflate share price
     */
    function totalAssets() public view returns (uint256) {
        // VULNERABILITY: Uses balanceOf(address(this)) for share price calculation
        // without internal balance tracking. Vulnerable to direct token donation manipulation
        return asset.balanceOf(address(this));
    }

    /**
     * @notice Preview deposit to calculate shares
     */
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return convertToShares(assets);
    }
}
