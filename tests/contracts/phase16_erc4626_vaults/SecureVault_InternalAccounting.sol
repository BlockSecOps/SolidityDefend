// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureVault_InternalAccounting
 * @notice SECURE: ERC-4626 vault with internal accounting
 *
 * MITIGATION: Internal balance tracking
 * - Maintains internal balance rather than using token.balanceOf(address(this))
 * - Direct token transfers to vault don't affect share price
 * - Prevents donation-based manipulation
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SecureVault_InternalAccounting {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // MITIGATION: Internal accounting prevents donation manipulation
    // Tracks actual deposited assets, not token.balanceOf(address(this))
    uint256 private totalDeposited;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice SECURE: Deposit assets and receive shares
     * @dev Uses internal accounting to prevent donation manipulation
     */
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        if (totalSupply == 0) {
            shares = assets;
        } else {
            // MITIGATION: Uses totalDeposited (internal accounting)
            // instead of token.balanceOf(address(this))
            // Direct token transfers don't affect share price
            shares = (assets * totalSupply) / totalAssets();
        }

        require(shares > 0, "Zero shares");

        balanceOf[receiver] += shares;
        totalSupply += shares;

        // MITIGATION: Update internal balance tracking
        totalDeposited += assets;

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

        // MITIGATION: Update internal balance tracking
        totalDeposited -= assets;

        require(asset.transfer(receiver, assets), "Transfer failed");

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    /**
     * @notice SECURE: Total assets calculation using internal accounting
     * @dev Returns tracked deposits, not actual balance
     */
    function totalAssets() public view returns (uint256) {
        // MITIGATION: Uses internal accounting (totalDeposited)
        // Direct donations don't inflate this value
        return totalDeposited;
    }

    /**
     * @notice Get actual token balance (may be higher due to donations)
     */
    function actualBalance() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /**
     * @notice Get untracked donations
     */
    function donations() public view returns (uint256) {
        uint256 balance = asset.balanceOf(address(this));
        return balance > totalDeposited ? balance - totalDeposited : 0;
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
