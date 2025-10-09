// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault_HookReentrancy
 * @notice VULNERABLE: ERC-4626 vault susceptible to reentrancy via ERC-777/ERC-1363 hooks
 *
 * VULNERABILITY: Hook reentrancy attack
 *
 * Attack scenario (ERC-777):
 * 1. Vault uses ERC-777 token with tokensReceived hook
 * 2. User deposits, triggering transferFrom()
 * 3. ERC-777 calls tokensReceived hook on attacker contract
 * 4. Attacker re-enters vault before shares are minted
 * 5. Attacker can manipulate totalSupply/totalAssets during callback
 * 6. Initial deposit gets wrong number of shares
 *
 * Reference: Uniswap V1 ~$300k loss, Cream Finance ~$18.8M loss
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault_HookReentrancy {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /**
     * @notice VULNERABLE: Deposit function
     * @dev State changes after token transfer, vulnerable to hook reentrancy
     *
     * VULNERABILITY: State changes after token transfer without reentrancy guard
     * - ERC-777/ERC-1363 callbacks can re-enter before state updates complete
     * - Balance/shares updated after token transfer. Hook reentrancy can read stale state before updates
     */
    function deposit(uint256 assets) public returns (uint256 shares) {
        // Calculate shares based on current state
        shares = totalSupply == 0 ? assets : (assets * totalSupply) / asset.balanceOf(address(this));

        // VULNERABILITY: State changes after token transfer without reentrancy guard.
        // ERC-777/ERC-1363 callbacks can re-enter before state updates complete

        // Transfer tokens (can trigger ERC-777 tokensReceived hook or ERC-1363 transferAndCall)
        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        // VULNERABILITY: Balance/shares updated after token transfer.
        // Hook reentrancy can read stale state before updates
        balanceOf[msg.sender] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, assets, shares);
    }

    /**
     * @notice VULNERABLE: Withdraw function
     * @dev Uses raw transfer() instead of SafeERC20
     *
     * VULNERABILITY: Multiple issues
     * - Uses raw transfer() instead of SafeERC20. No protection against malicious token implementations
     * - Accounting reads (totalAssets/totalSupply) after token transfer. Hook callbacks can manipulate state
     */
    function withdraw(uint256 shares) public returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        // VULNERABILITY: Accounting reads (totalAssets/totalSupply) after token transfer.
        // Hook callbacks can manipulate state during reentrancy
        assets = (shares * asset.balanceOf(address(this))) / totalSupply;

        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;

        // VULNERABILITY: Uses raw transfer() instead of SafeERC20.
        // No protection against malicious token implementations with callback hooks
        require(asset.transfer(msg.sender, assets), "Transfer failed");

        emit Withdraw(msg.sender, assets, shares);
    }

    /**
     * @notice VULNERABLE: Mint function
     * @dev Multiple token transfers without reentrancy protection
     *
     * VULNERABILITY: Multiple token transfers without reentrancy protection
     * - Each transfer is a potential reentrancy point via ERC-777/ERC-1363 hooks
     * - Violates checks-effects-interactions pattern
     */
    function mint(uint256 shares) public returns (uint256 assets) {
        assets = totalSupply == 0 ? shares : (shares * asset.balanceOf(address(this))) / totalSupply;

        // First transfer (reentrancy point 1)
        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer 1 failed");

        // VULNERABILITY: Multiple token transfers without reentrancy protection.
        // Each transfer is a potential reentrancy point via ERC-777/ERC-1363 hooks

        // State update after transfer (violates CEI)
        balanceOf[msg.sender] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, assets, shares);
    }

    /**
     * @notice VULNERABLE: Redeem function
     * @dev Violates checks-effects-interactions pattern
     *
     * VULNERABILITY: Violates checks-effects-interactions pattern
     * - Effects occur after interactions, vulnerable to reentrancy via token hooks
     */
    function redeem(uint256 shares) public returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        assets = (shares * asset.balanceOf(address(this))) / totalSupply;

        // External call before state update (violates CEI)
        require(asset.transfer(msg.sender, assets), "Transfer failed");

        // VULNERABILITY: Violates checks-effects-interactions pattern.
        // Effects occur after interactions, vulnerable to reentrancy via token hooks
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;

        emit Withdraw(msg.sender, assets, shares);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
