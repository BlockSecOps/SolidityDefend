// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault_WithdrawalDOS
 * @notice VULNERABLE: ERC-4626 vault susceptible to withdrawal DOS attacks
 *
 * VULNERABILITY: Withdrawal DOS via queue manipulation and liquidity locks
 *
 * Attack scenarios:
 * 1. Unbounded queue: Attacker creates many withdrawal requests, DOSing queue processing
 * 2. Liquidity lock: Large withdrawals drain liquidity, blocking subsequent withdrawers
 * 3. Failed calls: External call failures permanently block withdrawals
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault_WithdrawalDOS {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // VULNERABILITY: Unbounded withdrawal queue
    address[] public withdrawalQueue;
    mapping(address => uint256) public pendingWithdrawals;

    event Deposit(address indexed user, uint256 amount);
    event WithdrawalRequested(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    function deposit(uint256 assets) public returns (uint256 shares) {
        shares = totalSupply == 0 ? assets : (assets * totalSupply) / asset.balanceOf(address(this));

        balanceOf[msg.sender] += shares;
        totalSupply += shares;

        require(asset.transferFrom(msg.sender, address(this), assets));
        emit Deposit(msg.sender, assets);
    }

    /**
     * @notice VULNERABLE: Request withdrawal
     * @dev Unbounded queue without iteration limit enables DOS
     *
     * VULNERABILITY: Unbounded withdrawal queue processing
     * - No maximum queue length
     * - Attacker can create thousands of requests
     * - Queue processing will run out of gas
     */
    function requestWithdrawal(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: Unbounded withdrawal queue processing. Loop over queue without iteration limit
        // can be exploited for DOS by creating many requests
        withdrawalQueue.push(msg.sender);
        pendingWithdrawals[msg.sender] = amount;

        emit WithdrawalRequested(msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: Process withdrawal queue
     * @dev Processes entire queue without limits
     *
     * VULNERABILITY: Multiple issues
     * - Unbounded loop can cause out-of-gas
     * - No circuit breaker for emergencies
     * - Withdrawal requires successful external call, failing calls can permanently block withdrawals
     */
    function processWithdrawals() public {
        // VULNERABILITY: Unbounded withdrawal queue processing. Loop over queue without iteration limit
        // can be exploited for DOS by creating many requests
        for (uint256 i = 0; i < withdrawalQueue.length; i++) {
            address user = withdrawalQueue[i];
            uint256 amount = pendingWithdrawals[user];

            if (amount > 0) {
                uint256 assets = (amount * asset.balanceOf(address(this))) / totalSupply;

                balanceOf[user] -= amount;
                totalSupply -= amount;
                pendingWithdrawals[user] = 0;

                // VULNERABILITY: Withdrawal requires successful external call. Failing calls can permanently block withdrawals
                require(asset.transfer(user, assets), "Transfer failed");

                emit Withdraw(user, assets);
            }
        }

        delete withdrawalQueue;
    }

    /**
     * @notice VULNERABLE: Direct withdrawal
     * @dev No withdrawal cap or circuit breaker
     *
     * VULNERABILITY: Multiple issues
     * - No withdrawal cap or limit detected. Large withdrawals can drain liquidity and DOS subsequent withdrawers
     * - No circuit breaker or emergency withdrawal. Vault cannot be paused during attacks
     */
    function withdraw(uint256 shares) public {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        // VULNERABILITY: Potential accounting mismatch. Division by totalSupply without zero check
        // can cause withdrawal reverts and DOS
        uint256 assets = (shares * asset.balanceOf(address(this))) / totalSupply;

        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;

        // VULNERABILITY: No withdrawal cap or limit detected. Large withdrawals can drain liquidity
        // and DOS subsequent withdrawers
        require(asset.transfer(msg.sender, assets), "Transfer failed");

        emit Withdraw(msg.sender, assets);
    }
}
