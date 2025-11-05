// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/**
 * @title EzEthToken
 * @notice Placeholder contract for Renzo Protocol ezETH token
 * @dev This contract is a minimal placeholder as the full EzEthToken.sol
 * could not be included in the test suite. The actual ezETH token is a
 * liquid restaking token representing staked ETH in the Renzo protocol.
 *
 * Known vulnerabilities in liquid staking tokens:
 * - Share price manipulation via donation attacks
 * - Reentrancy in deposit/withdrawal flows
 * - Front-running of share price updates
 * - Oracle manipulation for exchange rates
 * - Improper validation of deposit amounts
 * - Missing access control on minting functions
 * - Integer overflow in share calculations
 */
contract EzEthToken {

    // State variables
    string public name = "Renzo Restaked ETH";
    string public symbol = "ezETH";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Restaking state
    uint256 public totalAssets;
    address public operator;
    bool public paused;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 assets, uint256 shares);

    modifier onlyOperator() {
        require(msg.sender == operator, "Not operator");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor() {
        operator = msg.sender;
    }

    /**
     * @notice Deposit ETH and receive ezETH shares
     * VULNERABLE: No minimum share check (inflation attack)
     * VULNERABLE: Reentrancy via external call
     * VULNERABLE: Missing validation of total supply
     */
    function deposit() external payable whenNotPaused returns (uint256 shares) {
        require(msg.value > 0, "Zero deposit");

        // VULNERABLE: Division before multiplication (precision loss)
        // VULNERABLE: First depositor can inflate share price
        if (totalSupply == 0) {
            shares = msg.value; // VULNERABLE: No minimum shares check
        } else {
            shares = (msg.value * totalSupply) / totalAssets; // VULNERABLE: Donation attack
        }

        // VULNERABLE: State update after potential revert conditions
        totalAssets += msg.value;
        totalSupply += shares;
        balanceOf[msg.sender] += shares;

        emit Deposit(msg.sender, msg.value, shares);
        emit Transfer(address(0), msg.sender, shares);
    }

    /**
     * @notice Withdraw ETH by burning ezETH shares
     * VULNERABLE: Reentrancy vulnerability
     * VULNERABLE: No slippage protection
     * VULNERABLE: State updates after external call
     */
    function withdraw(uint256 shares) external whenNotPaused returns (uint256 assets) {
        require(shares > 0, "Zero shares");
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");

        // Calculate assets to return
        assets = (shares * totalAssets) / totalSupply; // VULNERABLE: No slippage check

        // VULNERABLE: External call before state update (reentrancy)
        (bool success, ) = msg.sender.call{value: assets}("");
        require(success, "Transfer failed");

        // State updates after external call
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;

        emit Withdraw(msg.sender, assets, shares);
        emit Transfer(msg.sender, address(0), shares);
    }

    /**
     * @notice Transfer tokens
     * VULNERABLE: No validation of recipient address
     * VULNERABLE: Missing check for zero address
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        // VULNERABLE: No zero address check
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount; // VULNERABLE: Can transfer to zero address

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Approve spender
     * VULNERABLE: Classic ERC20 approve race condition
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        // VULNERABLE: Approve race condition
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfer from approved address
     * VULNERABLE: No validation of addresses
     * VULNERABLE: Unchecked allowance manipulation
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @notice Operator mints shares directly
     * VULNERABLE: Centralization risk - operator can mint unlimited tokens
     * VULNERABLE: No validation of recipient or amount
     */
    function operatorMint(address to, uint256 shares) external onlyOperator {
        // VULNERABLE: No cap on total supply
        totalSupply += shares;
        balanceOf[to] += shares;

        emit Transfer(address(0), to, shares);
    }

    /**
     * @notice Update total assets (for rebasing)
     * VULNERABLE: Operator can manipulate share price
     * VULNERABLE: No validation of new value
     * VULNERABLE: Front-running opportunity
     */
    function updateTotalAssets(uint256 newTotal) external onlyOperator {
        // VULNERABLE: No validation, no slippage limits
        totalAssets = newTotal;
    }

    /**
     * @notice Pause the contract
     * VULNERABLE: Centralization - operator can permanently lock funds
     */
    function pause() external onlyOperator {
        paused = true;
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyOperator {
        paused = false;
    }

    /**
     * @notice Get share price
     * VULNERABLE: View function can return manipulated data during reentrancy
     * VULNERABLE: Division by zero if totalSupply is 0
     */
    function getSharePrice() external view returns (uint256) {
        if (totalSupply == 0) {
            return 1e18; // VULNERABLE: Arbitrary initial price
        }
        return (totalAssets * 1e18) / totalSupply; // VULNERABLE: Can be manipulated
    }

    /**
     * @notice Convert assets to shares
     * VULNERABLE: Can be manipulated via totalAssets manipulation
     */
    function convertToShares(uint256 assets) external view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }
        return (assets * totalSupply) / totalAssets;
    }

    /**
     * @notice Convert shares to assets
     * VULNERABLE: Can be manipulated via totalAssets manipulation
     */
    function convertToAssets(uint256 shares) external view returns (uint256) {
        if (totalSupply == 0) {
            return 0;
        }
        return (shares * totalAssets) / totalSupply;
    }

    // Allow contract to receive ETH
    receive() external payable {
        // VULNERABLE: Anyone can donate ETH to manipulate share price
        totalAssets += msg.value;
    }
}
