// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/**
 * @title RestakeManager
 * @notice Placeholder contract for Renzo Protocol RestakeManager
 * @dev This contract is a minimal placeholder as the full RestakeManager.sol
 * could not be included in the test suite. The actual RestakeManager handles
 * deposits, withdrawals, operator management, and strategy allocations.
 *
 * Known vulnerabilities in restaking managers:
 * - Reentrancy in deposit/withdrawal flows
 * - Oracle manipulation for TVL calculations
 * - Unauthorized operator additions
 * - Missing validation of strategy allocations
 * - Front-running of rebalancing operations
 * - Integer overflow in reward calculations
 * - DOS via large operator/strategy arrays
 * - Missing slippage protection on withdrawals
 */
contract RestakeManager {

    // State variables
    address public owner;
    address public ezETHToken;

    mapping(address => bool) public isOperator;
    mapping(address => bool) public isStrategy;
    mapping(address => uint256) public operatorAllocations;
    mapping(address => uint256) public userDeposits;

    address[] public operators;
    address[] public strategies;

    uint256 public totalValueLocked;
    uint256 public maxDepositLimit;
    bool public paused;

    // Events
    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdraw(address indexed user, uint256 amount, uint256 shares);
    event OperatorAdded(address indexed operator);
    event StrategyAdded(address indexed strategy);
    event Rebalanced(uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor(address _ezETH) {
        owner = msg.sender;
        ezETHToken = _ezETH;
        maxDepositLimit = type(uint256).max; // VULNERABLE: No deposit limits
    }

    /**
     * @notice Deposit ETH and receive ezETH
     * VULNERABLE: Reentrancy via ezETH token interaction
     * VULNERABLE: No minimum deposit amount
     * VULNERABLE: Missing slippage protection
     */
    function deposit() external payable whenNotPaused returns (uint256 shares) {
        require(msg.value > 0, "Zero deposit");
        // VULNERABLE: No maximum deposit check against limit

        // Calculate shares (simplified)
        if (totalValueLocked == 0) {
            shares = msg.value; // VULNERABLE: First depositor attack
        } else {
            // VULNERABLE: Oracle manipulation possible
            shares = (msg.value * getTotalShares()) / totalValueLocked;
        }

        // VULNERABLE: External call before state update
        (bool success, ) = ezETHToken.call(
            abi.encodeWithSignature("mint(address,uint256)", msg.sender, shares)
        );
        require(success, "Mint failed");

        // State updates after external call
        userDeposits[msg.sender] += msg.value;
        totalValueLocked += msg.value;

        emit Deposit(msg.sender, msg.value, shares);
    }

    /**
     * @notice Withdraw ETH by burning ezETH
     * VULNERABLE: Reentrancy vulnerability
     * VULNERABLE: No withdrawal delay/queue
     * VULNERABLE: State updates after external calls
     */
    function withdraw(uint256 shares) external whenNotPaused returns (uint256 amount) {
        require(shares > 0, "Zero shares");

        // Calculate amount to return
        amount = (shares * totalValueLocked) / getTotalShares(); // VULNERABLE: No slippage
        require(address(this).balance >= amount, "Insufficient liquidity");

        // VULNERABLE: External call before state update
        (bool success, ) = ezETHToken.call(
            abi.encodeWithSignature("burn(address,uint256)", msg.sender, shares)
        );
        require(success, "Burn failed");

        // VULNERABLE: Another external call before state update
        (success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State updates after multiple external calls
        userDeposits[msg.sender] -= amount;
        totalValueLocked -= amount;

        emit Withdraw(msg.sender, amount, shares);
    }

    /**
     * @notice Add an operator to the protocol
     * VULNERABLE: No validation of operator address
     * VULNERABLE: No checks for duplicate operators
     * VULNERABLE: DOS via unbounded array growth
     */
    function addOperator(address operator) external onlyOwner {
        // VULNERABLE: No zero address check
        // VULNERABLE: No duplicate check
        isOperator[operator] = true;
        operators.push(operator); // VULNERABLE: Unbounded array

        emit OperatorAdded(operator);
    }

    /**
     * @notice Add a strategy to the protocol
     * VULNERABLE: Similar issues as addOperator
     */
    function addStrategy(address strategy) external onlyOwner {
        // VULNERABLE: No validation
        isStrategy[strategy] = true;
        strategies.push(strategy); // VULNERABLE: Unbounded array

        emit StrategyAdded(strategy);
    }

    /**
     * @notice Allocate funds to an operator
     * VULNERABLE: No validation of allocation amount
     * VULNERABLE: No check if operator exists
     * VULNERABLE: Reentrancy via operator interaction
     */
    function allocateToOperator(address operator, uint256 amount) external onlyOwner {
        // VULNERABLE: No validation that operator is registered
        require(address(this).balance >= amount, "Insufficient balance");

        // VULNERABLE: External call before state update
        (bool success, ) = operator.call{value: amount}("");
        require(success, "Allocation failed");

        // State update after external call
        operatorAllocations[operator] += amount;
    }

    /**
     * @notice Rebalance allocations across operators
     * VULNERABLE: DOS via large operator array
     * VULNERABLE: No slippage protection
     * VULNERABLE: Front-running opportunity
     * VULNERABLE: Unbounded loop
     */
    function rebalance() external onlyOwner {
        // VULNERABLE: Unbounded loop over operators array
        for (uint256 i = 0; i < operators.length; i++) {
            address operator = operators[i];
            uint256 targetAllocation = totalValueLocked / operators.length; // VULNERABLE: Simplified
            uint256 currentAllocation = operatorAllocations[operator];

            if (targetAllocation > currentAllocation) {
                uint256 toAllocate = targetAllocation - currentAllocation;
                // VULNERABLE: Multiple external calls in loop
                (bool success, ) = operator.call{value: toAllocate}("");
                if (success) {
                    operatorAllocations[operator] = targetAllocation;
                }
            }
        }

        emit Rebalanced(block.timestamp);
    }

    /**
     * @notice Calculate total TVL including operator allocations
     * VULNERABLE: DOS via large arrays
     * VULNERABLE: No caching, expensive computation
     */
    function calculateTotalTVL() external view returns (uint256 total) {
        total = address(this).balance;

        // VULNERABLE: Unbounded loop
        for (uint256 i = 0; i < operators.length; i++) {
            total += operatorAllocations[operators[i]];
        }

        // VULNERABLE: Unbounded loop
        for (uint256 i = 0; i < strategies.length; i++) {
            // VULNERABLE: External view call in loop (DOS risk)
            (bool success, bytes memory data) = strategies[i].staticcall(
                abi.encodeWithSignature("getTVL()")
            );
            if (success && data.length >= 32) {
                total += abi.decode(data, (uint256));
            }
        }
    }

    /**
     * @notice Get total shares from ezETH token
     * VULNERABLE: External call to potentially malicious contract
     * VULNERABLE: No validation of return value
     */
    function getTotalShares() public view returns (uint256) {
        (bool success, bytes memory data) = ezETHToken.staticcall(
            abi.encodeWithSignature("totalSupply()")
        );
        if (success && data.length >= 32) {
            return abi.decode(data, (uint256));
        }
        return 1e18; // VULNERABLE: Arbitrary fallback value
    }

    /**
     * @notice Update max deposit limit
     * VULNERABLE: Can be set to 0, preventing deposits
     * VULNERABLE: No minimum value validation
     */
    function setMaxDepositLimit(uint256 newLimit) external onlyOwner {
        // VULNERABLE: No validation
        maxDepositLimit = newLimit;
    }

    /**
     * @notice Pause the protocol
     * VULNERABLE: Centralization - owner can lock all funds
     */
    function pause() external onlyOwner {
        paused = true;
    }

    /**
     * @notice Unpause the protocol
     */
    function unpause() external onlyOwner {
        paused = false;
    }

    /**
     * @notice Emergency withdraw all ETH
     * VULNERABLE: Owner can rug pull all funds
     * VULNERABLE: No timelock or governance
     */
    function emergencyWithdraw() external onlyOwner {
        // VULNERABLE: No restrictions, immediate withdrawal
        uint256 balance = address(this).balance;
        (bool success, ) = owner.call{value: balance}("");
        require(success, "Withdrawal failed");
    }

    /**
     * @notice Get user's deposit value
     * VULNERABLE: Stale data during reentrancy
     */
    function getUserDepositValue(address user) external view returns (uint256) {
        return userDeposits[user];
    }

    /**
     * @notice Get number of operators
     * @dev Informational function
     */
    function getOperatorCount() external view returns (uint256) {
        return operators.length;
    }

    /**
     * @notice Get number of strategies
     * @dev Informational function
     */
    function getStrategyCount() external view returns (uint256) {
        return strategies.length;
    }

    // Allow contract to receive ETH
    receive() external payable {
        // VULNERABLE: Anyone can send ETH directly, affecting TVL calculations
        totalValueLocked += msg.value;
    }

    // Fallback function
    fallback() external payable {
        // VULNERABLE: Accepts arbitrary calls with value
        totalValueLocked += msg.value;
    }
}
