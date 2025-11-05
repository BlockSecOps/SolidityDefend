// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/**
 * @title Slasher
 * @notice Placeholder contract for EigenLayer Slasher
 * @dev This contract is a minimal placeholder as the full Slasher.sol
 * could not be included in the test suite. The actual Slasher contract
 * handles slashing logic for operators in the EigenLayer protocol.
 *
 * Known vulnerabilities in slashing contracts:
 * - Reentrancy during slashing operations
 * - Unauthorized slashing (access control bypass)
 * - Integer overflow in penalty calculations
 * - Improper validation of slashing evidence
 * - Front-running of slashing transactions
 * - DOS via gas-intensive slashing loops
 */
contract Slasher {

    // State variables
    address public owner;
    mapping(address => uint256) public slashableStakes;
    mapping(address => bool) public isSlashed;

    // Events
    event Slashed(address indexed operator, uint256 amount);
    event SlashingRecorded(address indexed operator, uint256 penalty);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Record slashable stake for an operator
     * @param operator The operator address
     * @param amount The slashable amount
     * VULNERABLE: Missing access control - anyone can record stakes
     */
    function recordStake(address operator, uint256 amount) external {
        slashableStakes[operator] = amount;
    }

    /**
     * @notice Slash an operator's stake
     * @param operator The operator to slash
     * @param slashAmount The amount to slash
     * VULNERABLE: No validation of slashing evidence
     * VULNERABLE: Unchecked arithmetic could overflow
     * VULNERABLE: Missing reentrancy protection
     */
    function slashOperator(address operator, uint256 slashAmount) external onlyOwner {
        require(!isSlashed[operator], "Already slashed");
        require(slashableStakes[operator] >= slashAmount, "Insufficient stake");

        // VULNERABLE: External call before state update (reentrancy)
        (bool success, ) = msg.sender.call{value: slashAmount}("");
        require(success, "Transfer failed");

        // State updates after external call
        slashableStakes[operator] -= slashAmount;
        isSlashed[operator] = true;

        emit Slashed(operator, slashAmount);
    }

    /**
     * @notice Batch slash multiple operators
     * @param operators Array of operators to slash
     * @param amounts Array of amounts to slash
     * VULNERABLE: No array length validation
     * VULNERABLE: Potential DOS via large arrays
     * VULNERABLE: No access control on batch operations
     */
    function batchSlash(address[] calldata operators, uint256[] calldata amounts) external {
        // VULNERABLE: Missing array length check
        for (uint256 i = 0; i < operators.length; i++) {
            address operator = operators[i];
            uint256 amount = amounts[i]; // VULNERABLE: Out of bounds if arrays differ

            if (slashableStakes[operator] >= amount) {
                slashableStakes[operator] -= amount;
                emit SlashingRecorded(operator, amount);
            }
        }
    }

    /**
     * @notice Get slashable stake for operator
     * @param operator The operator address
     * VULNERABLE: View function returns stale data during reentrancy
     */
    function getSlashableStake(address operator) external view returns (uint256) {
        return slashableStakes[operator];
    }

    /**
     * @notice Withdraw slashed funds
     * VULNERABLE: Anyone can withdraw (missing access control)
     * VULNERABLE: Reentrancy vulnerability
     */
    function withdrawSlashedFunds(uint256 amount) external {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    // Allow contract to receive ETH
    receive() external payable {}
}
