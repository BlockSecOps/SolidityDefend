// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title UncheckedReturn
 * @notice Test contract for SolidityDefend - Unchecked Return Values
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. unchecked-low-level-call - Line 22: call() return not checked
 * 2. unchecked-low-level-call - Line 30: delegatecall() return not checked
 * 3. unchecked-transfer - Line 38: transfer to contract that may reject
 *
 * TEST CATEGORY: simple
 * SEVERITY: high
 * REFERENCE: CWE-252 (Unchecked Return Value)
 */
contract UncheckedReturn {
    mapping(address => uint256) public balances;

    // VULNERABILITY 1: Unchecked call() Return Value
    // Expected: unchecked-low-level-call (HIGH)
    function sendFunds(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        // Return value not checked - transfer could fail silently
        recipient.call{value: amount}("");
    }

    // VULNERABILITY 2: Unchecked delegatecall() Return Value
    // Expected: unchecked-low-level-call (CRITICAL)
    function executeCode(address target, bytes memory data) public {
        // Delegatecall without checking return value
        target.delegatecall(data);
    }

    // VULNERABILITY 3: Transfer that may fail
    // Expected: unchecked-transfer or dos-failed-transfer (HIGH)
    function distribute(address[] memory recipients, uint256 amount) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            // If one transfer fails, all subsequent transfers fail
            payable(recipients[i]).transfer(amount);
        }
    }

    // VULNERABILITY 4: Unchecked ERC20 transfer
    // Expected: unchecked-erc20-transfer (HIGH)
    function transferToken(address token, address to, uint256 amount) public {
        // ERC20 transfer return value not checked
        (bool success,) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        // success not checked
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
