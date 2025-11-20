// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IntegerOverflow
 * @notice Test contract for SolidityDefend - Integer Overflow/Underflow
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. unchecked-arithmetic - Line 24: Unchecked addition overflow
 * 2. unchecked-arithmetic - Line 34: Unchecked multiplication overflow
 * 3. unchecked-arithmetic - Line 44: Unchecked subtraction underflow
 *
 * TEST CATEGORY: simple
 * SEVERITY: high
 * REFERENCE: CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)
 */
contract IntegerOverflow {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // VULNERABILITY 1: Unchecked Addition Overflow
    // Expected: unchecked-arithmetic (HIGH)
    function deposit() public payable {
        unchecked {
            // Overflow possible if balance near uint256 max
            balances[msg.sender] += msg.value;
            totalSupply += msg.value;
        }
    }

    // VULNERABILITY 2: Unchecked Multiplication Overflow
    // Expected: unchecked-arithmetic (HIGH)
    function calculateReward(uint256 amount, uint256 multiplier) public pure returns (uint256) {
        unchecked {
            // Overflow possible with large values
            return amount * multiplier;
        }
    }

    // VULNERABILITY 3: Unchecked Subtraction Underflow
    // Expected: unchecked-arithmetic (HIGH)
    function withdraw(uint256 amount) public {
        unchecked {
            // Underflow possible if amount > balance
            balances[msg.sender] -= amount;
            totalSupply -= amount;
        }
        payable(msg.sender).transfer(amount);
    }

    // VULNERABILITY 4: Unchecked Array Index
    // Expected: array-bounds-check (MEDIUM)
    function getBalanceAt(uint256 index) public view returns (uint256) {
        uint256[] memory values = new uint256[](10);
        unchecked {
            // Out of bounds access possible
            return values[index];
        }
    }
}
