// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bridge {
    modifier onlyTest() {
        _;
    }

    function mint(uint256 amount) external onlyTest {
        // mint logic
    }
}
