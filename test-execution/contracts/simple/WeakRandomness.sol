// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title WeakRandomness
 * @notice Test contract for SolidityDefend - Weak Randomness
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. weak-randomness - Line 23: Using block.timestamp for randomness
 * 2. weak-randomness - Line 31: Using block.number for randomness
 * 3. weak-randomness - Line 39: Using blockhash for randomness
 *
 * TEST CATEGORY: simple
 * SEVERITY: high
 * REFERENCE: CWE-330 (Use of Insufficiently Random Values)
 */
contract WeakRandomness {
    mapping(address => uint256) public balances;

    // VULNERABILITY 1: block.timestamp Randomness
    // Expected: weak-randomness (HIGH)
    function playLottery() public payable returns (bool) {
        require(msg.value == 1 ether, "Must send 1 ETH");

        // Miners can manipulate timestamp
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));

        if (random % 2 == 0) {
            payable(msg.sender).transfer(2 ether);
            return true;
        }
        return false;
    }

    // VULNERABILITY 2: block.number Randomness
    // Expected: weak-randomness (HIGH)
    function randomReward() public view returns (uint256) {
        // Predictable based on block number
        return uint256(keccak256(abi.encodePacked(block.number))) % 100;
    }

    // VULNERABILITY 3: blockhash Randomness
    // Expected: weak-randomness (HIGH)
    function pickWinner(uint256 blockNumber) public view returns (address) {
        // blockhash can be predicted or manipulated
        bytes32 hash = blockhash(blockNumber);
        uint256 random = uint256(hash);
        return address(uint160(random));
    }

    receive() external payable {}
}
