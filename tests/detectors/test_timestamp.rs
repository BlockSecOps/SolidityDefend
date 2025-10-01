use parser::arena::ArenaParser;
use detectors::{DetectorRegistry, AnalysisContext};
use semantic::SymbolTable;

/// Test timestamp dependence vulnerability detectors
/// These tests are designed to FAIL initially until the detectors are implemented

#[cfg(test)]
mod test_timestamp_detectors {
    use super::*;

    fn setup_test_contract(source: &str) -> (ArenaParser, AnalysisContext) {
        let mut parser = ArenaParser::new();
        let contract = parser.parse_contract(source, "test.sol").unwrap();
        let symbols = SymbolTable::new();
        let ctx = AnalysisContext::new(contract, symbols, source.to_string(), "test.sol".to_string());
        (parser, ctx)
    }

    #[test]
    #[should_panic(expected = "detector not found: timestamp-manipulation")]
    fn test_block_timestamp_manipulation_vulnerability() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableTimestamp {
    uint256 public deadline;
    mapping(address => uint256) public commitments;
    mapping(address => uint256) public rewards;

    // Vulnerable: Uses block.timestamp for critical logic
    function commitWithTimestamp(uint256 amount) external {
        require(block.timestamp < deadline, "Deadline passed");
        require(block.timestamp > 0, "Invalid timestamp"); // Redundant and vulnerable

        commitments[msg.sender] = amount;

        // Vulnerable: reward calculation based on timestamp
        uint256 timeBonus = (deadline - block.timestamp) * 100;
        rewards[msg.sender] = amount + timeBonus;
    }

    // Vulnerable: Uses block.timestamp for random number generation
    function generateRandomReward() external returns (uint256) {
        uint256 randomSeed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));

        uint256 reward = randomSeed % 1000;
        rewards[msg.sender] += reward;

        return reward;
    }

    // Vulnerable: Time-based access control
    function withdrawAfterDelay(uint256 amount) external {
        require(
            block.timestamp >= commitments[msg.sender] + 1 days,
            "Withdrawal delay not met"
        );

        // Vulnerable to miner manipulation
        require(block.timestamp % 2 == 0, "Can only withdraw on even timestamps");

        payable(msg.sender).transfer(amount);
    }

    // Vulnerable: Short time windows
    function flashSale() external payable {
        // 15-second window vulnerable to manipulation
        require(
            block.timestamp % 60 < 15,
            "Flash sale not active"
        );

        uint256 discount = 50; // 50% discount
        uint256 price = msg.value * (100 - discount) / 100;

        // Process sale...
    }

    // Vulnerable: Using now keyword (alias for block.timestamp)
    function checkExpiry(uint256 expiryTime) external view returns (bool) {
        return now > expiryTime; // 'now' is deprecated and vulnerable
    }

    // Vulnerable: Block number as time proxy
    function timeBasedOnBlocks() external view returns (bool) {
        // Assumes block time, vulnerable to manipulation
        uint256 estimatedTime = block.number * 15; // 15 seconds per block assumption
        return estimatedTime > deadline;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because timestamp manipulation detector is not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. block.timestamp usage in critical logic
        // 2. Timestamp-based randomness
        // 3. Short time windows
        // 4. Deprecated 'now' usage
        // 5. Block number as time proxy
        assert!(!findings.is_empty(), "Should detect timestamp manipulation vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: timestamp-manipulation")]
    fn test_block_difficulty_manipulation() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBlockData {
    mapping(address => uint256) public stakes;
    mapping(address => bool) public winners;

    // Vulnerable: Uses block.difficulty for randomness
    function participateInLottery() external payable {
        require(msg.value >= 0.1 ether, "Minimum stake required");

        stakes[msg.sender] += msg.value;

        // Vulnerable randomness based on block properties
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(
            block.difficulty,
            block.timestamp,
            block.coinbase,
            block.gaslimit
        )));

        // Winner determination vulnerable to miner manipulation
        if (randomNumber % 10 == 0) {
            winners[msg.sender] = true;
        }
    }

    // Vulnerable: Multiple block properties for "randomness"
    function advancedRandom() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.difficulty,
            block.timestamp,
            block.number,
            blockhash(block.number - 1),
            msg.sender
        )));
    }

    // Vulnerable: Difficulty-based game mechanics
    function difficultyBasedReward() external view returns (uint256) {
        // Reward based on mining difficulty - manipulable
        uint256 baseReward = 100;
        uint256 difficultyMultiplier = block.difficulty / 1e15;

        return baseReward * difficultyMultiplier;
    }

    // Vulnerable: Block hash dependency
    function blockHashRandom() external view returns (uint256) {
        // Using recent block hash for randomness
        bytes32 hash = blockhash(block.number - 1);
        return uint256(hash) % 1000;
    }

    // Vulnerable: Coinbase address usage
    function minerBasedLogic() external view returns (bool) {
        // Logic based on miner address - easily manipulated by miner
        return uint256(uint160(block.coinbase)) % 2 == 0;
    }

    // Vulnerable: Gas limit dependency
    function gasLimitBasedReward() external view returns (uint256) {
        // Reward calculation based on block gas limit
        return (block.gaslimit / 1000000) * 10;
    }

    // Multiple vulnerable patterns combined
    function multipleBlockDependencies() external {
        require(block.timestamp > 0, "Invalid block");
        require(block.difficulty > 0, "Invalid difficulty");
        require(block.number > 0, "Invalid block number");

        // Complex vulnerable calculation
        uint256 score = (block.timestamp + block.difficulty + block.number) % 1000;

        if (score > 500) {
            // Reward logic...
        }
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because timestamp manipulation detector is not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. block.difficulty usage
        // 2. block.coinbase dependency
        // 3. block.gaslimit usage
        // 4. blockhash() dependency
        // 5. Combined block property vulnerabilities
        assert!(!findings.is_empty(), "Should detect block data manipulation vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: timestamp-manipulation")]
    fn test_time_window_attacks() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableTimeWindows {
    uint256 public auctionStart;
    uint256 public auctionEnd;
    mapping(address => uint256) public bids;
    address public highestBidder;
    uint256 public highestBid;

    constructor() {
        auctionStart = block.timestamp;
        auctionEnd = block.timestamp + 1 hours;
    }

    // Vulnerable: Precise time window check
    function placeBid() external payable {
        require(
            block.timestamp >= auctionStart && block.timestamp <= auctionEnd,
            "Auction not active"
        );

        require(msg.value > highestBid, "Bid too low");

        bids[msg.sender] = msg.value;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    // Vulnerable: Last-minute bidding window
    function lastMinuteBid() external payable {
        // 60-second window before auction end
        require(
            block.timestamp > auctionEnd - 60 && block.timestamp <= auctionEnd,
            "Not in last minute window"
        );

        // Vulnerable to timestamp manipulation for unfair advantage
        require(msg.value > highestBid * 110 / 100, "Must bid 10% higher");

        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    // Vulnerable: Time-based state transitions
    function checkAuctionPhase() external view returns (string memory) {
        if (block.timestamp < auctionStart) {
            return "Not started";
        } else if (block.timestamp <= auctionEnd) {
            return "Active";
        } else if (block.timestamp <= auctionEnd + 1 days) {
            return "Grace period";
        } else {
            return "Ended";
        }
    }

    // Vulnerable: Time-sensitive operations
    function emergencyWithdraw() external {
        require(
            block.timestamp > auctionEnd + 7 days,
            "Emergency period not reached"
        );

        // Emergency withdrawal logic
        payable(msg.sender).transfer(bids[msg.sender]);
    }

    // Vulnerable: Hourly rewards
    function claimHourlyReward() external {
        uint256 currentHour = block.timestamp / 3600;
        uint256 lastClaimHour = lastClaimed[msg.sender] / 3600;

        require(currentHour > lastClaimHour, "Already claimed this hour");

        lastClaimed[msg.sender] = block.timestamp;
        // Reward logic...
    }

    mapping(address => uint256) public lastClaimed;

    // Vulnerable: Daily reset mechanism
    function dailyReset() external {
        uint256 currentDay = block.timestamp / 86400;
        uint256 lastResetDay = lastReset / 86400;

        if (currentDay > lastResetDay) {
            // Reset daily state
            delete highestBidder;
            highestBid = 0;
            lastReset = block.timestamp;
        }
    }

    uint256 public lastReset;
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because timestamp manipulation detector is not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Precise time window vulnerabilities
        // 2. Last-minute window manipulation
        // 3. Time-based state transitions
        // 4. Hourly/daily timing dependencies
        // 5. Emergency time-based access
        assert!(!findings.is_empty(), "Should detect time window attack vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: timestamp-manipulation")]
    fn test_randomness_timestamp_dependency() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableRandomness {
    mapping(address => uint256) public scores;
    mapping(address => bool) public claimed;

    // Vulnerable: Predictable pseudo-randomness
    function rollDice() external returns (uint256) {
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            msg.sender,
            block.difficulty
        ))) % 6 + 1;

        scores[msg.sender] = random;
        return random;
    }

    // Vulnerable: Weak randomness for critical decisions
    function distributePrizes() external {
        require(!claimed[msg.sender], "Already claimed");

        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.number
        )));

        uint256 prizeLevel = seed % 100;

        if (prizeLevel < 1) {
            // Grand prize - 1% chance
            payable(msg.sender).transfer(10 ether);
        } else if (prizeLevel < 10) {
            // Major prize - 9% chance
            payable(msg.sender).transfer(1 ether);
        } else if (prizeLevel < 50) {
            // Minor prize - 40% chance
            payable(msg.sender).transfer(0.1 ether);
        }

        claimed[msg.sender] = true;
    }

    // Vulnerable: Timestamp-based seed rotation
    function getRotatingSeed() external view returns (uint256) {
        // Seed changes every minute - predictable
        uint256 timeWindow = block.timestamp / 60;
        return uint256(keccak256(abi.encodePacked(timeWindow, block.difficulty)));
    }

    // Vulnerable: Game outcome based on timing
    function playTimingGame() external payable returns (bool) {
        require(msg.value >= 0.01 ether, "Minimum bet required");

        // Win if timestamp is divisible by 3
        bool winner = (block.timestamp % 3) == 0;

        if (winner) {
            payable(msg.sender).transfer(msg.value * 2);
            return true;
        }

        return false;
    }

    // Vulnerable: Committee selection based on timestamp
    function selectCommitteeMembers(address[] memory candidates)
        external view returns (address[] memory) {

        uint256 seed = block.timestamp;
        address[] memory selected = new address[](3);

        for (uint i = 0; i < 3; i++) {
            uint256 index = uint256(keccak256(abi.encodePacked(seed, i))) % candidates.length;
            selected[i] = candidates[index];
        }

        return selected;
    }

    // Vulnerable: Auction winner selection
    function selectAuctionWinner(uint256 totalBids) external view returns (uint256) {
        // Winner selection based on timestamp - predictable
        uint256 winningNumber = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            totalBids
        ))) % totalBids;

        return winningNumber;
    }

    // Multiple vulnerable randomness patterns
    function complexRandomLogic() external view returns (uint256) {
        uint256 a = block.timestamp % 7;
        uint256 b = block.number % 11;
        uint256 c = block.difficulty % 13;

        return uint256(keccak256(abi.encodePacked(a, b, c))) % 1000;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because timestamp manipulation detector is not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Predictable pseudo-randomness
        // 2. Timestamp-based game outcomes
        // 3. Weak seed generation
        // 4. Critical decision randomness flaws
        // 5. Committee/winner selection vulnerabilities
        assert!(!findings.is_empty(), "Should detect randomness timestamp dependencies");
    }

    #[test]
    #[should_panic(expected = "detector not found: timestamp-manipulation")]
    fn test_secure_timestamp_usage() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

contract SecureTimestampUsage is VRFConsumerBase {
    uint256 public constant TIME_BUFFER = 900; // 15-minute buffer
    uint256 public auctionEnd;
    bytes32 internal keyHash;
    uint256 internal fee;
    mapping(address => uint256) public commitments;

    constructor() VRFConsumerBase(
        0xdD3782915140c8f3b190B5D67eAc6dc5760C46E9, // VRF Coordinator
        0xa36085F69e2889c224210F603D836748e7dC0088  // LINK Token
    ) {
        keyHash = 0x6c3699283bda56ad74f6b855546325b68d482e983852a7a82979cc4807b641f4;
        fee = 0.1 * 10 ** 18; // 0.1 LINK
    }

    // Secure: Uses time buffers and external randomness
    function secureCommitReveal(bytes32 commitment) external {
        // Use time buffer to prevent last-block manipulation
        require(
            block.timestamp <= auctionEnd - TIME_BUFFER,
            "Too close to deadline"
        );

        commitments[msg.sender] = uint256(commitment);
    }

    // Secure: External oracle for randomness
    function requestRandomness() external returns (bytes32 requestId) {
        require(LINK.balanceOf(address(this)) >= fee, "Not enough LINK");
        return requestRandomness(keyHash, fee);
    }

    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
        // Use truly random value from Chainlink VRF
        uint256 winner = randomness % totalParticipants;
        // Process winner...
    }

    uint256 public totalParticipants;

    // Secure: Relative time checks with buffers
    function secureTimeCheck(uint256 userDeadline) external view returns (bool) {
        // Use relative time with reasonable buffer
        return block.timestamp >= userDeadline + TIME_BUFFER;
    }

    // Secure: Avoid precise timestamp dependencies
    function approxTimeCheck() external view returns (bool) {
        // Use block ranges instead of precise timestamps
        uint256 blockRange = block.number / 100; // ~15 minute ranges
        return blockRange > targetBlockRange;
    }

    uint256 public targetBlockRange;

    // Secure: External time oracle (example)
    function useExternalTimeOracle() external view returns (uint256) {
        // Would integrate with external time oracle for critical operations
        // return timeOracle.getCurrentTime();
        return block.timestamp; // Fallback
    }

    // Secure: Commit-reveal with proper timing
    function revealCommitment(
        uint256 value,
        uint256 nonce
    ) external {
        bytes32 commitment = keccak256(abi.encodePacked(value, nonce, msg.sender));
        require(commitments[msg.sender] == uint256(commitment), "Invalid reveal");

        // Process revealed value...
        delete commitments[msg.sender];
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because detectors are not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should NOT detect vulnerabilities in this secure contract
        assert!(findings.is_empty(), "Should not detect vulnerabilities in secure contract");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because detectors are not implemented yet
        let detector = registry.get_detector("timestamp-manipulation").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should NOT detect vulnerabilities in this secure contract
        assert!(findings.is_empty(), "Should not detect vulnerabilities in secure contract");
    }
}