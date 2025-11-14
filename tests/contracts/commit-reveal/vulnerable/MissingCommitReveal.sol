// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MissingCommitReveal - Vulnerable Patterns
 * @notice VULNERABLE: Operations without commit-reveal pattern
 * @dev This contract demonstrates patterns where commit-reveal is needed
 *      but not implemented, allowing front-running and manipulation.
 *
 * Vulnerabilities Demonstrated:
 * 1. Random number generation using block data
 * 2. Auction/bidding with visible bid amounts
 * 3. Voting with immediately visible votes
 * 4. Price oracle updates without commit-reveal
 * 5. Lottery using predictable randomness
 * 6. Rock-paper-scissors with visible moves
 * 7. Sealed bid auction without sealing
 * 8. Prediction market without commitment
 *
 * Attack Vectors:
 * - Front-running bids
 * - Predicting random outcomes
 * - Vote manipulation
 * - Price manipulation
 */

/**
 * @notice VULNERABLE Pattern 1: Random number from block data
 * @dev Miners can manipulate block.timestamp and blockhash
 */
contract VulnerableRandomNumber {
    uint256 public lastWinner;

    /**
     * @notice VULNERABLE: Uses block.timestamp for randomness
     * @dev Miner can manipulate timestamp to influence outcome
     */
    function pickWinner(address[] calldata participants) external {
        // VULNERABLE: Predictable randomness
        uint256 randomIndex = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            participants.length
        ))) % participants.length;

        lastWinner = randomIndex;
    }

    /**
     * @notice VULNERABLE: Uses blockhash for randomness
     */
    function drawLottery(uint256 ticketCount) external returns (uint256) {
        // VULNERABLE: Miners can influence blockhash
        return uint256(blockhash(block.number - 1)) % ticketCount;
    }
}

/**
 * @notice VULNERABLE Pattern 2: Auction without commit-reveal
 * @dev Bid amounts are visible, enabling front-running
 */
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public bids;

    /**
     * @notice VULNERABLE: Bid amount visible in transaction
     * @dev Front-runners can see bid and outbid by 1 wei
     */
    function placeBid() external payable {
        require(msg.value > highestBid, "Bid too low");

        // VULNERABLE: Bid visible before execution
        // Front-runner sees this and submits higher bid first
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        bids[msg.sender] = msg.value;
    }

    /**
     * @notice VULNERABLE: Sealed-bid auction that isn't sealed
     */
    function submitSealedBid(uint256 bidAmount) external payable {
        // VULNERABLE: "Sealed" bid is visible on-chain
        require(msg.value >= bidAmount, "Insufficient payment");
        bids[msg.sender] = bidAmount;
    }
}

/**
 * @notice VULNERABLE Pattern 3: Voting without commit-reveal
 * @dev Votes are immediately visible, enabling manipulation
 */
contract VulnerableVoting {
    mapping(uint256 => uint256) public votes; // proposalId => voteCount
    mapping(address => mapping(uint256 => bool)) public hasVoted;

    /**
     * @notice VULNERABLE: Votes visible immediately
     * @dev Last voters can see current results and vote accordingly
     */
    function vote(uint256 proposalId) external {
        require(!hasVoted[msg.sender][proposalId], "Already voted");

        // VULNERABLE: Vote recorded immediately and visibly
        votes[proposalId]++;
        hasVoted[msg.sender][proposalId] = true;
    }

    /**
     * @notice VULNERABLE: Choice-based voting
     */
    function voteChoice(uint256 proposalId, bool choice) external {
        require(!hasVoted[msg.sender][proposalId], "Already voted");

        // VULNERABLE: Choice visible in transaction
        if (choice) {
            votes[proposalId]++;
        }
        hasVoted[msg.sender][proposalId] = true;
    }
}

/**
 * @notice VULNERABLE Pattern 4: Price oracle without commit-reveal
 * @dev Price updates visible before execution
 */
contract VulnerablePriceOracle {
    uint256 public price;
    mapping(address => bool) public isReporter;

    constructor() {
        isReporter[msg.sender] = true;
    }

    /**
     * @notice VULNERABLE: Price update visible in mempool
     * @dev MEV bots can front-run trades based on visible price update
     */
    function updatePrice(uint256 newPrice) external {
        require(isReporter[msg.sender], "Not authorized");

        // VULNERABLE: New price visible before execution
        // Traders can see update and trade before it's applied
        price = newPrice;
    }

    /**
     * @notice VULNERABLE: Multiple reporters submit prices
     */
    function submitPrice(uint256 reportedPrice) external {
        require(isReporter[msg.sender], "Not reporter");

        // VULNERABLE: Price submission visible
        price = (price + reportedPrice) / 2;
    }
}

/**
 * @notice VULNERABLE Pattern 5: Lottery with weak randomness
 * @dev Uses predictable data for winner selection
 */
contract VulnerableLottery {
    address[] public participants;
    uint256 public ticketPrice = 0.1 ether;

    function buyTicket() external payable {
        require(msg.value == ticketPrice, "Wrong price");
        participants.push(msg.sender);
    }

    /**
     * @notice VULNERABLE: Predictable winner selection
     */
    function selectWinner() external {
        require(participants.length > 0, "No participants");

        // VULNERABLE: Can be predicted and manipulated
        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender,
            participants.length
        ))) % participants.length;

        address winner = participants[winnerIndex];
        payable(winner).transfer(address(this).balance);

        delete participants;
    }
}

/**
 * @notice VULNERABLE Pattern 6: Rock-Paper-Scissors without hiding
 * @dev Moves visible before opponent plays
 */
contract VulnerableRockPaperScissors {
    enum Move { Rock, Paper, Scissors }

    struct Game {
        address player1;
        address player2;
        Move move1;
        Move move2;
        bool player1Moved;
        bool player2Moved;
    }

    mapping(uint256 => Game) public games;
    uint256 public gameCount;

    /**
     * @notice VULNERABLE: Move visible when submitted
     */
    function playMove(uint256 gameId, Move move) external {
        Game storage game = games[gameId];

        // VULNERABLE: Move visible to opponent
        if (msg.sender == game.player1) {
            game.move1 = move;
            game.player1Moved = true;
        } else {
            game.move2 = move;
            game.player2Moved = true;
        }
    }
}

/**
 * @notice VULNERABLE Pattern 7: Prediction market without commitment
 * @dev Predictions visible before event occurs
 */
contract VulnerablePredictionMarket {
    struct Prediction {
        address predictor;
        uint256 outcome;
        uint256 amount;
    }

    mapping(uint256 => Prediction[]) public predictions; // eventId => predictions

    /**
     * @notice VULNERABLE: Prediction visible immediately
     */
    function predict(uint256 eventId, uint256 outcome) external payable {
        // VULNERABLE: Last predictor can see all predictions
        predictions[eventId].push(Prediction({
            predictor: msg.sender,
            outcome: outcome,
            amount: msg.value
        }));
    }
}

/**
 * @notice VULNERABLE Pattern 8: Pseudo-random with msg.sender
 * @dev User can compute hash before calling
 */
contract VulnerablePseudoRandom {
    /**
     * @notice VULNERABLE: User can pre-compute outcome
     */
    function randomReward() external {
        // VULNERABLE: User can compute this before calling
        uint256 random = uint256(keccak256(abi.encodePacked(
            msg.sender,
            block.timestamp
        ))) % 100;

        if (random < 10) {
            // Award prize
        }
    }
}

/**
 * @notice VULNERABLE Pattern 9: Commit without proper reveal
 * @dev Has commitment but no reveal mechanism
 */
contract VulnerableIncompleteCommit {
    mapping(address => bytes32) public commitments;

    /**
     * @notice Has commit but no reveal
     */
    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        // VULNERABLE: No reveal mechanism, commitment is useless
    }

    /**
     * @notice Direct action without reveal phase
     */
    function execute() external {
        // VULNERABLE: Executes without revealing commitment
        require(commitments[msg.sender] != bytes32(0), "No commitment");
    }
}

/**
 * @notice VULNERABLE Pattern 10: Time-based random with insufficient entropy
 * @dev Uses only timestamp for randomness
 */
contract VulnerableTimeRandom {
    /**
     * @notice VULNERABLE: Only timestamp for randomness
     */
    function selectRandomParticipant(address[] calldata participants)
        external
        view
        returns (address)
    {
        // VULNERABLE: Predictable from block.timestamp
        uint256 index = block.timestamp % participants.length;
        return participants[index];
    }
}
