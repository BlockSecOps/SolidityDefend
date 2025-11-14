// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MissingCommitRevealSafe - Secure Patterns
 * @notice SECURE: Operations with proper commit-reveal pattern
 * @dev This contract demonstrates secure patterns for operations requiring
 *      commit-reveal to prevent front-running and manipulation.
 *
 * Security Features:
 * - Proper commit-reveal for auctions
 * - Proper commit-reveal for voting
 * - Chainlink VRF for randomness
 * - Time delays between commit and reveal
 * - Nonces/salts to prevent replay
 * - Expiration deadlines
 */

/**
 * @notice SECURE: Chainlink VRF for randomness
 * @dev Uses Chainlink VRF instead of block data
 */
contract SecureRandomNumber {
    // Mock Chainlink VRF interface
    address public vrfCoordinator;
    uint256 public lastRandomNumber;

    constructor(address _vrfCoordinator) {
        vrfCoordinator = _vrfCoordinator;
    }

    /**
     * @notice SECURE: Uses Chainlink VRF
     * @dev Proper on-chain randomness
     */
    function requestRandomNumber() external {
        // SECURE: Request from Chainlink VRF
        // (simplified - actual implementation would use VRFConsumerBase)
        // vrfCoordinator.requestRandomWords();
    }

    /**
     * @notice SECURE: Callback from VRF
     */
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal {
        // SECURE: Randomness provided by Chainlink
        lastRandomNumber = randomWords[0];
    }
}

/**
 * @notice SECURE: Auction with commit-reveal
 * @dev Bids are hidden during commit phase
 */
contract SecureCommitRevealAuction {
    struct Commitment {
        bytes32 commitment;
        uint256 commitTime;
        bool revealed;
        uint256 bidAmount;
    }

    mapping(address => Commitment) public commitments;
    address public highestBidder;
    uint256 public highestBid;

    uint256 public constant REVEAL_DELAY = 1 hours;
    uint256 public constant REVEAL_PERIOD = 24 hours;
    uint256 public auctionEnd;

    constructor(uint256 duration) {
        auctionEnd = block.timestamp + duration;
    }

    /**
     * @notice SECURE: Commit to sealed bid
     * @dev Bid amount hidden with hash(amount, secret)
     */
    function commitBid(bytes32 commitment) external {
        require(block.timestamp < auctionEnd, "Auction ended");

        // SECURE: Store hash, not actual bid
        commitments[msg.sender] = Commitment({
            commitment: commitment,
            commitTime: block.timestamp,
            revealed: false,
            bidAmount: 0
        });
    }

    /**
     * @notice SECURE: Reveal bid after commit period
     * @dev Verify hash matches commitment
     */
    function revealBid(uint256 bidAmount, bytes32 secret) external payable {
        Commitment storage c = commitments[msg.sender];
        require(c.commitment != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // SECURE: Enforce time delay
        require(
            block.timestamp >= c.commitTime + REVEAL_DELAY,
            "Too early to reveal"
        );
        require(
            block.timestamp <= auctionEnd + REVEAL_PERIOD,
            "Reveal period ended"
        );

        // SECURE: Verify commitment matches reveal
        require(
            c.commitment == keccak256(abi.encodePacked(bidAmount, secret, msg.sender)),
            "Invalid reveal"
        );

        require(msg.value >= bidAmount, "Insufficient payment");

        c.revealed = true;
        c.bidAmount = bidAmount;

        if (bidAmount > highestBid) {
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }
            highestBidder = msg.sender;
            highestBid = bidAmount;
        } else {
            payable(msg.sender).transfer(msg.value);
        }
    }
}

/**
 * @notice SECURE: Voting with commit-reveal
 * @dev Votes hidden during commit phase
 */
contract SecureCommitRevealVoting {
    struct VoteCommitment {
        bytes32 commitment;
        uint256 commitTime;
        bool revealed;
    }

    mapping(address => mapping(uint256 => VoteCommitment)) public commitments;
    mapping(uint256 => uint256) public votes; // proposalId => voteCount

    uint256 public constant COMMIT_PHASE = 3 days;
    uint256 public constant REVEAL_PHASE = 1 days;
    uint256 public voteStart;

    constructor() {
        voteStart = block.timestamp;
    }

    /**
     * @notice SECURE: Commit to vote choice
     * @dev Vote choice hidden with hash(choice, secret)
     */
    function commitVote(uint256 proposalId, bytes32 commitment) external {
        require(
            block.timestamp < voteStart + COMMIT_PHASE,
            "Commit phase ended"
        );

        // SECURE: Store hash, not actual vote
        commitments[msg.sender][proposalId] = VoteCommitment({
            commitment: commitment,
            commitTime: block.timestamp,
            revealed: false
        });
    }

    /**
     * @notice SECURE: Reveal vote after commit phase
     */
    function revealVote(
        uint256 proposalId,
        bool choice,
        bytes32 secret
    ) external {
        VoteCommitment storage c = commitments[msg.sender][proposalId];
        require(c.commitment != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // SECURE: Only reveal after commit phase
        require(
            block.timestamp >= voteStart + COMMIT_PHASE,
            "Still in commit phase"
        );
        require(
            block.timestamp < voteStart + COMMIT_PHASE + REVEAL_PHASE,
            "Reveal phase ended"
        );

        // SECURE: Verify commitment
        require(
            c.commitment == keccak256(abi.encodePacked(proposalId, choice, secret, msg.sender)),
            "Invalid reveal"
        );

        c.revealed = true;
        if (choice) {
            votes[proposalId]++;
        }
    }
}

/**
 * @notice SECURE: Price oracle with commit-reveal
 * @dev Price updates hidden during commit phase
 */
contract SecureCommitRevealPriceOracle {
    struct PriceCommitment {
        bytes32 commitment;
        uint256 commitTime;
        bool revealed;
    }

    mapping(address => PriceCommitment) public commitments;
    uint256 public price;
    mapping(address => bool) public isReporter;

    uint256 public constant COMMIT_DELAY = 10 minutes;

    constructor() {
        isReporter[msg.sender] = true;
    }

    /**
     * @notice SECURE: Commit to price update
     */
    function commitPrice(bytes32 commitment) external {
        require(isReporter[msg.sender], "Not reporter");

        // SECURE: Store hash of price
        commitments[msg.sender] = PriceCommitment({
            commitment: commitment,
            commitTime: block.timestamp,
            revealed: false
        });
    }

    /**
     * @notice SECURE: Reveal price after delay
     */
    function revealPrice(uint256 newPrice, bytes32 secret) external {
        PriceCommitment storage c = commitments[msg.sender];
        require(c.commitment != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // SECURE: Enforce time delay
        require(
            block.timestamp >= c.commitTime + COMMIT_DELAY,
            "Too early"
        );

        // SECURE: Verify commitment
        require(
            c.commitment == keccak256(abi.encodePacked(newPrice, secret, msg.sender)),
            "Invalid reveal"
        );

        c.revealed = true;
        price = newPrice;
    }
}

/**
 * @notice SECURE: Rock-Paper-Scissors with commit-reveal
 * @dev Moves hidden until both players commit
 */
contract SecureRockPaperScissors {
    enum Move { Rock, Paper, Scissors }

    struct Game {
        address player1;
        address player2;
        bytes32 commit1;
        bytes32 commit2;
        Move move1;
        Move move2;
        bool revealed1;
        bool revealed2;
        uint256 commitDeadline;
        uint256 revealDeadline;
    }

    mapping(uint256 => Game) public games;
    uint256 public gameCount;

    uint256 public constant COMMIT_PHASE = 1 hours;
    uint256 public constant REVEAL_PHASE = 1 hours;

    /**
     * @notice SECURE: Create game
     */
    function createGame(address player2) external returns (uint256) {
        uint256 gameId = gameCount++;
        games[gameId] = Game({
            player1: msg.sender,
            player2: player2,
            commit1: bytes32(0),
            commit2: bytes32(0),
            move1: Move.Rock,
            move2: Move.Rock,
            revealed1: false,
            revealed2: false,
            commitDeadline: block.timestamp + COMMIT_PHASE,
            revealDeadline: block.timestamp + COMMIT_PHASE + REVEAL_PHASE
        });
        return gameId;
    }

    /**
     * @notice SECURE: Commit to move
     */
    function commitMove(uint256 gameId, bytes32 commitment) external {
        Game storage game = games[gameId];
        require(block.timestamp < game.commitDeadline, "Commit phase ended");

        // SECURE: Store hash of move
        if (msg.sender == game.player1) {
            game.commit1 = commitment;
        } else if (msg.sender == game.player2) {
            game.commit2 = commitment;
        } else {
            revert("Not a player");
        }
    }

    /**
     * @notice SECURE: Reveal move after both commit
     */
    function revealMove(uint256 gameId, Move move, bytes32 secret) external {
        Game storage game = games[gameId];
        require(block.timestamp >= game.commitDeadline, "Still committing");
        require(block.timestamp < game.revealDeadline, "Reveal ended");

        bytes32 commitment = keccak256(abi.encodePacked(move, secret, msg.sender));

        // SECURE: Verify commitment matches
        if (msg.sender == game.player1) {
            require(game.commit1 == commitment, "Invalid reveal");
            game.move1 = move;
            game.revealed1 = true;
        } else if (msg.sender == game.player2) {
            require(game.commit2 == commitment, "Invalid reveal");
            game.move2 = move;
            game.revealed2 = true;
        }
    }
}

/**
 * @notice SECURE: Prediction market with commit-reveal
 */
contract SecurePredictionMarket {
    struct Commitment {
        bytes32 commitment;
        uint256 commitTime;
        bool revealed;
        uint256 outcome;
        uint256 amount;
    }

    mapping(uint256 => mapping(address => Commitment)) public commitments;
    uint256 public constant REVEAL_DELAY = 1 hours;

    /**
     * @notice SECURE: Commit to prediction
     */
    function commitPrediction(uint256 eventId, bytes32 commitment) external payable {
        // SECURE: Store hash of prediction
        commitments[eventId][msg.sender] = Commitment({
            commitment: commitment,
            commitTime: block.timestamp,
            revealed: false,
            outcome: 0,
            amount: msg.value
        });
    }

    /**
     * @notice SECURE: Reveal prediction
     */
    function revealPrediction(
        uint256 eventId,
        uint256 outcome,
        bytes32 secret
    ) external {
        Commitment storage c = commitments[eventId][msg.sender];
        require(c.commitment != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");
        require(
            block.timestamp >= c.commitTime + REVEAL_DELAY,
            "Too early"
        );

        // SECURE: Verify commitment
        require(
            c.commitment == keccak256(abi.encodePacked(eventId, outcome, secret, msg.sender)),
            "Invalid reveal"
        );

        c.revealed = true;
        c.outcome = outcome;
    }
}

/**
 * @notice SECURE: Lottery with VRF
 */
contract SecureLotteryVRF {
    address[] public participants;
    uint256 public ticketPrice = 0.1 ether;
    uint256 public randomSeed;

    function buyTicket() external payable {
        require(msg.value == ticketPrice, "Wrong price");
        participants.push(msg.sender);
    }

    /**
     * @notice SECURE: Uses VRF for randomness
     */
    function selectWinner() external {
        require(participants.length > 0, "No participants");

        // SECURE: Would use Chainlink VRF in production
        // uint256 requestId = vrfCoordinator.requestRandomWords(...);
        // Randomness provided by oracle, not block data
    }

    function fulfillRandomWords(uint256, uint256[] memory randomWords) internal {
        uint256 winnerIndex = randomWords[0] % participants.length;
        address winner = participants[winnerIndex];
        payable(winner).transfer(address(this).balance);
        delete participants;
    }
}

/**
 * @notice SECURE: Proper commit-reveal with all features
 */
contract SecureFullCommitReveal {
    struct Commitment {
        bytes32 commitment;
        uint256 commitTime;
        uint256 nonce;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;
    uint256 public nonce;

    uint256 public constant COMMIT_DURATION = 1 hours;
    uint256 public constant REVEAL_DURATION = 1 hours;
    uint256 public phaseStart;

    /**
     * @notice SECURE: Complete commit-reveal pattern
     */
    function commit(bytes32 commitment) external {
        require(block.timestamp < phaseStart + COMMIT_DURATION, "Commit ended");

        // SECURE: All best practices
        // - Nonce prevents replay
        // - Time-boxed phases
        // - Commitment stored, not value
        commitments[msg.sender] = Commitment({
            commitment: commitment,
            commitTime: block.timestamp,
            nonce: nonce++,
            revealed: false
        });
    }

    /**
     * @notice SECURE: Reveal with full validation
     */
    function reveal(uint256 value, bytes32 secret, uint256 commitNonce) external {
        Commitment storage c = commitments[msg.sender];
        require(c.commitment != bytes32(0), "No commitment");
        require(!c.revealed, "Already revealed");

        // SECURE: Phase validation
        require(
            block.timestamp >= phaseStart + COMMIT_DURATION,
            "Still in commit phase"
        );
        require(
            block.timestamp < phaseStart + COMMIT_DURATION + REVEAL_DURATION,
            "Reveal phase ended"
        );

        // SECURE: Full verification
        require(c.nonce == commitNonce, "Invalid nonce");
        require(
            c.commitment == keccak256(abi.encodePacked(value, secret, msg.sender, commitNonce)),
            "Invalid reveal"
        );

        c.revealed = true;
    }
}
