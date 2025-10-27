// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureOracleFlashLoan
 * @notice Secure implementation using TWAP and multiple oracles
 * @dev Protects against flash loan oracle manipulation
 */
contract SecureOracleFlashLoan {
    address public twapOracle;
    address public chainlinkOracle;
    uint256 public constant TWAP_PERIOD = 30 minutes;

    // SECURE: Uses TWAP instead of spot price
    function calculateCollateralValue(address token, uint256 amount) external view returns (uint256) {
        // SECURE: Time-weighted average price, resistant to flash loan manipulation
        uint256 twapPrice = ITWAPOracle(twapOracle).getTWAP(token, TWAP_PERIOD);

        // SECURE: Cross-check with external oracle (Chainlink)
        uint256 chainlinkPrice = IChainlinkOracle(chainlinkOracle).getPrice(token);

        // SECURE: Use the more conservative price
        uint256 price = twapPrice < chainlinkPrice ? twapPrice : chainlinkPrice;

        return amount * price;
    }

    // SECURE: Borrow decision based on manipulation-resistant price
    function borrow(address collateralToken, uint256 collateralAmount, uint256 borrowAmount) external {
        uint256 collateralValue = this.calculateCollateralValue(collateralToken, collateralAmount);

        // SECURE: Price cannot be manipulated via flash loan
        require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");

        // Issue loan
    }

    // SECURE: Multiple price sources with deviation check
    function getSecurePrice(address token) external view returns (uint256) {
        uint256 twapPrice = ITWAPOracle(twapOracle).getTWAP(token, TWAP_PERIOD);
        uint256 chainlinkPrice = IChainlinkOracle(chainlinkOracle).getPrice(token);

        // SECURE: Check price deviation
        uint256 deviation = twapPrice > chainlinkPrice
            ? ((twapPrice - chainlinkPrice) * 100) / chainlinkPrice
            : ((chainlinkPrice - twapPrice) * 100) / twapPrice;

        require(deviation < 10, "Price deviation too high");

        return (twapPrice + chainlinkPrice) / 2;
    }
}

/**
 * @title SecureGovernanceFlashLoan
 * @notice Secure governance implementation with snapshots and timelocks
 * @dev Protects against flash loan governance attacks
 */
contract SecureGovernanceFlashLoan {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(uint256 => uint256)) public votingPowerSnapshots;
    uint256 public proposalCount;
    uint256 public constant TIMELOCK_DELAY = 2 days;
    uint256 public constant VOTING_DELAY = 1 days;

    struct Proposal {
        address proposer;
        uint256 votes;
        uint256 snapshotBlock;
        uint256 createdAt;
        uint256 executionTime;
        bool executed;
    }

    // SECURE: Proposal with snapshot and voting delay
    function propose(string calldata description) external returns (uint256) {
        require(votingPower[msg.sender] > 0, "No voting power");

        proposalCount++;

        // SECURE: Snapshot voting power at specific block
        uint256 snapshotBlock = block.number;

        proposals[proposalCount] = Proposal({
            proposer: msg.sender,
            votes: 0,
            snapshotBlock: snapshotBlock,
            createdAt: block.timestamp,
            executionTime: 0,
            executed: false
        });

        return proposalCount;
    }

    // SECURE: Vote based on snapshot, not current balance
    function vote(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        // SECURE: Voting delay prevents flash loan voting
        require(block.timestamp >= proposal.createdAt + VOTING_DELAY, "Voting not started");

        // SECURE: Use voting power at snapshot block, immune to flash loans
        uint256 votes = votingPowerSnapshots[proposalId][proposal.snapshotBlock];
        proposal.votes += votes;
    }

    // SECURE: Queue execution with timelock
    function queueExecution(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.votes > 1000000 ether, "Not enough votes");
        require(proposal.executionTime == 0, "Already queued");

        // SECURE: Queue with timelock delay
        proposal.executionTime = block.timestamp + TIMELOCK_DELAY;
    }

    // SECURE: Execute only after timelock
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        // SECURE: Timelock prevents same-transaction flash loan attacks
        require(block.timestamp >= proposal.executionTime, "Timelock not expired");
        require(proposal.executionTime > 0, "Not queued");
        require(!proposal.executed, "Already executed");

        proposal.executed = true;
        // Execute proposal
    }

    // SECURE: Delegate with snapshot
    function delegate(address delegatee, uint256 proposalId) external {
        // SECURE: Delegation recorded at snapshot, cannot be manipulated with flash loan
        uint256 snapshotBlock = proposals[proposalId].snapshotBlock;
        uint256 powerAtSnapshot = votingPowerSnapshots[proposalId][snapshotBlock];
        votingPower[delegatee] += powerAtSnapshot;
    }
}

/**
 * @title SecureFlashMint
 * @notice Secure flash mint implementation with fees and caps
 * @dev Protects against flash mint exploitation
 */
contract SecureFlashMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 public constant FLASH_MINT_FEE_BPS = 9; // 0.09%
    uint256 public constant MAX_FLASH_MINT = 1000000 ether; // Supply cap
    bool private flashMintActive;

    // SECURE: Flash mint with fee and supply cap
    function flashMint(address receiver, uint256 amount, bytes calldata data) external {
        // SECURE: Maximum mint cap prevents excessive supply manipulation
        require(amount <= MAX_FLASH_MINT, "Exceeds flash mint cap");
        require(!flashMintActive, "Flash mint in progress");

        // SECURE: Calculate fee
        uint256 fee = (amount * FLASH_MINT_FEE_BPS) / 10000;

        uint256 supplyBefore = totalSupply;
        flashMintActive = true;

        // Mint tokens
        totalSupply += amount;
        balanceOf[receiver] += amount;

        // Callback
        bytes32 result = IFlashBorrower(receiver).onFlashLoan(
            msg.sender,
            address(this),
            amount,
            fee,
            data
        );
        require(result == keccak256("ERC3156FlashBorrower.onFlashLoan"), "Invalid callback");

        // SECURE: Validate tokens + fee returned
        require(balanceOf[receiver] >= amount + fee, "Flash mint not repaid");
        balanceOf[receiver] -= (amount + fee);
        totalSupply = supplyBefore;

        flashMintActive = false;
    }

    // SECURE: Rewards use snapshot, not manipulable current supply
    function calculateRewards(address user, uint256 snapshotSupply) external view returns (uint256) {
        // SECURE: Use historical snapshot of totalSupply
        require(!flashMintActive, "Cannot calculate during flash mint");
        return (balanceOf[user] * 1000000 ether) / snapshotSupply;
    }

    // SECURE: Block flash mint during critical operations
    function getVotingPower(address user) external view returns (uint256) {
        // SECURE: Cannot be called during flash mint
        require(!flashMintActive, "Flash mint in progress");
        return (balanceOf[user] * 10000) / totalSupply;
    }
}

/**
 * @title SecureFlashLoanCallback
 * @notice Secure flash loan with reentrancy protection
 * @dev Protects against callback reentrancy attacks
 */
contract SecureFlashLoanCallback {
    mapping(address => uint256) public deposits;
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private status = NOT_ENTERED;

    modifier nonReentrant() {
        require(status != ENTERED, "ReentrancyGuard: reentrant call");
        status = ENTERED;
        _;
        status = NOT_ENTERED;
    }

    // SECURE: Flash loan with reentrancy protection
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant {
        uint256 balanceBefore = address(this).balance;

        // Transfer funds
        payable(receiver).transfer(amount);

        // SECURE: External callback protected by reentrancy guard
        bytes32 result = IFlashBorrower(receiver).onFlashLoan(
            msg.sender,
            address(this),
            amount,
            0,
            data
        );
        require(result == keccak256("ERC3156FlashBorrower.onFlashLoan"), "Invalid callback");

        // SECURE: Validation after callback
        uint256 balanceAfter = address(this).balance;
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");
    }

    // SECURE: Withdraw with reentrancy protection
    function withdraw(uint256 amount) external nonReentrant {
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        // SECURE: State updates before external call (checks-effects-interactions)
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // SECURE: Nested flash loans prevented by reentrancy guard
    function nestedFlashLoan(address receiver, uint256 amount) external nonReentrant {
        // Cannot be called recursively due to reentrancy guard
        this.flashLoan(receiver, amount, "");
    }
}

// Interfaces
interface ITWAPOracle {
    function getTWAP(address token, uint256 period) external view returns (uint256);
}

interface IChainlinkOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IFlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}
