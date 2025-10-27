// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableOracleFlashLoan
 * @notice Test contract vulnerable to flash loan oracle manipulation
 * @dev Should trigger: flashloan-oracle-manipulation detector
 * Exploits: Euler Finance ($197M), Mango Markets ($110M)
 */
contract VulnerableOracleFlashLoan {
    address public priceOracle;

    // VULNERABLE: Uses spot price from oracle without TWAP
    function calculateCollateralValue(address token, uint256 amount) external view returns (uint256) {
        // VULNERABLE: Single price feed susceptible to flash loan manipulation
        uint256 price = IOracle(priceOracle).getPrice(token);
        return amount * price;
    }

    // VULNERABLE: Borrow decision based on manipulable price
    function borrow(address collateralToken, uint256 collateralAmount, uint256 borrowAmount) external {
        uint256 collateralValue = this.calculateCollateralValue(collateralToken, collateralAmount);

        // VULNERABLE: Spot price can be manipulated via flash loan
        require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");

        // Issue loan
    }

    // VULNERABLE: Liquidation using manipulable price
    function liquidate(address borrower, address collateralToken) external {
        uint256 collateralValue = this.calculateCollateralValue(collateralToken, 1000 ether);

        // VULNERABLE: Flash loan can manipulate price to trigger false liquidation
        if (collateralValue < 1500 ether) {
            // Liquidate
        }
    }

    // VULNERABLE: AMM pool reserves used as price oracle
    function getPriceFromPool(address token0, address token1) external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(priceOracle).getReserves();
        // VULNERABLE: Spot price from reserves, no TWAP
        return (reserve1 * 1e18) / reserve0;
    }
}

/**
 * @title VulnerableGovernanceFlashLoan
 * @notice Test contract vulnerable to flash loan governance attacks
 * @dev Should trigger: flashloan-governance-attack detector
 * Exploits: Beanstalk ($182M), Build Finance ($470K)
 */
contract VulnerableGovernanceFlashLoan {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    struct Proposal {
        address proposer;
        uint256 votes;
        bool executed;
    }

    // VULNERABLE: Voting power based on current balance (flash loan exploitable)
    function propose(string calldata description) external returns (uint256) {
        // VULNERABLE: No snapshot of voting power at specific block
        require(votingPower[msg.sender] > 0, "No voting power");

        proposalCount++;
        proposals[proposalCount] = Proposal({
            proposer: msg.sender,
            votes: 0,
            executed: false
        });

        return proposalCount;
    }

    // VULNERABLE: Vote weight based on current balance
    function vote(uint256 proposalId) external {
        // VULNERABLE: Flash loan can be used to inflate voting power
        uint256 votes = IERC20(address(this)).balanceOf(msg.sender);
        proposals[proposalId].votes += votes;
    }

    // VULNERABLE: Instant execution without timelock
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        // VULNERABLE: No timelock delay, can be executed in same transaction as flash loan vote
        require(proposal.votes > 1000000 ether, "Not enough votes");
        require(!proposal.executed, "Already executed");

        proposal.executed = true;
        // Execute proposal
    }

    // VULNERABLE: Delegate votes without snapshot
    function delegate(address delegatee) external {
        // VULNERABLE: Delegation uses current balance, exploitable with flash loan
        votingPower[delegatee] += IERC20(address(this)).balanceOf(msg.sender);
    }
}

/**
 * @title VulnerableFlashMint
 * @notice Test contract vulnerable to flash mint attacks
 * @dev Should trigger: flashloan-flash-mint detector
 */
contract VulnerableFlashMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // VULNERABLE: Unlimited flash mint without fee or supply cap
    function flashMint(address receiver, uint256 amount, bytes calldata data) external {
        // VULNERABLE: No maximum mint cap
        // VULNERABLE: No fee charged
        totalSupply += amount;
        balanceOf[receiver] += amount;

        // Callback
        IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);

        // VULNERABLE: No validation that tokens were actually returned
        totalSupply -= amount;
        balanceOf[receiver] -= amount;
    }

    // VULNERABLE: Rewards calculated from total supply (exploitable via flash mint)
    function calculateRewards(address user) external view returns (uint256) {
        // VULNERABLE: Flash mint inflates totalSupply, manipulating reward calculation
        return (balanceOf[user] * 1000000 ether) / totalSupply;
    }

    // VULNERABLE: Voting power from flash-mintable supply
    function getVotingPower(address user) external view returns (uint256) {
        // VULNERABLE: Flash mint can temporarily inflate voting power
        return (balanceOf[user] * 10000) / totalSupply;
    }
}

/**
 * @title VulnerableFlashLoanCallback
 * @notice Test contract vulnerable to flash loan callback reentrancy
 * @dev Should trigger: flashloan-callback-reentrancy detector
 */
contract VulnerableFlashLoanCallback {
    mapping(address => uint256) public deposits;
    bool private locked;

    // VULNERABLE: Flash loan with callback but no reentrancy protection
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = address(this).balance;

        // Transfer funds
        payable(receiver).transfer(amount);

        // VULNERABLE: External callback without reentrancy guard
        IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);

        // VULNERABLE: State updates after external call
        uint256 balanceAfter = address(this).balance;
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");
    }

    // VULNERABLE: Withdraw function callable during flash loan callback
    function withdraw(uint256 amount) external {
        // VULNERABLE: No reentrancy protection
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // VULNERABLE: Multiple flash loans without reentrancy protection
    function nestedFlashLoan(address receiver, uint256 amount) external {
        // VULNERABLE: Can be called recursively during callback
        this.flashLoan(receiver, amount, "");
    }
}

/**
 * @title FlashLoanAttacker
 * @notice Example attacker contract demonstrating exploits
 */
contract FlashLoanAttacker is IFlashBorrower {
    // Attack vector: Oracle manipulation
    function attackOracle(address target, address pool, uint256 loanAmount) external {
        // 1. Take flash loan
        // 2. Manipulate pool reserves
        // 3. Call target contract's price-dependent function
        // 4. Profit from manipulated price
        // 5. Restore pool and repay flash loan
    }

    // Attack vector: Governance takeover
    function attackGovernance(address target, uint256 loanAmount) external {
        // 1. Flash loan governance tokens
        // 2. Create malicious proposal
        // 3. Vote with borrowed tokens
        // 4. Execute proposal in same transaction
        // 5. Repay flash loan
    }

    // Attack vector: Reentrancy via callback
    function attackReentrancy(address target, uint256 loanAmount) external {
        // 1. Request flash loan
        // 2. In callback, reenter target contract
        // 3. Drain funds before flash loan validation
        // 4. Repay flash loan from stolen funds
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // Malicious logic here
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// Interfaces
interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
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
