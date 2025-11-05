// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DelegationDeFiAttacks
 * @notice EIP-7702 Delegation Attacks in DeFi Context
 *
 * VULNERABILITY: DeFi protocol exploitation via delegation
 * EIP: EIP-7702 (Pectra upgrade, expected 2025)
 *
 * BACKGROUND:
 * DeFi protocols make assumptions about msg.sender behavior (EOA vs contract).
 * With EIP-7702, these assumptions break:
 * - EOAs can now have arbitrary logic
 * - Flash loan restrictions bypass
 * - Oracle manipulation via delegated EOA
 * - Liquidation protection bypass
 * - Governance attacks via delegation
 *
 * DEFI ATTACK VECTORS:
 * 1. Flash loan restrictions bypass (EOA flash loans)
 * 2. Oracle manipulation (delegated EOA can manipulate state)
 * 3. Liquidation bypass (delegated code prevents liquidation)
 * 4. Collateral inflation (delegated EOA reports fake balance)
 * 5. Governance manipulation (delegate voting power)
 * 6. MEV extraction via delegation
 * 7. Protocol fee bypass
 *
 * TESTED DETECTORS:
 * - eip7702-defi-flashloan
 * - eip7702-defi-oracle
 * - eip7702-defi-liquidation
 * - eip7702-defi-governance
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title LendingProtocolWithEOACheck
 * @notice Lending protocol that assumes EOAs can't perform flash loans
 */
contract LendingProtocolWithEOACheck {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;
    uint256 public constant COLLATERAL_RATIO = 150; // 150%

    event Deposit(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice VULNERABILITY 1: Flash loan restriction bypass via delegation
     * @dev Assumes EOAs can't perform flash loan attacks
     */
    function borrow(uint256 amount) external {
        // VULNERABLE: Checks if msg.sender has code
        // With EIP-7702, EOA can have delegated code!
        uint256 size;
        assembly {
            size := extcodesize(caller())
        }
        require(size == 0, "Contracts not allowed"); // BROKEN with EIP-7702!

        uint256 maxBorrow = (deposits[msg.sender] * 100) / COLLATERAL_RATIO;
        require(borrowed[msg.sender] + amount <= maxBorrow, "Insufficient collateral");

        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);

        emit Borrow(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 2: Same-block borrow-repay detection broken
     */
    mapping(address => uint256) public lastActionBlock;

    function borrowWithFlashProtection(uint256 amount) external {
        // VULNERABLE: Tries to prevent flash loans by blocking same-block borrow/repay
        // But with EIP-7702, EOA can delegate to complex logic that bypasses this
        require(lastActionBlock[msg.sender] != block.number, "Same block action");

        lastActionBlock[msg.sender] = block.number;

        uint256 maxBorrow = (deposits[msg.sender] * 100) / COLLATERAL_RATIO;
        require(borrowed[msg.sender] + amount <= maxBorrow, "Insufficient collateral");

        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    function repay() external payable {
        require(borrowed[msg.sender] >= msg.value, "Overpayment");

        borrowed[msg.sender] -= msg.value;
        emit Repay(msg.sender, msg.value);
    }

    receive() external payable {}
}

/**
 * @title OracleWithDelegation
 * @notice Price oracle vulnerable to delegation attacks
 */
contract OracleWithDelegation {
    mapping(address => uint256) public reportedPrices;
    mapping(address => bool) public isReporter;
    uint256 public aggregatedPrice;

    /**
     * @notice VULNERABILITY 3: Oracle reporter can delegate to manipulative code
     * @dev Reporter EOA delegates to contract that reports fake prices
     */
    function reportPrice(uint256 price) external {
        require(isReporter[msg.sender], "Not authorized reporter");

        // VULNERABLE: msg.sender could be EOA with delegated code
        // Delegated code can manipulate price based on external conditions
        reportedPrices[msg.sender] = price;

        // Update aggregated price
        updateAggregatedPrice();
    }

    function updateAggregatedPrice() internal {
        // Simplified aggregation
        uint256 sum = 0;
        uint256 count = 0;

        // In real implementation, would iterate over all reporters
        // For testing, simplified
        aggregatedPrice = sum / (count > 0 ? count : 1);
    }

    /**
     * @notice VULNERABILITY 4: Price can be manipulated via delegation
     */
    function getPrice() external view returns (uint256) {
        // VULNERABLE: Returns aggregated price that could be manipulated
        // by delegated reporter EOAs
        return aggregatedPrice;
    }

    function addReporter(address reporter) external {
        isReporter[reporter] = true;
    }
}

/**
 * @title LiquidationWithDelegation
 * @notice Liquidation system vulnerable to delegation
 */
contract LiquidationWithDelegation {
    LendingProtocolWithEOACheck public lending;
    OracleWithDelegation public oracle;

    mapping(address => uint256) public liquidationAttempts;

    constructor(address _lending, address _oracle) {
        lending = LendingProtocolWithEOACheck(_lending);
        oracle = OracleWithDelegation(_oracle);
    }

    /**
     * @notice VULNERABILITY 5: Liquidation bypass via delegation
     * @dev User delegates to code that prevents liquidation
     */
    function liquidate(address user) external {
        uint256 collateral = lending.deposits(user);
        uint256 debt = lending.borrowed(user);
        uint256 price = oracle.getPrice();

        uint256 collateralValue = collateral * price;
        uint256 requiredCollateral = (debt * 150) / 100;

        require(collateralValue < requiredCollateral, "Not liquidatable");

        // VULNERABLE: Try to call user to liquidate
        // If user delegated to protective code, liquidation can fail
        (bool success, ) = user.call(abi.encodeWithSignature("onLiquidation()"));

        // User's delegated code can:
        // 1. Revert to prevent liquidation
        // 2. Manipulate state to appear solvent
        // 3. Front-run with additional collateral

        if (!success) {
            liquidationAttempts[user]++;
        }
    }

    /**
     * @notice VULNERABILITY 6: Collateral check can be gamed
     */
    function checkHealth(address user) external view returns (bool) {
        uint256 collateral = lending.deposits(user);
        uint256 debt = lending.borrowed(user);

        // VULNERABLE: If user delegated to code that manipulates view functions,
        // health check could return false positive
        return (collateral * 100) >= (debt * 150);
    }
}

/**
 * @title GovernanceWithDelegation
 * @notice Governance system vulnerable to delegation attacks
 */
contract GovernanceWithDelegation {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => uint256) public proposalVotes;

    event Vote(address indexed voter, uint256 indexed proposalId, uint256 votes);

    /**
     * @notice VULNERABILITY 7: Vote delegation attack
     * @dev User delegates to code that votes multiple times or manipulates votes
     */
    function vote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(votingPower[msg.sender] > 0, "No voting power");

        // VULNERABLE: msg.sender could be EOA with delegated code
        // Delegated code can:
        // 1. Vote multiple times via re-delegation
        // 2. Manipulate voting power calculation
        // 3. Coordinate with other delegated EOAs

        uint256 votes = votingPower[msg.sender];
        proposalVotes[proposalId] += votes;
        hasVoted[proposalId][msg.sender] = true;

        emit Vote(msg.sender, proposalId, votes);
    }

    /**
     * @notice VULNERABILITY 8: Voting power can be inflated via delegation
     */
    function getVotingPower(address account) external view returns (uint256) {
        // VULNERABLE: If account delegated to code that manipulates balance checks,
        // voting power could be inflated
        return votingPower[account];
    }

    function setVotingPower(address account, uint256 power) external {
        votingPower[account] = power;
    }
}

/**
 * @title DEXWithDelegation
 * @notice DEX vulnerable to delegation attacks
 */
contract DEXWithDelegation {
    mapping(address => uint256) public tokenBalance;
    mapping(address => uint256) public ethBalance;
    uint256 public constant FEE = 30; // 0.3%

    /**
     * @notice VULNERABILITY 9: Fee bypass via delegation
     * @dev EOA delegates to code that bypasses fee payment
     */
    function swap(uint256 amountIn, bool ethToToken) external payable {
        // VULNERABLE: Fee calculation based on msg.sender behavior
        // Delegated EOA can manipulate fee calculation

        uint256 fee = (amountIn * FEE) / 10000;
        uint256 amountAfterFee = amountIn - fee;

        if (ethToToken) {
            require(msg.value == amountIn, "Incorrect ETH amount");

            // VULNERABLE: Delegated code can manipulate balance checks
            uint256 tokenAmount = calculateTokenAmount(amountAfterFee);
            tokenBalance[msg.sender] += tokenAmount;
        } else {
            require(tokenBalance[msg.sender] >= amountIn, "Insufficient tokens");

            tokenBalance[msg.sender] -= amountIn;
            uint256 ethAmount = calculateEthAmount(amountAfterFee);

            // VULNERABLE: Transfer to delegated EOA
            // Delegated code can manipulate receive logic
            payable(msg.sender).transfer(ethAmount);
        }
    }

    function calculateTokenAmount(uint256 ethAmount) internal pure returns (uint256) {
        // Simplified constant product formula
        return ethAmount * 100; // Example rate
    }

    function calculateEthAmount(uint256 tokenAmount) internal pure returns (uint256) {
        return tokenAmount / 100;
    }

    /**
     * @notice VULNERABILITY 10: MEV extraction via delegation
     * @dev Delegated EOA can detect and front-run profitable trades
     */
    function addLiquidity(uint256 tokenAmount) external payable {
        // VULNERABLE: Liquidity provision through delegated EOA
        // Can detect profitable arbitrage and front-run

        ethBalance[msg.sender] += msg.value;
        tokenBalance[msg.sender] += tokenAmount;
    }

    receive() external payable {}
}

/**
 * @title YieldFarmWithDelegation
 * @notice Yield farming vulnerable to delegation
 */
contract YieldFarmWithDelegation {
    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public lastClaimTime;
    mapping(address => uint256) public rewards;

    uint256 public constant REWARD_RATE = 100; // per second

    /**
     * @notice VULNERABILITY 11: Reward calculation manipulation
     * @dev Delegated EOA can manipulate time-based calculations
     */
    function stake(uint256 amount) external payable {
        require(msg.value == amount, "Incorrect amount");

        // Update rewards before staking
        updateRewards(msg.sender);

        stakedAmount[msg.sender] += amount;
        lastClaimTime[msg.sender] = block.timestamp;
    }

    function claimRewards() external {
        updateRewards(msg.sender);

        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");

        rewards[msg.sender] = 0;

        // VULNERABLE: Transfer rewards to delegated EOA
        // Delegated code can:
        // 1. Manipulate receive logic
        // 2. Re-enter to claim multiple times
        // 3. Coordinate with other delegated EOAs for MEV
        payable(msg.sender).transfer(reward);
    }

    function updateRewards(address user) internal {
        if (stakedAmount[user] > 0) {
            uint256 timeElapsed = block.timestamp - lastClaimTime[user];
            uint256 reward = (stakedAmount[user] * timeElapsed * REWARD_RATE) / 1e18;
            rewards[user] += reward;
        }
        lastClaimTime[user] = block.timestamp;
    }

    /**
     * @notice VULNERABILITY 12: Early unstake penalty bypass
     */
    function unstake(uint256 amount) external {
        require(stakedAmount[msg.sender] >= amount, "Insufficient stake");

        updateRewards(msg.sender);

        // VULNERABLE: Penalty calculation can be bypassed by delegated code
        uint256 timeStaked = block.timestamp - lastClaimTime[msg.sender];
        uint256 penalty = timeStaked < 7 days ? amount / 10 : 0;

        stakedAmount[msg.sender] -= amount;

        // Delegated EOA can manipulate to avoid penalty
        payable(msg.sender).transfer(amount - penalty);
    }

    receive() external payable {}
}

/**
 * @title FlashLoanWithDelegation
 * @notice Flash loan provider vulnerable to delegation
 */
contract FlashLoanWithDelegation {
    uint256 public poolBalance = 1000 ether;
    uint256 public constant FEE = 9; // 0.09%

    /**
     * @notice VULNERABILITY 13: EOA flash loans via delegation
     * @dev With EIP-7702, EOAs can now perform flash loan attacks
     */
    function flashLoan(uint256 amount) external {
        require(amount <= poolBalance, "Insufficient liquidity");

        uint256 balanceBefore = address(this).balance;
        uint256 fee = (amount * FEE) / 10000;
        uint256 requiredRepayment = amount + fee;

        // Send flash loan
        payable(msg.sender).transfer(amount);

        // VULNERABLE: Callback to msg.sender (could be delegated EOA)
        // EOA can now execute complex flash loan attack logic
        (bool success, ) = msg.sender.call(abi.encodeWithSignature("onFlashLoan(uint256)", amount));
        require(success, "Flash loan callback failed");

        // Check repayment
        require(
            address(this).balance >= balanceBefore + fee,
            "Flash loan not repaid"
        );

        poolBalance = address(this).balance;
    }

    /**
     * @notice VULNERABILITY 14: Re-entrancy via delegated flash loan
     */
    function flashLoanMultiple(uint256[] calldata amounts, address[] calldata recipients) external {
        require(amounts.length == recipients.length, "Length mismatch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= poolBalance, "Insufficient liquidity");

        // VULNERABLE: Multiple callbacks to potentially delegated EOAs
        for (uint256 i = 0; i < amounts.length; i++) {
            payable(recipients[i]).transfer(amounts[i]);

            // Each recipient could be delegated EOA
            (bool success, ) = recipients[i].call(
                abi.encodeWithSignature("onFlashLoan(uint256)", amounts[i])
            );
            require(success, "Callback failed");
        }

        // Check total repayment
        uint256 totalFee = (totalAmount * FEE) / 10000;
        require(address(this).balance >= poolBalance + totalFee, "Not repaid");
    }

    receive() external payable {}
}
