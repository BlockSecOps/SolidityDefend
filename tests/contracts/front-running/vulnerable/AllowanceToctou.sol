// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AllowanceToctou
 * @notice VULNERABLE: Allowance Time-of-Check-Time-of-Use vulnerabilities
 * @dev This contract demonstrates race conditions where allowance is checked but
 *      may change before use, leading to unexpected behavior.
 *
 * Vulnerability: CWE-367 (Time-of-check Time-of-use Race Condition)
 * Severity: MEDIUM
 * Impact: Race conditions, unexpected failures, MEV extraction
 *
 * Common scenario:
 * 1. Contract checks allowance(owner, spender) and makes decision
 * 2. User or protocol relies on that allowance value
 * 3. Between check and use, allowance changes (user calls approve again)
 * 4. Operation fails or behaves unexpectedly
 * 5. Potential for grief attacks or MEV
 */

interface IERC20 {
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

/**
 * @notice VULNERABLE: Check allowance then transferFrom without revalidation
 */
contract VulnerableAllowanceCheck {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Classic TOCTOU - check then use
     * @dev Allowance could change between check and transferFrom
     */
    function processTransfer(address from, uint256 amount) external {
        // VULNERABLE: Check allowance
        uint256 currentAllowance = token.allowance(from, address(this));
        require(currentAllowance >= amount, "Insufficient allowance");

        // ... do some processing ...
        // Allowance could be reduced here by front-running transaction

        // VULNERABLE: Use allowance without revalidation
        token.transferFrom(from, address(this), amount);
    }
}

/**
 * @notice VULNERABLE: Conditional logic based on allowance
 */
contract VulnerableConditional {
    IERC20 public token;
    mapping(address => uint256) public rewards;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Decide path based on allowance check
     * @dev Allowance could change between check and execution
     */
    function claimRewards(address user) external {
        uint256 reward = rewards[user];

        // VULNERABLE: Decision based on allowance
        uint256 allowance = token.allowance(user, address(this));

        if (allowance >= reward) {
            // Path A: transferFrom
            // VULNERABLE: Allowance could have been reduced
            token.transferFrom(user, address(this), reward);
        } else {
            // Path B: user must transfer manually
            require(msg.sender == user, "User must claim");
            // ... alternative flow
        }
    }
}

/**
 * @notice VULNERABLE: Multi-step operation relying on allowance
 */
contract VulnerableBatchProcessor {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Batch process without locking allowance
     * @dev Allowance could be modified mid-batch
     */
    function batchProcess(address[] calldata users, uint256[] calldata amounts) external {
        require(users.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            // VULNERABLE: Check allowance each iteration
            uint256 allowance = token.allowance(users[i], address(this));
            require(allowance >= amounts[i], "Insufficient allowance");

            // ... do external calls or state changes ...
            // User could front-run and reduce allowance mid-batch

            // VULNERABLE: transferFrom might fail unexpectedly
            token.transferFrom(users[i], address(this), amounts[i]);
        }
    }
}

/**
 * @notice VULNERABLE: Allowance check with external call between check and use
 */
contract VulnerableExternalCall {
    IERC20 public token;
    IExternalContract public externalContract;

    constructor(address _token, address _external) {
        token = IERC20(_token);
        externalContract = IExternalContract(_external);
    }

    /**
     * @notice VULNERABLE: External call between allowance check and use
     * @dev External contract could cause reentrancy or user could change allowance
     */
    function processWithCallback(address from, uint256 amount) external {
        // VULNERABLE: Check allowance
        uint256 allowance = token.allowance(from, address(this));
        require(allowance >= amount, "Insufficient allowance");

        // VULNERABLE: External call (potential reentrancy or state change)
        externalContract.callback(from, amount);

        // VULNERABLE: Use allowance (could have been changed)
        token.transferFrom(from, address(this), amount);
    }
}

interface IExternalContract {
    function callback(address user, uint256 amount) external;
}

/**
 * @notice VULNERABLE: Caching allowance value for later use
 */
contract VulnerableAllowanceCache {
    IERC20 public token;

    struct UserData {
        uint256 cachedAllowance;
        uint256 lastUpdate;
    }

    mapping(address => UserData) public userData;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Cache allowance value
     * @dev Cached value becomes stale if user changes allowance
     */
    function updateAllowanceCache(address user) external {
        // VULNERABLE: Store allowance for later use
        uint256 allowance = token.allowance(user, address(this));
        userData[user].cachedAllowance = allowance;
        userData[user].lastUpdate = block.timestamp;
    }

    /**
     * @notice VULNERABLE: Use cached allowance without refresh
     * @dev Stale data - real allowance might have changed
     */
    function processWithCachedAllowance(address user, uint256 amount) external {
        UserData memory data = userData[user];

        // VULNERABLE: Using stale allowance value
        require(data.cachedAllowance >= amount, "Insufficient cached allowance");

        // VULNERABLE: Real allowance might be different
        token.transferFrom(user, address(this), amount);
    }
}

/**
 * @notice VULNERABLE: Allowance check in view function, use in separate transaction
 */
contract VulnerableMultiTransaction {
    IERC20 public token;
    mapping(address => uint256) public pendingWithdrawals;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Check allowance in one transaction
     * @dev User might check, then reduce allowance before executing
     */
    function canWithdraw(address user) external view returns (bool) {
        uint256 pending = pendingWithdrawals[user];
        uint256 allowance = token.allowance(user, address(this));

        // Returns allowance check result
        return allowance >= pending;
    }

    /**
     * @notice VULNERABLE: Execute withdrawal in separate transaction
     * @dev Allowance could have been reduced since canWithdraw check
     */
    function executeWithdrawal(address user) external {
        uint256 amount = pendingWithdrawals[user];

        // VULNERABLE: No re-validation of allowance
        // User could have checked canWithdraw(), seen true, then reduced allowance
        token.transferFrom(user, address(this), amount);

        pendingWithdrawals[user] = 0;
    }
}

/**
 * @notice VULNERABLE: Calculate based on allowance, transfer later
 */
contract VulnerableCalculation {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Calculate amount based on allowance
     * @dev Calculated amount might exceed actual allowance at transfer time
     */
    function processProportional(address from) external {
        // VULNERABLE: Use allowance in calculation
        uint256 allowance = token.allowance(from, address(this));
        uint256 processAmount = allowance * 90 / 100; // 90% of allowance

        // ... do other operations ...

        // VULNERABLE: Allowance might have been reduced
        // processAmount might now exceed actual allowance
        token.transferFrom(from, address(this), processAmount);
    }
}

/**
 * @notice VULNERABLE: Allowance-based fee calculation
 */
contract VulnerableFeeCalculation {
    IERC20 public token;
    uint256 public feeRate = 100; // 1% (10000 = 100%)

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Calculate fee based on allowance check
     * @dev Fee calculation might fail if allowance changes
     */
    function processWithFee(address from, uint256 baseAmount) external {
        // VULNERABLE: Check allowance for base + fee
        uint256 requiredAllowance = baseAmount + (baseAmount * feeRate / 10000);
        uint256 currentAllowance = token.allowance(from, address(this));
        require(currentAllowance >= requiredAllowance, "Insufficient allowance for fee");

        // ... state changes or external calls ...

        // VULNERABLE: Allowance could have been reduced
        token.transferFrom(from, address(this), baseAmount);
        token.transferFrom(from, address(this), baseAmount * feeRate / 10000);
    }
}

/**
 * @notice VULNERABLE: Allowance verification with loop
 */
contract VulnerableAllowanceLoop {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Multi-step allowance usage
     * @dev Allowance could change between iterations
     */
    function multiTransfer(address from, address[] calldata recipients, uint256 amountEach) external {
        // VULNERABLE: Check total allowance once
        uint256 totalNeeded = recipients.length * amountEach;
        uint256 allowance = token.allowance(from, address(this));
        require(allowance >= totalNeeded, "Insufficient total allowance");

        // VULNERABLE: Loop uses allowance multiple times
        for (uint256 i = 0; i < recipients.length; i++) {
            // If allowance reduced mid-loop, later transfers fail
            token.transferFrom(from, recipients[i], amountEach);
        }
    }
}

/**
 * @notice VULNERABLE: Allowance-dependent access control
 */
contract VulnerableAccessControl {
    IERC20 public token;
    uint256 public constant REQUIRED_ALLOWANCE = 1000 * 10**18;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Access control based on allowance
     * @dev User could check allowance, get access, then reduce it
     */
    function privilegedFunction(address user) external {
        // VULNERABLE: Access control based on allowance check
        uint256 allowance = token.allowance(user, address(this));
        require(allowance >= REQUIRED_ALLOWANCE, "Insufficient allowance for access");

        // ... perform privileged operations ...

        // VULNERABLE: Might want to collect tokens at end
        // But allowance could have been reduced during execution
        token.transferFrom(user, address(this), REQUIRED_ALLOWANCE);
    }
}

/**
 * @notice VULNERABLE: Allowance snapshot without atomicity
 */
contract VulnerableSnapshot {
    IERC20 public token;

    struct Snapshot {
        uint256 allowance;
        uint256 timestamp;
        bool executed;
    }

    mapping(address => Snapshot) public snapshots;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Create snapshot of allowance
     * @dev Snapshot is not atomic - value could change before use
     */
    function createSnapshot(address user) external {
        // VULNERABLE: Store current allowance
        uint256 allowance = token.allowance(user, address(this));

        snapshots[user] = Snapshot({
            allowance: allowance,
            timestamp: block.timestamp,
            executed: false
        });
    }

    /**
     * @notice VULNERABLE: Execute based on snapshot
     * @dev Real allowance might differ from snapshot
     */
    function executeSnapshot(address user) external {
        Snapshot storage snap = snapshots[user];
        require(!snap.executed, "Already executed");

        // VULNERABLE: Using stale snapshot value
        // Real allowance might be less than snapshot.allowance
        token.transferFrom(user, address(this), snap.allowance);

        snap.executed = true;
    }
}

/**
 * @notice VULNERABLE: Allowance-based limit order
 */
contract VulnerableLimitOrder {
    IERC20 public token;

    struct Order {
        address trader;
        uint256 amount;
        uint256 minAllowance;
        bool executed;
    }

    Order[] public orders;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Create order with allowance requirement
     * @dev Allowance could be insufficient when order executes
     */
    function createOrder(uint256 amount, uint256 minAllowance) external {
        // VULNERABLE: No immediate allowance lock
        orders.push(Order({
            trader: msg.sender,
            amount: amount,
            minAllowance: minAllowance,
            executed: false
        }));
    }

    /**
     * @notice VULNERABLE: Execute order based on old allowance requirement
     * @dev Trader's actual allowance might be less than minAllowance
     */
    function executeOrder(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(!order.executed, "Already executed");

        // VULNERABLE: Check current allowance against min
        uint256 allowance = token.allowance(order.trader, address(this));
        require(allowance >= order.minAllowance, "Allowance too low");

        // ... price checks, other logic ...

        // VULNERABLE: Allowance could have been reduced since check
        token.transferFrom(order.trader, address(this), order.amount);

        order.executed = true;
    }
}

/**
 * @notice VULNERABLE: Allowance-based auction bid
 */
contract VulnerableAuctionBid {
    IERC20 public token;

    struct Bid {
        address bidder;
        uint256 amount;
        uint256 allowance;  // Stored allowance at bid time
    }

    Bid public highestBid;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice VULNERABLE: Store allowance at bid time
     * @dev Stored allowance might not match actual when auction ends
     */
    function bid(uint256 amount) external {
        require(amount > highestBid.amount, "Bid too low");

        // VULNERABLE: Check and store allowance
        uint256 allowance = token.allowance(msg.sender, address(this));
        require(allowance >= amount, "Insufficient allowance");

        highestBid = Bid({
            bidder: msg.sender,
            amount: amount,
            allowance: allowance
        });
    }

    /**
     * @notice VULNERABLE: Finalize auction using stored allowance data
     * @dev Actual allowance might be less than stored value
     */
    function finalizeAuction() external {
        // VULNERABLE: Using stored allowance data
        // Real allowance might have been reduced since bid
        token.transferFrom(highestBid.bidder, address(this), highestBid.amount);
    }
}
