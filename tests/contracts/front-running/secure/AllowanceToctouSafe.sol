// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AllowanceToctouSafe
 * @notice SECURE: Allowance TOCTOU protection patterns
 * @dev This contract demonstrates secure patterns for handling ERC20 allowances
 *      without Time-of-Check-Time-of-Use race conditions.
 *
 * Security Features:
 * - Re-validation before use
 * - Try-catch for graceful handling
 * - Permit (EIP-2612) for atomic operations
 * - Lock mechanisms for multi-step processes
 * - Reentrancy protection
 *
 * Reference: EIP-2612, Best Practices
 */

interface IERC20 {
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IExternalContract {
    function callback(address user, uint256 amount) external;
}

/**
 * @notice SECURE: Re-validation before transferFrom
 */
contract SecureAllowanceRevalidation {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Re-validate allowance immediately before use
     * @dev Checks allowance twice - once early, once right before transferFrom
     */
    function processTransfer(address from, uint256 amount) external {
        // Early check (optional, for better error messages)
        uint256 initialAllowance = token.allowance(from, address(this));
        require(initialAllowance >= amount, "Insufficient initial allowance");

        // ... do some processing ...

        // SECURE: Re-validate immediately before transferFrom
        uint256 currentAllowance = token.allowance(from, address(this));
        require(currentAllowance >= amount, "Allowance changed - now insufficient");

        // Safe to transfer now
        token.transferFrom(from, address(this), amount);
    }
}

/**
 * @notice SECURE: Try-catch for graceful handling
 */
contract SecureTryCatch {
    IERC20 public token;

    event TransferSuccess(address indexed from, uint256 amount);
    event TransferFailed(address indexed from, uint256 amount, string reason);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Handle allowance changes gracefully with try-catch
     * @dev Returns success status instead of reverting
     */
    function processTransfer(address from, uint256 amount) external returns (bool success) {
        // SECURE: Use try-catch to handle allowance changes
        try token.transferFrom(from, address(this), amount) returns (bool transferred) {
            if (transferred) {
                emit TransferSuccess(from, amount);
                return true;
            } else {
                emit TransferFailed(from, amount, "Transfer returned false");
                return false;
            }
        } catch Error(string memory reason) {
            emit TransferFailed(from, amount, reason);
            return false;
        } catch (bytes memory) {
            emit TransferFailed(from, amount, "Low-level error");
            return false;
        }
    }
}

/**
 * @notice SECURE: Atomic approve+transfer using permit (EIP-2612)
 */
contract SecurePermit {
    IERC20Permit public token;

    constructor(address _token) {
        token = IERC20Permit(_token);
    }

    /**
     * @notice SECURE: Use permit for atomic approve+transfer
     * @dev No TOCTOU possible - permit and transferFrom in same transaction
     */
    function processWithPermit(
        address from,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Atomically set allowance and transfer
        token.permit(from, address(this), amount, deadline, v, r, s);
        token.transferFrom(from, address(this), amount);

        // No race condition possible
    }
}

/**
 * @notice SECURE: Allowance snapshot with lock mechanism
 */
contract SecureAllowanceLock {
    IERC20 public token;

    struct AllowanceLock {
        uint256 amount;
        uint256 expiry;
        bool used;
    }

    mapping(address => AllowanceLock) public locks;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Create lock committing user to maintain allowance
     * @dev User commits to maintaining minimum allowance for duration
     */
    function createLock(address user, uint256 amount, uint256 duration) external {
        uint256 currentAllowance = token.allowance(user, address(this));
        require(currentAllowance >= amount, "Insufficient allowance");

        // Create lock commitment
        locks[user] = AllowanceLock({
            amount: amount,
            expiry: block.timestamp + duration,
            used: false
        });
    }

    /**
     * @notice SECURE: Execute transfer using locked allowance
     * @dev Validates lock and re-checks allowance before use
     */
    function executeWithLock(address user) external {
        AllowanceLock storage lock = locks[user];
        require(!lock.used, "Lock already used");
        require(block.timestamp <= lock.expiry, "Lock expired");

        // SECURE: Re-validate allowance matches lock
        uint256 currentAllowance = token.allowance(user, address(this));
        require(currentAllowance >= lock.amount, "Allowance below lock amount");

        token.transferFrom(user, address(this), lock.amount);
        lock.used = true;
    }
}

/**
 * @notice SECURE: Batch processing with isolated failures
 */
contract SecureBatchProcessor {
    IERC20 public token;

    struct BatchResult {
        address user;
        uint256 amount;
        bool success;
        string reason;
    }

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Batch with try-catch per transfer
     * @dev Individual failures don't cascade to entire batch
     */
    function batchProcess(
        address[] calldata users,
        uint256[] calldata amounts
    ) external returns (BatchResult[] memory results) {
        require(users.length == amounts.length, "Length mismatch");
        results = new BatchResult[](users.length);

        for (uint256 i = 0; i < users.length; i++) {
            // SECURE: Each transfer isolated with try-catch
            try token.transferFrom(users[i], address(this), amounts[i]) returns (bool success) {
                results[i] = BatchResult({
                    user: users[i],
                    amount: amounts[i],
                    success: success,
                    reason: success ? "" : "Transfer returned false"
                });
            } catch Error(string memory reason) {
                results[i] = BatchResult({
                    user: users[i],
                    amount: amounts[i],
                    success: false,
                    reason: reason
                });
            } catch {
                results[i] = BatchResult({
                    user: users[i],
                    amount: amounts[i],
                    success: false,
                    reason: "Unknown error"
                });
            }
        }

        // Batch completes regardless of individual failures
    }
}

/**
 * @notice SECURE: External call with reentrancy protection and revalidation
 */
contract SecureExternalCall {
    IERC20 public token;
    IExternalContract public externalContract;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _token, address _external) {
        token = IERC20(_token);
        externalContract = IExternalContract(_external);
    }

    /**
     * @notice SECURE: External call with reentrancy guard and revalidation
     * @dev Prevents reentrancy and re-validates allowance before use
     */
    function processWithCallback(address from, uint256 amount) external nonReentrant {
        // Check allowance
        uint256 initialAllowance = token.allowance(from, address(this));
        require(initialAllowance >= amount, "Insufficient allowance");

        // External call (protected from reentrancy)
        externalContract.callback(from, amount);

        // SECURE: Re-validate before transferFrom
        uint256 finalAllowance = token.allowance(from, address(this));
        require(finalAllowance >= amount, "Allowance changed during callback");

        // Safe to transfer
        token.transferFrom(from, address(this), amount);
    }
}

/**
 * @notice SECURE: No caching - always check fresh allowance
 */
contract SecureNoCaching {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: No caching - check allowance when needed
     * @dev Always queries fresh allowance value
     */
    function processTransfer(address user, uint256 amount) external {
        // SECURE: No caching - check right before use
        uint256 currentAllowance = token.allowance(user, address(this));
        require(currentAllowance >= amount, "Insufficient allowance");

        token.transferFrom(user, address(this), amount);
    }
}

/**
 * @notice SECURE: Multi-transaction flow with fresh validation
 */
contract SecureMultiTransaction {
    IERC20 public token;
    mapping(address => uint256) public pendingWithdrawals;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: View function provides info only
     * @dev Caller should not rely on this for execution decisions
     */
    function canWithdraw(address user) external view returns (bool) {
        uint256 pending = pendingWithdrawals[user];
        uint256 allowance = token.allowance(user, address(this));
        return allowance >= pending;
        // Note: This is informational only
    }

    /**
     * @notice SECURE: Execute with fresh allowance validation
     * @dev Does not rely on canWithdraw() - validates allowance fresh
     */
    function executeWithdrawal(address user) external {
        uint256 amount = pendingWithdrawals[user];

        // SECURE: Fresh validation - don't rely on previous canWithdraw() call
        uint256 currentAllowance = token.allowance(user, address(this));
        require(currentAllowance >= amount, "Insufficient allowance");

        token.transferFrom(user, address(this), amount);
        pendingWithdrawals[user] = 0;
    }
}

/**
 * @notice SECURE: Proportional calculation with immediate use
 */
contract SecureCalculation {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Calculate and use in same operation
     * @dev No gap between calculation and transfer
     */
    function processProportional(address from) external {
        // SECURE: Get allowance and use immediately
        uint256 allowance = token.allowance(from, address(this));
        uint256 processAmount = allowance * 90 / 100;

        // Immediate use - no opportunity for change
        token.transferFrom(from, address(this), processAmount);
    }
}

/**
 * @notice SECURE: Fee calculation with atomic transfer
 */
contract SecureFeeCalculation {
    IERC20 public token;
    uint256 public feeRate = 100; // 1%

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Calculate fee and transfer atomically
     * @dev Single transferFrom for total amount
     */
    function processWithFee(address from, uint256 baseAmount) external {
        uint256 fee = baseAmount * feeRate / 10000;
        uint256 totalAmount = baseAmount + fee;

        // SECURE: Single transferFrom for total (atomic)
        token.transferFrom(from, address(this), totalAmount);

        // Fee already accounted for in single transfer
    }
}

/**
 * @notice SECURE: Loop with individual validation
 */
contract SecureLoop {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Each iteration validates independently
     * @dev Using try-catch so individual failures don't block others
     */
    function multiTransfer(
        address from,
        address[] calldata recipients,
        uint256 amountEach
    ) external returns (uint256 successful) {
        for (uint256 i = 0; i < recipients.length; i++) {
            // SECURE: Each transfer independent with try-catch
            try token.transferFrom(from, recipients[i], amountEach) {
                successful++;
            } catch {
                // Skip failed transfers, continue with others
                continue;
            }
        }
    }
}

/**
 * @notice SECURE: Access control independent of allowance
 */
contract SecureAccessControl {
    IERC20 public token;
    uint256 public constant REQUIRED_ALLOWANCE = 1000 * 10**18;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Access control separate from token collection
     * @dev Validates allowance fresh when actually transferring
     */
    function privilegedFunction(address user) external {
        // Access check (informational)
        uint256 allowance = token.allowance(user, address(this));
        require(allowance >= REQUIRED_ALLOWANCE, "Insufficient allowance for access");

        // ... perform privileged operations ...

        // SECURE: Collect tokens with fresh validation
        uint256 finalAllowance = token.allowance(user, address(this));
        require(finalAllowance >= REQUIRED_ALLOWANCE, "Allowance changed");

        token.transferFrom(user, address(this), REQUIRED_ALLOWANCE);
    }
}

/**
 * @notice SECURE: Atomic snapshot and execute
 */
contract SecureAtomicSnapshot {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Snapshot and execute in single transaction
     * @dev No gap between snapshot and execution
     */
    function snapshotAndExecute(address user, uint256 amount) external {
        // SECURE: Snapshot and execute atomically
        uint256 allowance = token.allowance(user, address(this));
        require(allowance >= amount, "Insufficient allowance");

        // Immediate execution - no TOCTOU window
        token.transferFrom(user, address(this), amount);
    }
}

/**
 * @notice SECURE: Order execution with fresh validation
 */
contract SecureLimitOrder {
    IERC20 public token;

    struct Order {
        address trader;
        uint256 amount;
        bool executed;
    }

    Order[] public orders;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Create order without storing allowance
     * @dev Allowance validated when order executes
     */
    function createOrder(uint256 amount) external {
        orders.push(Order({
            trader: msg.sender,
            amount: amount,
            executed: false
        }));
    }

    /**
     * @notice SECURE: Execute with fresh allowance validation
     * @dev Validates allowance at execution time, not creation time
     */
    function executeOrder(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(!order.executed, "Already executed");

        // SECURE: Fresh validation at execution time
        uint256 allowance = token.allowance(order.trader, address(this));
        require(allowance >= order.amount, "Insufficient allowance");

        token.transferFrom(order.trader, address(this), order.amount);
        order.executed = true;
    }
}

/**
 * @notice SECURE: Auction with fresh validation at finalization
 */
contract SecureAuction {
    IERC20 public token;

    struct Bid {
        address bidder;
        uint256 amount;
    }

    Bid public highestBid;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @notice SECURE: Record bid without checking allowance
     * @dev Allowance validated only at finalization
     */
    function bid(uint256 amount) external {
        require(amount > highestBid.amount, "Bid too low");

        highestBid = Bid({
            bidder: msg.sender,
            amount: amount
        });
        // Don't check allowance here - will check at finalization
    }

    /**
     * @notice SECURE: Finalize with fresh allowance check
     * @dev Validates allowance when actually collecting payment
     */
    function finalizeAuction() external {
        // SECURE: Fresh validation at payment time
        uint256 allowance = token.allowance(highestBid.bidder, address(this));
        require(allowance >= highestBid.amount, "Winner has insufficient allowance");

        token.transferFrom(highestBid.bidder, address(this), highestBid.amount);
    }
}

/**
 * @notice SECURE: Combined permit and traditional flow
 */
contract SecureDualFlow {
    IERC20Permit public token;

    constructor(address _token) {
        token = IERC20Permit(_token);
    }

    /**
     * @notice SECURE: Preferred - use permit for atomic operation
     */
    function processWithPermit(
        address from,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Atomic approve+transfer
        token.permit(from, address(this), amount, deadline, v, r, s);
        token.transferFrom(from, address(this), amount);
    }

    /**
     * @notice SECURE: Fallback - traditional flow with try-catch
     */
    function processTraditional(address from, uint256 amount) external returns (bool) {
        // SECURE: Graceful handling with try-catch
        try token.transferFrom(from, address(this), amount) returns (bool success) {
            return success;
        } catch {
            return false;
        }
    }
}
