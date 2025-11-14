// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Erc20ApproveRaceSafe
 * @notice SECURE: ERC20 tokens with proper approve race condition mitigations
 * @dev This contract demonstrates secure patterns to prevent the approve front-running attack.
 *
 * Mitigation Strategies:
 * 1. increaseAllowance/decreaseAllowance pattern (recommended by OpenZeppelin)
 * 2. safeApprove with current allowance check
 * 3. approve with expected current value parameter
 * 4. approve combined with increaseAllowance/decreaseAllowance
 *
 * These patterns prevent the race condition by either:
 * - Making allowance changes additive/subtractive (no direct set)
 * - Validating current allowance before changing
 * - Allowing atomic allowance updates
 */

/**
 * @notice SECURE: ERC20 with increaseAllowance/decreaseAllowance (OpenZeppelin pattern)
 */
contract SecureERC20OpenZeppelin {
    string public name = "Secure Token";
    string public symbol = "SAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }

    /**
     * @notice Standard approve (still vulnerable, but safe alternatives provided)
     * @dev Users should prefer increaseAllowance/decreaseAllowance
     */
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Increases allowance atomically
     * @dev Prevents race condition by adding to current allowance
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        // SECURE: Additive change prevents race condition
        // Even if spender uses current allowance, the increase still applies correctly
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    /**
     * @notice SECURE: Decreases allowance atomically
     * @dev Prevents race condition by subtracting from current allowance
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");

        // SECURE: Subtractive change prevents race condition
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}

/**
 * @notice SECURE: ERC20 with safeApprove requiring zero reset
 */
contract SecureERC20SafeApprove {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice SECURE: Requires resetting to zero before changing non-zero allowance
     * @dev Prevents race by enforcing two-step approval changes
     */
    function safeApprove(address spender, uint256 value) external returns (bool) {
        // SECURE: Must either set to zero, or current must be zero
        // This forces users to reset before changing, preventing the race
        require(
            allowance[msg.sender][spender] == 0 || value == 0,
            "SafeApprove: approve from non-zero to non-zero allowance"
        );

        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Alternative safe methods
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}

/**
 * @notice SECURE: ERC20 with approve requiring expected current value
 */
contract SecureERC20ExpectedValue {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice SECURE: Validates current allowance before setting new value
     * @dev Atomic check-and-set prevents race condition
     */
    function approveWithExpected(
        address spender,
        uint256 expectedCurrent,
        uint256 newValue
    ) external returns (bool) {
        // SECURE: Transaction fails if current allowance doesn't match expected
        // This prevents the race because spender can't change allowance between check and set
        require(
            allowance[msg.sender][spender] == expectedCurrent,
            "Current allowance doesn't match expected"
        );

        allowance[msg.sender][spender] = newValue;
        emit Approval(msg.sender, spender, newValue);
        return true;
    }

    /**
     * @notice Standard approve (users should prefer approveWithExpected)
     */
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice Additional safe alternatives
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}

/**
 * @notice SECURE: Complete ERC20 with all mitigation patterns
 */
contract SecureERC20Complete {
    string public name = "Complete Secure Token";
    string public symbol = "CSAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }

    /**
     * @notice Standard approve (deprecated, use safe alternatives)
     */
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Atomic increase (recommended)
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    /**
     * @notice SECURE: Atomic decrease (recommended)
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    /**
     * @notice SECURE: Safe approve with zero check
     */
    function safeApprove(address spender, uint256 value) external returns (bool) {
        require(
            allowance[msg.sender][spender] == 0 || value == 0,
            "SafeApprove: approve from non-zero to non-zero"
        );
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Approve with expected current value
     */
    function approveWithExpected(
        address spender,
        uint256 expectedCurrent,
        uint256 newValue
    ) external returns (bool) {
        require(
            allowance[msg.sender][spender] == expectedCurrent,
            "Current allowance mismatch"
        );
        allowance[msg.sender][spender] = newValue;
        emit Approval(msg.sender, spender, newValue);
        return true;
    }
}

/**
 * @notice SECURE: Modern ERC20 with only safe methods
 */
contract ModernSecureERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    // SECURE: No approve() function at all - only safe alternatives

    /**
     * @notice Set initial allowance (can only be called when allowance is 0)
     */
    function setAllowance(address spender, uint256 value) external returns (bool) {
        require(allowance[msg.sender][spender] == 0, "Must be zero");
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Only atomic changes allowed
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    /**
     * @notice Reset allowance to zero
     */
    function revokeAllowance(address spender) external returns (bool) {
        allowance[msg.sender][spender] = 0;
        emit Approval(msg.sender, spender, 0);
        return true;
    }
}

/**
 * @notice SECURE: Upgradeable token with safe approve patterns
 */
contract UpgradeableSecureToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice Standard approve (users should prefer safe alternatives)
     */
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice SECURE: Safe alternatives provided
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}
