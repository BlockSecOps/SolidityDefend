// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Erc20ApproveRace
 * @notice VULNERABLE: ERC20 token with approve race condition vulnerability
 * @dev This contract demonstrates the classic ERC20 approve front-running attack
 *      where a malicious spender can extract more tokens than intended by monitoring
 *      the mempool and front-running approve transactions.
 *
 * Vulnerability: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
 * Severity: MEDIUM
 * Impact: Token theft, loss of funds, user approval manipulation
 *
 * The approve race condition occurs when:
 * 1. Alice approves Bob for 100 tokens
 * 2. Alice wants to reduce approval to 50 tokens
 * 3. Bob monitors mempool and sees Alice's approve(bob, 50) tx
 * 4. Bob front-runs by calling transferFrom to extract 100 tokens
 * 5. Alice's approve(bob, 50) executes
 * 6. Bob can now extract another 50 tokens
 * 7. Total extracted: 150 tokens instead of intended 50
 *
 * Real-world impact:
 * - Affects any ERC20 token using standard approve
 * - OpenZeppelin recommended increaseAllowance/decreaseAllowance in 2018
 * - Many tokens still vulnerable due to ERC20 standard compatibility
 * - Attack requires mempool monitoring and gas optimization
 * - Estimated impact: Potential for significant token theft on popular tokens
 */

/**
 * @notice VULNERABLE: Basic ERC20 with standard approve (race condition)
 */
contract VulnerableERC20Basic {
    string public name = "Vulnerable Token";
    string public symbol = "VULN";
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
     * @notice VULNERABLE: Standard approve without race condition protection
     * @dev This function directly sets the allowance, enabling the race condition attack
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Direct allowance assignment without any checks
        // Spender can front-run this to extract old allowance first
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}

/**
 * @notice VULNERABLE: ERC20 with approve but incomplete mitigation
 */
contract ERC20IncompleteProtection {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice VULNERABLE: Attempts protection but doesn't help against race
     * @dev Checking for zero doesn't prevent the race condition attack
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: This check doesn't prevent race condition
        // It only prevents setting from non-zero to non-zero
        // But attacker can still extract original allowance first
        require(allowance[msg.sender][spender] == 0 || value == 0, "Must reset to 0 first");

        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}

/**
 * @notice VULNERABLE: ERC20 with only approve (no safe alternatives)
 */
contract ERC20NoSafeAlternatives {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice VULNERABLE: Only approve function, no increaseAllowance/decreaseAllowance
     */
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // No increaseAllowance() - users forced to use vulnerable approve
    // No decreaseAllowance() - users forced to use vulnerable approve
}

/**
 * @notice VULNERABLE: Multiple tokens with approve race condition
 */
contract MultiTokenVulnerable {
    struct Token {
        mapping(address => uint256) balances;
        mapping(address => mapping(address => uint256)) allowances;
        string name;
    }

    mapping(uint256 => Token) public tokens;

    /**
     * @notice VULNERABLE: Multi-token approve without protection
     */
    function approve(uint256 tokenId, address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Each token's allowance vulnerable to race condition
        tokens[tokenId].allowances[msg.sender][spender] = value;
        return true;
    }
}

/**
 * @notice VULNERABLE: Wrapped token with approve race
 */
contract WrappedTokenVulnerable {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /**
     * @notice VULNERABLE: Wrapped token inherits approve vulnerability
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Wrapping doesn't fix the race condition
        allowance[msg.sender][spender] = value;
        return true;
    }

    function wrap(uint256 amount) external {}
    function unwrap(uint256 amount) external {}
}

/**
 * @notice VULNERABLE: Upgradeable token with approve race
 */
contract UpgradeableTokenV1 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /**
     * @notice VULNERABLE: Even upgradeable tokens can have race condition
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Upgradeability doesn't fix the race condition
        allowance[msg.sender][spender] = value;
        return true;
    }
}

/**
 * @notice VULNERABLE: Rebasing token with approve race
 */
contract RebasingTokenVulnerable {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public rebaseMultiplier = 1e18;

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account] * rebaseMultiplier / 1e18;
    }

    /**
     * @notice VULNERABLE: Rebasing doesn't protect against approve race
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Rebase mechanism doesn't prevent race condition
        allowance[msg.sender][spender] = value;
        return true;
    }
}

/**
 * @notice VULNERABLE: Fee-on-transfer token with approve race
 */
contract FeeOnTransferTokenVulnerable {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public transferFee = 100; // 1% fee

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        uint256 fee = value * transferFee / 10000;
        uint256 netValue = value - fee;

        balanceOf[from] -= value;
        balanceOf[to] += netValue;
        balanceOf[address(this)] += fee; // Fee to contract
        allowance[from][msg.sender] -= value;

        return true;
    }

    /**
     * @notice VULNERABLE: Fee mechanism doesn't fix approve race
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // VULNERABLE: Fees don't prevent the race condition
        allowance[msg.sender][spender] = value;
        return true;
    }
}

/**
 * @notice ATTACK DEMONSTRATION
 * @dev This contract demonstrates how the approve race attack works
 */
contract ApproveRaceAttacker {
    VulnerableERC20Basic public token;
    address public victim;

    constructor(address _token, address _victim) {
        token = VulnerableERC20Basic(_token);
        victim = _victim;
    }

    /**
     * @notice Execute the approve race attack
     * @dev Monitors mempool for victim's approve tx and front-runs it
     */
    function attack() external {
        // Step 1: Victim has approved attacker for 100 tokens
        uint256 oldAllowance = token.allowance(victim, address(this));

        // Step 2: Victim submits approve(attacker, 50) to reduce allowance
        // Attacker sees this in mempool

        // Step 3: Attacker front-runs by extracting old allowance
        if (oldAllowance > 0) {
            token.transferFrom(victim, address(this), oldAllowance);
        }

        // Step 4: Victim's approve(50) executes after our transferFrom
        // Step 5: Attacker can now extract another 50 tokens
        // Total extracted: oldAllowance + 50 (150 if oldAllowance was 100)
    }
}
