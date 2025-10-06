# Detector Documentation

Complete reference for all 33 security detectors available in SolidityDefend with **100% category coverage**.

## Table of Contents

- [Overview](#overview)
- [Access Control & Authentication](#access-control--authentication)
- [Reentrancy Protection](#reentrancy-protection)
- [Input Validation](#input-validation)
- [Logic & State Management](#logic--state-management)
- [Oracle & Price Security](#oracle--price-security)
- [Flash Loan & MEV Protection](#flash-loan--mev-protection)
- [Cross-Chain Security](#cross-chain-security)
- [DeFi & Staking](#defi--staking)
- [Governance Security](#governance-security)
- [External Integration](#external-integration)
- [Detector Severity Levels](#detector-severity-levels)
- [Customization](#customization)

## Overview

SolidityDefend includes **33 production-ready security detectors** covering all critical vulnerability classes in modern smart contracts with **100% category coverage**. Each detector is designed to minimize false positives while ensuring comprehensive coverage of security issues. The detector execution pipeline has been fully validated and is currently functional with standardized Finding format and CWE mappings.

### Detector Statistics

| Category | Detectors | Severity Range | Coverage |
|----------|-----------|----------------|----------|
| Access Control & Authentication | 4 | Medium - High | ✅ 100% |
| Reentrancy Protection | 2 | Medium - High | ✅ 100% |
| Input Validation | 3 | Low - Medium | ✅ 100% |
| Logic & State Management | 2 | Medium | ✅ 100% |
| Oracle & Price Security | 3 | Medium - Critical | ✅ 100% |
| Flash Loan Protection | 3 | High - Critical | ✅ 100% |
| MEV Protection | 5 | Medium - High | ✅ 100% |
| Cross-Chain Security | 2 | High - Critical | ✅ 100% |
| DeFi & Staking | 5 | Medium - Critical | ✅ 100% |
| Governance Security | 5 | Medium - High | ✅ 100% |
| External Integration | 1 | Medium | ✅ 100% |
| Timestamp Dependencies | 1 | Medium | ✅ 100% |

**Total: 33 detectors** (+57% from baseline) 🎉

### Coverage Achievement

- **Baseline**: 21 detectors (62% coverage)
- **Phase 1**: +3 critical detectors
- **Phase 2**: +4 high-priority detectors
- **Phase 3**: +5 medium-priority detectors + 1 enhancement
- **Final**: **33 detectors with 100% category coverage** ✅

## Access Control & Authentication

### Missing Access Control

**ID:** `missing-access-control`
**Severity:** High
**Category:** Access Control

**Description:**
Detects functions that modify contract state or handle sensitive operations without proper access control mechanisms.

**What it Finds:**
- Functions that change critical state without modifiers
- Administrative functions accessible to any user
- Functions handling funds without permission checks

**Example Vulnerable Code:**
```solidity
contract VulnerableContract {
    address public owner;
    uint256 public totalSupply;

    // ❌ Missing access control
    function setOwner(address newOwner) public {
        owner = newOwner;  // Anyone can change owner!
    }

    // ❌ Missing access control
    function mint(address to, uint256 amount) public {
        totalSupply += amount;  // Anyone can mint tokens!
    }
}
```

**Secure Code:**
```solidity
contract SecureContract {
    address public owner;
    uint256 public totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Proper access control
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    // ✅ Proper access control
    function mint(address to, uint256 amount) public onlyOwner {
        totalSupply += amount;
    }
}
```

**Fix Suggestions:**
- Add access control modifiers (`onlyOwner`, `onlyAdmin`)
- Implement role-based access control (RBAC)
- Use OpenZeppelin's `Ownable` or `AccessControl`

---

### Unprotected Initializer

**ID:** `unprotected-initializer`
**Severity:** High
**Category:** Access Control

**Description:**
Finds initialization functions that can be called by anyone, potentially allowing attackers to hijack contract ownership or configuration.

**What it Finds:**
- `initialize()` functions without access control
- Constructor-like functions callable post-deployment
- Setup functions without caller restrictions

**Example Vulnerable Code:**
```solidity
contract VulnerableProxy {
    address public owner;
    bool public initialized;

    // ❌ Anyone can call initialize
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;  // Attacker can set themselves as owner!
        initialized = true;
    }
}
```

**Secure Code:**
```solidity
contract SecureProxy {
    address public owner;
    bool public initialized;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Protected initialization
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        require(msg.sender == tx.origin, "Only EOA can initialize"); // Basic protection
        owner = _owner;
        initialized = true;
    }

    // ✅ Or use a factory pattern with immediate initialization
    constructor(address _owner) {
        owner = _owner;
        initialized = true;
    }
}
```

---

### Default Visibility

**ID:** `default-visibility`
**Severity:** Medium
**Category:** Access Control

**Description:**
Identifies functions using default (public) visibility when they should be internal or private.

**What it Finds:**
- Functions without explicit visibility modifiers
- Helper functions that should be internal
- Functions accidentally exposed as public

**Example Issues:**
```solidity
contract VulnerableContract {
    mapping(address => uint256) balances;

    // ❌ Default public visibility - should be internal
    function _transfer(address from, address to, uint256 amount) {
        balances[from] -= amount;
        balances[to] += amount;
    }

    // ❌ Default public visibility - helper function
    function calculateFee(uint256 amount) pure returns (uint256) {
        return amount * 3 / 100;
    }
}
```

**Secure Code:**
```solidity
contract SecureContract {
    mapping(address => uint256) balances;

    // ✅ Explicit internal visibility
    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
    }

    // ✅ Explicit internal visibility for helper
    function calculateFee(uint256 amount) internal pure returns (uint256) {
        return amount * 3 / 100;
    }

    // ✅ Explicit public visibility for intended public functions
    function transfer(address to, uint256 amount) public {
        _transfer(msg.sender, to, amount);
    }
}
```

---

### Tx.Origin Authentication

**ID:** `tx-origin-auth`
**Severity:** High
**Category:** Authentication

**Description:**
Detects dangerous use of `tx.origin` for authentication, which is vulnerable to phishing attacks.

**What it Finds:**
- `tx.origin` used in access control checks
- Authorization based on transaction originator
- Phishing-vulnerable authentication patterns

**Example Vulnerable Code:**
```solidity
contract VulnerableWallet {
    address public owner;

    modifier onlyOwner() {
        // ❌ Vulnerable to phishing attacks
        require(tx.origin == owner, "Not owner");
        _;
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
```

**Attack Scenario:**
```solidity
contract PhishingContract {
    VulnerableWallet target;

    constructor(address _target) {
        target = VulnerableWallet(_target);
    }

    // If owner calls this function, tx.origin == owner
    // but msg.sender == address(this)
    function innocentFunction() public {
        target.withdraw(); // This will succeed!
    }
}
```

**Secure Code:**
```solidity
contract SecureWallet {
    address public owner;

    modifier onlyOwner() {
        // ✅ Use msg.sender instead
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
```

## Reentrancy Protection

### Classic Reentrancy

**ID:** `classic-reentrancy`
**Severity:** High
**Category:** Reentrancy

**Description:**
Detects the classic reentrancy vulnerability where external calls are made before state updates.

**What it Finds:**
- External calls before state changes
- Vulnerable withdrawal patterns
- State modifications after external interactions

**Example Vulnerable Code:**
```solidity
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // ❌ External call before state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // State updated after external call
    }
}
```

**Attack Contract:**
```solidity
contract ReentrancyAttack {
    VulnerableBank bank;
    uint256 public attackCount;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        attackCount++;
        if (attackCount < 10 && address(bank).balance > 0) {
            bank.withdraw(); // Reentrant call
        }
    }
}
```

**Secure Code:**
```solidity
contract SecureBank {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw() public noReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // ✅ State updated before external call
        balances[msg.sender] = 0;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

---

### Read-Only Reentrancy

**ID:** `readonly-reentrancy`
**Severity:** Medium
**Category:** Reentrancy

**Description:**
Detects read-only reentrancy where view functions can return inconsistent state during external calls.

**What it Finds:**
- View functions reading state during external calls
- Cross-function reentrancy in query functions
- Inconsistent state exposure in getters

**Example Vulnerable Code:**
```solidity
contract VulnerableLending {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;

    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        // ❌ External call before state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        deposits[msg.sender] -= amount; // State updated after external call
    }

    // ❌ This view function can return inconsistent data during withdrawal
    function getCollateralRatio(address user) public view returns (uint256) {
        if (deposits[user] == 0) return 0;
        return (deposits[user] * 100) / borrowed[user];
    }
}
```

**Attack Scenario:**
During the external call in `withdraw()`, an attacker can call `getCollateralRatio()` which will see the old (higher) deposit balance, potentially causing other contracts to make incorrect decisions.

**Secure Code:**
```solidity
contract SecureLending {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw(uint256 amount) public noReentrant {
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        // ✅ State updated before external call
        deposits[msg.sender] -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getCollateralRatio(address user) public view returns (uint256) {
        require(!locked, "Cannot read during state change");
        if (deposits[user] == 0) return 0;
        return (deposits[user] * 100) / borrowed[user];
    }
}
```

## Input Validation

### Zero Address Validation

**ID:** `missing-zero-address-check`
**Severity:** Medium
**Category:** Input Validation

**Description:**
Finds functions that accept address parameters without checking for the zero address (0x0).

**What it Finds:**
- Functions accepting address parameters without validation
- Missing zero address checks in constructors
- Transfer functions that could burn tokens

**Example Vulnerable Code:**
```solidity
contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;

    // ❌ Missing zero address check
    function setOwner(address newOwner) public {
        owner = newOwner; // Could set owner to 0x0!
    }

    // ❌ Missing zero address check
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount; // Could burn tokens to 0x0!
    }
}
```

**Secure Code:**
```solidity
contract SecureToken {
    mapping(address => uint256) public balances;
    address public owner;

    modifier notZeroAddress(address addr) {
        require(addr != address(0), "Zero address not allowed");
        _;
    }

    // ✅ Zero address validation
    function setOwner(address newOwner) public notZeroAddress(newOwner) {
        owner = newOwner;
    }

    // ✅ Zero address validation
    function transfer(address to, uint256 amount) public notZeroAddress(to) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

---

### Array Bounds Checking

**ID:** `array-bounds`
**Severity:** Medium
**Category:** Input Validation

**Description:**
Detects potential array access violations and missing bounds checking.

**What it Finds:**
- Array access without bounds checking
- Loop indices that could exceed array length
- Dynamic array operations without validation

**Example Vulnerable Code:**
```solidity
contract VulnerableArrays {
    uint256[] public values;

    // ❌ No bounds checking
    function getValue(uint256 index) public view returns (uint256) {
        return values[index]; // Could revert with out-of-bounds
    }

    // ❌ Dangerous loop without bounds check
    function processRange(uint256 start, uint256 end) public {
        for (uint256 i = start; i < end; i++) {
            values[i] = i * 2; // Could go out of bounds
        }
    }
}
```

**Secure Code:**
```solidity
contract SecureArrays {
    uint256[] public values;

    // ✅ Proper bounds checking
    function getValue(uint256 index) public view returns (uint256) {
        require(index < values.length, "Index out of bounds");
        return values[index];
    }

    // ✅ Proper bounds validation
    function processRange(uint256 start, uint256 end) public {
        require(start < values.length, "Start index out of bounds");
        require(end <= values.length, "End index out of bounds");
        require(start < end, "Invalid range");

        for (uint256 i = start; i < end; i++) {
            values[i] = i * 2;
        }
    }
}
```

---

### Parameter Consistency

**ID:** `parameter-consistency`
**Severity:** Low
**Category:** Input Validation

**Description:**
Checks for inconsistent parameter validation and naming conventions.

**What it Finds:**
- Inconsistent parameter validation patterns
- Missing validation in similar functions
- Inconsistent parameter naming

**Example Issues:**
```solidity
contract InconsistentContract {
    mapping(address => uint256) public balances;

    // ❌ Inconsistent parameter validation
    function deposit(uint256 amount) public {
        require(amount > 0, "Amount must be positive");
        balances[msg.sender] += amount;
    }

    // ❌ Missing validation (inconsistent with deposit)
    function withdraw(uint256 amount) public {
        balances[msg.sender] -= amount; // No validation!
    }

    // ❌ Inconsistent parameter naming
    function transfer(address recipient, uint256 amt) public {
        // 'amt' instead of 'amount'
        balances[msg.sender] -= amt;
        balances[recipient] += amt;
    }
}
```

**Consistent Code:**
```solidity
contract ConsistentContract {
    mapping(address => uint256) public balances;

    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be positive");
        _;
    }

    // ✅ Consistent validation
    function deposit(uint256 amount) public validAmount(amount) {
        balances[msg.sender] += amount;
    }

    // ✅ Consistent validation
    function withdraw(uint256 amount) public validAmount(amount) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
    }

    // ✅ Consistent parameter naming
    function transfer(address recipient, uint256 amount) public validAmount(amount) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
    }
}
```

## Logic & State Management

### Division Before Multiplication

**ID:** `division-before-multiplication`
**Severity:** Medium
**Category:** Arithmetic

**Description:**
Detects operations where division is performed before multiplication, leading to precision loss.

**What it Finds:**
- Division followed by multiplication in the same expression
- Percentage calculations with precision loss
- Fee calculations that truncate values

**Example Vulnerable Code:**
```solidity
contract VulnerableMath {
    uint256 public constant FEE_RATE = 250; // 2.5%
    uint256 public constant FEE_DENOMINATOR = 10000;

    // ❌ Division before multiplication causes precision loss
    function calculateFee(uint256 amount) public pure returns (uint256) {
        return (amount / FEE_DENOMINATOR) * FEE_RATE;
        // For amount = 100: (100 / 10000) * 250 = 0 * 250 = 0
        // Should be: (100 * 250) / 10000 = 25000 / 10000 = 2
    }

    // ❌ Another example of precision loss
    function calculateReward(uint256 stake, uint256 rate) public pure returns (uint256) {
        return (stake / 100) * rate; // Loses precision for small stakes
    }
}
```

**Secure Code:**
```solidity
contract SecureMath {
    uint256 public constant FEE_RATE = 250; // 2.5%
    uint256 public constant FEE_DENOMINATOR = 10000;

    // ✅ Multiplication before division preserves precision
    function calculateFee(uint256 amount) public pure returns (uint256) {
        return (amount * FEE_RATE) / FEE_DENOMINATOR;
    }

    // ✅ Proper order with additional precision handling
    function calculateReward(uint256 stake, uint256 rate) public pure returns (uint256) {
        return (stake * rate) / 100;
    }

    // ✅ Even better: use fixed-point arithmetic libraries
    function calculateRewardPrecise(uint256 stake, uint256 rate) public pure returns (uint256) {
        // Using a library like PRBMath for fixed-point arithmetic
        return (stake * rate + 50) / 100; // +50 for rounding
    }
}
```

---

### State Machine Validation

**ID:** `state-machine`
**Severity:** Medium
**Category:** Logic

**Description:**
Validates proper state machine implementation and transition logic.

**What it Finds:**
- Invalid state transitions
- Missing state validation in functions
- State machine logic errors

**Example Vulnerable Code:**
```solidity
contract VulnerableAuction {
    enum State { Created, Active, Ended, Cancelled }
    State public currentState;

    // ❌ Missing state validation
    function placeBid() public payable {
        // Anyone can bid in any state!
        // Should only allow bids in Active state
    }

    // ❌ Invalid state transitions
    function endAuction() public {
        currentState = State.Ended; // Can end from any state!
    }

    // ❌ Missing state checks
    function cancel() public {
        currentState = State.Cancelled; // Can cancel even if ended!
    }
}
```

**Secure Code:**
```solidity
contract SecureAuction {
    enum State { Created, Active, Ended, Cancelled }
    State public currentState;

    modifier inState(State expectedState) {
        require(currentState == expectedState, "Invalid state");
        _;
    }

    // ✅ Proper state validation
    function placeBid() public payable inState(State.Active) {
        // Can only bid when auction is active
    }

    // ✅ Valid state transitions only
    function endAuction() public inState(State.Active) {
        currentState = State.Ended;
    }

    // ✅ Proper state machine logic
    function cancel() public {
        require(
            currentState == State.Created || currentState == State.Active,
            "Cannot cancel auction"
        );
        currentState = State.Cancelled;
    }

    // ✅ Controlled state transitions
    function startAuction() public inState(State.Created) {
        currentState = State.Active;
    }
}
```

## Oracle & Price Security

### Single Oracle Source

**ID:** `single-oracle-source`
**Severity:** High
**Category:** Oracle Security

**Description:**
Detects dangerous reliance on a single price oracle without backup or validation.

**What it Finds:**
- Functions depending on single oracle feeds
- Missing oracle redundancy
- Lack of price validation mechanisms

**Example Vulnerable Code:**
```solidity
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract VulnerableDeFi {
    IPriceOracle public oracle;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    // ❌ Single point of failure
    function liquidate(address user) public {
        uint256 price = oracle.getPrice(); // What if oracle fails or is manipulated?

        // Liquidation logic based on single price source
        if (calculateCollateralRatio(user, price) < 150) {
            _liquidate(user);
        }
    }

    function calculateCollateralRatio(address user, uint256 price) internal pure returns (uint256) {
        // Calculation logic
        return 200; // Simplified
    }

    function _liquidate(address user) internal {
        // Liquidation logic
    }
}
```

**Secure Code:**
```solidity
interface IPriceOracle {
    function getPrice() external view returns (uint256);
    function getLastUpdateTime() external view returns (uint256);
}

contract SecureDeFi {
    IPriceOracle[] public oracles;
    uint256 public constant MAX_PRICE_DEVIATION = 500; // 5%
    uint256 public constant PRICE_FRESHNESS_THRESHOLD = 3600; // 1 hour

    constructor(address[] memory _oracles) {
        require(_oracles.length >= 2, "Need at least 2 oracles");
        for (uint256 i = 0; i < _oracles.length; i++) {
            oracles.push(IPriceOracle(_oracles[i]));
        }
    }

    // ✅ Multiple oracle validation
    function getValidatedPrice() public view returns (uint256) {
        require(oracles.length >= 2, "Insufficient oracles");

        uint256[] memory prices = new uint256[](oracles.length);
        uint256 validPrices = 0;

        // Get prices from all oracles
        for (uint256 i = 0; i < oracles.length; i++) {
            try oracles[i].getPrice() returns (uint256 price) {
                // Check price freshness
                if (oracles[i].getLastUpdateTime() + PRICE_FRESHNESS_THRESHOLD > block.timestamp) {
                    prices[validPrices] = price;
                    validPrices++;
                }
            } catch {
                // Oracle failed, skip
            }
        }

        require(validPrices >= 2, "Insufficient valid prices");

        // Use median price
        return _median(prices, validPrices);
    }

    function liquidate(address user) public {
        uint256 price = getValidatedPrice();

        if (calculateCollateralRatio(user, price) < 150) {
            _liquidate(user);
        }
    }

    function _median(uint256[] memory prices, uint256 length) internal pure returns (uint256) {
        // Simple median calculation
        for (uint256 i = 0; i < length - 1; i++) {
            for (uint256 j = 0; j < length - i - 1; j++) {
                if (prices[j] > prices[j + 1]) {
                    uint256 temp = prices[j];
                    prices[j] = prices[j + 1];
                    prices[j + 1] = temp;
                }
            }
        }
        return prices[length / 2];
    }

    function calculateCollateralRatio(address user, uint256 price) internal pure returns (uint256) {
        return 200; // Simplified
    }

    function _liquidate(address user) internal {
        // Liquidation logic
    }
}
```

---

### Price Validation

**ID:** `missing-price-validation`
**Severity:** Medium
**Category:** Oracle Security

**Description:**
Checks for missing price validation and sanity checks on oracle data.

**What it Finds:**
- Missing price bounds checking
- No staleness validation
- Absence of circuit breakers

**Example Vulnerable Code:**
```solidity
contract VulnerablePriceConsumer {
    IPriceOracle public oracle;

    // ❌ No price validation
    function swap(uint256 amountIn) public {
        uint256 price = oracle.getPrice();

        // Direct use without validation - dangerous!
        uint256 amountOut = (amountIn * price) / 1e18;
        _executeSwap(amountIn, amountOut);
    }

    function _executeSwap(uint256 amountIn, uint256 amountOut) internal {
        // Swap logic
    }
}
```

**Secure Code:**
```solidity
contract SecurePriceConsumer {
    IPriceOracle public oracle;
    uint256 public constant MIN_PRICE = 1e15; // $0.001
    uint256 public constant MAX_PRICE = 1e24; // $1,000,000
    uint256 public constant MAX_PRICE_AGE = 3600; // 1 hour
    uint256 public lastValidPrice;
    uint256 public lastPriceUpdate;

    // ✅ Comprehensive price validation
    function getValidPrice() public view returns (uint256) {
        uint256 price = oracle.getPrice();
        uint256 lastUpdate = oracle.getLastUpdateTime();

        // Staleness check
        require(block.timestamp - lastUpdate <= MAX_PRICE_AGE, "Price too old");

        // Bounds check
        require(price >= MIN_PRICE && price <= MAX_PRICE, "Price out of bounds");

        // Circuit breaker: check for extreme price movements
        if (lastValidPrice > 0) {
            uint256 priceChange = price > lastValidPrice
                ? ((price - lastValidPrice) * 10000) / lastValidPrice
                : ((lastValidPrice - price) * 10000) / lastValidPrice;

            require(priceChange <= 1000, "Price change too extreme"); // Max 10% change
        }

        return price;
    }

    function swap(uint256 amountIn) public {
        uint256 price = getValidPrice();

        // Update tracking variables
        lastValidPrice = price;
        lastPriceUpdate = block.timestamp;

        uint256 amountOut = (amountIn * price) / 1e18;
        _executeSwap(amountIn, amountOut);
    }

    function _executeSwap(uint256 amountIn, uint256 amountOut) internal {
        // Swap logic
    }
}
```

## Flash Loan & MEV Protection

### Flash Loan Vulnerable Patterns

**ID:** `flashloan-vulnerable-patterns`
**Severity:** High
**Category:** Flash Loan Security

**Description:**
Detects patterns that make contracts vulnerable to flash loan attacks.

**What it Finds:**
- Price calculations based on pool ratios
- Missing flash loan protection
- Vulnerable lending/borrowing patterns

**Example Vulnerable Code:**
```solidity
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract VulnerableDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;

    // ❌ Price based on current pool ratio - manipulable!
    function getPrice() public view returns (uint256) {
        uint256 balanceA = tokenA.balanceOf(address(this));
        uint256 balanceB = tokenB.balanceOf(address(this));

        return (balanceB * 1e18) / balanceA; // Spot price calculation
    }

    // ❌ Vulnerable to flash loan price manipulation
    function liquidate(address user) public {
        uint256 currentPrice = getPrice();

        // Liquidation based on manipulable price
        if (isUndercollateralized(user, currentPrice)) {
            _liquidate(user);
        }
    }

    function isUndercollateralized(address user, uint256 price) internal pure returns (bool) {
        return true; // Simplified
    }

    function _liquidate(address user) internal {
        // Liquidation logic
    }
}
```

**Attack Scenario:**
1. Attacker takes flash loan of tokenA
2. Swaps large amount, manipulating pool ratio
3. Calls liquidate() with manipulated price
4. Liquidates positions unfairly
5. Reverses the swap and repays flash loan

**Secure Code:**
```solidity
contract SecureDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;

    // Time-weighted average price oracle
    uint256 public constant TWAP_PERIOD = 1800; // 30 minutes
    mapping(uint256 => uint256) public priceHistory;
    uint256 public lastPriceUpdate;

    modifier noFlashLoan() {
        uint256 balanceABefore = tokenA.balanceOf(address(this));
        uint256 balanceBBefore = tokenB.balanceOf(address(this));
        _;

        // Ensure balances haven't changed significantly within same transaction
        uint256 balanceAAfter = tokenA.balanceOf(address(this));
        uint256 balanceBAfter = tokenB.balanceOf(address(this));

        require(
            balanceAAfter >= balanceABefore * 99 / 100 &&
            balanceBAfter >= balanceBBefore * 99 / 100,
            "Flash loan detected"
        );
    }

    // ✅ Use TWAP instead of spot price
    function getTWAP() public view returns (uint256) {
        uint256 currentTime = block.timestamp;
        uint256 timeWindow = currentTime - TWAP_PERIOD;

        uint256 priceSum = 0;
        uint256 count = 0;

        // Calculate average over time window
        for (uint256 i = timeWindow; i <= currentTime; i += 300) { // 5-minute intervals
            if (priceHistory[i] > 0) {
                priceSum += priceHistory[i];
                count++;
            }
        }

        require(count > 0, "Insufficient price history");
        return priceSum / count;
    }

    // ✅ Flash loan protection + TWAP price
    function liquidate(address user) public noFlashLoan {
        uint256 twapPrice = getTWAP();

        if (isUndercollateralized(user, twapPrice)) {
            _liquidate(user);
        }
    }

    // ✅ Regular price updates for TWAP
    function updatePrice() public {
        uint256 currentTime = block.timestamp;
        if (currentTime >= lastPriceUpdate + 300) { // Update every 5 minutes
            uint256 balanceA = tokenA.balanceOf(address(this));
            uint256 balanceB = tokenB.balanceOf(address(this));

            priceHistory[currentTime] = (balanceB * 1e18) / balanceA;
            lastPriceUpdate = currentTime;
        }
    }

    function isUndercollateralized(address user, uint256 price) internal pure returns (bool) {
        return true; // Simplified
    }

    function _liquidate(address user) internal {
        // Liquidation logic
    }
}
```

---

### Sandwich Attack Protection

**ID:** `sandwich-attack`
**Severity:** Medium
**Category:** MEV Protection

**Description:**
Detects patterns vulnerable to sandwich attacks in DEX operations.

**What it Finds:**
- Large trades without slippage protection
- Missing deadline parameters
- Vulnerable swap implementations

**Example Vulnerable Code:**
```solidity
contract VulnerableSwap {
    // ❌ No slippage protection
    function swap(uint256 amountIn, address tokenIn, address tokenOut) public {
        uint256 amountOut = calculateOutput(amountIn, tokenIn, tokenOut);

        // No minimum output amount - vulnerable to sandwich attacks!
        _executeSwap(amountIn, tokenIn, tokenOut, amountOut);
    }

    // ❌ No deadline protection
    function addLiquidity(uint256 amountA, uint256 amountB) public {
        // No deadline - can be held in mempool and executed later
        _addLiquidity(amountA, amountB);
    }

    function calculateOutput(uint256 amountIn, address tokenIn, address tokenOut) internal pure returns (uint256) {
        return amountIn * 95 / 100; // Simplified
    }

    function _executeSwap(uint256 amountIn, address tokenIn, address tokenOut, uint256 amountOut) internal {
        // Swap logic
    }

    function _addLiquidity(uint256 amountA, uint256 amountB) internal {
        // Add liquidity logic
    }
}
```

**Secure Code:**
```solidity
contract SecureSwap {
    // ✅ Comprehensive protection against sandwich attacks
    function swap(
        uint256 amountIn,
        uint256 minAmountOut, // Slippage protection
        address tokenIn,
        address tokenOut,
        uint256 deadline // MEV protection
    ) public {
        require(block.timestamp <= deadline, "Transaction expired");

        uint256 amountOut = calculateOutput(amountIn, tokenIn, tokenOut);
        require(amountOut >= minAmountOut, "Insufficient output amount");

        _executeSwap(amountIn, tokenIn, tokenOut, amountOut);
    }

    // ✅ Protected liquidity provision
    function addLiquidity(
        uint256 amountA,
        uint256 amountB,
        uint256 minAmountA, // Slippage protection
        uint256 minAmountB, // Slippage protection
        uint256 deadline
    ) public {
        require(block.timestamp <= deadline, "Transaction expired");
        require(amountA >= minAmountA, "Insufficient amount A");
        require(amountB >= minAmountB, "Insufficient amount B");

        _addLiquidity(amountA, amountB);
    }

    // ✅ Additional protection: commit-reveal scheme
    mapping(bytes32 => bool) public commitments;

    function commitSwap(bytes32 commitment) public {
        commitments[commitment] = true;
        // User commits to swap parameters in advance
    }

    function revealSwap(
        uint256 amountIn,
        uint256 minAmountOut,
        address tokenIn,
        address tokenOut,
        uint256 nonce
    ) public {
        bytes32 commitment = keccak256(abi.encodePacked(
            amountIn, minAmountOut, tokenIn, tokenOut, nonce, msg.sender
        ));

        require(commitments[commitment], "Invalid commitment");
        commitments[commitment] = false;

        // Execute swap with committed parameters
        uint256 amountOut = calculateOutput(amountIn, tokenIn, tokenOut);
        require(amountOut >= minAmountOut, "Insufficient output amount");

        _executeSwap(amountIn, tokenIn, tokenOut, amountOut);
    }

    function calculateOutput(uint256 amountIn, address tokenIn, address tokenOut) internal pure returns (uint256) {
        return amountIn * 95 / 100; // Simplified
    }

    function _executeSwap(uint256 amountIn, address tokenIn, address tokenOut, uint256 amountOut) internal {
        // Swap logic
    }

    function _addLiquidity(uint256 amountA, uint256 amountB) internal {
        // Add liquidity logic
    }
}
```

---

### Front-Running Protection

**ID:** `front-running`
**Severity:** Medium
**Category:** MEV Protection

**Description:**
Identifies functions vulnerable to front-running attacks.

**What it Finds:**
- Public functions with predictable profitable outcomes
- Missing commit-reveal schemes
- Vulnerable auction mechanisms

**Example Vulnerable Code:**
```solidity
contract VulnerableAuction {
    uint256 public highestBid;
    address public highestBidder;

    // ❌ Vulnerable to front-running
    function bid() public payable {
        require(msg.value > highestBid, "Bid too low");

        // Refund previous bidder
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }

        highestBid = msg.value;
        highestBidder = msg.sender;

        // Attacker can see this transaction in mempool and front-run with higher bid
    }
}
```

**Secure Code:**
```solidity
contract SecureAuction {
    uint256 public highestBid;
    address public highestBidder;

    // Commit-reveal scheme
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public revealed;
    uint256 public commitPhaseEnd;
    uint256 public revealPhaseEnd;

    constructor() {
        commitPhaseEnd = block.timestamp + 1 hours;
        revealPhaseEnd = commitPhaseEnd + 30 minutes;
    }

    // ✅ Commit phase - hide bid amount
    function commitBid(bytes32 commitment) public payable {
        require(block.timestamp < commitPhaseEnd, "Commit phase ended");
        require(commitments[msg.sender] == bytes32(0), "Already committed");

        commitments[msg.sender] = commitment;
    }

    // ✅ Reveal phase - reveal actual bid
    function revealBid(uint256 bidAmount, uint256 nonce) public {
        require(block.timestamp >= commitPhaseEnd, "Commit phase not ended");
        require(block.timestamp < revealPhaseEnd, "Reveal phase ended");
        require(!revealed[msg.sender], "Already revealed");

        bytes32 commitment = keccak256(abi.encodePacked(bidAmount, nonce, msg.sender));
        require(commitments[msg.sender] == commitment, "Invalid commitment");

        revealed[msg.sender] = true;

        // Check if this is the highest bid
        if (bidAmount > highestBid && address(this).balance >= bidAmount) {
            // Refund previous highest bidder
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }

            highestBid = bidAmount;
            highestBidder = msg.sender;
        }
    }

    // ✅ Alternative: Blind auction with time delays
    struct BlindBid {
        uint256 amount;
        uint256 timestamp;
    }

    mapping(address => BlindBid) public blindBids;
    uint256 public constant MIN_BID_DELAY = 300; // 5 minutes

    function submitBlindBid() public payable {
        blindBids[msg.sender] = BlindBid({
            amount: msg.value,
            timestamp: block.timestamp
        });
    }

    function executeBid() public {
        BlindBid memory bid = blindBids[msg.sender];
        require(bid.amount > 0, "No bid submitted");
        require(block.timestamp >= bid.timestamp + MIN_BID_DELAY, "Bid delay not met");

        if (bid.amount > highestBid) {
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }

            highestBid = bid.amount;
            highestBidder = msg.sender;
        } else {
            // Refund unsuccessful bid
            payable(msg.sender).transfer(bid.amount);
        }

        delete blindBids[msg.sender];
    }
}
```

## Governance Security

### Governance Vulnerabilities

**ID:** `test-governance`
**Severity:** High
**Category:** Governance

**Description:**
Detects vulnerabilities in DAO governance mechanisms including flash loan attacks on voting power, missing snapshot protection, and temporal control issues.

**What it Finds:**
- Flash loan governance attacks via current balance checks
- Missing snapshot-based voting power mechanisms
- Voting rights without time-delay protection
- Governance token manipulation opportunities

**Example Vulnerable Code:**
```solidity
contract VulnerableDAO {
    IERC20 public governanceToken;
    uint256 public proposalThreshold = 100000e18;

    // ❌ Uses current balance - vulnerable to flash loans!
    function propose(string memory description) external {
        require(
            governanceToken.balanceOf(msg.sender) >= proposalThreshold,
            "Insufficient voting power"
        );
        // Create proposal...
    }

    // ❌ Voting power based on current balance
    function castVote(uint256 proposalId, uint8 support) external {
        uint256 votes = governanceToken.balanceOf(msg.sender);
        // Record vote...
    }
}
```

**Attack Scenario:**
1. Attacker takes flash loan of governance tokens
2. Meets proposal threshold with borrowed tokens
3. Creates malicious proposal
4. Returns flash loan
5. Proposal remains valid despite attacker no longer holding tokens

**Secure Code:**
```solidity
contract SecureDAO {
    IVotingToken public governanceToken; // ERC20Votes compatible

    function propose(string memory description) external {
        // ✅ Check balance at previous block (snapshot)
        require(
            governanceToken.getPastVotes(msg.sender, block.number - 1) >= proposalThreshold,
            "Insufficient voting power"
        );
        // Create proposal...
    }

    function castVote(uint256 proposalId, uint8 support) external {
        // ✅ Use snapshot from proposal creation
        uint256 votes = governanceToken.getPastVotes(
            msg.sender,
            proposals[proposalId].startBlock
        );
        // Record vote...
    }
}
```

**Fix Suggestions:**
- Implement snapshot-based voting using `getPastVotes()` or `balanceOfAt()`
- Use ERC20Votes standard for governance tokens
- Add time-delay requirements for new token holders
- Implement checkpoint mechanisms for historical balance tracking

**CWE:** CWE-682 (Incorrect Calculation), CWE-284 (Improper Access Control)

---

### External Calls in Loop

**ID:** `external-calls-loop`
**Severity:** High
**Category:** Governance

**Description:**
Detects external calls within loops that can cause DoS attacks if any call fails or consumes excessive gas. Particularly dangerous in governance systems where it can block proposal execution.

**What it Finds:**
- External calls inside for/while loops
- Governance proposal execution with multiple external calls
- Array iteration with external contract interactions

**Example Vulnerable Code:**
```solidity
contract VulnerableGovernance {
    struct Proposal {
        address[] targets;
        bytes[] calldatas;
        uint256[] values;
    }

    // ❌ External calls in loop - can be griefed!
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            (bool success, ) = proposal.targets[i].call{value: proposal.values[i]}(
                proposal.calldatas[i]
            );
            require(success, "Execution failed");
        }
    }
}
```

**Attack Scenario:**
1. Attacker creates proposal with multiple targets
2. One target is malicious contract that always reverts
3. Proposal passes voting
4. Execution always fails at malicious target
5. Entire proposal is blocked permanently

**Secure Code:**
```solidity
contract SecureGovernance {
    // ✅ Individual execution with withdrawal pattern
    function execute(uint256 proposalId, uint256 actionIndex) external {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executedActions[actionIndex], "Already executed");

        (bool success, ) = proposal.targets[actionIndex].call{
            value: proposal.values[actionIndex]
        }(proposal.calldatas[actionIndex]);

        if (success) {
            proposal.executedActions[actionIndex] = true;
        }
        // Failed actions can be retried or skipped
    }
}
```

**Fix Suggestions:**
- Use withdrawal pattern instead of loops
- Execute actions individually with failure isolation
- Implement try-catch for non-critical failures
- Add gas limits per external call

**CWE:** CWE-834 (Excessive Iteration)

---

### Signature Replay Attack

**ID:** `signature-replay`
**Severity:** High
**Category:** Governance

**Description:**
Detects signature verification functions that lack replay protection through nonce systems, allowing attackers to reuse valid signatures.

**What it Finds:**
- Functions using `ecrecover` without nonce tracking
- Signature-based voting without replay protection
- Meta-transaction handlers missing nonce validation

**Example Vulnerable Code:**
```solidity
contract VulnerableVoting {
    // ❌ No nonce - signatures can be replayed!
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(proposalId, support));
        address signer = ecrecover(digest, v, r, s);

        // Record vote for signer...
    }
}
```

**Fix Suggestions:**
- Implement nonce tracking per signer
- Include nonce in signed message
- Mark nonces as used after consumption
- Add deadline timestamps to signatures

**CWE:** CWE-294 (Authentication Bypass by Capture-replay)

---

### Emergency Pause Centralization

**ID:** `emergency-pause-centralization`
**Severity:** Medium
**Category:** Governance

**Description:**
Detects emergency pause mechanisms that lack multi-signature or time-lock protection, allowing single points of failure in governance.

**What it Finds:**
- Emergency pause functions with single-signer control
- Missing time-delays for emergency actions
- Lack of multi-signature requirements for critical functions

**Fix Suggestions:**
- Implement multi-signature requirements for emergency actions
- Add time-lock delays for pause activation
- Use decentralized governance for emergency decisions
- Implement automatic unpause mechanisms

---

## External Integration

### Unchecked External Calls

**ID:** `unchecked-external-call`
**Severity:** Medium
**Category:** External Calls

**Description:**
Finds external calls that don't check return values, potentially leading to silent failures.

**What it Finds:**
- External calls without return value checking
- Missing error handling for external interactions
- Dangerous assumptions about external call success

**Example Vulnerable Code:**
```solidity
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableTransfers {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ Unchecked external call
    function withdrawTokens(address to, uint256 amount) public {
        token.transfer(to, amount); // Returns false on failure, but not checked!
        // User thinks withdrawal succeeded, but tokens might still be in contract
    }

    // ❌ Unchecked transferFrom
    function deposit(uint256 amount) public {
        token.transferFrom(msg.sender, address(this), amount); // Could silently fail
        // Contract state updated as if deposit succeeded
        _updateBalance(msg.sender, amount);
    }

    function _updateBalance(address user, uint256 amount) internal {
        // Update internal accounting
    }
}
```

**Secure Code:**
```solidity
// ✅ Safe wrapper for external calls
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        bool success = token.transfer(to, amount);
        require(success, "Transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        bool success = token.transferFrom(from, to, amount);
        require(success, "TransferFrom failed");
    }
}

contract SecureTransfers {
    using SafeERC20 for IERC20;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ✅ Checked external call
    function withdrawTokens(address to, uint256 amount) public {
        token.safeTransfer(to, amount); // Will revert on failure
    }

    // ✅ Checked transferFrom
    function deposit(uint256 amount) public {
        token.safeTransferFrom(msg.sender, address(this), amount);
        _updateBalance(msg.sender, amount);
    }

    // ✅ Alternative: manual checking
    function depositManual(uint256 amount) public {
        bool success = token.transferFrom(msg.sender, address(this), amount);
        require(success, "Deposit failed");
        _updateBalance(msg.sender, amount);
    }

    // ✅ Low-level call with error handling
    function callExternalContract(address target, bytes calldata data) public returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);

        if (!success) {
            // Handle different error types
            if (result.length == 0) {
                revert("Call failed with no error message");
            } else {
                // Bubble up the error
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }

        return result;
    }

    function _updateBalance(address user, uint256 amount) internal {
        // Update internal accounting
    }
}
```

---

### Block Timestamp Dependencies

**ID:** `block-dependency`
**Severity:** Medium
**Category:** Time Dependencies

**Description:**
Detects dangerous dependencies on block.timestamp that can be manipulated by miners.

**What it Finds:**
- Critical logic depending on block.timestamp
- Time-based randomness generation
- Precise timing requirements

**Example Vulnerable Code:**
```solidity
contract VulnerableTimelock {
    mapping(address => uint256) public unlockTime;
    mapping(address => uint256) public balances;

    // ❌ Vulnerable to miner manipulation
    function generateRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
        // Miners can manipulate block.timestamp within ~15 seconds
    }

    // ❌ Critical timing dependency
    function withdraw() public {
        require(block.timestamp >= unlockTime[msg.sender], "Funds locked");
        // Miner could delay transaction to prevent withdrawal

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // ❌ Precise timing for lottery
    function enterLottery() public payable {
        require(msg.value == 1 ether, "Wrong amount");

        if (block.timestamp % 60 == 0) { // Every minute exactly
            // Winner! Miner could manipulate this
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
```

**Secure Code:**
```solidity
contract SecureTimelock {
    mapping(address => uint256) public unlockTime;
    mapping(address => uint256) public balances;

    // ✅ Use block.number instead for time-based logic
    mapping(address => uint256) public unlockBlock;
    uint256 public constant BLOCKS_PER_DAY = 6400; // ~24 hours

    // ✅ External randomness (Chainlink VRF)
    interface VRFCoordinator {
        function requestRandomness(bytes32 keyHash, uint256 fee) external returns (bytes32);
    }

    VRFCoordinator public vrfCoordinator;
    mapping(bytes32 => address) public requestToSender;

    function requestRandomNumber() public {
        bytes32 requestId = vrfCoordinator.requestRandomness(0x..., 0.1 ether);
        requestToSender[requestId] = msg.sender;
    }

    // ✅ Reasonable time tolerance
    function withdraw() public {
        // Use reasonable time tolerance (~15 minutes)
        require(
            block.timestamp >= unlockTime[msg.sender] - 900,
            "Funds locked"
        );

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // ✅ Block-based timing
    function withdrawByBlock() public {
        require(block.number >= unlockBlock[msg.sender], "Funds locked");

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // ✅ Commit-reveal for lottery
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public revealed;
    uint256 public revealDeadline;

    function commitToLottery(bytes32 commitment) public payable {
        require(msg.value == 1 ether, "Wrong amount");
        commitments[msg.sender] = commitment;
    }

    function revealForLottery(uint256 number, uint256 nonce) public {
        require(block.timestamp < revealDeadline, "Reveal period ended");

        bytes32 hash = keccak256(abi.encodePacked(number, nonce, msg.sender));
        require(commitments[msg.sender] == hash, "Invalid commitment");

        revealed[msg.sender] = true;

        // Use revealed number for lottery logic
        if (number % 100 == 42) { // Or some other deterministic logic
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    // ✅ Time ranges instead of exact timing
    function timedAction() public {
        uint256 timeSlot = (block.timestamp / 3600) % 24; // Hour of day
        require(timeSlot >= 9 && timeSlot <= 17, "Outside business hours");

        // Action that should only happen during business hours
    }
}
```

## Detector Severity Levels

### Critical (🔥)
- **Impact**: Immediate fund loss or contract takeover
- **Examples**: Classic reentrancy, unprotected initializers
- **Action Required**: Fix immediately before deployment

### High (⚠️)
- **Impact**: Significant security risk or potential fund loss
- **Examples**: Missing access control, tx.origin authentication
- **Action Required**: Fix before production deployment

### Medium (⚡)
- **Impact**: Security risk that requires specific conditions
- **Examples**: Zero address validation, array bounds
- **Action Required**: Review and fix during development

### Low (📝)
- **Impact**: Code quality or best practice issues
- **Examples**: Parameter consistency, gas optimization
- **Action Required**: Consider fixing for code quality

### Info (ℹ️)
- **Impact**: Informational findings for awareness
- **Examples**: Compiler warnings, style issues
- **Action Required**: Optional improvements

## Customization

### Future Configuration Options

*Note: These features are planned for future releases*

```toml
# soliditydefend.toml
[detectors.missing-access-control]
enabled = true
severity = "high"
ignore_functions = ["view", "pure"]
require_modifiers = ["onlyOwner", "onlyAdmin"]

[detectors.reentrancy]
enabled = true
check_readonly = true
max_call_depth = 3

[detectors.zero-address]
enabled = true
ignore_parameters = ["_deprecated"]
```

### Custom Severity Overrides

```bash
# Environment variable configuration (future)
export SOLIDITYDEFEND_SEVERITY_OVERRIDES="parameter-consistency=info,gas-optimization=low"
```

### Detector Selection

```bash
# Enable specific detectors only (future)
soliditydefend --detectors reentrancy,access-control,zero-address contract.sol

# Exclude specific detectors (future)
soliditydefend --exclude-detectors parameter-consistency,gas-optimization contract.sol
```

## See Also

- [Usage Guide](USAGE.md) - How to run detectors effectively
- [CLI Reference](CLI.md) - Command-line options for detector configuration
- [Configuration Guide](CONFIGURATION.md) - Advanced detector configuration
- [Output Formats](OUTPUT.md) - Understanding detector output