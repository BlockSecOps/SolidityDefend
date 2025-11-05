# Reentrancy Detectors

**Total:** 10 detectors

---

## Flash Loan Reentrancy Combo

**ID:** `flash-loan-reentrancy-combo`  
**Severity:** Critical  
**Categories:** FlashLoan, Reentrancy  

### Description



### Details

Flash Loan Reentrancy Combo Detector

Detects combined flash loan + reentrancy attacks (Penpie $27M pattern).
Identifies state inconsistency during flash loan callbacks.

### Source

`crates/detectors/src/flashloan_enhanced/reentrancy_combo.rs`

---

## Transient Storage Reentrancy

**ID:** `transient-storage-reentrancy`  
**Severity:** Critical  
**Categories:** Reentrancy, ReentrancyAttacks  

### Description



### Details

Transient Storage Reentrancy Detector

Detects low-gas reentrancy vulnerabilities via EIP-1153 transient storage (TSTORE/TLOAD).

**CRITICAL Vulnerability**: EIP-1153 breaks the decade-old assumption that transfer() and
send() are safe against reentrancy. With only 100 gas cost per TSTORE, attackers can now
modify state within the 2300 gas stipend.

## Attack Scenario

```solidity
contract Vulnerable {
mapping(address => uint256) public balances;

function withdraw() public {
uint256 amount = balances[msg.sender];
require(amount > 0);

// ❌ UNSAFE: transfer() no longer prevents reentrancy
payable(msg.sender).transfer(amount);

balances[msg.sender] = 0;
}
}

contract Attacker {
uint256 transient counter;  // Only 100 gas per TSTORE!

receive() external payable {
if (counter < 10) {
counter++;  // Reentrancy with 2300 gas!
Vulnerable(msg.sender).withdraw();
}
}
}
```

## Detection Strategy

1. Find contracts using transient storage (Solidity 0.8.24+)
2. Identify external calls with gas limits (transfer, send, call{gas: X})
3. Check if state changes occur after external calls
4. Flag patterns vulnerable to transient storage reentrancy

Severity: CRITICAL
Category: Reentrancy

References:
- ChainSecurity: TSTORE Low Gas Reentrancy research (2024)
- EIP-1153: https://eips.ethereum.org/EIPS/eip-1153

### Source

`crates/detectors/src/transient/reentrancy.rs`

---

## Classic Reentrancy

**ID:** `classic-reentrancy`  
**Severity:** High  
**Categories:** ReentrancyAttacks  

### Description



### Source

`crates/detectors/src/reentrancy.rs`

---

## Classic Reentrancy

**ID:** `classic-reentrancy`  
**Severity:** High  
**Categories:** ReentrancyAttacks  

### Description



### Source

`crates/detectors/src/reentrancy.rs`

---

## Diamond Init Reentrancy

**ID:** `diamond-init-reentrancy`  
**Severity:** High  
**Categories:** Diamond, Upgradeable, Reentrancy  
**CWE:** CWE-841, CWE-841, CWE-841, CWE-841  

### Description



### Source

`crates/detectors/src/diamond_init_reentrancy.rs`

---

## Hook Reentrancy Enhanced

**ID:** `hook-reentrancy-enhanced`  
**Severity:** High  
**Categories:** DeFi, Reentrancy  

### Description



### Details

Hook-Based Reentrancy Enhanced Detector

Detects reentrancy vulnerabilities specific to Uniswap V4 hooks and similar systems.
Uniswap V4 introduces hooks that execute at specific points during swaps:
- beforeSwap: Executes before the swap
- afterSwap: Executes after the swap

These hooks create new attack surfaces if they make external calls without
proper reentrancy protection, as they can re-enter the pool during a swap.

### Source

`crates/detectors/src/defi_advanced/hook_reentrancy_enhanced.rs`

---

## Vault Hook Reentrancy

**ID:** `vault-hook-reentrancy`  
**Severity:** High  
**Categories:** Reentrancy, DeFi  
**CWE:** CWE-841, CWE-362  

### Description



### Source

`crates/detectors/src/vault_hook_reentrancy.rs`

---

## Flashloan Callback Reentrancy

**ID:** `flashloan-callback-reentrancy`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

Flash Loan Callback Reentrancy Detector

Detects reentrancy vulnerabilities in flash loan callbacks:
- State changes after external call
- No reentrancy guard
- Unchecked callback return value

Severity: MEDIUM

### Remediation

- Add nonReentrant modifier from OpenZeppelin

### Source

`crates/detectors/src/flashloan/callback_reentrancy.rs`

---

## Transient Reentrancy Guard

**ID:** `transient-reentrancy-guard`  
**Severity:** Medium  
**Categories:** Reentrancy  

### Description



### Details

Transient Reentrancy Guard Detector

Detects improper usage of transient storage for reentrancy guards with low-gas external calls.

## Problem

While transient storage is ideal for reentrancy guards (gas-efficient, auto-clears), it
creates a new attack vector when combined with low-gas external calls that can now modify state.

## Vulnerability Example

```solidity
contract VulnerableGuard {
uint256 transient private locked;

modifier nonReentrant() {
require(locked == 0, "Reentrant");
locked = 1;
_;
locked = 0;
}

function withdraw() public nonReentrant {
uint256 amount = balances[msg.sender];

// ❌ transfer() can now set transient state with 100 gas
payable(msg.sender).transfer(amount);

// Traditional guard still works, but attacker can use TSTORE
// to manipulate read-only reentrancy or side channels
balances[msg.sender] = 0;
}
}
```

## New Attack Surface

With EIP-1153, even low-gas calls (transfer, send) can:
1. Set transient storage flags to coordinate multi-step attacks
2. Signal state to other contracts in same transaction
3. Pollute transient state for subsequent calls

Severity: MEDIUM
Category: Reentrancy

### Source

`crates/detectors/src/transient/guard.rs`

---

## Read Only Reentrancy

**ID:** `readonly-reentrancy`
**Severity:** Medium
**Categories:** Reentrancy

### Description

Read-only functions may be vulnerable to view reentrancy.

### Details

Read-only reentrancy (also called "view reentrancy") is a subtle vulnerability where view/pure functions that read from external contracts can be exploited. This occurs when a contract's view function calls another contract that can manipulate its state during execution, causing inconsistent reads.

**Vulnerability Pattern:**

A view function that:
1. Calls an external contract to read data
2. Uses that data in calculations
3. Returns values that depend on that external state

The external contract can manipulate what the view function sees, leading to:
- Incorrect price calculations in DeFi protocols
- Manipulated collateral valuations
- Incorrect voting power calculations
- Flash loan price manipulation

**Example Vulnerable Code:**

```solidity
contract PriceOracle {
    IVault public vault;

    // ❌ View function vulnerable to read-only reentrancy
    function getCollateralValue(address token, uint amount) external view returns (uint) {
        uint price = vault.getPrice(token);  // External call in view
        return amount * price / 1e18;
    }
}

contract AttackerVault {
    uint public manipulatedPrice;

    function getPrice(address token) external view returns (uint) {
        // During a withdrawal callback, this could return manipulated values
        if (inCallback) {
            return manipulatedPrice;  // Return inflated price
        }
        return realPrice;
    }
}
```

**Attack Scenario:**

1. Attacker initiates a withdrawal from a vault
2. During the withdrawal callback (before state updates):
   - Attacker calls a view function that reads vault state
   - View function sees inconsistent state (tokens withdrawn but balances not updated)
   - Attacker exploits the inconsistent view to drain funds

**Real-World Example:**

The Curve Finance read-only reentrancy vulnerability (2023) allowed attackers to manipulate LP token prices during withdrawal callbacks, leading to significant losses across multiple DeFi protocols.

### Remediation

- **Use Reentrancy Guards on State-Changing Functions:** Even though view functions can't change state directly, protect functions that change state before view functions are called
- **Implement Checks-Effects-Interactions Pattern:** Update state before making external calls
- **Use Reentrancy Locks:** Implement locks that prevent external calls during sensitive operations
- **Query Internal State:** Prefer reading internal state over external contract state when possible
- **Validate External Data:** Always validate data from external contracts, even in view functions

**Secure Pattern:**

```solidity
contract SecurePriceOracle {
    IVault public vault;
    bool private locked;

    modifier noReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }

    // ✅ Protected against read-only reentrancy
    function getCollateralValue(address token, uint amount) external view returns (uint) {
        require(!locked, "No reentrancy");  // Check lock even in view
        uint price = vault.getPrice(token);
        require(price > 0 && price < MAX_PRICE, "Invalid price");  // Validate
        return amount * price / 1e18;
    }

    // Or use snapshot-based approach
    mapping(address => uint) public cachedPrices;

    function updatePrice(address token) external noReentrant {
        cachedPrices[token] = vault.getPrice(token);
    }

    function getCollateralValueSafe(address token, uint amount) external view returns (uint) {
        uint price = cachedPrices[token];  // Use cached internal state
        return amount * price / 1e18;
    }
}
```

### Source

`crates/detectors/src/reentrancy.rs`

---

