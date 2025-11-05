# Code Quality Detectors

**Total:** 59 detectors

---

## Cross Rollup Atomicity

**ID:** `cross-rollup-atomicity`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description



### Details

Cross-Rollup Atomicity Detector

### Remediation

- Implement two-phase commit or rollback mechanism

### Source

`crates/detectors/src/modular_blockchain/cross_rollup_atomicity.rs`

---

## Intent Signature Replay

**ID:** `intent-signature-replay`  
**Severity:** Critical  
**Categories:** CrossChain, DeFi  

### Description



### Details

Analyzes signature verification for replay protection

### Remediation

- Add chainId validation: require(order.originChainId == block.chainid, \
- Add nonce validation and tracking:\n\
                 require(!usedNonces[order.user][order.nonce], \

### Source

`crates/detectors/src/erc7683/signature_replay.rs`

---

## Metamorphic Contract

**ID:** `metamorphic-contract`  
**Severity:** Critical  
**Categories:** Metamorphic, Deployment, Logic  

### Description



### Details

Metamorphic Contract Detection

Detects contracts that implement the metamorphic contract pattern using CREATE2 + SELFDESTRUCT,
which allows changing contract code at the same address, bypassing immutability assumptions.

### Source

`crates/detectors/src/metamorphic_contract.rs`

---

## Multisig Bypass

**ID:** `multisig-bypass`  
**Severity:** Critical  
**Categories:** AccessControl, Auth, Logic  

### Description



### Details

Multi-Signature Bypass Detection

Detects multi-signature wallets and governance systems with flawed signature verification
that allows threshold bypass, signature reuse, or owner manipulation.

### Source

`crates/detectors/src/multisig_bypass.rs`

---

## Optimistic Challenge Bypass

**ID:** `optimistic-challenge-bypass`  
**Severity:** Critical  
**Categories:** L2, CrossChain  
**CWE:** CWE-682, CWE-345, CWE-20  

### Description



### Source

`crates/detectors/src/optimistic_challenge_bypass.rs`

---

## Storage Collision

**ID:** `storage-collision`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-662, CWE-829  

### Description



### Details

Check if contract is upgradeable (proxy pattern)

### Remediation

- Ensure storage layout compatibility in '{}'. \
                    Verify that delegatecall targets have identical storage layout, \
                    use storage slots explicitly, or implement storage layout versioning.

### Source

`crates/detectors/src/storage_collision.rs`

---

## Ai Agent Decision Manipulation

**ID:** `ai-agent-decision-manipulation`  
**Severity:** High  
**Categories:** Oracle  

### Description



### Details

AI Agent Decision Manipulation Detector

### Source

`crates/detectors/src/ai_agent/decision_manipulation.rs`

---

## Ai Agent Prompt Injection

**ID:** `ai-agent-prompt-injection`  
**Severity:** High  
**Categories:** Logic  

### Description



### Details

AI Agent Prompt Injection Detector

### Source

`crates/detectors/src/ai_agent/prompt_injection.rs`

---

## Auction Timing Manipulation

**ID:** `auction-timing-manipulation`  
**Severity:** High  
**Categories:** MEV, DeFi  
**CWE:** CWE-362, CWE-841  

### Description



### Details

Check if function has auction timing vulnerability

### Source

`crates/detectors/src/auction_timing.rs`

---

## Block Stuffing Vulnerable

**ID:** `block-stuffing-vulnerable`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-405  

### Description



### Details

Check for block stuffing vulnerabilities

### Source

`crates/detectors/src/block_stuffing_vulnerable.rs`

---

## Celestia Data Availability

**ID:** `celestia-data-availability`  
**Severity:** High  
**Categories:** DataAvailability  

### Description



### Details

Celestia Data Availability Detector

Detects data availability layer issues in modular blockchain systems.

### Source

`crates/detectors/src/modular_blockchain/data_availability.rs`

---

## Centralization Risk

**ID:** `centralization-risk`  
**Severity:** High  
**Categories:** AccessControl  
**CWE:** CWE-269, CWE-284, CWE-269, CWE-284  

### Description



### Source

`crates/detectors/src/centralization_risk.rs`

---

## Circular Dependency

**ID:** `circular-dependency`  
**Severity:** High  
**Categories:** Logic, ExternalCalls  
**CWE:** CWE-674, CWE-834  

### Description



### Remediation

- Break circular dependency in '{}'. \
                    Use events instead of callbacks, implement depth limits for recursive calls, \
                    add reentrancy guards, use pull pattern instead of push, \
                    implement circuit breakers, and add visited tracking for graph traversal.

### Source

`crates/detectors/src/circular_dependency.rs`

---

## Delegation Loop

**ID:** `delegation-loop`  
**Severity:** High  
**Categories:** Auth, DeFi  
**CWE:** CWE-840, CWE-834  

### Description



### Details

Check if function has delegation loop vulnerability

### Remediation

- Implement loop detection in function '{}'. \
                    Example: Track delegation chain depth and reject if exceeds limit, \
                    or traverse delegation chain to detect cycles before allowing delegation.

### Source

`crates/detectors/src/delegation_loop.rs`

---

## Hardware Wallet Delegation

**ID:** `hardware-wallet-delegation`  
**Severity:** High  
**Categories:** AccessControl, Validation  
**CWE:** CWE-1188, CWE-665, CWE-672, CWE-404, CWE-269, CWE-250, CWE-494, CWE-345, CWE-306, CWE-862, CWE-20, CWE-704  

### Description



### Source

`crates/detectors/src/hardware_wallet_delegation.rs`

---

## Insufficient Randomness

**ID:** `insufficient-randomness`  
**Severity:** High  
**Categories:** Validation  
**CWE:** CWE-338, CWE-330  

### Description



### Source

`crates/detectors/src/insufficient_randomness.rs`

---

## Intent Nonce Management

**ID:** `intent-nonce-management`  
**Severity:** High  
**Categories:** DeFi, CrossChain  

### Description



### Details

Checks if nonce storage is properly declared
Checks for nonce validation and proper incrementation

### Source

`crates/detectors/src/erc7683/nonce_management.rs`

---

## Intent Solver Manipulation

**ID:** `intent-solver-manipulation`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description



### Details

Checks for solver authentication in fill functions
Checks for reentrancy protection

### Source

`crates/detectors/src/erc7683/solver_manipulation.rs`

---

## Logic Error Patterns

**ID:** `logic-error-patterns`  
**Severity:** High  
**Categories:** BestPractices, Logic  

### Description



### Details

Logic Error Patterns Detector (OWASP 2025)

Detects common logic errors that led to $63.8M in losses in 2024-2025:
- Division before multiplication (precision loss)
- Faulty reward distribution
- Rounding errors in calculations

### Source

`crates/detectors/src/owasp2025/logic_error_patterns.rs`

---

## Missing Slippage Protection

**ID:** `missing-slippage-protection`  
**Severity:** High  
**Categories:** DeFi, MEV  
**CWE:** CWE-20, CWE-682  

### Description



### Source

`crates/detectors/src/slippage_protection.rs`

---

## Optimistic Fraud Proof Timing

**ID:** `optimistic-fraud-proof-timing`  
**Severity:** High  
**Categories:** L2  

### Description



### Details

Optimistic Fraud Proof Timing Detector

### Source

`crates/detectors/src/modular_blockchain/fraud_proof_timing.rs`

---

## Permit Signature Exploit

**ID:** `permit-signature-exploit`  
**Severity:** High  
**Categories:** Auth, Validation, MEV  

### Description



### Details

Permit Signature Exploitation Detection

Detects EIP-2612 permit() and EIP-712 signature systems with insufficient validation,
enabling frontrunning, signature theft, and approval manipulation.

### Source

`crates/detectors/src/permit_signature_exploit.rs`

---

## Plaintext Secret Storage

**ID:** `plaintext-secret-storage`  
**Severity:** High  
**Categories:** BestPractices  

### Description



### Details

Plaintext Secret Storage Detector

### Remediation

- NEVER store plaintext secrets on-chain:\n\
                 \n\
                 ❌ INSECURE:\n\
                 string private password = \

### Source

`crates/detectors/src/privacy/plaintext_secret_storage.rs`

---

## Pool Donation Enhanced

**ID:** `pool-donation-enhanced`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description



### Details

Pool Donation Attack Enhanced Detector

Detects advanced pool donation attacks where an attacker:
1. Becomes the first depositor in an empty pool/vault
2. Donates tokens directly to the pool (not through deposit function)
3. Inflates the share price to make small deposits round down to zero shares
4. Steals subsequent depositors' funds

This enhanced version specifically targets:
- ERC-4626 vault share inflation attacks
- AMM pool initialization vulnerabilities
- Missing virtual/dead shares protection
- Unprotected share price calculations

### Remediation

- Mint initial dead shares or use virtual shares/assets in share calculation to prevent first-depositor manipulation

### Source

`crates/detectors/src/defi_advanced/pool_donation_enhanced.rs`

---

## Private Variable Exposure

**ID:** `private-variable-exposure`  
**Severity:** High  
**Categories:** BestPractices  

### Description



### Details

Private Variable Exposure Detector

Educational detector for developers misunderstanding "private" visibility.

### Source

`crates/detectors/src/privacy/private_variable_exposure.rs`

---

## Privilege Escalation Paths

**ID:** `privilege-escalation-paths`  
**Severity:** High  
**Categories:** AccessControl  

### Description



### Details

Privilege Escalation Paths Detector

Detects indirect paths to gain higher privileges through function chains,
delegatecall vulnerabilities, and role manipulation sequences.

### Source

`crates/detectors/src/access_control_advanced/privilege_escalation_paths.rs`

---

## Selfdestruct Abuse

**ID:** `selfdestruct-abuse`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-670, CWE-404  

### Description



### Details

Check if function has selfdestruct abuse

### Source

`crates/detectors/src/selfdestruct_abuse.rs`

---

## Selfdestruct Recipient Manipulation

**ID:** `selfdestruct-recipient-manipulation`  
**Severity:** High  
**Categories:** Logic, Metamorphic, Deployment  

### Description



### Details

SELFDESTRUCT Recipient Manipulation Detection

Detects contracts that use SELFDESTRUCT with user-controlled or unchecked recipients,
which can be used to force ether to contracts or manipulate accounting.

### Source

`crates/detectors/src/selfdestruct_recipient.rs`

---

## Signature Malleability

**ID:** `signature-malleability`  
**Severity:** High  
**Categories:** Auth, Validation  
**CWE:** CWE-347, CWE-354  

### Description



### Source

`crates/detectors/src/signature_malleability.rs`

---

## Slashing Mechanism

**ID:** `slashing-mechanism`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-841, CWE-670  

### Description



### Details

Check for slashing mechanism vulnerabilities

### Remediation

- Fix slashing mechanism in '{}'. \
                    Implement cooldown periods between slashings, add maximum slashing limits per period, \
                    require evidence verification with dispute periods, implement progressive penalties, \
                    add multi-signature requirements for large slashings, and protect against double-slashing.

### Source

`crates/detectors/src/slashing_mechanism.rs`

---

## Timestamp Manipulation

**ID:** `timestamp-manipulation`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-367, CWE-829  

### Description



### Details

Check for timestamp manipulation vulnerabilities

### Source

`crates/detectors/src/timestamp_manipulation.rs`

---

## Transient Storage Composability

**ID:** `transient-storage-composability`  
**Severity:** High  
**Categories:** Logic  

### Description



### Details

Transient Storage Composability Detector

Detects composability issues in contracts using EIP-1153 transient storage.

## Problem

Transient storage is cleared at the end of each transaction, which creates unexpected
behavior in multi-call scenarios and atomic transaction groups.

## Vulnerability Example

```solidity
contract TokenSwap {
uint256 transient private swapState;

function startSwap(uint256 amount) public {
swapState = amount;  // TSTORE
}

function completeSwap() public {
require(swapState > 0, "No active swap");  // May fail!
// ... swap logic
}
}

// ❌ This multicall will FAIL:
multicall.aggregate([
tokenSwap.startSwap(100),  // Sets transient state
tokenSwap.completeSwap()   // State is GONE if separate call
]);
```

## Detection Strategy

1. Identify functions that write to transient storage
2. Identify functions that read from transient storage
3. Flag if reader/writer are in separate functions (composability risk)
4. Warn about multicall compatibility issues

Severity: HIGH
Category: Logic

### Source

`crates/detectors/src/transient/composability.rs`

---

## Uninitialized Storage

**ID:** `uninitialized-storage`  
**Severity:** High  
**Categories:** Logic, Validation  
**CWE:** CWE-824, CWE-457  

### Description



### Source

`crates/detectors/src/uninitialized_storage.rs`

---

## Withdrawal Delay

**ID:** `withdrawal-delay`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-400, CWE-667  

### Description



### Details

Check for withdrawal delay vulnerabilities

### Remediation

- Fix withdrawal mechanism in '{}'. \
                    Implement maximum withdrawal delay caps, add emergency withdrawal options with penalties, \
                    prevent admin from extending delays arbitrarily, implement fair queue systems, \
                    add partial withdrawal capabilities, and document clear withdrawal timelines.

### Source

`crates/detectors/src/withdrawal_delay.rs`

---

## Ai Agent Resource Exhaustion

**ID:** `ai-agent-resource-exhaustion`  
**Severity:** Medium  
**Categories:** Logic  

### Description



### Details

AI Agent Resource Exhaustion Detector

### Source

`crates/detectors/src/ai_agent/resource_exhaustion.rs`

---

## Block Dependency

**ID:** `block-dependency`  
**Severity:** Medium  
**Categories:** Timestamp, DeFi  
**CWE:** CWE-330, CWE-367  

### Description



### Source

`crates/detectors/src/timestamp.rs`

---

## Deadline Manipulation

**ID:** `deadline-manipulation`  
**Severity:** Medium  
**Categories:** MEV, Logic  
**CWE:** CWE-367, CWE-362  

### Description



### Details

Check for deadline manipulation vulnerabilities

### Source

`crates/detectors/src/deadline_manipulation.rs`

---

## Emergency Function Abuse

**ID:** `emergency-function-abuse`  
**Severity:** Medium  
**Categories:** Auth, AccessControl  
**CWE:** CWE-269, CWE-284  

### Description



### Details

Check if function has emergency abuse vulnerability

### Source

`crates/detectors/src/emergency_function_abuse.rs`

---

## Emergency Withdrawal Abuse

**ID:** `emergency-withdrawal-abuse`  
**Severity:** Medium  
**Categories:** DeFi, AccessControl  
**CWE:** CWE-841, CWE-863  

### Description



### Details

Check if function has emergency withdrawal abuse vulnerability

### Remediation

- Refactor emergency withdrawal in function '{}' to respect lock periods \
                    and preserve user rewards. Example: Apply emergency fee but maintain \
                    lock period checks, or preserve accumulated rewards in escrow.

### Source

`crates/detectors/src/emergency_withdrawal_abuse.rs`

---

## Extcodesize Bypass

**ID:** `extcodesize-bypass`  
**Severity:** Medium  
**Categories:** Validation, Logic, Deployment  
**CWE:** CWE-754  

### Description



### Details

EXTCODESIZE Bypass Detection

Detects contracts that use EXTCODESIZE or address.code.length checks to validate
if an address is a contract, which can be bypassed by calling from a constructor.

### Source

`crates/detectors/src/extcodesize_bypass.rs`

---

## Missing Commit Reveal

**ID:** `missing-commit-reveal`  
**Severity:** Medium  
**Categories:** BestPractices  

### Description



### Details

Missing Commit-Reveal Detector

### Source

`crates/detectors/src/privacy/missing_commit_reveal.rs`

---

## Nonce Reuse

**ID:** `nonce-reuse`  
**Severity:** Medium  
**Categories:** Auth, Logic  
**CWE:** CWE-294, CWE-330  

### Description



### Details

Check for nonce reuse vulnerabilities

### Source

`crates/detectors/src/nonce_reuse.rs`

---

## Reward Calculation Manipulation

**ID:** `reward-calculation-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, Oracle  
**CWE:** CWE-682, CWE-20  

### Description



### Details

Check if function has reward calculation manipulation vulnerability

### Remediation

- Refactor reward calculation in function '{}' to use TWAP prices instead \
                    of spot prices, and remove incentives for price deviation. Example: Use \
                    time-weighted average prices and cap multipliers based on deviation.

### Source

`crates/detectors/src/reward_calculation.rs`

---

## Shadowing Variables

**ID:** `shadowing-variables`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-710  

### Description



### Remediation

- Rename shadowing variables in '{}'. \
                        Use different names for local variables to avoid shadowing state variables. \
                        Consider prefixes like '_' for function parameters or descriptive names.

### Source

`crates/detectors/src/shadowing_variables.rs`

---

## Short Address Attack

**ID:** `short-address-attack`  
**Severity:** Medium  
**Categories:** Validation, BestPractices  
**CWE:** CWE-20, CWE-707  

### Description



### Details


Detects functions that accept address parameters but don't validate msg.data.length.
Short address attacks occur when an attacker provides a truncated address, causing
the EVM to pad it and potentially shift other parameters like amounts.
Check if function is vulnerable to short address attack

### Source

`crates/detectors/src/short_address.rs`

---

## Storage Slot Predictability

**ID:** `storage-slot-predictability`  
**Severity:** Medium  
**Categories:** BestPractices  

### Description



### Details

Storage Slot Predictability Detector

### Source

`crates/detectors/src/privacy/storage_slot_predictability.rs`

---

## Transient Storage Misuse

**ID:** `transient-storage-misuse`  
**Severity:** Medium  
**Categories:** Logic  

### Description



### Details

Transient Storage Misuse Detector

Detects incorrect usage of transient storage for data that should persist across transactions.

## Problem

Developers may mistakenly use transient storage for data that needs to persist, causing
critical state loss between transactions.

## Vulnerability Examples

```solidity
contract MisuseExample {
// ❌ BAD: User balances in transient storage!
mapping(address => uint256) transient public balances;

function deposit() public payable {
balances[msg.sender] += msg.value;
// Lost at end of transaction!
}

function withdraw() public {
// Always zero in a new transaction!
uint256 amount = balances[msg.sender];
// ...
}
}
```

## Detection Strategy

Flag transient storage used for:
1. User balances, allowances, ownership
2. Contract configuration (owner, paused state)
3. Accounting data (totalSupply, reserves)
4. State that's read by view functions

Severity: MEDIUM
Category: Logic

### Source

`crates/detectors/src/transient/misuse.rs`

---

## Transient Storage State Leak

**ID:** `transient-storage-state-leak`  
**Severity:** Medium  
**Categories:** Logic, BestPractices  

### Description



### Details

Transient Storage State Leak Detector

Detects intentional lack of transient storage cleanup that blocks other contract interactions.

## Attack Scenario

Malicious contracts can intentionally leave transient storage "dirty" to interfere with
subsequent contract calls in the same transaction (e.g., multicall, router patterns).

```solidity
contract MaliciousContract {
uint256 transient private poisonState;

function poisonTransaction() public {
poisonState = type(uint256).max;
// Intentionally NO cleanup - pollutes transaction state
}
}

contract VictimContract {
uint256 transient private expectedCleanState;

function operate() public {
require(expectedCleanState == 0, "Dirty state detected");
// ❌ This fails if poisonTransaction() was called earlier!
}
}

// Attack:
multicall([
malicious.poisonTransaction(),  // Poisons transient storage
victim.operate()                // Fails due to polluted state
]);
```

Severity: MEDIUM
Category: Logic, BestPractices

### Source

`crates/detectors/src/transient/state_leak.rs`

---

## Unchecked External Call

**ID:** `unchecked-external-call`  
**Severity:** Medium  
**Categories:** ExternalCalls  
**CWE:** CWE-252  

### Description



### Details

Check statements for unchecked external calls

### Source

`crates/detectors/src/external.rs`

---

## Unchecked Math

**ID:** `unchecked-math`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-682, CWE-190  

### Description



### Remediation

- Remove unsafe unchecked blocks in '{}'. \
                        Solidity 0.8+ has built-in overflow protection. \
                        Only use 'unchecked' for gas optimization when overflow is mathematically impossible. \
                        Add explicit validation or use OpenZeppelin SafeMath for Solidity <0.8.

### Source

`crates/detectors/src/unchecked_math.rs`

---

## Unsafe Type Casting

**ID:** `unsafe-type-casting`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-704, CWE-197  

### Description



### Source

`crates/detectors/src/unsafe_type_casting.rs`

---

## Weak Commit Reveal

**ID:** `weak-commit-reveal`  
**Severity:** Medium  
**Categories:** MEV, DeFi  
**CWE:** CWE-362, CWE-841  

### Description



### Details

Check if function has weak commit-reveal vulnerability

### Remediation

- Increase commit-reveal delay in function '{}' to at least 5 minutes and \
                    add randomization. Example: Use VRF for unpredictable reveal windows or \
                    implement variable delays based on block hash.

### Source

`crates/detectors/src/weak_commit_reveal.rs`

---

## Deprecated Functions

**ID:** `deprecated-functions`  
**Severity:** Low  
**Categories:** Validation  
**CWE:** CWE-477  

### Description



### Source

`crates/detectors/src/deprecated_functions.rs`

---

## Floating Pragma

**ID:** `floating-pragma`  
**Severity:** Low  
**Categories:** BestPractices  
**CWE:** CWE-710, CWE-710, CWE-710, CWE-710  

### Description



### Source

`crates/detectors/src/floating_pragma.rs`

---

## Inefficient Storage

**ID:** `inefficient-storage`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description



### Source

`crates/detectors/src/inefficient_storage.rs`

---

## Redundant Checks

**ID:** `redundant-checks`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description



### Source

`crates/detectors/src/redundant_checks.rs`

---

## Unused State Variables

**ID:** `unused-state-variables`
**Severity:** Low
**Categories:** BestPractices, Logic
**CWE:** CWE-563

### Description



### Source

`crates/detectors/src/unused_state_variables.rs`

---

## Division Before Multiplication

**ID:** `division-before-multiplication`
**Severity:** Medium
**Categories:** Logic
**CWE:** CWE-682

### Description

Detects operations that perform division before multiplication, causing precision loss.

### Details

In Solidity, integer division truncates, discarding the fractional part. When division occurs before multiplication, significant precision loss can occur.

**Vulnerable Pattern:**
```solidity
uint result = (amount / price) * multiplier;  // ❌ Division first, loses precision
```

**Secure Pattern:**
```solidity
uint result = (amount * multiplier) / price;  // ✅ Multiplication first, preserves precision
```

**Impact:**
- Incorrect financial calculations
- Users receiving less tokens/funds than expected
- Rounding errors that compound over time
- Potential for economic exploits

**Example:**
- `amount = 100, price = 3, multiplier = 2`
- Division-first: `(100 / 3) * 2 = 33 * 2 = 66` (loses remainder)
- Multiplication-first: `(100 * 2) / 3 = 200 / 3 = 66` (same in this case, but generally more accurate)

### Remediation

- Always perform multiplication before division in calculations
- Use higher precision intermediate values when possible
- Consider using fixed-point math libraries (e.g., PRBMath) for financial calculations
- Document any intentional truncation behavior
- Test edge cases with small values where rounding matters

### Source

`crates/detectors/src/logic/division_order.rs`

---

## Invalid State Transition

**ID:** `invalid-state-transition`
**Severity:** High
**Categories:** Logic
**CWE:** CWE-664

### Description

Detects invalid state machine transitions and uninitialized states.

### Details

State machines are common in smart contracts (auctions, ICOs, multi-phase protocols). Invalid state transitions can allow:
- Bypassing required phases
- Re-entering completed states
- Operating in uninitialized/invalid states
- Breaking protocol invariants

**Common Issues:**
1. **Missing State Validation:** Functions don't check current state before executing
2. **Invalid Transitions:** Moving from State A directly to State C, skipping State B
3. **Uninitialized State:** No explicit initialization, allowing operation before setup
4. **State Confusion:** Multiple state variables with inconsistent values

**Example Vulnerability:**
```solidity
enum State { Pending, Active, Finalized }
State public state;

function withdraw() public {
    // ❌ No state check - can withdraw even when Pending
    payable(msg.sender).transfer(balance);
}
```

**Secure Pattern:**
```solidity
function withdraw() public {
    require(state == State.Finalized, "Not finalized");  // ✅ Validate state
    payable(msg.sender).transfer(balance);
}
```

### Remediation

- Add explicit state validation to all state-dependent functions
- Use modifiers for state checks: `modifier onlyInState(State _state)`
- Document valid state transitions
- Initialize state variables in constructor or initializer
- Consider using OpenZeppelin's StateMachine patterns
- Test all possible state transitions, including invalid ones

### Source

`crates/detectors/src/logic/state_machine.rs`

---

