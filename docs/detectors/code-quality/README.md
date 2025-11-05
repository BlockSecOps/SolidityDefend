# Code Quality Detectors

**Total:** 37 detectors

---

## AI Agent Prompt Injection

**ID:** `ai-agent-prompt-injection`  
**Severity:** High  
**Categories:** Logic  

### Description

Detects prompt injection vulnerabilities in AI contracts

### Remediation

- Sanitize AI inputs: require(isValidPrompt(userInput))

### Source

`ai_agent/prompt_injection.rs`

---

## AI Agent Resource Exhaustion

**ID:** `ai-agent-resource-exhaustion`  
**Severity:** Medium  
**Categories:** Logic  

### Description

Detects computational DOS attacks via resource exhaustion

### Remediation

- Add rate limiting: require(lastCall[msg.sender] + COOLDOWN < block.timestamp)

### Source

`ai_agent/resource_exhaustion.rs`

---

## Batch Transfer Overflow

**ID:** `batch-transfer-overflow`  
**Severity:** Critical  
**Categories:** Logic, BestPractices  

### Description

Detects multiplication of array length with value that can overflow in batch transfers

### Vulnerable Patterns

- array.length * value (direct overflow risk)
- Intermediate variable multiplying count with value
- Using unchecked block with multiplication (bypasses Solidity 0.8+ overflow protection)

### Source

`src/batch_transfer_overflow.rs`

---

## Block Dependency

**ID:** `block-dependency`  
**Severity:** Medium  
**Categories:** Timestamp, DeFi  
**CWE:** CWE-330, CWE-367  

### Description

Dangerous dependence on block properties including timestamp manipulation for time-based calculations

### Source

`src/timestamp.rs`

---

## Circular Dependency

**ID:** `circular-dependency`  
**Severity:** High  
**Categories:** Logic, ExternalCalls  
**CWE:** CWE-674, CWE-834  

### Description

Detects circular dependencies between contracts that can lead to deadlocks, infinite recursion, or DOS attacks

### Vulnerable Patterns

- Callback pattern without reentrancy guard
- Mutual contract calls without depth limit

### Source

`src/circular_dependency.rs`

---

## Division Before Multiplication

**ID:** `division-before-multiplication`  
**Severity:** Medium  
**Categories:** Logic  
**CWE:** CWE-682  

### Description

Detects operations that perform division before multiplication, causing precision loss

### Remediation

- Reorder operations to multiply before dividing, or use fixed-point arithmetic
- Reorder operations to multiply before dividing
- Combine divisions into a single operation or use higher precision arithmetic

### Source

`logic/division_order.rs`

---

## DoS by Failed Transfer

**ID:** `dos-failed-transfer`  
**Severity:** High  
**Categories:** Logic, BestPractices  

### Description

Detects push pattern transfers that can cause DoS if recipient reverts. Use pull pattern instead.

### Vulnerable Patterns

- transfer() or send() in a function that updates state after
- Transfer happens before state updates (push pattern)
- Transfer in a loop (especially dangerous)
- Transfer without error handling
- Refund pattern (transfer to previous participant)

### Source

`src/dos_failed_transfer.rs`

---

## DOS via Unbounded Operation

**ID:** `dos-unbounded-operation`  
**Severity:** High  
**Categories:** Logic  
**CWE:** CWE-400, CWE-834  

### Description

Detects unbounded loops and operations that can cause denial of service

### Vulnerable Patterns

- Loop over unbounded array
- Deleting large structures

### Source

`src/dos_unbounded_operation.rs`

---

## Emergency Function Abuse

**ID:** `emergency-function-abuse`  
**Severity:** Medium  
**Categories:** Auth, AccessControl  
**CWE:** CWE-269, CWE-284  

### Description

Detects emergency functions without time-locks or multi-sig protection, enabling admin abuse

### Vulnerable Patterns

- Explicit vulnerability comment
- Has admin access (onlyOwner, onlyGuardian)

### Source

`src/emergency_function_abuse.rs`

---

## External Calls in Loop

**ID:** `external-calls-loop`  
**Severity:** High  
**Categories:** ExternalCalls, Logic  

### Description

Detects external calls within loops that can cause DoS or unexpected behavior

### Source

`src/governance.rs`

---

## Floating Pragma

**ID:** `floating-pragma`  
**Severity:** Low  
**Categories:** BestPractices  
**CWE:** CWE-710  

### Description

Detects floating pragma directives (e.g., ^0.8.0) that allow compilation with multiple compiler versions, potentially causing inconsistent behavior and security issues

### Vulnerable Patterns

- Caret operator (^) - floating pragma
- Range operator (>=) - floating pragma
- Multiple versions or complex ranges

### Remediation

- Lock pragma to specific version range with both lower and upper bounds: \

### Source

`src/floating_pragma.rs`

---

## Integer Overflow/Underflow

**ID:** `integer-overflow`  
**Severity:** High  
**Categories:** Logic, Validation  
**CWE:** CWE-190, CWE-191  

### Description

Detects unchecked arithmetic operations in Solidity < 0.8.0 or within unchecked blocks that can cause overflow/underflow

### Source

`src/integer_overflow.rs`

---

## Invalid State Transition

**ID:** `invalid-state-transition`  
**Severity:** High  
**Categories:** Logic  

### Description

Detects invalid state machine transitions and uninitialized states

### Source

`logic/state_machine.rs`

---

## Logic Error Patterns

**ID:** `logic-error-patterns`  
**Severity:** High  
**Categories:** BestPractices, Logic  

### Description

Detects division before multiplication and faulty reward calculations

### Remediation

- ❌ PRECISION LOSS ($63.8M in losses): \
      uint256 reward = (amount / totalSupply) * rewardRate; \
      // Result: 0 if amount < totalSupply! \
      \
      ✅ CORRECT ORDER: \
      uint256 reward = (amount * rewardRate) / totalSupply; \
      // Maximizes precision, multiply before divide \
      \
      ✅ BEST: Use fixed-point math: \
      uint256 reward = (amount * rewardRate * 1e18) / totalSupply / 1e18; \
      \
      Real incidents: \
      - Cork Protocol: $11M (May 2025) - Division rounding \
      - SIR.trading: $355K (March 2025) - Reward calculation \
      - Multiple 2024 incidents: $63.8M total
- Common reward distribution errors: \
     \
     1. Integer division truncation: \
     ❌ reward = balance / users; // Loses remainder \
     ✅ reward = balance * 1e18 / users / 1e18; \
     \
     2. Accumulating rounding errors: \
     ❌ Track individual rewards that sum != total \
     ✅ Use lastUser = total - sum(others) \
     \
     3. Division before multiplication: \
     ❌ (balance / total) * multiplier \
     ✅ (balance * multiplier) / total \
     \
     4. Missing remainder handling: \
     uint256 perUser = total / userCount; \
     uint256 remainder = total % userCount; \
     // Handle remainder explicitly!

### Source

`owasp2025/logic_error_patterns.rs`

---

## Missing Commit-Reveal Scheme

**ID:** `missing-commit-reveal`  
**Severity:** Medium  
**Categories:** BestPractices  

### Description

Detects auctions/bidding without commit-reveal protection

### Remediation

- Implement commit-reveal pattern: \
     \
     mapping(address => bytes32) public commitments; \
     mapping(address => uint256) public bids; \
     uint256 public commitDeadline; \
     uint256 public revealDeadline; \
     \
     // Phase 1: Commit (hide bid amount) \
     function commitBid(bytes32 commitment) external { \
      require(block.timestamp < commitDeadline); \
      commitments[msg.sender] = commitment; \
     } \
     \
     // Phase 2: Reveal (after commit deadline) \
     function revealBid(uint256 amount, bytes32 salt) external payable { \
      require(block.timestamp >= commitDeadline); \
      require(block.timestamp < revealDeadline); \
      \
      bytes32 commitment = keccak256(abi.encode(amount, salt)); \
      require(commitment == commitments[msg.sender], \

### Source

`privacy/missing_commit_reveal.rs`

---

## Nonce Reuse Vulnerability

**ID:** `nonce-reuse`  
**Severity:** Medium  
**Categories:** Auth, Logic  
**CWE:** CWE-294, CWE-330  

### Description

Detects improper nonce management that allows replay attacks or transaction reordering

### Vulnerable Patterns

- Nonce not incremented after use
- Nonce incremented before validation
- No nonce validation in signature verification

### Source

`src/nonce_reuse.rs`

---

## Optimistic Rollup Challenge Period Bypass

**ID:** `optimistic-challenge-bypass`  
**Severity:** Critical  
**Categories:** L2, CrossChain  
**CWE:** CWE-345, CWE-682  

### Description

Detects missing or insufficient challenge periods in optimistic rollup withdrawal finalization, allowing premature withdrawals before fraud proofs can be submitted

### Source

`src/optimistic_challenge_bypass.rs`

---

## Optimistic Fraud Proof Timing

**ID:** `optimistic-fraud-proof-timing`  
**Severity:** High  
**Categories:** L2  

### Description

Detects fraud proof timing issues

### Remediation

- Enforce challenge period: require(block.timestamp >= startTime + CHALLENGE_PERIOD)

### Source

`modular_blockchain/fraud_proof_timing.rs`

---

## Permit Signature Exploitation

**ID:** `permit-signature-exploit`  
**Severity:** High  
**Categories:** Auth, Validation, MEV  

### Description

Detects EIP-2612 permit() and EIP-712 signatures with insufficient validation that enable frontrunning, signature theft, and approval manipulation

### Vulnerable Patterns

- Missing deadline validation
- Missing or insufficient nonce tracking
- Permit callable by anyone (frontrunning risk)
- Weak ecrecover validation

### Source

`src/permit_signature_exploit.rs`

---

## Plaintext Secret Storage

**ID:** `plaintext-secret-storage`  
**Severity:** High  
**Categories:** BestPractices  

### Description

Detects unhashed secrets stored on-chain

### Remediation

- NEVER store plaintext secrets on-chain: \
     \
     ❌ INSECURE: \
     string private password = \

### Source

`privacy/plaintext_secret_storage.rs`

---

## Post-0.8.0 Overflow Detection

**ID:** `post-080-overflow`  
**Severity:** Medium  
**Categories:** Logic, BestPractices  

### Description

Detects unchecked blocks and assembly arithmetic ($223M Cetus impact)

### Remediation

- ⚠️ UNCHECKED BLOCKS BYPASS SOLIDITY 0.8.0+ PROTECTION! \
     \
     Solidity 0.8.0+ has automatic overflow/underflow checks, \
     but

### Source

`owasp2025/post_080_overflow.rs`

---

## Private Variable Exposure

**ID:** `private-variable-exposure`  
**Severity:** High  
**Categories:** BestPractices  

### Description

Detects sensitive data stored in 'private' variables (all blockchain data is public)

### Remediation

- CRITICAL:

### Source

`privacy/private_variable_exposure.rs`

---

## Selfdestruct Abuse

**ID:** `selfdestruct-abuse`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-404, CWE-670  

### Description

Detects unrestricted selfdestruct usage and force-sending ether vulnerabilities

### Vulnerable Patterns

- Public/External selfdestruct without access control
- Selfdestruct with user-controlled beneficiary
- Selfdestruct without time-lock or governance

### Source

`src/selfdestruct_abuse.rs`

---

## SELFDESTRUCT Recipient Manipulation

**ID:** `selfdestruct-recipient-manipulation`  
**Severity:** High  
**Categories:** Logic, Metamorphic, Deployment  

### Description

Detects unsafe SELFDESTRUCT usage with unchecked recipients that could force ether to contracts or manipulate balances

### Vulnerable Patterns

- User-controlled recipient
- SELFDESTRUCT to msg.sender
- SELFDESTRUCT in constructor (metamorphic pattern)

### Source

`src/selfdestruct_recipient.rs`

---

## Signature Malleability

**ID:** `signature-malleability`  
**Severity:** High  
**Categories:** Auth, Validation  
**CWE:** CWE-347, CWE-354  

### Description

Detects ECDSA signatures without proper 's' value validation, enabling signature replay via malleability

### Source

`src/signature_malleability.rs`

---

## Signature Replay Attack

**ID:** `signature-replay`  
**Severity:** High  
**Categories:** Auth, BestPractices  

### Description

Detects signature verification without replay protection (nonce system)

### Source

`src/governance.rs`

---

## Slashing Mechanism Vulnerability

**ID:** `slashing-mechanism`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-670, CWE-841  

### Description

Detects vulnerabilities in validator slashing mechanisms that can lead to unfair penalties or griefing attacks

### Vulnerable Patterns

- No cooldown between slashing events
- No maximum slashing limit per period
- Slashing without evidence verification

### Source

`src/slashing_mechanism.rs`

---

## Storage Collision Vulnerability

**ID:** `storage-collision`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-662, CWE-829  

### Description

Detects storage layout conflicts in proxy patterns and delegatecall usage that can cause data corruption

### Vulnerable Patterns

- Delegatecall without storage layout verification
- Delegatecall with variable target
- Vulnerability marker

### Source

`src/storage_collision.rs`

---

## Storage Slot Predictability

**ID:** `storage-slot-predictability`  
**Severity:** Medium  
**Categories:** BestPractices  

### Description

Detects predictable storage slots used for sensitive data

### Remediation

- Storage slots are predictable and can be read: \
     \
     ❌ Predictable: \
     uint256[10] private seeds; // Slot 0-9 are known \
     \
     ✅ Better approaches: \
     \
     1. Hash before storing: \
     mapping(address => bytes32) public seedHashes; \
     seedHashes[user] = keccak256(abi.encode(seed, salt)); \
     \
     2. Use commit-reveal: \
     mapping(address => bytes32) public commitments; \
     // Commit phase \
     commitments[user] = keccak256(abi.encode(value, salt)); \
     // Reveal phase (after commitment period) \
     require(keccak256(abi.encode(value, salt)) == commitments[user]); \
     \
     3. Store off-chain, only store hash on-chain

### Source

`privacy/storage_slot_predictability.rs`

---

## Transient Storage Composability Issues

**ID:** `transient-storage-composability`  
**Severity:** High  
**Categories:** Logic  

### Description

Detects multi-call and composability issues with transient storage that may break atomic operations

### Source

`transient/composability.rs`

---

## Transient Storage Misuse

**ID:** `transient-storage-misuse`  
**Severity:** Medium  
**Categories:** Logic  

### Description

Detects persistent data incorrectly stored in transient storage, causing state loss

### Source

`transient/misuse.rs`

---

## Transient Storage State Leak

**ID:** `transient-storage-state-leak`  
**Severity:** Medium  
**Categories:** Logic, BestPractices  

### Description

Detects missing cleanup of transient storage that could poison transaction state for subsequent calls

### Source

`transient/state_leak.rs`

---

## Unchecked External Call

**ID:** `unchecked-external-call`  
**Severity:** Medium  
**Categories:** ExternalCalls  
**CWE:** CWE-252  

### Description

External calls without return value checking

### Source

`src/external.rs`

---

## Uninitialized Storage Pointer

**ID:** `uninitialized-storage`  
**Severity:** High  
**Categories:** Logic, Validation  
**CWE:** CWE-457, CWE-824  

### Description

Detects uninitialized struct or array variables that point to storage slot 0, causing state corruption

### Vulnerable Patterns

- Struct declaration without initialization
- Array declaration without initialization
- Explicit vulnerability marker

### Source

`src/uninitialized_storage.rs`

---

## Unused State Variables

**ID:** `unused-state-variables`  
**Severity:** Low  
**Categories:** BestPractices, Logic  
**CWE:** CWE-563  

### Description

Detects state variables that are declared but never used, wasting storage slots and deployment gas

### Source

`src/unused_state_variables.rs`

---

## Validator Griefing Attack

**ID:** `validator-griefing`  
**Severity:** High  
**Categories:** Logic, MEV  
**CWE:** CWE-400, CWE-405  

### Description

Detects vulnerabilities where validators can be griefed through malicious actions that harm validators without benefiting attackers

### Vulnerable Patterns

- Free or low-cost slashing reports
- No rate limiting on validator actions
- Anyone can report without stake requirement

### Source

`src/validator_griefing.rs`

---

## Withdrawal Delay Vulnerability

**ID:** `withdrawal-delay`  
**Severity:** High  
**Categories:** Logic, AccessControl  
**CWE:** CWE-400, CWE-667  

### Description

Detects vulnerabilities in stake withdrawal mechanisms that can lock funds indefinitely or enable unfair delays

### Vulnerable Patterns

- Unbounded withdrawal delay
- Admin can arbitrarily extend withdrawal delay
- No emergency withdrawal mechanism

### Source

`src/withdrawal_delay.rs`

---

