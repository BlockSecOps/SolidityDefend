# Governance Detectors

**Total:** 4 detectors

---

## Test Governance

**ID:** `test-governance`
**Severity:** High
**Categories:** FlashLoan, Logic, BestPractices
**CWE:** CWE-682, CWE-284

### Description

Detects vulnerabilities in DAO governance mechanisms including flash loan attacks, delegation loops, and voting manipulation.

### Details

This detector identifies critical governance vulnerabilities that can be exploited to manipulate voting and governance decisions:

1. **Flash Loan Governance Attacks:** Functions that use current token balance for voting power without snapshot protection, allowing attackers to temporarily acquire large amounts of governance tokens to manipulate votes.

2. **Missing Snapshot Protection:** Governance tokens without snapshot mechanisms that enable flash loan attacks where attackers can temporarily acquire tokens to manipulate governance decisions.

3. **Temporal Control Issues:** Timing-based vulnerabilities in governance systems.

**Key Vulnerabilities:**
- Uses current balance instead of snapshot-based voting power
- No time-delayed voting rights for governance tokens
- Vulnerable to flash loan attacks on governance
- Missing snapshot mechanisms (block-based or time-based)

**Real-World Context:**
Flash loan governance attacks have been used to manipulate DAO votes and pass malicious proposals. Attackers temporarily acquire large amounts of governance tokens using flash loans, vote on proposals, and return the tokens within the same transaction.

### Remediation

- Implement snapshot-based voting power to prevent flash loan manipulation
- Use time-delayed voting rights for governance tokens
- Implement block-based or time-based snapshots for vote tracking
- Consider using established governance frameworks (Governor Bravo, OpenZeppelin Governor)
- Add proper timelock mechanisms for execution delays

### Source

`crates/detectors/src/governance.rs`

---

## External Calls Loop

**ID:** `external-calls-loop`
**Severity:** High
**Categories:** ExternalCalls, Logic
**CWE:** CWE-834

### Description

Detects external calls within loops that can cause DoS or unexpected behavior.

### Details

Functions that make external calls inside loops are vulnerable to denial of service and other attacks. This pattern is particularly dangerous in governance systems where proposal execution can be blocked.

**Vulnerable Patterns:**
- External calls (`.call()`, `.delegatecall()`, `.transfer()`, `.send()`) within loops
- Array iteration with external calls (e.g., DAO proposal execution)
- Governance execution patterns with loops and external calls

**Key Risks:**
- **DoS Attacks:** If any external call fails or consumes excessive gas, the entire loop fails
- **Governance Blocking:** In DAO systems, malicious proposals can block execution
- **Gas Griefing:** Excessive gas consumption can make functions unusable
- **Unpredictable Behavior:** External contracts can behave unpredictably

**Example Vulnerable Code:**
```solidity
function executeProposals(address[] calldata targets, bytes[] calldata data) external {
    for (uint i = 0; i < targets.length; i++) {
        // ❌ External call in loop - vulnerable to DoS
        targets[i].call(data[i]);
    }
}
```

### Remediation

- Avoid external calls in loops whenever possible
- Use a withdrawal pattern where users pull funds instead of pushing
- Implement batch processing with fail-safe mechanisms
- Consider circuit breakers for critical operations
- Allow individual execution of items instead of batch processing

**Secure Pattern:**
```solidity
// ✅ Withdrawal pattern - users pull their own funds
mapping(address => uint) public pendingWithdrawals;

function withdraw() external {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### Source

`crates/detectors/src/governance.rs`

---

## Signature Replay

**ID:** `signature-replay`
**Severity:** High
**Categories:** Auth, BestPractices
**CWE:** CWE-294

### Description

Detects signature verification without replay protection (nonce system).

### Details

Functions that verify signatures without implementing replay protection allow attackers to reuse valid signatures to perform unauthorized actions multiple times. This is particularly dangerous in governance systems for vote manipulation.

**Vulnerable Patterns:**
- Functions with signature parameters (v, r, s) without nonce tracking
- Use of `ecrecover` or `ECDSA.recover` without replay protection
- Signature verification without used-signature tracking

**Attack Scenario:**
1. User signs a valid message (e.g., voting transaction, token transfer)
2. Transaction is executed once successfully
3. Attacker captures the signature from blockchain
4. Attacker replays the same signature multiple times
5. Action is executed repeatedly without user consent

**Example Vulnerable Code:**
```solidity
function voteWithSignature(
    uint proposalId,
    bool support,
    uint8 v, bytes32 r, bytes32 s
) external {
    address signer = ecrecover(hash, v, r, s);
    // ❌ No nonce check - signature can be replayed
    _vote(signer, proposalId, support);
}
```

### Remediation

- Implement a nonce system to prevent signature replay attacks
- Include a unique nonce in the signed message structure
- Track used nonces in a mapping: `mapping(address => uint256) public nonces`
- Consider using EIP-712 for structured signature data
- Include chainId and contract address in signed message
- Optionally implement deadline/expiration for signatures

**Secure Pattern:**
```solidity
mapping(address => uint256) public nonces;

function voteWithSignature(
    uint proposalId,
    bool support,
    uint256 nonce,
    uint8 v, bytes32 r, bytes32 s
) external {
    // ✅ Verify nonce to prevent replay
    require(nonce == nonces[msg.sender], "Invalid nonce");

    bytes32 hash = keccak256(abi.encodePacked(proposalId, support, nonce));
    address signer = ecrecover(hash, v, r, s);

    // Increment nonce to prevent replay
    nonces[signer]++;

    _vote(signer, proposalId, support);
}
```

### Source

`crates/detectors/src/governance.rs`

---

## Emergency Pause Centralization

**ID:** `emergency-pause-centralization`
**Severity:** Medium
**Categories:** AccessControl, BestPractices
**CWE:** CWE-285

### Description

Detects emergency pause functionality controlled by a single entity without multisig protection.

### Details

Contracts with centralized emergency pause functionality create a single point of failure. A single compromised account can halt the entire system, leading to:

- **Single Point of Failure:** One compromised private key can shut down the entire protocol
- **Rug Pull Risk:** Malicious owner can pause withdrawals and trap user funds
- **Censorship:** Selective pausing can censor specific users or transactions
- **Availability Issues:** Accidental or malicious pausing affects all users

**Vulnerable Patterns:**
- Emergency functions (`pause`, `freeze`, `halt`, `stop`, `disable`, `shutdown`) with single-signer access control
- Use of `onlyOwner`, `onlyAdmin`, or `onlyGuardian` modifiers without multisig
- No timelock or governance mechanism for emergency actions

**Example Vulnerable Code:**
```solidity
// ❌ Single owner can pause entire system
function emergencyPause() external onlyOwner {
    _pause();
}

function emergencyWithdraw() external onlyOwner {
    // Owner can drain funds
    payable(owner).transfer(address(this).balance);
}
```

### Remediation

- Implement multisig requirements for emergency functions
- Use time delays (timelocks) for critical operations
- Require multiple signatures or governance approval for emergency actions
- Consider decentralized governance for emergency controls
- Implement graduated emergency powers (limited pause vs. full shutdown)
- Add transparency mechanisms (events, off-chain notifications)

**Secure Pattern:**
```solidity
// ✅ Requires multisig approval for emergency pause
address public immutable multisig;
uint256 public emergencyDelay = 1 days;

function scheduleEmergencyPause() external onlyMultisig {
    pauseScheduledAt = block.timestamp;
    emit EmergencyPauseScheduled(block.timestamp + emergencyDelay);
}

function executeEmergencyPause() external onlyMultisig {
    require(pauseScheduledAt > 0, "Not scheduled");
    require(block.timestamp >= pauseScheduledAt + emergencyDelay, "Too early");
    _pause();
}
```

### Source

`crates/detectors/src/governance.rs`

---
