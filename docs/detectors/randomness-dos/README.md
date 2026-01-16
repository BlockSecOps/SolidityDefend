# Randomness & DoS Detectors

This category contains **10 detectors** for weak randomness vulnerabilities and denial of service attack patterns in Solidity smart contracts.

## Overview

Weak randomness and DoS attacks represent critical vulnerabilities in smart contracts, particularly in gambling, lottery, and high-value DeFi applications. These detectors identify:

- **Weak Randomness**: Predictable "random" number generation using block variables
- **DoS Push Patterns**: Unbounded array growth causing gas exhaustion
- **DoS External Calls**: Loops with external calls vulnerable to griefing
- **Revert Bombs**: Malicious contracts forcing transaction failures

## Detectors

| ID | Name | Severity | CWE |
|----|------|----------|-----|
| `blockhash-randomness` | Blockhash Randomness | High | CWE-330 |
| `multi-block-randomness` | Multi-Block Randomness | High | CWE-330 |
| `modulo-block-variable` | Modulo Block Variable | High | CWE-330 |
| `chainlink-vrf-misuse` | Chainlink VRF Misuse | Medium | CWE-330 |
| `commit-reveal-timing` | Commit-Reveal Timing | High | CWE-330 |
| `dos-push-pattern` | DoS Push Pattern | High | CWE-400 |
| `dos-unbounded-storage` | DoS Unbounded Storage | High | CWE-400 |
| `dos-external-call-loop` | DoS External Call Loop | High | CWE-400 |
| `dos-block-gas-limit` | DoS Block Gas Limit | High | CWE-400 |
| `dos-revert-bomb` | DoS Revert Bomb | High | CWE-400 |

## Weak Randomness Detectors

### blockhash-randomness

Detects weak randomness patterns using `block.prevrandao`, `blockhash`, or other block variables that can be manipulated by miners/validators.

**Example Vulnerable Code:**
```solidity
function random() public view returns (uint256) {
    // Vulnerable: block.prevrandao is known before block finalization
    return uint256(keccak256(abi.encodePacked(
        block.prevrandao,
        block.timestamp,
        msg.sender
    )));
}
```

**Fix:**
```solidity
// Use Chainlink VRF for verifiable randomness
function requestRandomWords() external {
    s_requestId = COORDINATOR.requestRandomWords(
        keyHash,
        s_subscriptionId,
        requestConfirmations,
        callbackGasLimit,
        numWords
    );
}

function fulfillRandomWords(uint256, uint256[] memory randomWords) internal override {
    s_randomWord = randomWords[0];
}
```

### multi-block-randomness

Detects patterns combining multiple block variables for randomness, which falsely appears more secure but remains predictable.

**Example Vulnerable Code:**
```solidity
// Vulnerable: combining predictable values doesn't create unpredictability
uint256 random = uint256(keccak256(abi.encodePacked(
    block.timestamp,
    block.number,
    block.coinbase,
    block.prevrandao
)));
```

### modulo-block-variable

Detects `block.timestamp % N` or `block.number % N` patterns used for random selection.

**Example Vulnerable Code:**
```solidity
// Vulnerable: miners can manipulate timestamp within ~15 second range
function selectWinner() public {
    uint256 winnerIndex = block.timestamp % participants.length;
    address winner = participants[winnerIndex];
}
```

### chainlink-vrf-misuse

Detects improper Chainlink VRF integration patterns that could compromise randomness guarantees.

**Issues Detected:**
- VRF request without callback implementation
- Immediate use of request ID (VRF is asynchronous)
- Unrestricted VRF request functions
- Hardcoded subscription IDs

### commit-reveal-timing

Detects commit-reveal schemes with timing vulnerabilities such as insufficient delays or missing time bounds.

**Issues Detected:**
- Commit without timestamp recording
- Reveal without time validation
- Same-block commit and reveal allowed
- Short commit-reveal deadlines

## DoS Detectors

### dos-push-pattern

Detects unbounded array growth via push operations that could lead to denial of service when iterating.

**Example Vulnerable Code:**
```solidity
address[] public participants;

// Vulnerable: no limit on array size
function join() external {
    participants.push(msg.sender);
}

// Vulnerable: iteration over unbounded array
function selectWinner() external {
    for (uint i = 0; i < participants.length; i++) {
        // Gas will exceed block limit for large arrays
    }
}
```

**Fix:**
```solidity
uint256 constant MAX_PARTICIPANTS = 1000;

function join() external {
    require(participants.length < MAX_PARTICIPANTS, "Max reached");
    participants.push(msg.sender);
}

// Or use pagination
function processParticipants(uint256 start, uint256 count) external {
    uint256 end = start + count;
    if (end > participants.length) end = participants.length;
    for (uint i = start; i < end; i++) {
        // process
    }
}
```

### dos-unbounded-storage

Detects unbounded storage operations that can lead to denial of service through excessive gas costs.

**Issues Detected:**
- Unbounded storage arrays without length checks
- Mapping arrays without per-user limits
- Storage deletion in loops
- Nested mapping unbounded writes

### dos-external-call-loop

Detects external calls within loops that can lead to denial of service if any recipient reverts.

**Example Vulnerable Code:**
```solidity
// Vulnerable: single malicious recipient blocks all payouts
function distribute() external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(amounts[i]);
    }
}
```

**Fix (Pull Pattern):**
```solidity
mapping(address => uint256) pendingWithdrawals;

function distribute() external {
    for (uint i = 0; i < recipients.length; i++) {
        pendingWithdrawals[recipients[i]] += amounts[i];
    }
}

function withdraw() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### dos-block-gas-limit

Detects operations that can exceed block gas limit, making functions impossible to execute.

**Issues Detected:**
- Unbounded loops over storage arrays
- Functions accepting unbounded array inputs
- Nested loops (O(n*m) complexity)
- Large data copy operations
- String concatenation in loops

### dos-revert-bomb

Detects patterns vulnerable to revert bomb attacks where external contracts can force transaction failures.

**Issues Detected:**
- `transfer()` usage (always reverts on failure)
- Unchecked `send()` return values
- Callback-dependent patterns without try-catch
- Auction patterns refunding inline
- Safe transfers with state changes after callback
- Unlimited gas forwarding

## False Positive Mitigations (v1.8.6)

The following patterns are intentionally excluded to avoid false positives:

### Randomness Detectors

| Pattern | Reason | Example |
|---------|--------|---------|
| Power-of-2 modulo | Type casting for overflow protection | `uint32(block.timestamp % 2**32)` |
| Secure commit-reveal | Contracts with proper timing checks | `commitTime`, `REVEAL_DELAY`, `block.timestamp >=` |

### DoS Detectors

| Pattern | Reason | Example |
|---------|--------|---------|
| ERC20 token transfers | 2-arg transfers controlled by token contract | `token.transfer(addr, amount)` |
| Constructor loops | Constructor runs once at deployment | `for` loop in constructor |
| Standard token patterns | Well-established secure patterns | `approve()`, `setApprovalForAll()`, `permit()` |
| Function signature returns | `returns` != `return` statement | `returns (address[] memory)` |

## CWE Mappings

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-330 | Use of Insufficiently Random Values | blockhash-randomness, multi-block-randomness, modulo-block-variable, chainlink-vrf-misuse, commit-reveal-timing |
| CWE-400 | Uncontrolled Resource Consumption | dos-push-pattern, dos-unbounded-storage, dos-external-call-loop, dos-block-gas-limit, dos-revert-bomb |

## Best Practices

### For Randomness

1. **Use Chainlink VRF** for verifiable, tamper-proof randomness
2. **Implement commit-reveal** with proper timing and economic bonds
3. **Never use block variables** alone for random selection
4. **Add minimum delays** between commit and reveal phases

### For DoS Prevention

1. **Use pull-over-push** pattern for payments
2. **Limit array sizes** with explicit maximums
3. **Implement pagination** for large data operations
4. **Use try-catch** for external calls in loops
5. **Add gas limits** for forwarded calls

## References

- [SWC-120: Weak Sources of Randomness](https://swcregistry.io/docs/SWC-120)
- [SWC-128: DoS With Block Gas Limit](https://swcregistry.io/docs/SWC-128)
- [Chainlink VRF Documentation](https://docs.chain.link/vrf)
- [OpenZeppelin Pull Payment Pattern](https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment)
