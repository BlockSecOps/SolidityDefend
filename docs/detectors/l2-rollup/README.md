# L2/Rollup & Cross-Chain Advanced Detectors

**Category:** L2 Security, Cross-Chain Bridges, Data Availability
**Detectors:** 10
**Added:** v1.8.5 (Phase 48)

---

## Overview

These detectors identify vulnerabilities specific to Layer 2 solutions, rollups, and cross-chain interactions. They cover sequencer-related risks, challenge period bypasses, data availability issues, and EIP-4844 blob security.

---

## Detectors

### Critical Severity (2)

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `bridge-merkle-bypass` | Missing merkle proof validation in cross-chain bridges | CWE-345 |
| `challenge-period-bypass` | Premature withdrawal before challenge period expires | CWE-367 |

### High Severity (7)

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `sequencer-fee-exploitation` | L2 sequencer fee model exploitation for MEV | CWE-400 |
| `escape-hatch-dependency` | Over-reliance on L1 escape mechanisms | CWE-754 |
| `cross-l2-frontrunning` | Race conditions between L2 finality and L1 confirmation | CWE-362 |
| `l2-mev-sequencer-leak` | Sequencer MEV extraction via transaction ordering | CWE-362 |
| `da-sampling-attack` | Data availability under-sampling vulnerabilities | CWE-20 |
| `cross-rollup-state-mismatch` | State inconsistency across rollups | CWE-662 |
| `blob-data-manipulation` | EIP-4844 blob data tampering without KZG verification | CWE-20 |

### Medium Severity (1)

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `optimistic-inference-attack` | State inference from partial commits in optimistic rollups | CWE-200 |

---

## Detector Details

### bridge-merkle-bypass

**Severity:** Critical
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

Detects missing or weak merkle proof validation in cross-chain bridges that could allow unauthorized withdrawals or message forgery.

**Vulnerable Pattern:**
```solidity
function withdraw(uint256 amount, address recipient) external {
    // Missing merkle proof verification!
    token.transfer(recipient, amount);
}
```

**Secure Pattern:**
```solidity
function withdraw(
    uint256 amount,
    address recipient,
    bytes32[] calldata proof,
    bytes32 root
) external {
    require(verifyProof(proof, root, keccak256(abi.encode(amount, recipient))), "Invalid proof");
    require(confirmedRoots[root], "Unconfirmed root");
    token.transfer(recipient, amount);
}
```

---

### challenge-period-bypass

**Severity:** Critical
**CWE:** CWE-367 (TOCTOU Race Condition)

Detects vulnerabilities allowing premature withdrawals or state finalization before the challenge period expires in optimistic rollups.

**Vulnerable Pattern:**
```solidity
function finalizeWithdrawal(uint256 id) external {
    // No challenge period check!
    Withdrawal storage w = withdrawals[id];
    token.transfer(w.recipient, w.amount);
}
```

**Secure Pattern:**
```solidity
function finalizeWithdrawal(uint256 id) external {
    Withdrawal storage w = withdrawals[id];
    require(
        block.timestamp >= w.initiatedAt + CHALLENGE_PERIOD,
        "Challenge period not elapsed"
    );
    require(!w.disputed, "Withdrawal disputed");
    token.transfer(w.recipient, w.amount);
}
```

---

### sequencer-fee-exploitation

**Severity:** High
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

Detects vulnerabilities in L2 sequencer fee models that can be exploited for MEV extraction or fee manipulation attacks.

**Vulnerable Pattern:**
```solidity
function executeSwap() external {
    uint256 fee = tx.gasprice * gasUsed; // Sequencer-controlled!
    // ...
}
```

**Secure Pattern:**
```solidity
function executeSwap(uint256 maxFee) external {
    uint256 fee = getL2GasFee(); // Use L2-specific oracle
    require(fee <= maxFee, "Fee exceeds maximum");
    require(block.timestamp - lastOracleUpdate < MAX_STALENESS, "Stale fee");
    // ...
}
```

---

### blob-data-manipulation

**Severity:** High
**CWE:** CWE-20 (Improper Input Validation)

Detects EIP-4844 blob data vulnerabilities including missing KZG verification and improper blob lifecycle handling.

**Vulnerable Pattern:**
```solidity
function processBlob(uint256 blobIndex) external {
    bytes32 hash = blobhash(blobIndex);
    // Using blob hash without KZG verification!
    processData(hash);
}
```

**Secure Pattern:**
```solidity
function processBlob(
    uint256 blobIndex,
    bytes calldata commitment,
    bytes calldata proof,
    bytes32 z,
    bytes32 y
) external {
    bytes32 hash = blobhash(blobIndex);
    require(hash != bytes32(0), "No blob at index");
    require(verifyKZGProof(commitment, z, y, proof), "Invalid KZG proof");
    processData(hash);
}
```

---

## Related Real-World Exploits

| Protocol | Loss | Vulnerability Type |
|----------|------|-------------------|
| Ronin Bridge | $625M | Bridge validation bypass |
| Wormhole | $320M | Cross-chain message forgery |
| Nomad Bridge | $190M | Merkle proof bypass |
| BNB Bridge | $100M | IAVL proof validation |

---

## References

- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)
- [Optimism Challenge Period](https://docs.optimism.io/stack/rollup/withdrawal-flow)
- [Arbitrum Sequencer](https://docs.arbitrum.io/sequencer)
- [L2BEAT Risk Framework](https://l2beat.com/glossary)
