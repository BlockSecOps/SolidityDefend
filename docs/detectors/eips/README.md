# EIP-Specific Detectors

**Total:** 34 detectors
- EIP-7702: 11
- ERC-7683: 6
- ERC-7821: 5
- EIP-1153: 5
- **Phase 51 (v1.9.1):** 8 (EIP-3074: 5, EIP-4844: 1, EIP-6780: 1, PUSH0: 1)

**Last Updated:** 2026-01-26
**Version:** v1.10.11

---

## Phase 51: EIP-3074 & Future Standards (v1.9.1)

See **[phase51-eip3074-future.md](phase51-eip3074-future.md)** for detailed documentation.

| Detector | Severity | Description |
|----------|----------|-------------|
| `eip3074-upgradeable-invoker` | Critical | Forbidden upgradeable invoker contracts |
| `eip3074-commit-validation` | High | Improper commit hash verification |
| `eip3074-replay-attack` | High | Missing replay protection in AUTH |
| `eip3074-invoker-authorization` | High | Missing invoker authorization checks |
| `eip4844-blob-validation` | High | Blob transaction validation issues |
| `eip3074-call-depth-griefing` | Medium | Call depth manipulation attacks |
| `eip6780-selfdestruct-change` | Medium | Post-Cancun selfdestruct behavior |
| `push0-stack-assumption` | Low | PUSH0 cross-chain compatibility |

---

## EIP-7702 Account Delegation Security

### EIP-7702 Delegation Phishing (v1.8.0)

**ID:** `eip7702-delegation-phishing`
**Severity:** Critical
**Categories:** AccessControl, Logic
**CWE:** CWE-284

#### Description

Detects SET_CODE authorization patterns that could lead to phishing attacks where users are tricked into delegating code execution to malicious contracts.

#### Source

`eip7702_delegation_phishing.rs`

---

### EIP-7702 Storage Corruption (v1.8.0)

**ID:** `eip7702-storage-corruption`
**Severity:** Critical
**Categories:** Logic, Upgradeable
**CWE:** CWE-119

#### Description

Detects potential storage corruption when contract code is delegated to an EOA via EIP-7702. Storage slot collisions between delegated code and EOA state can corrupt critical data.

#### Source

`eip7702_storage_corruption.rs`

---

### EIP-7702 Sweeper Attack (v1.8.0)

**ID:** `eip7702-sweeper-attack`
**Severity:** Critical
**Categories:** DeFi, AccessControl
**CWE:** CWE-306

#### Description

Detects sweeper contract patterns that can drain all assets from delegated EOA accounts. Responsible for 97% of malicious EIP-7702 delegations.

#### Source

`eip7702_sweeper_attack.rs`

---

### EIP-7702 Authorization Bypass (v1.8.0)

**ID:** `eip7702-authorization-bypass`
**Severity:** High
**Categories:** AccessControl
**CWE:** CWE-862

#### Description

Detects missing or insufficient authorization checks in EIP-7702 delegation target contracts that could allow unauthorized access to delegated accounts.

#### Source

`eip7702_authorization_bypass.rs`

---

### EIP-7702 Replay Vulnerability (v1.8.0)

**ID:** `eip7702-replay-vulnerability`
**Severity:** High
**Categories:** CrossChain, Logic
**CWE:** CWE-294

#### Description

Detects delegation signatures that can be replayed across chains or contexts due to missing chain ID, nonce, or domain separator validation.

#### Source

`eip7702_replay_vulnerability.rs`

---

## EIP-7702 Batch Phishing

**ID:** `eip7702-batch-phishing`  
**Severity:** High  
**Categories:** MEV  

### Description

Detects batch execution used for multi-asset drainage in phishing attacks

### Source

`eip7702/batch_phishing.rs`

---

## EIP-7702 Delegate Access Control

**ID:** `eip7702-delegate-access-control`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description

Detects missing authorization in delegate execution functions allowing arbitrary calls

### Source

`eip7702/delegate_access_control.rs`

---

## EIP-7702 Initialization Front-Running

**ID:** `eip7702-init-frontrun`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description

Detects unprotected initialization vulnerable to front-running attacks in EIP-7702 delegates ($1.54M August 2025 loss)

### Source

`eip7702/init_frontrun.rs`

---

## EIP-7702 Storage Collision

**ID:** `eip7702-storage-collision`  
**Severity:** High  
**Categories:** Logic  

### Description

Detects storage layout mismatches between EOA and delegate contracts

### Remediation

- Use EIP-7201 namespaced storage to avoid collisions: \
     \
     bytes32 private constant STORAGE_LOCATION = \
      keccak256(\

### Source

`eip7702/storage_collision.rs`

---

## EIP-7702 Malicious Sweeper Detection

**ID:** `eip7702-sweeper-detection`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects sweeper contract patterns responsible for 97% of malicious EIP-7702 delegations in 2025

### Source

`eip7702/sweeper_detection.rs`

---

## EIP-7702 tx.origin Bypass

**ID:** `eip7702-txorigin-bypass`  
**Severity:** High  
**Categories:** Auth  

### Description

Detects tx.origin authentication that fails with EIP-7702 delegation

### Remediation

- EIP-7702 breaks tx.origin assumptions: \
     \
     Before: tx.origin == msg.sender for EOAs \
     After EIP-7702: tx.origin != msg.sender (msg.sender is delegate) \
     \
     Fix: Use msg.sender instead: \
     require(msg.sender == owner, \

### Source

`eip7702/txorigin_bypass.rs`

---

## ERC-7683 Cross-Chain Replay

**ID:** `erc7683-cross-chain-replay`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description

Detects missing chain-ID validation enabling cross-chain replay attacks

### Source

`src/erc7683_replay_attack.rs`

---

## ERC-7683 Cross-Chain Validation

**ID:** `erc7683-crosschain-validation`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description

Detects missing cross-chain message validation in intent settlement contracts

### Remediation

- Add chain ID validation: \
     \
     function settle( \
      CrossChainOrder calldata order, \
      bytes calldata originProof \
     ) external { \
      // ✅ Validate origin chain \
      require( \
       order.originChainId == EXPECTED_ORIGIN_CHAIN, \
       \
- Add Merkle proof verification: \
     \
     function _verifyMerkleProof( \
      bytes32[] calldata proof, \
      bytes32 leaf \
     ) internal view returns (bool) { \
      bytes32 computedHash = leaf; \
      \
      for (uint256 i = 0; i < proof.length; i++) { \
       computedHash = _hashPair(computedHash, proof[i]); \
      } \
      \
      return computedHash == merkleRoot; \
     }

### Source

`erc7683/crosschain_validation.rs`

---

## ERC-7683 Filler Front-Running

**ID:** `erc7683-filler-frontrunning`  
**Severity:** High  
**Categories:** CrossChain, MEV  

### Description

Detects missing MEV protection in ERC-7683 settlements

### Source

`src/erc7683_filler_frontrunning.rs`

---

## ERC-7683 Oracle Dependency

**ID:** `erc7683-oracle-dependency`  
**Severity:** High  
**Categories:** CrossChain, Oracle  

### Description

Detects risky oracle dependencies in cross-chain settlements

### Source

`src/erc7683_oracle_dependency.rs`

---

## ERC-7683 Settlement Validation

**ID:** `erc7683-settlement-validation`  
**Severity:** High  
**Categories:** CrossChain  

### Description

Detects missing nonce, deadline, and Permit2 validation in ERC-7683 settlements

### Source

`src/erc7683_settlement_validation.rs`

---

## ERC-7683 Unsafe Permit2

**ID:** `erc7683-unsafe-permit2`  
**Severity:** Medium  
**Categories:** CrossChain  

### Description

Detects unsafe token approval patterns in ERC-7683 settlements

### Source

`src/erc7683_permit2_integration.rs`

---

## ERC-7821 Batch Authorization

**ID:** `erc7821-batch-authorization`  
**Severity:** High  
**Categories:** AccessControl  

### Description

Detects missing authorization in ERC-7821 batch executor implementations

### Source

`erc7821/batch_authorization.rs`

---

## ERC-7821 msg.sender Validation

**ID:** `erc7821-msg-sender-validation`  
**Severity:** Medium  
**Categories:** Auth  

### Description

Detects msg.sender authentication issues in batch execution context

### Remediation

- Be explicit about msg.sender context: \
     \
     // In batch executor: \
     // msg.sender = settler contract \
     // tx.origin = original user \
     \
     function executeBatch(address user, ...) external { \
      // ✅ Pass user explicitly, don

### Source

`erc7821/msg_sender_validation.rs`

---

## ERC-7821 Replay Protection

**ID:** `erc7821-replay-protection`  
**Severity:** High  
**Categories:** Logic  

### Description

Detects missing nonce or replay protection in batch executors

### Remediation

- Add nonce-based replay protection: \
     \
     mapping(address => uint256) public nonces; \
     \
     function executeBatch( \
      uint256 nonce, \
      bytes calldata signature \
     ) external { \
      require(nonce == nonces[msg.sender], \

### Source

`erc7821/replay_protection.rs`

---

## ERC-7821 Token Approval Security

**ID:** `erc7821-token-approval`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects unsafe token approval patterns in batch executors, recommends Permit2

### Remediation

- ERC-7821 should integrate with Permit2 for secure token approvals: \
     \
     import {IPermit2} from \

### Source

`erc7821/token_approval.rs`

---

## EIP-1153 Transient Storage Security (v1.8.0)

### EIP-1153 Transient Storage Reentrancy

**ID:** `eip1153-transient-reentrancy`
**Severity:** Critical
**Categories:** Reentrancy, Logic
**CWE:** CWE-841

#### Description

Detects reentrancy vulnerabilities involving EIP-1153 transient storage. Transient storage (TSTORE/TLOAD) clears after each transaction, which can lead to unexpected reentrancy if used for state that should persist.

#### Source

`eip1153_transient_reentrancy.rs`

---

### EIP-1153 Cross-Transaction Assumption

**ID:** `eip1153-cross-tx-assumption`
**Severity:** High
**Categories:** Logic
**CWE:** CWE-362

#### Description

Detects incorrect assumptions about transient storage persisting across transactions. Transient storage clears after each transaction, but contracts may incorrectly assume data persists.

#### Source

`eip1153_cross_tx_assumption.rs`

---

### EIP-1153 Callback Manipulation

**ID:** `eip1153-callback-manipulation`
**Severity:** High
**Categories:** Reentrancy, Logic
**CWE:** CWE-367

#### Description

Detects transient storage state that can be manipulated during external callbacks. When a contract stores state in transient storage and then makes an external call, the callee can manipulate that transient state.

#### Source

`eip1153_callback_manipulation.rs`

---

### EIP-1153 Composability Risk

**ID:** `eip1153-composability-risk`
**Severity:** Medium
**Categories:** Logic
**CWE:** CWE-664

#### Description

Detects transient storage slot collisions when multiple contracts use transient storage. Without proper namespacing, different contracts in a call chain may overwrite each other's transient state.

#### Source

`eip1153_composability_risk.rs`

---

### EIP-1153 Guard Bypass

**ID:** `eip1153-guard-bypass`
**Severity:** High
**Categories:** Reentrancy
**CWE:** CWE-667

#### Description

Detects flawed implementations of reentrancy guards using transient storage that can be bypassed due to incorrect check order, missing guard resets, or improper modifier patterns.

#### Source

`eip1153_guard_bypass.rs`

---

