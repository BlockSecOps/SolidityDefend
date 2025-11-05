# EIP-Specific Detectors

**Total:** 16 detectors

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

