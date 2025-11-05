# Eips Detectors

**Total:** 14 detectors

---

## Eip7702 Delegate Access Control

**ID:** `eip7702-delegate-access-control`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description



### Details

EIP-7702 Delegate Access Control Detector

Detects missing authorization in EIP-7702 delegate execute functions that allow
arbitrary execution and token drainage.

Severity: CRITICAL
Real-World: Part of $12M+ 2025 phishing attacks

### Source

`crates/detectors/src/eip7702/delegate_access_control.rs`

---

## Eip7702 Init Frontrun

**ID:** `eip7702-init-frontrun`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description



### Details

EIP-7702 Initialization Front-Running Detector

Detects unprotected initialization in EIP-7702 delegate contracts that can be front-run
for account takeover.

**CRITICAL**: $1.54M lost in August 2025 single attack via initialization front-running.

## Attack Scenario

```solidity
contract VulnerableDelegate {
address public owner;

// ❌ VULNERABLE: Anyone can call first
function initialize(address _owner) public {
require(owner == address(0), "Already initialized");
owner = _owner;
}

function execute(address target, bytes calldata data) public {
require(msg.sender == owner);
target.call(data);
}
}

// Attack:
// 1. User signs EIP-7702 authorization for VulnerableDelegate
// 2. Attacker front-runs with initialize(attackerAddress)
// 3. Attacker now owns user's EOA delegation
// 4. Attacker drains all assets
```

Severity: CRITICAL
Category: AccessControl

### Source

`crates/detectors/src/eip7702/init_frontrun.rs`

---

## Eip7702 Sweeper Detection

**ID:** `eip7702-sweeper-detection`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

EIP-7702 Sweeper Detection

Detects malicious sweeper contracts - 97% of 2025 EIP-7702 delegations were sweepers.

**CRITICAL**: Responsible for majority of $12M+ phishing losses.

### Source

`crates/detectors/src/eip7702/sweeper_detection.rs`

---

## Erc7683 Crosschain Validation

**ID:** `erc7683-crosschain-validation`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description



### Details

ERC-7683 Cross-Chain Validation Detector

Detects missing or weak cross-chain message validation in intent-based systems.

### Source

`crates/detectors/src/erc7683/crosschain_validation.rs`

---

## Erc7821 Token Approval

**ID:** `erc7821-token-approval`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

ERC-7821 Token Approval Detector

Detects token approval vulnerabilities in ERC-7821 batch executors.

### Remediation

- ERC-7821 should integrate with Permit2 for secure token approvals:\n\
                 \n\
                 import {IPermit2} from \

### Source

`crates/detectors/src/erc7821/token_approval.rs`

---

## Eip7702 Batch Phishing

**ID:** `eip7702-batch-phishing`  
**Severity:** High  
**Categories:** MEV  

### Description



### Details

EIP-7702 Batch Phishing Detector

Detects batch execution patterns used in phishing attacks to drain multiple assets.

### Source

`crates/detectors/src/eip7702/batch_phishing.rs`

---

## Eip7702 Storage Collision

**ID:** `eip7702-storage-collision`  
**Severity:** High  
**Categories:** Logic  

### Description



### Details

EIP-7702 Storage Collision Detector

Detects storage layout mismatches that can corrupt EOA state when using delegation.

### Remediation

- Use EIP-7201 namespaced storage to avoid collisions:\n\
                 \n\
                 bytes32 private constant STORAGE_LOCATION = \n\
                     keccak256(\

### Source

`crates/detectors/src/eip7702/storage_collision.rs`

---

## Eip7702 Txorigin Bypass

**ID:** `eip7702-txorigin-bypass`  
**Severity:** High  
**Categories:** Auth  

### Description



### Details

EIP-7702 tx.origin Bypass Detector

Detects contracts assuming tx.origin == msg.sender which breaks with EIP-7702 delegation.

### Source

`crates/detectors/src/eip7702/txorigin_bypass.rs`

---

## Erc721 Callback Reentrancy

**ID:** `erc721-callback-reentrancy`  
**Severity:** High  
**Categories:** Reentrancy, Logic  
**CWE:** CWE-841, CWE-691  

### Description



### Source

`crates/detectors/src/erc721_callback_reentrancy.rs`

---

## Erc777 Reentrancy Hooks

**ID:** `erc777-reentrancy-hooks`  
**Severity:** High  
**Categories:** Reentrancy, DeFi  
**CWE:** CWE-841, CWE-691  

### Description



### Source

`crates/detectors/src/erc777_reentrancy_hooks.rs`

---

## Erc7821 Batch Authorization

**ID:** `erc7821-batch-authorization`  
**Severity:** High  
**Categories:** AccessControl  

### Description



### Details

ERC-7821 Batch Authorization Detector

Detects missing authorization checks in ERC-7821 batch executor implementations.

### Source

`crates/detectors/src/erc7821/batch_authorization.rs`

---

## Erc7821 Replay Protection

**ID:** `erc7821-replay-protection`  
**Severity:** High  
**Categories:** Logic  

### Description



### Details

ERC-7821 Replay Protection Detector

### Source

`crates/detectors/src/erc7821/replay_protection.rs`

---

## Erc721 Enumeration Dos

**ID:** `erc721-enumeration-dos`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

ERC-721 Enumeration DOS Detector

Detects enumeration gas bombs in ERC-721 implementations.
Unbounded loops over token ownership can cause DOS.

### Remediation

- Add maximum iteration limit or use off-chain enumeration with pagination

### Source

`crates/detectors/src/token_standards_extended/enumeration_dos.rs`

---

## Erc7821 Msg Sender Validation

**ID:** `erc7821-msg-sender-validation`  
**Severity:** Medium  
**Categories:** Auth  

### Description



### Details

ERC-7821 msg.sender Validation Detector

### Source

`crates/detectors/src/erc7821/msg_sender_validation.rs`

---

