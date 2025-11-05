# Tokens Detectors

**Total:** 8 detectors

---

## Batch Transfer Overflow

**ID:** `batch-transfer-overflow`  
**Severity:** Critical  
**Categories:** Logic, BestPractices  
**CWE:** CWE-190, CWE-682  

### Description



### Details


Detects the pattern where array.length * value can overflow, bypassing balance checks.
This was exploited in the BeautyChain (BEC) token hack.
Check if function has batch transfer overflow vulnerability

### Source

`crates/detectors/src/batch_transfer_overflow.rs`

---

## Token Supply Manipulation

**ID:** `token-supply-manipulation`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-682, CWE-840  

### Description



### Remediation

- Fix token supply controls in '{}'. \
                    Implement maximum supply cap, add minting rate limits, \
                    require multi-signature for minting, add supply change events, \
                    validate burn amounts, and implement supply monitoring.

### Source

`crates/detectors/src/token_supply_manipulation.rs`

---

## Dos Failed Transfer

**ID:** `dos-failed-transfer`  
**Severity:** High  
**Categories:** Logic, BestPractices  
**CWE:** CWE-841, CWE-400  

### Description



### Details


Detects when a function can be blocked if a transfer to an external address fails.
This is also known as the "push over pull" anti-pattern.
Check if function has DoS by failed transfer vulnerability

### Source

`crates/detectors/src/dos_failed_transfer.rs`

---

## Token Decimal Confusion

**ID:** `token-decimal-confusion`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

Token Decimal Confusion Detector

Detects decimal mismatch errors that can lead to loss of funds.
Different tokens have different decimals (6, 8, 18) causing calculation errors.

### Source

`crates/detectors/src/token_standards_extended/decimal_confusion.rs`

---

## Erc1155 Batch Validation

**ID:** `erc1155-batch-validation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

ERC-1155 Batch Validation Detector

Detects missing batch validation in ERC-1155 implementations.
Array length mismatches can lead to loss of funds or exploits.

### Remediation

- Add validation: require(ids.length == amounts.length, \

### Source

`crates/detectors/src/token_standards_extended/batch_validation.rs`

---

## Erc20 Approve Race

**ID:** `erc20-approve-race`  
**Severity:** Medium  
**Categories:** Logic, DeFi  
**CWE:** CWE-362  

### Description



### Source

`crates/detectors/src/erc20_approve_race.rs`

---

## Erc20 Transfer Return Bomb

**ID:** `erc20-transfer-return-bomb`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

ERC-20 Transfer Return Bomb Detector

Detects return data bombs that can cause DOS via excessive return data size.
Malicious ERC-20 tokens can return huge amounts of data to exhaust gas.

### Source

`crates/detectors/src/token_standards_extended/transfer_return_bomb.rs`

---

## Erc20 Infinite Approval

**ID:** `erc20-infinite-approval`  
**Severity:** Low  
**Categories:** Logic, DeFi  
**CWE:** CWE-284  

### Description



### Source

`crates/detectors/src/erc20_infinite_approval.rs`

---

