# Input Validation Detectors

**Total:** 13 detectors

---

## Avs Validation Bypass

**ID:** `avs-validation-bypass`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

AVS Validation Bypass Detector

Detects Actively Validated Service (AVS) registration without proper security validation,
allowing malicious services to slash operator stakes without adequate oversight.

Severity: HIGH
Category: DeFi, Restaking

Vulnerabilities Detected:
1. No AVS security requirements (audit, validator count)
2. No AVS collateral requirement
3. No slashing policy limits (AVS can set 100% slashing)
4. Operators cannot opt-out of AVS

Real-World Context:
- AVSs can slash operator stakes if they misbehave
- Malicious/poorly-designed AVSs pose systemic risk
- Small validator pools vulnerable to 51% attacks before joining EigenLayer
Checks AVS registration for collateral requirement

### Source

`crates/detectors/src/restaking/avs_validation.rs`

---

## Enhanced Input Validation

**ID:** `enhanced-input-validation`  
**Severity:** High  
**Categories:** Validation, BestPractices  

### Description



### Details

Enhanced Input Validation Detector (OWASP 2025)

Detects missing comprehensive bounds checking that led to $14.6M in losses.
Array length validation, parameter bounds, zero-value checks.

### Source

`crates/detectors/src/owasp2025/enhanced_input_validation.rs`

---

## Integer Overflow

**ID:** `integer-overflow`  
**Severity:** High  
**Categories:** Logic, Validation  
**CWE:** CWE-190, CWE-191, CWE-190, CWE-191  

### Description



### Source

`crates/detectors/src/integer_overflow.rs`

---

## Intent Settlement Validation

**ID:** `intent-settlement-validation`  
**Severity:** High  
**Categories:** DeFi, CrossChain  

### Description



### Details

Checks deadline validation in settlement functions

### Source

`crates/detectors/src/erc7683/settlement_validation.rs`

---

## Missing Chainid Validation

**ID:** `missing-chainid-validation`  
**Severity:** High  
**Categories:** CrossChain, CrossChain  

### Description



### Details

Chain-ID Validation Detector for Bridge Contracts
Get function source code with comments stripped to avoid false positives

### Source

`crates/detectors/src/bridge_chain_id_validation.rs`

---

## Weak Signature Validation

**ID:** `weak-signature-validation`  
**Severity:** High  
**Categories:** Auth, CrossChain  
**CWE:** CWE-345, CWE-347  

### Description



### Details

Check if function has weak signature validation

### Remediation

- Add duplicate signer check in function '{}'. \
                    Example: Track seen signers in a mapping or check array for duplicates. \
                    require(!seen[signer], \

### Source

`crates/detectors/src/weak_signature_validation.rs`

---

## Array Length Mismatch

**ID:** `array-length-mismatch`  
**Severity:** Medium  
**Categories:** Validation, Logic  
**CWE:** CWE-20, CWE-129  

### Description



### Details


Detects functions that accept multiple arrays but don't validate they have the same length.
This can cause out-of-bounds access, incorrect calculations, or silent failures.
Check if function has array length mismatch vulnerability

### Source

`crates/detectors/src/array_length_mismatch.rs`

---

## Missing Input Validation

**ID:** `missing-input-validation`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-20, CWE-1284  

### Description



### Source

`crates/detectors/src/missing_input_validation.rs`

---

## Post 080 Overflow

**ID:** `post-080-overflow`  
**Severity:** Medium  
**Categories:** Logic, BestPractices  

### Description



### Details

Post-0.8.0 Overflow Detector (OWASP 2025)

Detects unchecked block overflows and assembly arithmetic.
Even with Solidity 0.8.0+ overflow protection, unchecked blocks bypass it.
$223M Cetus DEX hack (May 2025) was caused by assembly overflow.

### Source

`crates/detectors/src/owasp2025/post_080_overflow.rs`

---

## Sovereign Rollup Validation

**ID:** `sovereign-rollup-validation`
**Severity:** Medium
**Categories:** L2

### Description



### Details

Sovereign Rollup Validation Detector

### Source

`crates/detectors/src/modular_blockchain/sovereign_rollup.rs`

---

## Array Bounds Check

**ID:** `array-bounds-check`
**Severity:** High
**Categories:** Validation
**CWE:** CWE-129, CWE-119

### Description

Detects potential array out-of-bounds access and missing length validation.

### Details

This detector identifies functions that access arrays without proper bounds checking. Array out-of-bounds vulnerabilities can lead to:
- Contract reverts and denial of service
- Reading incorrect data from memory/storage
- In some edge cases, memory corruption

The detector checks for:
- Unchecked array access with dynamic indices
- Loop bounds that may exceed array length
- Missing length validation on array parameters
- Off-by-one errors in array iteration

### Remediation

- Always validate array indices before access: `require(index < array.length, "Index out of bounds")`
- Use `for (uint i = 0; i < array.length; i++)` for safe iteration
- Validate array parameter lengths at function start
- Consider using SafeMath or checked arithmetic for index calculations
- Use array bounds checks even for arrays that "should never" be accessed out of bounds

### Source

`crates/detectors/src/validation/array_bounds.rs`

---

## Missing Zero Address Check

**ID:** `missing-zero-address-check`
**Severity:** Medium
**Categories:** Validation
**CWE:** CWE-20

### Description

Detects functions that accept address parameters without checking for address(0).

### Details

Functions that accept address parameters should typically validate that the address is not zero (0x0000...0000) unless intentionally burning tokens or revoking approvals.

Missing zero address checks can lead to:
- Accidental token burns
- Loss of funds sent to address(0)
- Assignment of roles to address(0)
- Permanently locked contract ownership

The detector identifies critical functions (ownership transfer, role assignment, fund transfers, etc.) that accept address parameters but don't validate against zero address.

**Note:** Standard token functions (transfer, approve, etc.) may intentionally allow zero address for burning/revoking, and are excluded from this detector.

### Remediation

- Add zero address validation: `require(_address != address(0), "Invalid zero address")`
- Use at function start for critical address parameters
- Document when zero address is intentionally allowed
- Consider using OpenZeppelin's Address library

### Source

`crates/detectors/src/validation/zero_address.rs`

---

## Parameter Consistency Check

**ID:** `parameter-consistency`
**Severity:** Medium
**Categories:** Validation
**CWE:** CWE-20, CWE-129

### Description

Detects inconsistent parameter validation and mismatched array lengths.

### Details

This detector identifies functions with parameter validation issues:

1. **Array Length Mismatches:** Multiple array parameters that aren't validated for equal length
2. **Missing Parameter Validation:** Critical parameters without proper validation
3. **Inconsistent Ordering:** Similar functions with different parameter orders
4. **Parameter Shadowing:** Parameters that shadow state variables

Common vulnerabilities include:
- Iterating over multiple arrays of different lengths causing out-of-bounds access
- Accepting unvalidated parameters that cause unexpected behavior
- Parameter confusion due to inconsistent ordering

### Remediation

- Validate array lengths are equal: `require(array1.length == array2.length, "Length mismatch")`
- Add parameter validation for critical values
- Maintain consistent parameter ordering across similar functions
- Avoid parameter names that shadow state variables
- Document parameter validation requirements

### Source

`crates/detectors/src/validation/parameter_check.rs`

---

