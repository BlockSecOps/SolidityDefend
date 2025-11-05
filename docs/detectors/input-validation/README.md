# Input Validation Detectors

**Total:** 16 detectors

---

## Array Bounds Check

**ID:** `array-bounds-check`  
**Severity:** High  
**Categories:** Validation  

### Description

Detects potential array out-of-bounds access and missing length validation

### Source

`validation/array_bounds.rs`

---

## Array Length Mismatch

**ID:** `array-length-mismatch`  
**Severity:** Medium  
**Categories:** Validation, Logic  
**CWE:** CWE-20, CWE-129  

### Description

Detects functions accepting multiple arrays without validating equal lengths

### Source

`src/array_length_mismatch.rs`

---

## Deprecated Functions

**ID:** `deprecated-functions`  
**Severity:** Low  
**Categories:** Validation  
**CWE:** CWE-477  

### Description

Detects usage of deprecated Solidity functions and patterns that should be replaced with modern alternatives

### Source

`src/deprecated_functions.rs`

---

## Enhanced Input Validation

**ID:** `enhanced-input-validation`  
**Severity:** High  
**Categories:** Validation, BestPractices  

### Description

Detects missing bounds checking and array validation ($14.6M impact)

### Remediation

- ❌ MISSING ARRAY VALIDATION (OWASP 2025 - $14.6M impact): \
      function process(uint256[] calldata ids) external { \
       for (uint256 i = 0; i < ids.length; i++) { \
        // What if ids is empty? Or too large? \
       } \
      } \
      \
      ✅ VALIDATE ARRAY LENGTH: \
      function process(uint256[] calldata ids) external { \
       // Check minimum length \
       require(ids.length > 0, \

### Source

`owasp2025/enhanced_input_validation.rs`

---

## EXTCODESIZE Bypass Detection

**ID:** `extcodesize-bypass`  
**Severity:** Medium  
**Categories:** Validation, Logic, Deployment  

### Description

Detects use of EXTCODESIZE or address.code.length for EOA validation, which can be bypassed during constructor execution

### Vulnerable Patterns

- address.code.length checks
- Assembly EXTCODESIZE
- isContract() helper functions
- EOA-only restrictions

### Source

`src/extcodesize_bypass.rs`

---

## Insufficient Randomness

**ID:** `insufficient-randomness`  
**Severity:** High  
**Categories:** Validation  
**CWE:** CWE-330, CWE-338  

### Description

Detects use of weak or manipulable randomness sources like block.timestamp or blockhash

### Vulnerable Patterns

- block.timestamp for randomness
- blockhash for randomness
- block.number for randomness
- msg.sender or tx.origin in randomness

### Source

`src/insufficient_randomness.rs`

---

## Intent Settlement Validation

**ID:** `intent-settlement-validation`  
**Severity:** High  
**Categories:** DeFi, CrossChain  

### Description

Detects missing validation in ERC-7683 settlement contracts (deadlines, outputs, fill instructions)

### Remediation

- Add fillDeadline validation: \
      \
      function fill( \
       bytes32 orderId, \
       bytes calldata originData, \
       bytes calldata fillerData \
      ) external { \
       ResolvedCrossChainOrder memory order = abi.decode( \
        originData, \
        (ResolvedCrossChainOrder) \
       ); \
       \
       // Validate fillDeadline \
       require( \
        block.timestamp <= order.fillDeadline, \
        \
- Add openDeadline validation: \
      \
      function openFor( \
       GaslessCrossChainOrder calldata order, \
       bytes calldata signature, \
       bytes calldata originFillerData \
      ) external { \
       // Validate openDeadline \
       require( \
        block.timestamp <= order.openDeadline, \
        \

### Source

`erc7683/settlement_validation.rs`

---

## Missing Chain-ID Validation

**ID:** `missing-chainid-validation`  
**Severity:** High  
**Categories:** CrossChain  

### Description

Detects missing chain-ID validation in bridge message processing

### Source

`src/bridge_chain_id_validation.rs`

---

## Missing Input Validation

**ID:** `missing-input-validation`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-20, CWE-1284  

### Description

Detects functions missing critical input parameter validation like zero address checks or bounds validation

### Vulnerable Patterns

- Function signature has address parameter but no zero check
- Transfer/withdraw functions without amount validation
- Array parameter without length check

### Source

`src/missing_input_validation.rs`

---

## Missing Zero Address Check

**ID:** `missing-zero-address-check`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-476  

### Description

Detects functions that accept address parameters without checking for address(0)

### Source

`validation/zero_address.rs`

---

## Parameter Consistency Check

**ID:** `parameter-consistency`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-20  

### Description

Detects inconsistent parameter validation and mismatched array lengths

### Source

`validation/parameter_check.rs`

---

## Variable Shadowing

**ID:** `shadowing-variables`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-710  

### Description

Detects variable shadowing where local variables hide state variables or inherited variables causing confusion

### Source

`src/shadowing_variables.rs`

---

## Short Address Attack

**ID:** `short-address-attack`  
**Severity:** Medium  
**Categories:** Validation, BestPractices  
**CWE:** CWE-20, CWE-707  

### Description

Detects missing msg.data.length validation that enables short address attacks

### Source

`src/short_address.rs`

---

## Unchecked Math Operations

**ID:** `unchecked-math`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-190, CWE-682  

### Description

Detects arithmetic operations in unchecked blocks that can overflow or underflow without reversion

### Vulnerable Patterns

- Check for unchecked blocks with arithmetic
- Pre-0.8 Solidity without SafeMath

### Source

`src/unchecked_math.rs`

---

## Unsafe Type Casting

**ID:** `unsafe-type-casting`  
**Severity:** Medium  
**Categories:** Validation  
**CWE:** CWE-197, CWE-704  

### Description

Detects unsafe type conversions that can lead to data loss, truncation, or unexpected behavior

### Vulnerable Patterns

- Downcasting (larger type to smaller type)
- int to uint conversion (sign loss)
- uint to int conversion (overflow risk)
- address conversions without validation

### Source

`src/unsafe_type_casting.rs`

---

## Weak Signature Validation

**ID:** `weak-signature-validation`  
**Severity:** High  
**Categories:** Auth, CrossChain  
**CWE:** CWE-345, CWE-347  

### Description

Detects multi-signature validation without duplicate signer checks, enabling signature reuse

### Vulnerable Patterns

- Explicit vulnerability comment
- Has signature recovery/validation in loop

### Source

`src/weak_signature_validation.rs`

---

