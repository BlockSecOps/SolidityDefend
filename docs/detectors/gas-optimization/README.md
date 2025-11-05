# Gas Optimization Detectors

**Total:** 4 detectors

---

## Dos Unbounded Operation

**ID:** `dos-unbounded-operation`  
**Severity:** High  
**Categories:** Logic  
**CWE:** CWE-834, CWE-400  

### Description



### Remediation

- Fix unbounded operation in '{}'. \
                    Add pagination for large loops, implement maximum iteration limits, \
                    use pull pattern instead of push, add circuit breakers, batch operations.

### Source

`crates/detectors/src/dos_unbounded_operation.rs`

---

## Validator Griefing

**ID:** `validator-griefing`  
**Severity:** High  
**Categories:** Logic, MEV  
**CWE:** CWE-405, CWE-400  

### Description



### Details

Check for validator griefing vulnerabilities

### Source

`crates/detectors/src/validator_griefing.rs`

---

## Gas Griefing

**ID:** `gas-griefing`  
**Severity:** Medium  
**Categories:** Logic, ExternalCalls  
**CWE:** CWE-400, CWE-405  

### Description



### Remediation

- Mitigate gas griefing in '{}'. \
                    Use pull pattern for transfers, limit array sizes, add gas stipends, \
                    implement gas-efficient loops, avoid unbounded operations, use OpenZeppelin SafeERC20.

### Source

`crates/detectors/src/gas_griefing.rs`

---

## Excessive Gas Usage

**ID:** `excessive-gas-usage`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description



### Source

`crates/detectors/src/excessive_gas_usage.rs`

---

