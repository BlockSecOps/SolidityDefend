# Gas Optimization Detectors

**Total:** 5 detectors

---

## Excessive Gas Usage

**ID:** `excessive-gas-usage`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description

Detects patterns causing excessive gas consumption such as storage operations in loops, redundant storage reads, and inefficient data structures

### Vulnerable Patterns

- Storage operations in loops
- Redundant storage reads
- String concatenation in loop or multiple times
- Dynamic array length in loop condition
- Emitting events in loops

### Source

`src/excessive_gas_usage.rs`

---

## Gas Griefing Attack

**ID:** `gas-griefing`  
**Severity:** Medium  
**Categories:** Logic, ExternalCalls  
**CWE:** CWE-400, CWE-405  

### Description

Detects vulnerabilities where attackers can grief users by forcing high gas consumption

### Vulnerable Patterns

- External call in loop without gas limit
- Transfer without gas stipend
- Push pattern for mass distribution

### Source

`src/gas_griefing.rs`

---

## Gas Price Manipulation

**ID:** `gas-price-manipulation`  
**Severity:** Medium  
**Categories:** MEV, DeFi  
**CWE:** CWE-358, CWE-693  

### Description

Detects MEV protection using tx.gasprice which can be bypassed through flashbots or other mechanisms

### Vulnerable Patterns

- Explicit vulnerability comment
- Uses tx.gasprice in require/check
- MEV protection based on gas price
- MEV detection using gas price

### Source

`src/gas_price_manipulation.rs`

---

## Inefficient Storage Usage

**ID:** `inefficient-storage`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description

Detects inefficient storage patterns including unpacked structs, redundant storage variables, and suboptimal storage layout that waste gas

### Vulnerable Patterns

- Unpacked structs (mixed sizes without optimization)
- Single boolean flags as storage variables
- Small uint types as standalone storage variables

### Source

`src/inefficient_storage.rs`

---

## Redundant Checks

**ID:** `redundant-checks`  
**Severity:** Low  
**Categories:** Logic  
**CWE:** CWE-400  

### Description

Detects redundant validation checks that unnecessarily waste gas, including duplicate require statements, unnecessary overflow checks, and redundant modifiers

### Vulnerable Patterns

- Duplicate require statements
- Redundant overflow checks in Solidity >=0.8
- Checking same condition in modifier and function

### Source

`src/redundant_checks.rs`

---

