# Governance Security Detectors

**Total:** 4 detectors

---

## Delegation Loop Vulnerability

**ID:** `delegation-loop`  
**Severity:** High  
**Categories:** Auth, DeFi  
**CWE:** CWE-834, CWE-840  

### Description

Detects governance delegation without circular delegation protection, enabling vote manipulation

### Vulnerable Patterns

- Explicit vulnerability comment
- Has delegation assignment but no loop check
- Missing loop detection mechanisms
- Has self-delegation check but no chain check

### Source

`src/delegation_loop.rs`

---

## Multi-Signature Bypass Detection

**ID:** `multisig-bypass`  
**Severity:** Critical  
**Categories:** AccessControl, Auth, Logic  

### Description

Detects multi-signature systems with flawed signature verification that allows threshold bypass, signature reuse, or owner manipulation

### Vulnerable Patterns

- Missing nonce validation in signature verification
- Insufficient duplicate signature check
- Owner enumeration issues

### Source

`src/multisig_bypass.rs`

---

## Governance Attacks

**ID:** `test-governance`  
**Severity:** High  
**Categories:** FlashLoan, Logic, BestPractices  

### Description

Detects vulnerabilities in DAO governance mechanisms including flash loan attacks, delegation loops, and voting manipulation

### Source

`src/governance.rs`

---

## Weak Commit-Reveal Scheme

**ID:** `weak-commit-reveal`  
**Severity:** Medium  
**Categories:** MEV, DeFi  
**CWE:** CWE-362, CWE-841  

### Description

Detects commit-reveal schemes with insufficient delay or weak parameters, enabling MEV attacks

### Vulnerable Patterns

- Explicit vulnerability comment
- Uses short delay (< 5 minutes)
- Predictable timing wi

### Source

`src/weak_commit_reveal.rs`

---

