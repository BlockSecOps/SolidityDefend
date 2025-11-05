# Zero Knowledge Detectors

**Total:** 5 detectors

---

## Zk Circuit Under Constrained

**ID:** `zk-circuit-under-constrained`  
**Severity:** Critical  
**Categories:** ZKRollup  

### Description



### Details

ZK Circuit Under-Constrained Detector

Detects under-constrained ZK circuits where missing constraints allow
invalid proofs to be accepted.

### Remediation

- Add range constraints: require(publicInput < FIELD_SIZE, \
- Validate all public inputs before proof verification

### Source

`crates/detectors/src/zk_proofs/circuit_constraints.rs`

---

## Zk Proof Bypass

**ID:** `zk-proof-bypass`  
**Severity:** Critical  
**Categories:** L2, ZKRollup  
**CWE:** CWE-345, CWE-20, CWE-20  

### Description



### Source

`crates/detectors/src/zk_proof_bypass.rs`

---

## Zk Proof Malleability

**ID:** `zk-proof-malleability`  
**Severity:** Critical  
**Categories:** ZKRollup  

### Description



### Details

ZK Proof Malleability Detector

Detects proof malleability attacks where proofs can be modified while
remaining valid, allowing unauthorized operations.

### Remediation

- Include unique identifier in proof: require(!usedProofs[proofHash], \

### Source

`crates/detectors/src/zk_proofs/proof_malleability.rs`

---

## Zk Recursive Proof Validation

**ID:** `zk-recursive-proof-validation`  
**Severity:** High  
**Categories:** ZKRollup  

### Description



### Details

ZK Recursive Proof Validation Detector

Detects recursive proof validation issues in proof aggregation systems.

### Remediation

- Validate each proof individually before aggregation or use proper aggregation scheme

### Source

`crates/detectors/src/zk_proofs/recursive_proof.rs`

---

## Zk Trusted Setup Bypass

**ID:** `zk-trusted-setup-bypass`  
**Severity:** High  
**Categories:** ZKRollup  

### Description



### Details

ZK Trusted Setup Bypass Detector

Detects compromised or missing trusted setup validation in ZK systems.

### Source

`crates/detectors/src/zk_proofs/trusted_setup_bypass.rs`

---

