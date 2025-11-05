# Zero-Knowledge Proof Detectors

**Total:** 5 detectors

---

## ZK Circuit Under-Constrained

**ID:** `zk-circuit-under-constrained`  
**Severity:** Critical  
**Categories:** ZKRollup  

### Description

Detects under-constrained ZK circuits with missing constraints

### Vulnerable Patterns

- Public inputs without range constraints
- No input validation for proof

### Remediation

- Add range constraints: require(publicInput < FIELD_SIZE, \
- Validate all public inputs before proof verification

### Source

`zk_proofs/circuit_constraints.rs`

---

## ZK Proof Verification Bypass

**ID:** `zk-proof-bypass`  
**Severity:** Critical  
**Categories:** L2, ZKRollup  
**CWE:** CWE-20, CWE-345  

### Description

Detects missing or incomplete ZK proof verification in rollup contracts, including proof replay vulnerabilities, public input manipulation, and batch submission without proper verification

### Source

`src/zk_proof_bypass.rs`

---

## ZK Proof Malleability

**ID:** `zk-proof-malleability`  
**Severity:** Critical  
**Categories:** ZKRollup  

### Description

Detects proof malleability attacks in ZK systems

### Vulnerable Patterns

- Proof verification without uniqueness check
- No binding to specific transaction
- Missing signature over proof

### Remediation

- Include unique identifier in proof: require(!usedProofs[proofHash], \
- Include msg.sender in public inputs: verifyProof(proof, [msg.sender, ...otherInputs])
- Require signature over proof hash: bytes32 proofHash = keccak256(proof); verify signature

### Source

`zk_proofs/proof_malleability.rs`

---

## ZK Recursive Proof Validation

**ID:** `zk-recursive-proof-validation`  
**Severity:** High  
**Categories:** ZKRollup  

### Description

Detects recursive proof validation issues

### Vulnerable Patterns

- Batch proof verification without individual validation
- No depth limit on recursion

### Remediation

- Validate each proof individually before aggregation or use proper aggregation scheme
- Add recursion depth limit: require(depth <= MAX_DEPTH, \

### Source

`zk_proofs/recursive_proof.rs`

---

## ZK Trusted Setup Bypass

**ID:** `zk-trusted-setup-bypass`  
**Severity:** High  
**Categories:** ZKRollup  

### Description

Detects compromised trusted setup validation

### Vulnerable Patterns

- Verifier parameters hardcoded without validation
- No ceremony validation

### Remediation

- Validate verifying key against known hash: require(keccak256(vk) == EXPECTED_VK_HASH)
- Document and validate setup ceremony: // Setup hash: 0x... from ceremony with N participants

### Source

`zk_proofs/trusted_setup_bypass.rs`

---

