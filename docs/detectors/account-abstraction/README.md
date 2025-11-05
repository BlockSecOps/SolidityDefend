# Account Abstraction Detectors

**Total:** 20 detectors

---

## Aa Account Takeover

**ID:** `aa-account-takeover`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  
**CWE:** CWE-284, CWE-639, CWE-269, CWE-862, CWE-345, CWE-290, CWE-749, CWE-670, CWE-913, CWE-494  

### Description



### Source

`crates/detectors/src/aa_account_takeover.rs`

---

## Aa Calldata Encoding Exploit

**ID:** `aa-calldata-encoding-exploit`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

AA Calldata Encoding Exploit Detector

Detects calldata manipulation vulnerabilities after signature validation in
ERC-4337 Account Abstraction wallets. This was a critical vulnerability
discovered in production AA wallets in 2024.

### Remediation

- Ensure signature covers the final executed calldata. Use hash of complete UserOperation struct including calldata.

### Source

`crates/detectors/src/aa_advanced/calldata_encoding_exploit.rs`

---

## Aa Paymaster Fund Drain

**ID:** `aa-paymaster-fund-drain`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

AA Paymaster Fund Drain Detector

Detects paymaster sponsorship abuse patterns that can drain paymaster funds.
Paymasters in ERC-4337 sponsor gas for users, but improper validation can
lead to fund drainage attacks.

### Source

`crates/detectors/src/aa_advanced/paymaster_fund_drain.rs`

---

## Erc4337 Entrypoint Trust

**ID:** `erc4337-entrypoint-trust`  
**Severity:** Critical  
**Categories:** AccessControl, Validation  
**CWE:** CWE-798, CWE-670, CWE-20, CWE-345, CWE-284, CWE-862, CWE-1104  

### Description



### Source

`crates/detectors/src/erc4337_entrypoint_trust.rs`

---

## Erc4337 Paymaster Abuse

**ID:** `erc4337-paymaster-abuse`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  

### Description



### Details

ERC-4337 Paymaster Abuse Detector

### Source

`crates/detectors/src/erc4337_paymaster_abuse.rs`

---

## Erc4337 Paymaster Abuse

**ID:** `erc4337-paymaster-abuse`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

ERC-4337 Paymaster Abuse Detector

Detects vulnerabilities in ERC-4337 paymaster implementations that allow:
1. Replay attacks via nonce bypass (Biconomy exploit)
2. Gas estimation manipulation (~0.05 ETH per exploit)
3. Arbitrary transaction sponsorship
4. Missing spending limits (sponsor fund draining)
5. No chain ID binding (cross-chain replay)

Severity: CRITICAL
Category: DeFi, Account Abstraction

Real-World Exploit:
- Biconomy Nonce Bypass (2024): Attacker upgraded accounts to bypass nonce verification,
drained paymaster funds via signature replay
- Alchemy Audit (2025): Compromised signer API can withdraw full approval

### Source

`crates/detectors/src/aa/paymaster_abuse.rs`

---

## Aa Bundler Dos Enhanced

**ID:** `aa-bundler-dos-enhanced`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description



### Details

AA Bundler DOS Enhanced Detector

Enhanced detection for bundler DOS attacks via gas griefing and computational
complexity attacks. Covers 2024 discovered patterns beyond the basic detector.

### Remediation

- Add strict bounds to loops in validateUserOp; enforce maximum iteration count

### Source

`crates/detectors/src/aa_advanced/bundler_dos_enhanced.rs`

---

## Aa Initialization Vulnerability

**ID:** `aa-initialization-vulnerability`  
**Severity:** High  
**Categories:** AccessControl, Validation  
**CWE:** CWE-306, CWE-665, CWE-665, CWE-362, CWE-284, CWE-863, CWE-20, CWE-639, CWE-20, CWE-913  

### Description



### Source

`crates/detectors/src/aa_initialization_vulnerability.rs`

---

## Aa Nonce Management

**ID:** `aa-nonce-management`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

AA Nonce Management Detector

Detects improper nonce management in ERC-4337 accounts:
1. Always uses nonce key 0 (no parallel operation support)
2. Manual nonce tracking (not using EntryPoint)
3. Non-sequential nonce validation
4. Session keys share nonce space (collision risk)

Severity: HIGH
Category: Account Abstraction

### Source

`crates/detectors/src/aa/nonce_management.rs`

---

## Aa Session Key Vulnerabilities

**ID:** `aa-session-key-vulnerabilities`  
**Severity:** High  
**Categories:** AccessControl, Logic  

### Description



### Details

Account Abstraction Session Key Vulnerabilities Detector

### Source

`crates/detectors/src/aa_session_key_vulnerabilities.rs`

---

## Aa Session Key Vulnerabilities

**ID:** `aa-session-key-vulnerabilities`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

AA Session Key Vulnerabilities Detector

Detects insecure session key implementations:
1. Unlimited permissions (session key = full account access)
2. No expiration time (indefinite access)
3. Missing target/function restrictions
4. No spending limits
5. No emergency pause mechanism

### Remediation

- Add SessionKeyData struct with validUntil, allowedTargets, spendingLimit fields
- Add validUntil field and time validation in validateUserOp
- Add allowedTargets array and validation

### Source

`crates/detectors/src/aa/session_key_vulnerabilities.rs`

---

## Aa Signature Aggregation

**ID:** `aa-signature-aggregation`  
**Severity:** High  
**Categories:** AccessControl, Logic  

### Description



### Details

Account Abstraction Signature Aggregation Issues Detector

### Source

`crates/detectors/src/aa_signature_aggregation.rs`

---

## Aa Signature Aggregation Bypass

**ID:** `aa-signature-aggregation-bypass`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

AA Signature Aggregation Bypass Detector

Detects signature aggregation vulnerabilities where batch operations can be
executed without proper validation of all signatures in the aggregated batch.

### Remediation

- Validate each UserOp signature individually in a loop before batch acceptance

### Source

`crates/detectors/src/aa_advanced/signature_aggregation_bypass.rs`

---

## Aa User Operation Replay

**ID:** `aa-user-operation-replay`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

AA User Operation Replay Detector

Detects UserOperation replay vulnerabilities across bundlers and chains.
Prevents double-spending and cross-chain replay attacks.

### Source

`crates/detectors/src/aa_advanced/user_operation_replay.rs`

---

## Aa Bundler Dos

**ID:** `aa-bundler-dos`  
**Severity:** Medium  
**Categories:** Logic, Validation  
**CWE:** CWE-400, CWE-834, CWE-834, CWE-606, CWE-1321, CWE-913, CWE-405, CWE-400, CWE-367, CWE-829  

### Description



### Source

`crates/detectors/src/aa_bundler_dos.rs`

---

## Aa Entry Point Reentrancy

**ID:** `aa-entry-point-reentrancy`  
**Severity:** Medium  
**Categories:** DeFi, Reentrancy  

### Description



### Details

AA Entry Point Reentrancy Detector

Detects reentrancy vulnerabilities in EntryPoint's handleOps and validateUserOp
functions. AA-specific reentrancy can manipulate state during validation phase.

### Source

`crates/detectors/src/aa_advanced/entry_point_reentrancy.rs`

---

## Aa Signature Aggregation

**ID:** `aa-signature-aggregation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

AA Signature Aggregation Detector

Detects vulnerabilities in ERC-4337 signature aggregation:
1. No aggregator validation
2. Missing signature count verification
3. No signer deduplication
4. Threshold bypass via aggregation

### Remediation

- Add trusted aggregator whitelist
- Require signers.length >= THRESHOLD

### Source

`crates/detectors/src/aa/signature_aggregation.rs`

---

## Aa Social Recovery

**ID:** `aa-social-recovery`  
**Severity:** Medium  
**Categories:** AccessControl, Logic  

### Description



### Details

Account Abstraction Social Recovery Attacks Detector

### Source

`crates/detectors/src/aa_social_recovery.rs`

---

## Aa Social Recovery

**ID:** `aa-social-recovery`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

AA Social Recovery Detector

Detects vulnerabilities in social recovery mechanisms:
1. No recovery delay (instant takeover)
2. Insufficient guardian threshold (1-of-N)
3. No recovery cancellation

### Remediation

- Add 24-48 hour delay between initiateRecovery and executeRecovery
- Add cancelRecovery function callable by current owner

### Source

`crates/detectors/src/aa/social_recovery.rs`

---

## Erc4337 Gas Griefing

**ID:** `erc4337-gas-griefing`  
**Severity:** Low  
**Categories:** DeFi  

### Description



### Details

ERC-4337 Gas Griefing Detector

Detects gas griefing vectors in ERC-4337:
1. Large error messages (gas DoS)
2. Unbounded loops in validation
3. Storage writes in validation (high gas, banned by spec)

### Remediation

- Avoid storage writes in validation phase

### Source

`crates/detectors/src/aa/gas_griefing.rs`

---

