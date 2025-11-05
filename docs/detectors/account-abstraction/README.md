# Account Abstraction Detectors

**Total:** 21 detectors

---

## Account Abstraction Takeover Vulnerability

**ID:** `aa-account-takeover`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  
**CWE:** CWE-269, CWE-284, CWE-639, CWE-862  

### Description

Detects vulnerabilities allowing EntryPoint replacement attacks and full account takeover in ERC-4337 wallets

### Vulnerable Patterns

- Unprotected EntryPoint replacement
- Module system vulnerabilities

### Remediation

- Prevent EntryPoint replacement: \
     (1) Make EntryPoint immutable if possible, \
     (2) Add strict access control (multi-sig required), \
     (3) Implement time-lock for EntryPoint updates, \
     (4) Require user signature for changes, \
     (5) Emit EntryPointChanged event for monitoring.

### Source

`src/aa_account_takeover.rs`

---

## Account Abstraction Bundler DoS

**ID:** `aa-bundler-dos`  
**Severity:** Medium  
**Categories:** Logic, Validation  
**CWE:** CWE-400, CWE-606, CWE-834, CWE-913, CWE-1321  

### Description

Detects verification logic in ERC-4337 validateUserOp that is susceptible to denial-of-service attacks against bundlers

### Vulnerable Patterns

- External calls in validateUserOp
- Unbounded loops in validation
- Storage access violations

### Remediation

- Remove external calls from validateUserOp: \
     (1) Move external calls to execution phase, \
     (2) Use view-only calls for validation, \
     (3) Cache validation data on-chain, \
     (4) Follow ERC-4337 validation restrictions, \
     (5) Minimize storage access in validation.
- Remove or bound loops in validateUserOp: \
     (1) Avoid loops in validation phase, \
     (2) Use fixed-size arrays if needed, \
     (3) Move iteration to execution phase, \
     (4) Add maximum iteration limits, \
     (5) Simplify validation logic.
- Restrict storage access in validateUserOp: \
     (1) Only access account

### Source

`src/aa_bundler_dos.rs`

---

## AA Bundler DOS Enhanced

**ID:** `aa-bundler-dos-enhanced`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description

Enhanced bundler DOS detection covering 2024 attack patterns

### Vulnerable Patterns

- validateUserOp with unbounded computation
- Expensive operations in validation without gas limit
- Storage reads from unknown contracts
- Paymaster validation without timeout

### Remediation

- Add strict bounds to loops in validateUserOp; enforce maximum iteration count
- Limit expensive operations or check gasleft() before execution; cap total validation gas
- Avoid external storage reads in validation or whitelist trusted contracts only

### Source

`aa_advanced/bundler_dos_enhanced.rs`

---

## AA Calldata Encoding Exploit

**ID:** `aa-calldata-encoding-exploit`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects calldata manipulation after signature validation in AA wallets

### Vulnerable Patterns

- Calldata decoded after signature validation
- UserOperation fields modified after validation
- Calldata passed to external contract without hash check

### Remediation

- Ensure signature covers the final executed calldata. Use hash of complete UserOperation struct including calldata.
- Do not modify UserOperation fields after signature validation. Create new struct if needed.

### Source

`aa_advanced/calldata_encoding_exploit.rs`

---

## AA Entry Point Reentrancy

**ID:** `aa-entry-point-reentrancy`  
**Severity:** Medium  
**Categories:** DeFi, Reentrancy  

### Description

Detects reentrancy in handleOps and validateUserOp functions

### Vulnerable Patterns

- External call in validateUserOp without reentrancy guard
- handleOps processes multiple operations without reentrancy protection
- State changes after external call in validation

### Remediation

- Add nonReentrant modifier to validateUserOp or use checks-effects-interactions pattern
- Add nonReentrant modifier to handleOps function to prevent reentrancy across batch

### Source

`aa_advanced/entry_point_reentrancy.rs`

---

## Account Abstraction Initialization Vulnerability

**ID:** `aa-initialization-vulnerability`  
**Severity:** High  
**Categories:** AccessControl, Validation  
**CWE:** CWE-284, CWE-306, CWE-362, CWE-665, CWE-863  

### Description

Detects missing signature verification in EIP-7702 initialization and account abstraction setup that allows unauthorized initialization

### Vulnerable Patterns

- Initialization without signature verification
- Missing initialization lock
- EntryPoint-only initialization bypass

### Remediation

- Implement secure initialization: \
     (1) Add initWithSig function requiring user signature, \
     (2) Verify signature matches expected owner, \
     (3) Use nonce to prevent replay attacks, \
     (4) Implement one-time initialization flag, \
     (5) Consider ERC-4337 EntryPoint-only initialization.
- Add initialization protection: \
     (1) Use initialized boolean flag, \
     (2) Require !initialized in init function, \
     (3) Set initialized = true after setup, \
     (4) Consider OpenZeppelin

### Source

`src/aa_initialization_vulnerability.rs`

---

## AA Nonce Management Vulnerabilities

**ID:** `aa-nonce-management`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects improper nonce management causing parallel operation failures and transaction collisions

### Remediation

- Support dynamic nonce keys for parallel operations: \
       \
       function validateUserOp(...) external { \
        // Extract nonce key from userOp.nonce \
        uint192 key = uint192(userOp.nonce >> 64); \
        \
        // Use key-specific nonce validation \
        uint256 expectedNonce = entryPoint.getNonce(address(this), key); \
        require(userOp.nonce == expectedNonce, \
- Use EntryPoint

### Source

`aa/nonce_management.rs`

---

## Advanced Nonce Management

**ID:** `aa-nonce-management-advanced`  
**Severity:** Medium  
**Categories:** AccessControl, Logic  

### Description

Detects parallel nonce issues, key-specific nonce problems, and transaction replay risks

### Source

`src/aa_nonce_management.rs`

---

## AA Paymaster Fund Drain

**ID:** `aa-paymaster-fund-drain`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects paymaster sponsorship abuse that can drain paymaster funds

### Vulnerable Patterns

- No gas limit cap on sponsored operations
- No user whitelist or rate limiting
- Paymaster balance not checked before sponsorship
- No per-user spending limit

### Remediation

- Implement max gas limit per operation (e.g., require(userOp.callGasLimit <= MAX_GAS_LIMIT))
- Implement either user whitelist OR rate limiting (requests per user per time period)
- Check paymaster balance before accepting sponsorship: require(getDeposit() >= estimatedCost)

### Source

`aa_advanced/paymaster_fund_drain.rs`

---

## Session Key Vulnerabilities

**ID:** `aa-session-key-vulnerabilities`  
**Severity:** High  
**Categories:** AccessControl, Logic  

### Description

Detects overly permissive session keys, missing expiration, and scope limit issues

### Source

`src/aa_session_key_vulnerabilities.rs`

---

## AA Session Key Vulnerabilities

**ID:** `aa-session-key-vulnerabilities`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects insecure session key implementations with unlimited permissions or missing restrictions

### Remediation

- Add SessionKeyData struct with validUntil, allowedTargets, spendingLimit fields
- Add validUntil field and time validation in validateUserOp
- Add allowedTargets array and validation
- Add allowedSelectors array (bytes4[]) and validation
- Add periodDuration and periodStart for resetting limits

### Source

`aa/session_key_vulnerabilities.rs`

---

## Signature Aggregation Issues

**ID:** `aa-signature-aggregation`  
**Severity:** High  
**Categories:** AccessControl, Logic  

### Description

Detects missing individual signature validation and aggregation bypass vulnerabilities

### Source

`src/aa_signature_aggregation.rs`

---

## AA Signature Aggregation Bypass

**ID:** `aa-signature-aggregation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects vulnerabilities in signature aggregation allowing threshold bypass

### Remediation

- Add trusted aggregator whitelist
- Require signers.length >= THRESHOLD
- Add duplicate signer check (nested loop or seen mapping)

### Source

`aa/signature_aggregation.rs`

---

## AA Signature Aggregation Bypass

**ID:** `aa-signature-aggregation-bypass`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects signature aggregation vulnerabilities in batch UserOperations

### Vulnerable Patterns

- Batch validation without individual signature checks
- Missing array length validation
- Signature aggregation without unique operation IDs
- Batch execution without failure handling

### Remediation

- Validate each UserOp signature individually in a loop before batch acceptance
- Require userOps.length == signatures.length before processing batch
- Generate unique operation ID for each UserOp: keccak256(abi.encode(userOp, nonce, chainId))

### Source

`aa_advanced/signature_aggregation_bypass.rs`

---

## Social Recovery Attacks

**ID:** `aa-social-recovery`  
**Severity:** Medium  
**Categories:** AccessControl, Logic  

### Description

Detects insufficient guardian thresholds, missing timelock delays, and recovery manipulation risks

### Source

`src/aa_social_recovery.rs`

---

## AA Social Recovery Vulnerabilities

**ID:** `aa-social-recovery`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects vulnerabilities in social recovery mechanisms

### Remediation

- Add 24-48 hour delay between initiateRecovery and executeRecovery
- Use threshold >= 50% of guardians (e.g., 3-of-5)
- Add cancelRecovery function callable by current owner

### Source

`aa/social_recovery.rs`

---

## AA User Operation Replay

**ID:** `aa-user-operation-replay`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects UserOperation replay across bundlers and chains

### Vulnerable Patterns

- Missing nonce validation
- No chain ID validation for cross-chain deployment
- UserOp hash doesn't include all fields

### Remediation

- Validate and increment nonce: require(userOp.nonce == currentNonce++, \
- Include chain ID in UserOp hash: keccak256(abi.encode(userOp, block.chainid))
- Include all UserOp fields in hash: sender, nonce, initCode, callData, callGasLimit, etc.

### Source

`aa_advanced/user_operation_replay.rs`

---

## ERC-4337 Untrusted EntryPoint

**ID:** `erc4337-entrypoint-trust`  
**Severity:** Critical  
**Categories:** AccessControl, Validation  
**CWE:** CWE-20, CWE-284, CWE-345, CWE-670, CWE-798, CWE-862  

### Description

Detects hardcoded or untrusted EntryPoint contracts in ERC-4337 account abstraction wallets that could allow full account takeover

### Vulnerable Patterns

- Hardcoded EntryPoint address
- Missing EntryPoint validation
- Mutable EntryPoint without access control

### Remediation

- Implement upgradeable EntryPoint pattern: \
     (1) Use storage variable for EntryPoint address, \
     (2) Add secure upgrade mechanism with time-lock, \
     (3) Emit events on EntryPoint changes, \
     (4) Implement EntryPoint validation checks, \
     (5) Consider multi-sig approval for EntryPoint updates.
- Add EntryPoint validation: \
     (1) Verify msg.sender is trusted EntryPoint in validateUserOp, \
     (2) Implement onlyEntryPoint modifier, \
     (3) Store and validate EntryPoint address, \
     (4) Revert on unauthorized callers, \
     (5) Use OpenZeppelin

### Source

`src/erc4337_entrypoint_trust.rs`

---

## ERC-4337 Gas Griefing Attacks

**ID:** `erc4337-gas-griefing`  
**Severity:** Low  
**Categories:** DeFi  

### Description

Detects gas griefing vectors that can DoS bundlers

### Remediation

- Add maximum iteration limit (e.g., <= 10)
- Avoid storage writes in validation phase

### Source

`aa/gas_griefing.rs`

---

## ERC-4337 Paymaster Abuse

**ID:** `erc4337-paymaster-abuse`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  

### Description

Detects unlimited sponsorship, missing gas validation, and spending limit issues in paymasters

### Source

`src/erc4337_paymaster_abuse.rs`

---

## ERC-4337 Paymaster Abuse

**ID:** `erc4337-paymaster-abuse`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects vulnerabilities in paymaster implementations allowing replay attacks, gas griefing, and sponsor fund draining

### Remediation

- Add hash tracking to prevent replay attacks: \
       \
       mapping(bytes32 => bool) public usedHashes; \
       \
       function validatePaymasterUserOp(...) external { \
        require(!usedHashes[userOpHash], \
- Implement per-account spending limits: \
       \
       mapping(address => uint256) public accountSpent; \
       uint256 public constant MAX_PER_ACCOUNT = 0.1 ether; \
       \
       function validatePaymasterUserOp(..., uint256 maxCost) external { \
        require( \
         accountSpent[userOp.sender] + maxCost <= MAX_PER_ACCOUNT, \
         \

### Source

`aa/paymaster_abuse.rs`

---

