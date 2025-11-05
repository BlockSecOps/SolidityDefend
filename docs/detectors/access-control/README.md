# Access Control Detectors

**Total:** 9 detectors

---

## Enhanced Access Control

**ID:** `enhanced-access-control`  
**Severity:** Critical  
**Categories:** AccessControl, BestPractices  

### Description



### Details

Enhanced Access Control Detector (OWASP 2025)

Detects role management flaws and privilege escalation risks.
Access control failures led to $953M in losses in 2024.

### Source

`crates/detectors/src/owasp2025/enhanced_access_control.rs`

---

## Role Hierarchy Bypass

**ID:** `role-hierarchy-bypass`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description



### Details

Role Hierarchy Bypass Detector

Detects role hierarchy violations in OpenZeppelin AccessControl systems where
lower privilege roles can execute admin functions. This was the cause of the
KiloEx DEX $7M loss in 2024.

### Source

`crates/detectors/src/access_control_advanced/role_hierarchy_bypass.rs`

---

## Time Locked Admin Bypass

**ID:** `time-locked-admin-bypass`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description



### Details

Time-Locked Admin Bypass Detector

Detects timelock circumvention patterns and missing delay enforcement on critical
admin functions. Prevents instant rug pulls despite timelock promises.

### Remediation

- Route all admin functions through timelock contract with schedule→execute pattern

### Source

`crates/detectors/src/access_control_advanced/time_locked_admin_bypass.rs`

---

## Tx Origin Authentication

**ID:** `tx-origin-authentication`  
**Severity:** Critical  
**Categories:** AccessControl, BestPractices  
**CWE:** CWE-477, CWE-284  

### Description



### Details


Detects when tx.origin is used for access control, which is vulnerable
to phishing attacks where a malicious contract can call the victim's
contract while tx.origin remains the victim's address.
Check if function contains tx.origin usage for authentication
Extract function source code from context

### Source

`crates/detectors/src/auth.rs`

---

## Missing Access Control Modifiers

**ID:** `missing-access-modifiers`
**Severity:** Critical
**Categories:** AccessControl
**CWE:** CWE-284

### Description

Detects functions that perform critical operations without proper access control modifiers.

### Details

This detector identifies functions with names suggesting critical operations (withdraw, transfer, mint, burn, admin actions, etc.) that lack access control modifiers like `onlyOwner`, `onlyAdmin`, or similar protection.

Critical operations without access control can allow any user to execute privileged functionality, leading to:
- Unauthorized fund withdrawals
- Unauthorized minting/burning of tokens
- Contract takeover
- Protocol manipulation

### Remediation

- Add appropriate access control modifiers (`onlyOwner`, `onlyAdmin`, `onlyRole`, etc.) to functions performing critical operations
- For user-facing functions that operate on `msg.sender`'s own resources, ensure proper authorization checks are in place
- Consider using OpenZeppelin's AccessControl or Ownable contracts for standardized access control patterns

### Source

`crates/detectors/src/access_control.rs`

---

## Unprotected Initializer

**ID:** `unprotected-initializer`
**Severity:** High
**Categories:** AccessControl
**CWE:** CWE-284, CWE-665

### Description

Initializer functions lack proper access control.

### Details

Detects initializer functions (init, initialize, setup, configure) that can be called by anyone. Unprotected initializers are a common vulnerability in upgradeable contracts and can lead to:
- Contract takeover by malicious actors
- Re-initialization attacks
- Unauthorized configuration changes

The detector looks for functions with names containing "init", "setup", "configure", or exactly named "initialize" that lack access control modifiers.

### Remediation

- Add an access control modifier to initializer functions (e.g., `onlyOwner`, `onlyProxy`)
- Ensure initializers can only be called once during deployment
- Use OpenZeppelin's Initializable pattern with the `initializer` modifier
- Consider using a factory pattern where initialization happens atomically during deployment

### Source

`crates/detectors/src/access_control.rs`

---

## Default Visibility

**ID:** `default-visibility`
**Severity:** Medium
**Categories:** AccessControl
**CWE:** CWE-200

### Description

Detects functions and state variables using default visibility.

### Details

In older Solidity versions (prior to 0.5.0), functions and state variables without explicit visibility modifiers defaulted to `public`. This can unintentionally expose internal functionality or sensitive data.

This detector specifically targets contracts using Solidity 0.4.x versions where:
- Functions without visibility keywords are implicitly `public`
- State variables without visibility are implicitly `public`

### Remediation

- Explicitly declare visibility for all functions and state variables
- Use `private` or `internal` for functions that shouldn't be publicly accessible
- Upgrade to Solidity 0.5.0 or later where explicit visibility is required
- Review all public functions to ensure they should be externally callable

### Source

`crates/detectors/src/access_control.rs`

---

## Multi Role Confusion

**ID:** `multi-role-confusion`  
**Severity:** High  
**Categories:** AccessControl  

### Description



### Details

Multi-Role Confusion Detector

Detects functions with contradictory role requirements and inconsistent access
patterns across similar functions.

### Remediation

- Ensure clear separation of duties - same storage should not be modifiable by multiple unrelated roles

### Source

`crates/detectors/src/access_control_advanced/multi_role_confusion.rs`

---

## Guardian Role Centralization

**ID:** `guardian-role-centralization`  
**Severity:** Medium  
**Categories:** AccessControl  

### Description



### Details

Guardian Role Centralization Detector

Detects guardian/emergency roles with excessive power that create single points
of failure and rug pull risks. Emergency powers should be limited in scope
and subject to multisig or DAO control.

### Remediation

- Require multisig approval or implement delay mechanism for emergency pause actions

### Source

`crates/detectors/src/access_control_advanced/guardian_role_centralization.rs`

---

