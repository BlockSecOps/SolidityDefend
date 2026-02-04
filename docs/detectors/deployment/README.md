# Deployment & Metamorphic Contract Detectors

**Total:** 12 detectors (4 base + 8 Phase 45 Metamorphic/CREATE2)

---

## Phase 45: Metamorphic & CREATE2 Patterns (v1.8.2)

### Metamorphic Contract Risk

**ID:** `metamorphic-contract-risk`
**Severity:** Critical
**Categories:** Metamorphic, Deployment
**CWE:** CWE-913

Detects CREATE2 + SELFDESTRUCT patterns that enable bytecode mutation at the same address. Attackers can deploy benign code, get it approved, destroy it, and redeploy malicious code at the same address.

**Source:** `src/metamorphic_contract_risk.rs`

---

### CREATE2 Salt Front-running

**ID:** `create2-salt-frontrunning`
**Severity:** High
**Categories:** Metamorphic, Deployment
**CWE:** CWE-330

Detects predictable CREATE2 salts that enable deployment front-running. Attackers can predict deployment addresses and front-run with their own contracts.

**Source:** `src/create2_salt_frontrunning.rs`

---

### CREATE2 Address Collision

**ID:** `create2-address-collision`
**Severity:** Critical
**Categories:** Metamorphic, Deployment
**CWE:** CWE-706

Detects intentional address reuse patterns after contract destruction that enable code substitution attacks. Includes salt reuse detection, pre-approval patterns, and address precomputation.

**Source:** `src/create2_address_collision.rs`

---

### EXTCODESIZE Check Bypass

**ID:** `extcodesize-check-bypass`
**Severity:** High
**Categories:** Validation, Logic
**CWE:** CWE-670

Detects EXTCODESIZE checks used for EOA detection that can be bypassed during contract construction when code size is temporarily 0. Covers isContract() patterns and onlyEOA modifiers.

**Source:** `src/extcodesize_check_bypass.rs`

---

### Selfdestruct Recipient Control

**ID:** `selfdestruct-recipient-control`
**Severity:** High
**Categories:** AccessControl, Logic
**CWE:** CWE-284

Detects selfdestruct operations where the recipient address can be controlled by users, enabling fund theft. Covers parameterized recipients, unprotected selfdestruct, and msg.sender recipients.

**Source:** `src/selfdestruct_recipient_control.rs`

---

### Contract Recreation Attack

**ID:** `contract-recreation-attack`
**Severity:** Critical
**Categories:** Metamorphic, Deployment
**CWE:** CWE-913

Detects patterns where contracts can be destroyed and recreated at the same address with different code. Includes destroy-redeploy patterns, mutable bytecode storage, and factory recreation.

**Source:** `src/contract_recreation_attack.rs`

---

### Constructor Reentrancy

**ID:** `constructor-reentrancy`
**Severity:** High
**Categories:** Reentrancy, Deployment
**CWE:** CWE-841

Detects external calls in constructors that can enable reentrancy before security mechanisms are fully initialized. Covers external calls, callback triggers, and state-after-call patterns.

**Important:** This detector correctly distinguishes between ERC standards:
- **ERC20 `_mint()`** - Does NOT trigger callbacks, NOT flagged
- **ERC721/ERC1155 `_safeMint()`** - Triggers `onERC721Received`/`onERC1155Received`, IS flagged
- **`safeTransferFrom()`** - Triggers receiver callbacks, IS flagged

**Source:** `src/constructor_reentrancy.rs`

---

### Initcode Injection

**ID:** `initcode-injection`
**Severity:** Critical
**Categories:** Deployment, Validation
**CWE:** CWE-94

Detects CREATE2 deployments where initcode can be controlled or manipulated by attackers to deploy malicious contracts. Covers user-controlled bytecode, dynamic construction, and unvalidated deployment.

**Source:** `src/initcode_injection.rs`

---

## Base Deployment Detectors

### Metamorphic Contract

**ID:** `metamorphic-contract`
**Severity:** Critical

Base metamorphic contract detection.

---

### CREATE2 Front-running

**ID:** `create2-frontrunning`
**Severity:** High

CREATE2 front-running vulnerability detection.

---

### Selfdestruct Recipient

**ID:** `selfdestruct-recipient`
**Severity:** High

Selfdestruct recipient vulnerability detection.

---

### EXTCODESIZE Bypass

**ID:** `extcodesize-bypass`
**Severity:** High

EXTCODESIZE bypass detection.

---

## CWE Mappings

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-913 | Improper Control of Dynamically-Managed Code Resources | metamorphic-contract-risk, contract-recreation-attack |
| CWE-94 | Improper Control of Generation of Code (Code Injection) | initcode-injection |
| CWE-706 | Use of Incorrectly-Resolved Name or Reference | create2-address-collision |
| CWE-330 | Use of Insufficiently Random Values | create2-salt-frontrunning |
| CWE-670 | Always-Incorrect Control Flow Implementation | extcodesize-check-bypass |
| CWE-284 | Improper Access Control | selfdestruct-recipient-control |
| CWE-841 | Improper Enforcement of Behavioral Workflow | constructor-reentrancy |

---

## Real-World Attack Examples

### Tornado Cash Governance Attack (2023)

A metamorphic contract was deployed that appeared legitimate, passed governance checks, was approved, then destroyed and redeployed with malicious code that drained the governance treasury.

**Detectors that would catch this:**
- `metamorphic-contract-risk`
- `contract-recreation-attack`
- `create2-address-collision`

### CREATE2 Address Manipulation

Attackers can precompute CREATE2 addresses and get pre-approvals for tokens/permissions before deploying the actual contract. The deployed contract can then drain approved funds.

**Detectors that would catch this:**
- `create2-address-collision`
- `initcode-injection`
- `create2-salt-frontrunning`
