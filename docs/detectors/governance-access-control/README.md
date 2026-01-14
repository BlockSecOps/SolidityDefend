# Governance & Access Control Detectors

**Total:** 10 detectors (Phase 47 - v1.8.4)

---

## Phase 47: Governance & Access Control (v1.8.4)

### Governance Parameter Bypass

**ID:** `governance-parameter-bypass`
**Severity:** Critical
**Categories:** AccessControl, Logic
**CWE:** CWE-284

Detects governance parameters that can be changed before timelock restrictions apply, enabling admins to bypass governance controls. Covers setter functions without timelock protection, emergency functions modifying governance params, and direct state changes to governance variables.

**Source:** `src/governance_parameter_bypass.rs`

---

### Voting Snapshot Manipulation

**ID:** `voting-snapshot-manipulation`
**Severity:** High
**Categories:** AccessControl, DeFi
**CWE:** CWE-362

Detects voting systems where snapshots can be taken after token acquisition or delegation, enabling flash loan voting attacks. Covers current block snapshots, missing historical snapshots, and immediate delegation effects.

**Source:** `src/voting_snapshot_manipulation.rs`

---

### Quorum Calculation Overflow

**ID:** `quorum-calculation-overflow`
**Severity:** Critical
**Categories:** AccessControl, Logic
**CWE:** CWE-190

Detects quorum calculations vulnerable to overflow or reentrancy attacks that can over-count votes and bypass quorum requirements. Covers unchecked arithmetic, division before multiplication precision loss, and vote counting without reentrancy protection.

**Source:** `src/quorum_calculation_overflow.rs`

---

### Proposal Front-running

**ID:** `proposal-frontrunning`
**Severity:** High
**Categories:** MEV, AccessControl
**CWE:** CWE-362

Detects governance systems vulnerable to proposal front-running where attackers can submit counter-proposals in the same block. Covers missing same-block prevention, predictable proposal IDs, and zero/low voting delays.

**Source:** `src/proposal_frontrunning.rs`

---

### Governor Refund Drain

**ID:** `governor-refund-drain`
**Severity:** Critical
**Categories:** AccessControl, Logic
**CWE:** CWE-284

Detects governance systems where refund parameters can be changed to drain the treasury through excessive gas refunds or bounties. Covers unbounded refund amounts, unprotected refund rate setters, and uncapped gas price in refund calculations.

**Source:** `src/governor_refund_drain.rs`

---

### Timelock Bypass via Delegatecall

**ID:** `timelock-bypass-delegatecall`
**Severity:** Critical
**Categories:** AccessControl, Upgradeable
**CWE:** CWE-863

Detects patterns where timelock restrictions can be bypassed by routing calls through proxy contracts with delegatecall. Covers delegatecall without timelock verification, execute functions bypassing timelock, and msg.sender confusion in delegatecall context.

**Source:** `src/timelock_bypass_delegatecall.rs`

---

### Role Escalation via Upgrade

**ID:** `role-escalation-upgrade`
**Severity:** Critical
**Categories:** AccessControl, Upgradeable
**CWE:** CWE-269

Detects upgrade patterns where new implementation constructors can grant elevated privileges, bypassing access control. Covers constructor privilege grants in upgradeable contracts, reinitializer role escalation, and weak upgrade protection.

**Source:** `src/role_escalation_upgrade.rs`

---

### Access Control Race Condition

**ID:** `accesscontrol-race-condition`
**Severity:** High
**Categories:** AccessControl, Logic
**CWE:** CWE-362

Detects access control patterns vulnerable to race conditions where concurrent grant/revoke operations can lead to privilege confusion. Covers non-atomic batch role operations, stale role checks during execution, and admin role transfers without atomic revoke.

**Source:** `src/accesscontrol_race_condition.rs`

---

### Operator Whitelist Inheritance

**ID:** `operator-whitelist-inheritance`
**Severity:** Medium
**Categories:** AccessControl, Upgradeable
**CWE:** CWE-732

Detects upgradeable contracts where operator approvals may persist after upgrades, granting unintended access to previous operators. Covers approval mapping persistence, missing versioning in approvals, and initializers without approval reset.

**Source:** `src/operator_whitelist_inheritance.rs`

---

### Cross-Contract Role Confusion

**ID:** `cross-contract-role-confusion`
**Severity:** High
**Categories:** AccessControl, Logic
**CWE:** CWE-863

Detects access control patterns where roles defined in one contract are mistakenly used for authorization in another contract. Covers external role checks, shared role constants, generic role names with collision risk, and role checks in delegatecall context.

**Source:** `src/cross_contract_role_confusion.rs`

---

## CWE Mappings

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-284 | Improper Access Control | governance-parameter-bypass, governor-refund-drain |
| CWE-190 | Integer Overflow or Wraparound | quorum-calculation-overflow |
| CWE-269 | Improper Privilege Management | role-escalation-upgrade |
| CWE-362 | Concurrent Execution with Shared Resource | voting-snapshot-manipulation, proposal-frontrunning, accesscontrol-race-condition |
| CWE-732 | Incorrect Permission Assignment | operator-whitelist-inheritance |
| CWE-863 | Incorrect Authorization | timelock-bypass-delegatecall, cross-contract-role-confusion |

---

## Real-World Attack Examples

### Governance Parameter Manipulation (2023-2024)

Multiple DeFi governance systems have been exploited by admins changing parameters before timelock restrictions took effect, allowing instant parameter changes that should have been time-delayed.

**Detectors that would catch this:**
- `governance-parameter-bypass`
- `timelock-bypass-delegatecall`

### Flash Loan Governance Attacks

Several protocols have been exploited through flash loan voting attacks where attackers borrow tokens, vote, and return in a single transaction due to improper snapshot timing.

**Detectors that would catch this:**
- `voting-snapshot-manipulation`
- `quorum-calculation-overflow`

### Upgrade Role Escalation

Upgradeable contracts have been exploited when new implementations grant elevated privileges in constructors, bypassing intended access control.

**Detectors that would catch this:**
- `role-escalation-upgrade`
- `operator-whitelist-inheritance`

### Cross-Contract Authorization Confusion

Multi-contract systems have been exploited when role checks from one contract are incorrectly used to authorize actions in another contract with different semantics.

**Detectors that would catch this:**
- `cross-contract-role-confusion`
- `accesscontrol-race-condition`
