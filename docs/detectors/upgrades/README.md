# Upgrade Security Detectors

**Total:** 8 detectors

---

## Diamond Delegatecall to Zero Address

**ID:** `diamond-delegatecall-zero`  
**Severity:** Critical  
**Categories:** Diamond, Upgradeable, ExternalCalls  
**CWE:** CWE-476  

### Description

Detects unsafe delegatecall in Diamond fallback that fails to validate facet address existence before execution

### Vulnerable Patterns

- Missing address(0) validation
- Missing code existence validation

### Source

`src/diamond_delegatecall_zero.rs`

---

## Diamond Initialization Reentrancy

**ID:** `diamond-init-reentrancy`  
**Severity:** High  
**Categories:** Diamond, Upgradeable, Reentrancy  
**CWE:** CWE-841  

### Description

Detects reentrancy vulnerabilities during Diamond initialization caused by external calls in diamondCut without reentrancy guards

### Vulnerable Patterns

- diamondCut with delegatecall but no reentrancy guard
- State changes after initialization delegatecall

### Source

`src/diamond_init_reentrancy.rs`

---

## Diamond Loupe Standard Violation

**ID:** `diamond-loupe-violation`  
**Severity:** Medium  
**Categories:** Diamond, Upgradeable, BestPractices  
**CWE:** CWE-573  

### Description

Detects missing or incorrect ERC-2535 Diamond Loupe functions required for introspection and facet discovery

### Vulnerable Patterns

- Missing IDiamondLoupe interface support

### Source

`src/diamond_loupe_violation.rs`

---

## Diamond Function Selector Collision

**ID:** `diamond-selector-collision`  
**Severity:** High  
**Categories:** Diamond, Upgradeable  
**CWE:** CWE-694  

### Description

Detects function selector collisions in Diamond facets caused by duplicate selectors across facets or missing validation during diamondCut operations

### Vulnerable Patterns

- Missing selector uniqueness validation
- Missing FacetCutAction validation

### Source

`src/diamond_selector_collision.rs`

---

## Diamond Storage Collision

**ID:** `diamond-storage-collision`  
**Severity:** Critical  
**Categories:** Diamond, Upgradeable  
**CWE:** CWE-1321  

### Description

Detects storage collision risks in Diamond facets caused by direct storage variable declarations instead of using the Diamond Storage pattern for namespace isolation

### Vulnerable Patterns

- Direct storage variables without Diamond Storage pattern
- Missing namespace isolation even with library pattern

### Source

`src/diamond_storage_collision.rs`

---

## Metamorphic Contract Detection

**ID:** `metamorphic-contract`  
**Severity:** Critical  
**Categories:** Metamorphic, Deployment, Logic  

### Description

Detects metamorphic contract patterns (CREATE2 + SELFDESTRUCT) that enable changing contract code at the same address

### Vulnerable Patterns

- Full metamorphic pattern (CREATE2 + SELFDESTRUCT in constructor)
- Factory that deploys contracts with SELFDESTRUCT

### Source

`src/metamorphic_contract.rs`

---

## Storage Layout Upgrade Violation

**ID:** `storage-layout-upgrade`  
**Severity:** Critical  
**Categories:** Upgradeable, Logic  

### Description

Detects upgradeable contracts with storage layout violations that cause state corruption during upgrades

### Vulnerable Patterns

- Missing storage gap in base contracts
- Storage gap that's too small
- REMOVED - Constants don't use storage slots and are safe
- Complex inheritance without gap

### Source

`src/storage_layout_upgrade.rs`

---

## Upgradeable Proxy Issues

**ID:** `upgradeable-proxy-issues`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-665, CWE-913  

### Description

Detects vulnerabilities in upgradeable proxy patterns including storage collisions, initialization issues, and unsafe upgrades

### Vulnerable Patterns

- Unprotected upgrade function
- Initialize function can be called multiple times
- Missing storage gap for future upgrades

### Source

`src/upgradeable_proxy_issues.rs`

---

