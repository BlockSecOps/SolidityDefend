# Upgrades Detectors

**Total:** 7 detectors

---

## Dangerous Delegatecall

**ID:** `dangerous-delegatecall`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  
**CWE:** CWE-829, CWE-494  

### Description



### Details

Check if function has dangerous delegatecall

### Source

`crates/detectors/src/dangerous_delegatecall.rs`

---

## Diamond Delegatecall Zero

**ID:** `diamond-delegatecall-zero`  
**Severity:** Critical  
**Categories:** Diamond, Upgradeable, ExternalCalls  
**CWE:** CWE-476, CWE-476, CWE-476, CWE-476  

### Description



### Source

`crates/detectors/src/diamond_delegatecall_zero.rs`

---

## Diamond Storage Collision

**ID:** `diamond-storage-collision`  
**Severity:** Critical  
**Categories:** Diamond, Upgradeable  
**CWE:** CWE-1321, CWE-1321  

### Description



### Source

`crates/detectors/src/diamond_storage_collision.rs`

---

## Storage Layout Upgrade

**ID:** `storage-layout-upgrade`  
**Severity:** Critical  
**Categories:** Upgradeable, Logic  

### Description



### Details

Storage Layout Upgrade Violation Detection

Detects upgradeable proxy patterns with storage layout violations that cause
state corruption during upgrades.

### Source

`crates/detectors/src/storage_layout_upgrade.rs`

---

## Upgradeable Proxy Issues

**ID:** `upgradeable-proxy-issues`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-665, CWE-913  

### Description



### Details

Check for upgradeable proxy vulnerabilities

### Remediation

- Fix proxy implementation in '{}'. \
                    Use storage gaps for future upgrades, implement initializer modifiers, \
                    add upgrade delay with timelock, validate implementation addresses, \
                    use UUPS pattern with _authorizeUpgrade, and emit events for all upgrades.

### Source

`crates/detectors/src/upgradeable_proxy_issues.rs`

---

## Diamond Selector Collision

**ID:** `diamond-selector-collision`  
**Severity:** High  
**Categories:** Diamond, Upgradeable  
**CWE:** CWE-694, CWE-694, CWE-694, CWE-694  

### Description



### Source

`crates/detectors/src/diamond_selector_collision.rs`

---

## Diamond Loupe Violation

**ID:** `diamond-loupe-violation`  
**Severity:** Medium  
**Categories:** Diamond, Upgradeable, BestPractices  
**CWE:** CWE-573, CWE-573, CWE-573, CWE-573  

### Description



### Source

`crates/detectors/src/diamond_loupe_violation.rs`

---

