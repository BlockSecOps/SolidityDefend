# Changelog

All notable changes to SolidityDefend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.8.1] - 2026-01-13

### Advanced MEV & Front-Running Detection - Phase 44

This release adds **12 new detectors** for advanced MEV (Maximal Extractable Value) and front-running attack patterns. MEV detection rate improved from 45% to ~65%. Total detectors: **269**.

#### Added

##### **Critical Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `sandwich-conditional-swap` | Conditional swap patterns vulnerable to sophisticated sandwich attacks | CWE-362 |
| `jit-liquidity-extraction` | JIT liquidity manipulation enabling MEV extraction | CWE-362 |
| `liquidation-mev` | Liquidation front-running including flash loan liquidations | CWE-362 |
| `token-launch-mev` | Token launch sniping targeting initial liquidity | CWE-362 |

##### **High Severity Detectors (7)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `backrunning-opportunity` | State changes exploitable via backrunning | CWE-362 |
| `bundle-inclusion-leak` | Information leakage enabling bundle prediction | CWE-200 |
| `order-flow-auction-abuse` | Order flow auction manipulation patterns | CWE-362 |
| `cross-domain-mev` | MEV extraction across L1/L2 boundaries | CWE-362 |
| `oracle-update-mev` | Oracle update front-running patterns | CWE-362 |
| `governance-proposal-mev` | Governance proposal front-running | CWE-362 |
| `nft-mint-mev` | NFT mint front-running and sniping | CWE-362 |

##### **Medium Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `encrypted-mempool-timing` | Timing attacks on encrypted transactions | CWE-208 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-362 | Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition) | 11 detectors |
| CWE-200 | Exposure of Sensitive Information | bundle-inclusion-leak |
| CWE-208 | Observable Timing Discrepancy | encrypted-mempool-timing |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| MEV/Front-Running | 45% | ~65% | +20% |
| Total MEV Detectors | 16 | 28 | +12 |

#### Changed

- Detector count increased from 257 to 269
- Total MEV-related detectors: 28

---

## [1.8.0] - 2026-01-13

### EIP-7702 & EIP-1153 New Standards Security - Phase 43

This release adds **10 new detectors** for emerging Ethereum standards EIP-7702 (Account Delegation) and EIP-1153 (Transient Storage). These are critical new attack surfaces in post-Dencun Ethereum. Total detectors: **257**.

#### Added

##### **Critical Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip7702-delegation-phishing` | Contracts that phish users into delegating EOA code execution via SET_CODE | CWE-284 |
| `eip7702-storage-corruption` | Storage collision between delegated code and EOA state | CWE-119 |
| `eip7702-sweeper-attack` | Contracts designed to drain all assets from delegating EOAs | CWE-306 |
| `eip1153-transient-reentrancy` | Reentrancy via transient storage state manipulation | CWE-841 |

##### **High Severity Detectors (5)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip7702-authorization-bypass` | Missing EIP-7702 authorization checks in delegation targets | CWE-862 |
| `eip7702-replay-vulnerability` | Delegation replay across chains/contexts (missing chain ID, nonce, domain) | CWE-294 |
| `eip1153-cross-tx-assumption` | Code assuming transient storage persists between transactions | CWE-362 |
| `eip1153-callback-manipulation` | Transient state manipulation during callbacks | CWE-367 |
| `eip1153-guard-bypass` | Flawed transient reentrancy guard implementations | CWE-667 |

##### **Medium Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip1153-composability-risk` | Transient storage slot collisions in composed transactions | CWE-664 |

#### Changed

- Detector count increased from 247 to 257
- Added comprehensive coverage for 2024-2025 emerging Ethereum standards

---

## [1.7.0] - 2026-01-12

### Advanced Proxy Security & Vulnerability Patterns - Phase 42

This release adds **14 new detectors** covering advanced proxy/upgradeable contract vulnerabilities and critical vulnerability pattern gaps. Total detectors: **247**.

#### Added

##### **Critical Severity Detectors (2)**

| Detector ID | Description | Real-World Exploit |
|-------------|-------------|-------------------|
| `reinitializer-vulnerability` | Contracts allowing re-initialization after upgrade via corrupted version tracking | AllianceBlock ($1.8M, 2024) |
| `storage-layout-inheritance-shift` | Storage slot shifts from inheritance chain changes causing data corruption | Audius ($6M, 2022) |

##### **High Severity Detectors (8)**

| Detector ID | Description |
|-------------|-------------|
| `beacon-single-point-of-failure` | Beacon pattern centralization risks - beacon deletion/compromise affects all proxies |
| `clones-immutable-args-bypass` | ClonesWithImmutableArgs calldata override vulnerability allowing auth bypass |
| `upgrade-abi-incompatibility` | Interface/ABI removals in upgrades breaking dependent contracts |
| `diamond-facet-code-existence` | Diamond delegatecall to empty/deleted facets (missing extcodesize check) |
| `delegatecall-in-loop` | Delegatecall inside loops enabling gas griefing and reentrancy |
| `fallback-delegatecall-pattern` | Fallback function delegating all calls without selector filtering |
| `erc20-approve-race` | ERC20 approve front-running race condition vulnerability |
| `cross-chain-replay-protection` | Missing chain ID in signatures allowing cross-chain replay attacks |

##### **Medium Severity Detectors (4)**

| Detector ID | Description |
|-------------|-------------|
| `proxy-context-visibility-mismatch` | Visibility differences between proxy and implementation exposing functions |
| `upgrade-event-missing` | Missing/malformed upgrade events (Upgraded, AdminChanged) for monitoring |
| `unchecked-send-return` | send() calls with ignored return value leading to silent failures |
| `transaction-ordering-dependence` | State depending on transaction ordering vulnerable to MEV/front-running |
| `l2-sequencer-dependency` | L2 Chainlink oracle usage without sequencer uptime check |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-665 | Improper Initialization | reinitializer-vulnerability |
| CWE-119 | Buffer Errors | storage-layout-inheritance-shift |
| CWE-284 | Improper Access Control | beacon-single-point-of-failure |
| CWE-20 | Improper Input Validation | clones-immutable-args-bypass |
| CWE-439 | Behavioral Change | upgrade-abi-incompatibility |
| CWE-476 | NULL Pointer Dereference | diamond-facet-code-existence |
| CWE-732 | Incorrect Permission | proxy-context-visibility-mismatch |
| CWE-778 | Insufficient Logging | upgrade-event-missing |
| CWE-834 | Excessive Iteration | delegatecall-in-loop |
| CWE-749 | Exposed Dangerous Method | fallback-delegatecall-pattern |
| CWE-362 | Race Condition | erc20-approve-race, transaction-ordering-dependence |
| CWE-252 | Unchecked Return Value | unchecked-send-return |
| CWE-662 | Improper Synchronization | l2-sequencer-dependency |
| CWE-294 | Authentication Bypass | cross-chain-replay-protection |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Delegatecall Issues | 38% | ~60% | +22% |
| Front-Running | 29% | ~45% | +16% |
| Unchecked Returns | 33% | ~50% | +17% |
| Proxy/Upgradeable | 31 detectors | 45 detectors | +14 |

#### Changed

- Detector count increased from 233 to 247
- Total proxy/upgradeable detectors: 45 (was 31)

---

## [1.6.0] - 2026-01-12

### Proxy & Upgradeable Contract Security - Phase 41

This release adds **12 new proxy/upgradeable contract detectors** targeting real-world exploits like Wormhole ($320M), Audius ($6M), and Parity ($150M). Total detectors: **233**.

#### Added

##### **Critical Severity Detectors (5)**

| Detector ID | Description | Real-World Exploit |
|-------------|-------------|-------------------|
| `implementation-not-initialized` | Implementation contract left uninitialized, allowing attacker takeover | Wormhole ($320M) |
| `uups-missing-disable-initializers` | UUPS implementation missing `_disableInitializers()` in constructor | Audius ($6M) |
| `implementation-selfdestruct` | Implementation contract contains selfdestruct, can brick all proxies | Parity ($150M) |
| `uups-upgrade-unsafe` | `_authorizeUpgrade()` missing access control | - |
| `beacon-upgrade-unprotected` | Beacon `upgradeTo()` without access control affects all proxies | - |

##### **High Severity Detectors (4)**

| Detector ID | Description |
|-------------|-------------|
| `function-selector-clash` | Proxy/implementation function selector collision (4-byte clash) |
| `transparent-proxy-admin-issues` | Transparent proxy admin routing problems and selector conflicts |
| `minimal-proxy-clone-issues` | EIP-1167 clone vulnerabilities (uninitialized clones, predictable addresses) |
| `initializer-reentrancy` | External calls before state changes in initializer functions |

##### **Medium Severity Detectors (3)**

| Detector ID | Description |
|-------------|-------------|
| `missing-storage-gap` | Upgradeable base contracts missing `__gap` storage arrays |
| `immutable-in-upgradeable` | Immutable variables in upgradeable contracts (stored in bytecode) |
| `eip1967-slot-compliance` | Non-standard EIP-1967 storage slots for proxy addresses |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-284 | Improper Access Control | uups-upgrade-unsafe, beacon-upgrade-unprotected, implementation-selfdestruct |
| CWE-665 | Improper Initialization | implementation-not-initialized, uups-missing-disable-initializers |
| CWE-436 | Interpretation Conflict | function-selector-clash, transparent-proxy-admin-issues |
| CWE-841 | Improper Enforcement of Behavioral Workflow | initializer-reentrancy |
| CWE-672 | Operation on Resource After Expiration | minimal-proxy-clone-issues |

#### Changed

- Detector count increased from 221 to 233

---

## [1.5.0] - 2026-01-11

### SWC Coverage Expansion - Phase 1

This release expands SWC (Smart Contract Weakness Classification) coverage with **4 new critical detectors** addressing unprotected ether operations and hash collision vulnerabilities.

#### Added

##### **New SWC-Aligned Detectors**

| Detector ID | SWC | Severity | Description |
|-------------|-----|----------|-------------|
| `swc105-unprotected-ether-withdrawal` | SWC-105 | Critical | Detects withdraw functions lacking access control |
| `swc106-unprotected-selfdestruct` | SWC-106 | Critical | Detects unprotected selfdestruct operations |
| `swc132-unexpected-ether-balance` | SWC-132 | Medium | Detects exact ether balance assumptions |
| `swc133-hash-collision-varlen` | SWC-133 | High | Detects abi.encodePacked() with variable-length args |

##### **Detection Capabilities**

**SWC-105: Unprotected Ether Withdrawal**
- Withdrawal functions without `onlyOwner` modifier
- Missing `require(msg.sender == owner)` checks
- Functions using `.transfer()`, `.send()`, `.call{value:}` without authorization
- Distinguishes between Ether and token transfers

**SWC-106: Unprotected SELFDESTRUCT**
- Public/external selfdestruct without access control
- User-controlled beneficiary addresses
- Both `selfdestruct()` and legacy `suicide()` syntax

**SWC-132: Unexpected Ether Balance**
- `require(address(this).balance == X)` exact checks
- Balance assumptions vulnerable to force-send via `selfdestruct`

**SWC-133: Hash Collision with Variable Length Arguments**
- `abi.encodePacked()` with multiple variable-length arguments (string, bytes)
- Excludes fixed-size types (bytes1-bytes32) to reduce false positives

#### Changed

##### **Docker Updates**
- Updated Rust from 1.75-slim to 1.85-slim (required for newer dependencies)
- Fixed `as` → `AS` casing for Docker best practices

#### Statistics

- **Total Detectors:** 221 (up from 217)
- **New SWC Mappings:** 4 (SWC-105, SWC-106, SWC-132, SWC-133)
- **New CWE Mappings:** 6 (CWE-284, CWE-328, CWE-670, CWE-697, CWE-862)

---

## [1.4.1] - 2025-11-29

### SWC (Smart Contract Weakness Classification) Support

This release adds **SWC ID mappings** to findings for better vulnerability classification and integration with industry-standard security tools.

#### Added

##### **SWC Classification in Findings**
Findings now include SWC (Smart Contract Weakness Classification) IDs alongside CWE mappings:

```json
{
