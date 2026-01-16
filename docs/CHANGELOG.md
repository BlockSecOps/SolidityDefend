# Changelog

All notable changes to SolidityDefend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.9.1] - 2026-01-15

### EIP-3074 & Future Standards - Phase 51

This release adds **8 new detectors** for EIP-3074 (AUTH/AUTHCALL), EIP-4844 (Blob Transactions), EIP-6780 (Selfdestruct Changes), and PUSH0 compatibility. Total detectors: **332**.

#### Added

##### **Critical Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip3074-upgradeable-invoker` | Forbidden upgradeable invoker contracts in EIP-3074 | CWE-284 |

##### **High Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip3074-commit-validation` | Improper commit hash verification in AUTH | CWE-345 |
| `eip3074-replay-attack` | Missing replay protection in AUTH signatures | CWE-294 |
| `eip3074-invoker-authorization` | Missing invoker authorization checks | CWE-862 |
| `eip4844-blob-validation` | Blob transaction validation issues | CWE-20 |

##### **Medium Severity Detectors (2)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `eip3074-call-depth-griefing` | Call depth manipulation attacks | CWE-400 |
| `eip6780-selfdestruct-change` | Post-Cancun selfdestruct behavior changes | CWE-670 |

##### **Low Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `push0-stack-assumption` | Stack alignment issues with PUSH0 opcode | CWE-682 |

### Fixed

#### Detector Crash Fixes
- **dos-revert-bomb**: Fixed slice bounds panic when `func_end <= line_num` during token callback vulnerability detection
- **create2-salt-frontrunning**: Fixed slice bounds panic when detecting CREATE2 patterns near end of file

#### False Positive Reductions
- **eip7702-storage-corruption**: Fixed false positive where function parameter types were incorrectly detected as state variable names
- **eip7702-storage-corruption**: Added interface exclusion - no longer flags interface declarations
- **dos-revert-bomb**: Added interface exclusion - no longer flags interface function declarations

#### Phase 51 False Positive Fixes
- **eip3074-replay-attack**: Added `is_eip3074_contract()` check to prevent matching "authorization", "authenticate" (eliminated 404 false positives)
- **eip3074-commit-validation**: Added same EIP-3074 specific detection (eliminated 38 false positives)
- **eip4844-blob-validation**: Require specific blob opcodes/patterns, not generic "blob" string (reduced 56%)
- **push0-stack-assumption**: Require specific cross-chain patterns instead of generic L1/L2 references (reduced 9%)

### Changed

#### JSON Output Enhancement
- Added `file` field to JSON location object for complete file path information

---

## [1.9.0] - 2026-01-15

### Diamond Proxy & Advanced Upgrades - Phase 50

This release adds **4 new detectors** for Diamond proxy vulnerabilities and advanced upgrade patterns. These detect critical issues in EIP-2535 Diamond implementations, proxy storage gaps, double initialization attacks, and delegatecall-to-self patterns. Total detectors: **321**.

#### Added

##### **Critical Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `proxy-double-initialize` | Double initialization via beacon downgrade or implementation change | CWE-665 |

##### **High Severity Detectors (3)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `diamond-init-frontrunning` | DiamondCut initialization frontrunning attacks | CWE-362 |
| `proxy-gap-underflow` | __gap array smaller than needed for storage expansion | CWE-119 |
| `delegatecall-to-self` | Unintended delegatecall to address(this) | CWE-829 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-119 | Improper Restriction of Operations within Memory Buffer | proxy-gap-underflow |
| CWE-362 | Concurrent Execution Using Shared Resource with Improper Synchronization | diamond-init-frontrunning |
| CWE-665 | Improper Initialization | proxy-double-initialize |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | delegatecall-to-self |

#### Detection Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Diamond Proxy | ~70% | ~85% | +15% |
| Upgrade Security | ~75% | ~90% | +15% |

---

## [1.8.6] - 2026-01-15

### Weak Randomness & DoS Expansion - Phase 49

This release adds **10 new detectors** for weak randomness vulnerabilities and denial of service (DoS) attack patterns. These detect critical randomness issues including blockhash manipulation, VRF misuse, commit-reveal timing attacks, and various DoS vectors including push patterns, unbounded storage, and revert bombs. Total detectors: **317**.

#### Added

##### **High Severity Detectors (8)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `blockhash-randomness` | Weak randomness using block.prevrandao, blockhash, or block variables | CWE-330 |
| `multi-block-randomness` | Multiple block variables combined for false security | CWE-330 |
| `modulo-block-variable` | block.timestamp % N or block.number % N for random selection | CWE-330 |
| `commit-reveal-timing` | Commit-reveal schemes with timing vulnerabilities | CWE-330 |
| `dos-push-pattern` | Unbounded array growth via push operations | CWE-400 |
| `dos-unbounded-storage` | Unbounded storage operations causing gas exhaustion | CWE-400 |
| `dos-external-call-loop` | External calls in loops allowing DoS | CWE-400 |
| `dos-block-gas-limit` | Operations that can exceed block gas limit | CWE-400 |

##### **Medium Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `chainlink-vrf-misuse` | Improper Chainlink VRF integration patterns | CWE-330 |

##### **High Severity DoS Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `dos-revert-bomb` | Revert bomb attacks via fallback/receive manipulation | CWE-400 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-330 | Use of Insufficiently Random Values | blockhash-randomness, multi-block-randomness, modulo-block-variable, chainlink-vrf-misuse, commit-reveal-timing |
| CWE-400 | Uncontrolled Resource Consumption | dos-push-pattern, dos-unbounded-storage, dos-external-call-loop, dos-block-gas-limit, dos-revert-bomb |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Weak Randomness | ~50% | ~85% | +35% |
| DoS Attacks | ~55% | ~80% | +25% |

#### Changed

- Detector count increased from 307 to 317
- Added comprehensive weak randomness detection
- Added DoS pattern detection for push/pull, storage, loops
- Total randomness/DoS detectors: 10

#### Fixed

False positive improvements for Phase 49 detectors:

| Detector | Issue Fixed |
|----------|-------------|
| `dos-revert-bomb` | ERC20 token transfers no longer flagged as ETH transfers (distinguish by arg count) |
| `dos-block-gas-limit` | Constructor loops skipped (run once, not DoS risk) |
| `dos-block-gas-limit` | Function signatures with `returns` no longer match `return` check |
| `dos-unbounded-storage` | Standard ERC20/ERC721 approve patterns skipped |
| `modulo-block-variable` | Type casting patterns like `uint32(block.timestamp % 2**32)` skipped |
| `commit-reveal-timing` | Secure patterns with `commitTime`, `REVEAL_DELAY` now recognized |

**Test Results:**
- 0 false positives on 8 real production contracts
- 0 false positives on fixture contracts (ERC20, UniswapV2Pair)
- 0 false positives on secure ERC4626 vault contracts
- 190+ true positives on vulnerable test contracts

---

## [1.8.5] - 2026-01-15

### L2/Rollup & Cross-Chain Advanced Detection - Phase 48

This release adds **10 new detectors** for Layer 2, rollup, and advanced cross-chain vulnerabilities. These detect complex attack vectors including sequencer MEV extraction, challenge period bypasses, cross-rollup state mismatches, and EIP-4844 blob data manipulation. Total detectors: **307**.

#### Added

##### **Critical Severity Detectors (2)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `bridge-merkle-bypass` | Missing merkle proof validation in cross-chain bridges | CWE-345 |
| `challenge-period-bypass` | Premature withdrawal before challenge period expires | CWE-367 |

##### **High Severity Detectors (7)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `sequencer-fee-exploitation` | L2 sequencer fee model exploitation for MEV | CWE-400 |
| `escape-hatch-dependency` | Over-reliance on L1 escape mechanisms | CWE-754 |
| `cross-l2-frontrunning` | Race conditions between L2 finality and L1 confirmation | CWE-362 |
| `l2-mev-sequencer-leak` | Sequencer MEV extraction via transaction ordering | CWE-362 |
| `da-sampling-attack` | Data availability under-sampling vulnerabilities | CWE-20 |
| `cross-rollup-state-mismatch` | State inconsistency across rollups | CWE-662 |
| `blob-data-manipulation` | EIP-4844 blob data tampering without KZG verification | CWE-20 |

##### **Medium Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `optimistic-inference-attack` | State inference from partial commits in optimistic rollups | CWE-200 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-20 | Improper Input Validation | da-sampling-attack, blob-data-manipulation |
| CWE-200 | Information Exposure | optimistic-inference-attack |
| CWE-345 | Insufficient Verification of Data Authenticity | bridge-merkle-bypass |
| CWE-362 | Race Condition | cross-l2-frontrunning, l2-mev-sequencer-leak |
| CWE-367 | TOCTOU Race Condition | challenge-period-bypass |
| CWE-400 | Uncontrolled Resource Consumption | sequencer-fee-exploitation |
| CWE-662 | Improper Synchronization | cross-rollup-state-mismatch |
| CWE-754 | Improper Check for Unusual Conditions | escape-hatch-dependency |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| L2/Rollup | ~55% | ~80% | +25% |
| Cross-Chain | ~55% | ~75% | +20% |

#### Changed

- Detector count increased from 297 to 307
- Added comprehensive L2/rollup security detection
- Added EIP-4844 blob transaction security
- Expanded cross-chain bridge security coverage
- Total L2/cross-chain detectors: 10+

---

## [1.8.4] - 2026-01-14

### Governance & Access Control Detection - Phase 47

This release adds **10 new detectors** for governance and access control vulnerabilities. These detect complex attack vectors including timelock bypass, role escalation, and cross-contract authorization confusion. Total detectors: **297**.

#### Added

##### **Critical Severity Detectors (5)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `governance-parameter-bypass` | Governance params changeable before timelock restrictions apply | CWE-284 |
| `quorum-calculation-overflow` | Quorum over-counting via reentrancy or arithmetic issues | CWE-190 |
| `governor-refund-drain` | Refund parameters manipulated to drain treasury | CWE-284 |
| `timelock-bypass-delegatecall` | Timelock guard bypass via proxy delegatecall | CWE-863 |
| `role-escalation-upgrade` | Constructor grants elevated privileges in upgradeable contracts | CWE-269 |

##### **High Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `voting-snapshot-manipulation` | Snapshot taken after delegation enabling flash loan voting | CWE-362 |
| `proposal-frontrunning` | Counter-proposal submission in same block | CWE-362 |
| `accesscontrol-race-condition` | Grant/revoke race between transactions | CWE-362 |
| `cross-contract-role-confusion` | Roles from one contract misused in another | CWE-863 |

##### **Medium Severity Detectors (1)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `operator-whitelist-inheritance` | Operator approvals persist unexpectedly after upgrade | CWE-732 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-284 | Improper Access Control | governance-parameter-bypass, governor-refund-drain |
| CWE-190 | Integer Overflow | quorum-calculation-overflow |
| CWE-269 | Improper Privilege Management | role-escalation-upgrade |
| CWE-362 | Race Condition | voting-snapshot-manipulation, proposal-frontrunning, accesscontrol-race-condition |
| CWE-732 | Incorrect Permission Assignment | operator-whitelist-inheritance |
| CWE-863 | Incorrect Authorization | timelock-bypass-delegatecall, cross-contract-role-confusion |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Governance Attacks | ~50% | ~85% | +35% |
| Access Control | ~60% | ~80% | +20% |

#### Bug Fixes

- **governance-proposal-mev**: Fixed slice bounds panic when analyzing files where `getVotes`/`getPriorVotes` appears near end of file. The context window now correctly caps at file length using `.min(lines.len())`.

#### Changed

- Detector count increased from 287 to 297
- Added comprehensive governance attack detection
- Added new detector category: Governance/Access Control
- Total governance/access control detectors: 10

---

## [1.8.3] - 2026-01-13

### Callback Chains & Multicall Detection - Phase 46

This release adds **10 new detectors** for callback chain vulnerabilities and multicall exploitation patterns. These detect complex DeFi attack vectors including nested callbacks, msg.value reuse, and protocol-specific callback chains (ERC721, ERC1155, Uniswap V4, Compound). Total detectors: **287**.

#### Added

##### **Critical Severity Detectors (3)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `nested-callback-reentrancy` | Nested safe callbacks enabling state corruption via chained reentrancy | CWE-841 |
| `multicall-msgvalue-reuse` | msg.value reused across multicall items enabling ETH double-spending | CWE-837 |
| `batch-cross-function-reentrancy` | Cross-function reentrancy between batched multicall operations | CWE-841 |

##### **High Severity Detectors (7)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `callback-in-callback-loop` | Recursive callback exploitation via looped callback invocations | CWE-674 |
| `multicall-partial-revert` | Partial success in batch operations causing inconsistent state | CWE-754 |
| `flash-callback-manipulation` | Flash loan callback TOCTOU state manipulation | CWE-367 |
| `erc721-safemint-callback` | onERC721Received callback exploitation during safeMint | CWE-841 |
| `erc1155-callback-reentrancy` | ERC1155 batch callback reentrancy via onERC1155Received | CWE-841 |
| `uniswap-v4-hook-callback` | Uniswap V4 hook callback exploitation and state manipulation | CWE-841 |
| `compound-callback-chain` | Compound-style cToken callback chains enabling market manipulation | CWE-841 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-841 | Improper Enforcement of Behavioral Workflow | nested-callback-reentrancy, batch-cross-function-reentrancy, erc721-safemint-callback, erc1155-callback-reentrancy, uniswap-v4-hook-callback, compound-callback-chain |
| CWE-674 | Uncontrolled Recursion | callback-in-callback-loop |
| CWE-837 | Improper Enforcement of a Single, Unique Action | multicall-msgvalue-reuse |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | multicall-partial-revert |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | flash-callback-manipulation |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Callback Patterns | ~40% | ~70% | +30% |
| Multicall Vulnerabilities | ~30% | ~65% | +35% |

#### Changed

- Detector count increased from 277 to 287
- Added new detector category: Callback Chain
- Total callback/multicall detectors: 10

---

## [1.8.2] - 2026-01-13

### Metamorphic & CREATE2 Patterns - Phase 45

This release adds **8 new detectors** for metamorphic contract attacks and CREATE2-related vulnerabilities. These detect advanced contract deployment attacks including code substitution, address collision, and bytecode injection. Total detectors: **277**.

#### Added

##### **Critical Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `metamorphic-contract-risk` | CREATE2 + SELFDESTRUCT patterns enabling bytecode mutation at same address | CWE-913 |
| `create2-address-collision` | Intentional address reuse after destruction for code substitution attacks | CWE-706 |
| `contract-recreation-attack` | Contracts recreated with different code at same address | CWE-913 |
| `initcode-injection` | Malicious initcode injection in CREATE2 deployments | CWE-94 |

##### **High Severity Detectors (4)**

| Detector ID | Description | CWE |
|-------------|-------------|-----|
| `create2-salt-frontrunning` | Predictable CREATE2 salts enabling deployment front-running | CWE-330 |
| `extcodesize-check-bypass` | EXTCODESIZE=0 during construction enabling EOA check bypass | CWE-670 |
| `selfdestruct-recipient-control` | User-controlled selfdestruct beneficiary enabling fund theft | CWE-284 |
| `constructor-reentrancy` | Reentrancy during contract construction before guards initialized | CWE-841 |

##### **CWE Mappings**

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-913 | Improper Control of Dynamically-Managed Code Resources | metamorphic-contract-risk, contract-recreation-attack |
| CWE-94 | Improper Control of Generation of Code (Code Injection) | initcode-injection |
| CWE-706 | Use of Incorrectly-Resolved Name or Reference | create2-address-collision |
| CWE-330 | Use of Insufficiently Random Values | create2-salt-frontrunning |
| CWE-670 | Always-Incorrect Control Flow Implementation | extcodesize-check-bypass |
| CWE-284 | Improper Access Control | selfdestruct-recipient-control |
| CWE-841 | Improper Enforcement of Behavioral Workflow | constructor-reentrancy |

#### Detection Rate Improvements

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| Metamorphic/CREATE2 | 4 | 12 | +8 |
| Deployment Attacks | ~40% | ~65% | +25% |

#### Changed

- Detector count increased from 269 to 277
- Total metamorphic/CREATE2 detectors: 12

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
