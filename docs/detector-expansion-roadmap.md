# SolidityDefend Detector Expansion Roadmap

**Current Version:** 0.8.0 (71 detectors)
**Target Version:** 1.0.0 (106+ detectors)
**Timeline:** 15-19 weeks
**Last Updated:** 2025-10-07

---

## Executive Summary

SolidityDefend currently implements **71 security detectors** (59 functional, 12 stubs) with proven production readiness through SmartBugs validation (85%+ F1-score). This roadmap outlines expansion to **106+ detectors** by addressing emerging 2025 attack vectors across:

- Cross-chain security (ERC-7683, bridges)
- Account abstraction (ERC-4337)
- Restaking protocols (EigenLayer, liquid staking)
- Vault security (ERC-4626)
- Token standard edge cases
- DeFi protocol-specific vulnerabilities

---

## Current State Analysis

### Detector Distribution (71 total)

| Phase | Category | Detectors | Status |
|-------|----------|-----------|--------|
| 1-5 | Core Security | 45 | ✅ Complete |
| 6 | MEV & Timing | 2 | ✅ Complete |
| 7 | Staking & Validators | 7 | ✅ Complete |
| 8 | Advanced Logic | 3 | ✅ Complete |
| 9 | Gas & Optimization | 5 | ⚠️ 2 functional, 3 stub |
| 10 | Advanced Security | 4 | ❌ Stub only |
| 11 | Code Quality | 5 | ❌ Stub only |

**Functional Rate:** 83% (59/71)

### Coverage Gaps Identified

Based on 2025 threat landscape analysis:

1. **No cross-chain security detectors** - Critical gap given ERC-7683 adoption and $223M+ bridge exploits
2. **No account abstraction coverage** - ERC-4337 introduces new attack surface (paymasters, bundlers)
3. **Missing restaking security** - EigenLayer and liquid staking have documented cascading risks
4. **Limited vault security** - ERC-4626 inflation attacks caused multiple 2024-2025 exploits
5. **Incomplete stub implementations** - 12 detectors need full implementation

---

## Proposed Expansion: 35 New Detectors

### Phase 13: Cross-Chain Intent & Bridge Security
**Priority:** Critical | **Timeline:** Weeks 1-4 | **Detectors:** 8

| ID | Detector Name | Severity | Rationale |
|----|---------------|----------|-----------|
| 13.1 | ERC-7683 Settlement Validation | High | ERC-7683 settlement contracts have documented security gaps |
| 13.2 | Cross-Chain Replay Attack | Critical | Replay protection is critical per ERC-7683 spec |
| 13.3 | Filler Front-Running | High | Fillers are vulnerable to MEV exploitation |
| 13.4 | Oracle Dependency Risk | High | Cross-chain oracles are major vulnerability vector |
| 13.5 | Permit2 Integration Issues | Medium | ERC-7683 recommends Permit2, unsafe approvals are vulnerable |
| 13.6 | Bridge Token Minting | Critical | Unprotected minting caused multiple bridge hacks |
| 13.7 | Bridge Message Verification | Critical | Weak signature validation led to Nomad, Wormhole exploits |
| 13.8 | Chain-ID Validation | High | Missing chain-id enables cross-fork replay attacks |

**Key Vulnerabilities Addressed:**
- Settlement contract security gaps (ERC-7683 spec warnings)
- Bridge message authenticity (Merkle proofs, multi-sig)
- Replay protection across chains
- Oracle manipulation in cross-chain contexts

**Implementation Plan:** See `phase-13-implementation-plan.md`

---

### Phase 14: Account Abstraction & ERC-4337
**Priority:** Critical | **Timeline:** Weeks 5-8 | **Detectors:** 7

| ID | Detector Name | Severity | Source |
|----|---------------|----------|--------|
| 14.1 | Paymaster Gas Griefing | High | OpenZeppelin ERC-4337 audit findings |
| 14.2 | Bundler Throttling Abuse | Medium | OpenZeppelin medium severity issue |
| 14.3 | UserOperation Validation Bypass | Critical | ERC-4337 verification requirements |
| 14.4 | Paymaster Deposit Draining | Critical | Stake/deposit mechanism vulnerabilities |
| 14.5 | EntryPoint Reentrancy | High | Complex call flow creates reentrancy surface |
| 14.6 | Account Factory Issues | High | Predictable addresses, initialization gaps |
| 14.7 | Session Key Abuse | Medium | Overly permissive session keys |

**Key Vulnerabilities Addressed:**
- Gas manipulation (10% penalty mechanism bypass)
- Paymaster stake/reputation abuse
- UserOperation verification gaps
- Account deployment security

**Expected Impact:** High - ERC-4337 adoption growing rapidly in 2025

---

### Phase 15: Restaking & Liquid Staking Security
**Priority:** Critical | **Timeline:** Weeks 9-11 | **Detectors:** 6

| ID | Detector Name | Severity | Source |
|----|---------------|----------|--------|
| 15.1 | Cascading Slashing Risk | Critical | Industry expert warnings on restaking |
| 15.2 | AVS Malicious Governance | Critical | EigenLayer security documentation |
| 15.3 | Withdrawal Queue Manipulation | High | Liquid restaking protocol analysis |
| 15.4 | LRT Token Depeg Risk | High | Sigma Prime vulnerability research |
| 15.5 | Operator Centralization | Medium | Cobo restaking best practices |
| 15.6 | Restaking Loop Amplification | Critical | Systemic cascade risk analysis |

**Key Vulnerabilities Addressed:**
- Multi-AVS slashing exposure
- Governance attack vectors on restaked assets
- Withdrawal DOS and queue manipulation
- Circular dependency amplification
- Liquidity crisis scenarios

**Expected Impact:** Critical - $15B+ TVL in restaking protocols

---

### Phase 16: ERC-4626 Vault Security
**Priority:** High | **Timeline:** Weeks 12-14 | **Detectors:** 5

| ID | Detector Name | Severity | Source |
|----|---------------|----------|--------|
| 16.1 | ERC-4626 Inflation Attack | Critical | Cetus DEX hack (May 2025, $223M loss) |
| 16.2 | Vault Donation Attack | High | Known ERC-4626 vulnerability pattern |
| 16.3 | Vault Withdrawal DOS | High | Liquidity lock vulnerabilities |
| 16.4 | Vault Fee Manipulation | Medium | Fee front-running attacks |
| 16.5 | Vault Hook Reentrancy | High | ERC-777/ERC-1363 callback attacks |

**Key Vulnerabilities Addressed:**
- First depositor share manipulation
- Direct donation price inflation
- Withdrawal queue DOS
- Fee parameter manipulation
- Callback reentrancy through token hooks

**Expected Impact:** Critical - ERC-4626 is standard for DeFi vaults

---

### Phase 17: Token Standard Edge Cases
**Priority:** Medium | **Timeline:** Weeks 15-16 | **Detectors:** 4

| ID | Detector Name | Severity | Source |
|----|---------------|----------|--------|
| 17.1 | ERC-20 Approve Race Condition | Medium | SWC-114, long-standing vulnerability |
| 17.2 | Infinite Approval Risk | Low | User security best practice |
| 17.3 | ERC-777 Reentrancy Hooks | High | tokensReceived callback attacks |
| 17.4 | ERC-721/1155 Callback Reentrancy | High | NFT safeTransfer callback exploitation |

**Key Vulnerabilities Addressed:**
- Front-running approve() changes
- Unlimited approval security implications
- Token callback reentrancy (ERC-777, ERC-721, ERC-1155)

**Expected Impact:** Medium - Completes token security coverage

---

### Phase 18: DeFi Protocol-Specific
**Priority:** Medium | **Timeline:** Weeks 17-18 | **Detectors:** 3

| ID | Detector Name | Severity | Applicability |
|----|---------------|----------|---------------|
| 18.1 | Uniswap V4 Hook Vulnerabilities | High | Uniswap V4 implementations |
| 18.2 | AMM Constant Product Violation | Critical | All AMM protocols |
| 18.3 | Lending Protocol Borrow Bypass | Critical | Lending/borrowing protocols |

**Key Vulnerabilities Addressed:**
- Uniswap V4 hook callback security
- AMM invariant violations (x*y=k)
- Collateral and health factor bypasses

**Expected Impact:** Medium - Protocol-specific but high severity

---

### Phase 19: Complete Stub Implementations
**Priority:** Low | **Timeline:** Weeks 19 | **Detectors:** 2 + 12 stubs

| ID | Detector Name | Severity | Status |
|----|---------------|----------|--------|
| 19.1 | Floating Pragma Detection | Low | New |
| 19.2 | Unused State Variables | Low | New |
| 9.3-9.5 | Gas & Optimization (3 stubs) | Low-Medium | Complete Phase 9 |
| 10.1-10.4 | Advanced Security (4 stubs) | High | Complete Phase 10 |
| 11.1-11.5 | Code Quality (5 stubs) | Low-Medium | Complete Phase 11 |

**Expected Impact:** Low-Medium - Quality of life improvements

---

## Implementation Timeline

### Quarter View

**Q1 2025: Critical Security Gaps (21 detectors)**
- Weeks 1-4: Phase 13 (Cross-Chain) - 8 detectors
- Weeks 5-8: Phase 14 (Account Abstraction) - 7 detectors
- Weeks 9-11: Phase 15 (Restaking) - 6 detectors

**Q2 2025: High-Value Additions (12 detectors)**
- Weeks 12-14: Phase 16 (ERC-4626 Vaults) - 5 detectors
- Weeks 15-16: Phase 17 (Token Standards) - 4 detectors
- Weeks 17-18: Phase 18 (DeFi Protocol) - 3 detectors

**Q3 2025: Completion & Polish (14 detectors)**
- Week 19: Phase 19 (Stubs + Quality) - 2 new + 12 completions

### Parallel Execution Opportunities

**Weeks 1-4 (Phase 13):**
- Detectors 13.1-13.4 can be developed in parallel (different vulnerability classes)
- Detectors 13.5-13.8 can be developed in parallel after core infrastructure

**Weeks 5-8 (Phase 14):**
- Detectors 14.1-14.3 (core ERC-4337) sequential
- Detectors 14.4-14.7 (peripheral) parallel after core

**Weeks 9-11 (Phase 15):**
- All detectors can be developed in parallel (independent vulnerability classes)

---

## Resource Requirements

### Development Effort

| Phase | Detectors | Complexity | Estimated Effort |
|-------|-----------|------------|-----------------|
| 13 | 8 | High (new domain) | 3-4 weeks |
| 14 | 7 | High (complex flow) | 3-4 weeks |
| 15 | 6 | Medium-High | 2-3 weeks |
| 16 | 5 | Medium | 2-3 weeks |
| 17 | 4 | Low-Medium | 2 weeks |
| 18 | 3 | Medium | 2 weeks |
| 19 | 14 | Low (mostly stubs) | 1 week |
| **Total** | **47** | - | **15-19 weeks** |

Note: 47 = 35 new + 12 stub completions

### Test Contract Collection

**Required:**
- 50+ cross-chain contracts (Phase 13)
- 40+ ERC-4337 implementations (Phase 14)
- 30+ restaking protocols (Phase 15)
- 25+ ERC-4626 vaults (Phase 16)
- 20+ token implementations (Phase 17)
- 15+ DeFi protocols (Phase 18)

**Total:** 180+ real-world contract examples

### Infrastructure Extensions

**New Components Required:**
1. ERC-7683 AST pattern matchers
2. ERC-4337 UserOperation flow analysis
3. Multi-contract interaction tracking (restaking)
4. ERC-4626 share calculation analysis
5. Token callback detection framework

**Existing Infrastructure (Reusable):**
- ✅ AST traversal and pattern matching
- ✅ Dataflow analysis with taint tracking
- ✅ Control flow graph construction
- ✅ Symbol resolution and type checking
- ✅ Detector registry and parallel execution

---

## Success Metrics

### Quantitative Targets

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| Total Detectors | 71 | 106+ | Count |
| Functional Rate | 83% | 95%+ | Functional/Total |
| F1-Score | 85% | 85%+ maintained | SmartBugs validation |
| False Positive Rate | <20% | <15% | Per-detector average |
| Performance | <100ms | <150ms | All detectors per contract |
| Coverage | 11 phases | 19 phases | Complete expansion |

### Qualitative Targets

- ✅ Cover all OWASP Smart Contract Top 10 (2025)
- ✅ Address major 2024-2025 exploit patterns
- ✅ Support emerging standards (ERC-7683, ERC-4337)
- ✅ Complete stub implementations (no technical debt)
- ✅ Maintain backward compatibility

---

## Risk Assessment

### High Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| High false positive rates on new detectors | High | Medium | Extensive testing with real contracts, tunable thresholds |
| Performance degradation with 106 detectors | High | Medium | Parallel execution, early termination, profiling |
| Emerging standards change before release | Medium | Low | Focus on general patterns, not spec-specific |
| Insufficient test contract availability | Medium | Medium | Collaborate with security firms, audit reports |

### Medium Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| Timeline slip due to complexity | Medium | Medium | Parallel development, clear milestones |
| Integration issues with existing detectors | Medium | Low | Comprehensive integration testing |
| Community adoption of new detectors | Medium | Low | Documentation, examples, marketing |

---

## Validation Strategy

### Benchmarking

1. **SmartBugs Validation:** Maintain 85%+ F1-score across expanded detector set
2. **Known Exploits:** Validate against documented 2024-2025 hacks
   - Cetus DEX ($223M) - ERC-4626 inflation
   - Nomad Bridge - Message verification bypass
   - EigenLayer test scenarios - Restaking risks
3. **Real-World Projects:** Test on 50+ production contracts per category

### Performance Validation

**Target:** <150ms total analysis time for all 106 detectors on 1K LOC contract

**Profiling:**
- Per-detector execution time
- Memory usage tracking
- Cache hit rate monitoring
- Parallel execution efficiency

### Accuracy Validation

**Per-Detector Metrics:**
- True Positive Rate (Recall): >90% for critical detectors
- False Positive Rate: <15% average
- Precision: >85% for all detectors

**Cross-Detector Validation:**
- No conflicting findings
- Proper severity correlation
- Complementary coverage

---

## Documentation Requirements

### User-Facing Documentation

1. **Detector Reference Guide**
   - Description, severity, CWE mapping for all 106 detectors
   - Vulnerable and secure code examples
   - Remediation guidance

2. **Security Best Practices**
   - Cross-chain security guidelines
   - Account abstraction security
   - Restaking protocol safety
   - Vault implementation security

3. **Migration Guide**
   - Upgrading from 71 to 106 detectors
   - Configuration changes
   - New CLI options

### Developer Documentation

1. **Architecture Documentation**
   - New analysis techniques (cross-chain tracking, ERC-4337 flow)
   - Pattern matching enhancements
   - Dataflow extensions

2. **Contribution Guide**
   - Adding new detectors
   - Testing requirements
   - Integration process

---

## Competitive Analysis

### Current Tool Landscape

| Tool | Detectors | Cross-Chain | ERC-4337 | Restaking | Vault Security |
|------|-----------|-------------|----------|-----------|----------------|
| **SolidityDefend (Current)** | 71 | ❌ | ❌ | ❌ | Partial |
| **SolidityDefend (Proposed)** | 106 | ✅ 8 | ✅ 7 | ✅ 6 | ✅ 5 |
| Slither | ~80 | ❌ | ❌ | ❌ | Partial |
| Mythril | ~50 | ❌ | ❌ | ❌ | ❌ |
| Securify | ~40 | ❌ | ❌ | ❌ | ❌ |

**Key Differentiator:** SolidityDefend will be the first open-source tool with comprehensive coverage of 2025 attack vectors.

---

## Go/No-Go Decision Points

### End of Week 4 (Phase 13 Complete)
**Decision Criteria:**
- ✅ All 8 detectors functional
- ✅ F1-score >80% on cross-chain benchmark
- ✅ Performance <120ms for Phase 13 detectors
- ✅ False positive rate <18%

**Action if criteria not met:** Extend Phase 13 by 1 week, delay subsequent phases

### End of Week 8 (Phase 14 Complete)
**Decision Criteria:**
- ✅ ERC-4337 detectors validated against OpenZeppelin audit findings
- ✅ Zero false negatives on known paymaster vulnerabilities
- ✅ Performance budget maintained

**Action if criteria not met:** Re-prioritize Phase 15-16 based on technical challenges

### End of Week 11 (Phase 15 Complete)
**Decision Criteria:**
- ✅ Restaking detectors validated on EigenLayer test cases
- ✅ Cascading risk analysis functional
- ✅ Overall tool performance <140ms per contract

**Action if criteria not met:** Consider stub implementations for low-priority Phase 17-18 detectors

---

## Appendices

### Appendix A: Related Documents
- `additional-detectors-proposal.md` - Detailed detector specifications
- `phase-13-implementation-plan.md` - Phase 13 implementation guide
- `SPRINT-PLAN.md` - Original 28-week sprint plan
- `tasks.md` - Task breakdown for Phases 1-7

### Appendix B: Research References
1. OWASP Smart Contract Top 10 (2025)
2. ERC-7683 Specification and Security Considerations
3. OpenZeppelin ERC-4337 Audit Report (2024)
4. Sigma Prime: Common Vulnerabilities in Liquid Restaking Protocols
5. Cetus DEX Post-Mortem (May 2025)
6. Industry Experts on Restaking Vulnerabilities (BeInCrypto, 2024)

### Appendix C: Test Contract Sources
- SmartBugs Curated Dataset
- DeFiVulnLabs (by SunWeb3Sec)
- Real-world audit reports (2024-2025)
- Etherscan verified contracts
- OpenZeppelin Contracts (negative tests)

---

**Document Status:** Approved for Implementation
**Next Review:** End of Q1 2025 (Critical Phases 13-15)
**Owner:** SolidityDefend Core Team
