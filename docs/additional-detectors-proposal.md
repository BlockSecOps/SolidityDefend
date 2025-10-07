# Additional Detector Proposals for SolidityDefend

**Generated:** 2025-10-07
**Current Status:** 71 detectors implemented (59 functional, 12 stubs)
**Target:** Expand to 100+ detectors with modern 2025 attack vectors

---

## Executive Summary

Based on analysis of:
- Current implementation: 71 detectors across 11 phases
- OWASP Smart Contract Top 10 (2025)
- Recent exploits and security research (2024-2025)
- Emerging standards (ERC-7683, ERC-4337, restaking protocols)

**Proposed Additions:** 35+ new detectors across 6 new categories

---

## Phase 13: Cross-Chain Intent & Bridge Security (8 detectors)

### Category: ERC-7683 Cross-Chain Intents

**Rationale:** ERC-7683 is an emerging standard for cross-chain intents with documented security concerns around settlement contracts, oracle dependencies, and replay protection.

#### 13.1 Settlement Contract Validation
- **ID:** `erc7683-settlement-validation`
- **Severity:** High
- **Description:** Validates settlement contract implementations for proper security checks
- **Detects:**
  - Missing settlement validation in fillOrder implementations
  - Inadequate nonce verification for replay protection
  - Missing deadline checks in cross-chain orders
  - Unsafe token handling in settlement contracts

#### 13.2 Cross-Chain Replay Attack
- **ID:** `erc7683-cross-chain-replay`
- **Severity:** Critical
- **Description:** Detects insufficient replay protection in cross-chain order execution
- **Detects:**
  - Missing or weak nonce mechanisms
  - Lack of chain-id validation
  - Reusable order signatures across chains
  - Missing order status tracking

#### 13.3 Filler Front-Running Vulnerability
- **ID:** `erc7683-filler-frontrunning`
- **Severity:** High
- **Description:** Detects vulnerabilities where fillers can be front-run during settlement
- **Detects:**
  - Missing slippage protection in fillOrder
  - Predictable order execution timing
  - Lack of commit-reveal for filler selection
  - Insufficient MEV protection for fillers

#### 13.4 Oracle Dependency Risk
- **ID:** `erc7683-oracle-dependency`
- **Severity:** High
- **Description:** Identifies unsafe oracle dependencies in cross-chain verification
- **Detects:**
  - Single oracle source for cross-chain data
  - Missing staleness checks on oracle data
  - Lack of oracle failure handling
  - Unsafe price feed aggregation

#### 13.5 Permit2 Integration Issues
- **ID:** `erc7683-unsafe-permit2`
- **Severity:** Medium
- **Description:** Detects improper Permit2 integration in token approvals
- **Detects:**
  - Use of standard approve() instead of Permit2
  - Missing signature validation
  - Incorrect witness data handling
  - Inadequate permission scoping

#### 13.6 Bridge Token Minting Vulnerability
- **ID:** `bridge-token-mint-control`
- **Severity:** Critical
- **Description:** Detects unsafe token minting in bridge contracts
- **Detects:**
  - Missing access control on bridge mint functions
  - Lack of supply cap verification
  - Missing cross-chain validation before minting
  - Unsafe token wrapping/unwrapping

#### 13.7 Bridge Message Verification
- **ID:** `bridge-message-verification`
- **Severity:** Critical
- **Description:** Validates proper verification of cross-chain messages
- **Detects:**
  - Weak message signature validation
  - Missing merkle proof verification
  - Inadequate validator quorum checks
  - Replay vulnerabilities in bridge messages

#### 13.8 Chain-ID Validation
- **ID:** `missing-chainid-validation`
- **Severity:** High
- **Description:** Detects missing chain-id validation in cross-chain operations
- **Detects:**
  - Signatures without chain-id inclusion
  - Missing block.chainid checks
  - Reusable signatures across forks
  - Inadequate network identification

---

## Phase 14: Account Abstraction & ERC-4337 Security (7 detectors)

### Category: Account Abstraction Security

**Rationale:** ERC-4337 introduces new attack vectors around paymasters, bundlers, and user operations. OpenZeppelin's 2024 audit identified multiple medium-severity issues.

#### 14.1 Paymaster Gas Griefing
- **ID:** `paymaster-gas-griefing`
- **Severity:** High
- **Description:** Detects gas griefing attacks against paymasters
- **Detects:**
  - User operations with excessive gas limits
  - Missing gas limit validation in paymaster
  - Lack of penalty mechanisms for gas abuse
  - Inadequate gas accounting in postOp

#### 14.2 Bundler Throttling Abuse
- **ID:** `bundler-throttling-abuse`
- **Severity:** Medium
- **Description:** Identifies patterns that can cause unfair bundler throttling
- **Detects:**
  - Operations that falsely trigger throttling
  - Missing stake/reputation checks
  - Inadequate simulation validation
  - Unauthorized operation inclusion

#### 14.3 UserOperation Validation Bypass
- **ID:** `userop-validation-bypass`
- **Severity:** Critical
- **Description:** Detects vulnerabilities in UserOperation validation
- **Detects:**
  - Missing signature validation
  - Weak nonce validation
  - Insufficient sender verification
  - Paymaster verification bypass

#### 14.4 Paymaster Deposit Draining
- **ID:** `paymaster-deposit-drain`
- **Severity:** Critical
- **Description:** Identifies attacks that can drain paymaster deposits
- **Detects:**
  - Missing deposit checks before sponsorship
  - Lack of rate limiting on sponsored operations
  - Inadequate postOp failure handling
  - Unsafe sponsor allowance management

#### 14.5 EntryPoint Reentrancy
- **ID:** `entrypoint-reentrancy`
- **Severity:** High
- **Description:** Detects reentrancy vulnerabilities in EntryPoint interactions
- **Detects:**
  - Unsafe external calls during validation
  - Missing reentrancy guards in account contracts
  - State changes after external calls in handleOps
  - Vulnerable postOp implementations

#### 14.6 Account Factory Vulnerabilities
- **ID:** `account-factory-issues`
- **Severity:** High
- **Description:** Identifies security issues in account factory contracts
- **Detects:**
  - Predictable account addresses
  - Missing initialization in deployed accounts
  - Unsafe CREATE2 salt generation
  - Account ownership takeover risks

#### 14.7 Session Key Abuse
- **ID:** `session-key-abuse`
- **Severity:** Medium
- **Description:** Detects improper session key validation and management
- **Detects:**
  - Overly permissive session key scopes
  - Missing expiration checks
  - Lack of revocation mechanisms
  - Inadequate operation allowlist enforcement

---

## Phase 15: Restaking & Liquid Staking Security (6 detectors)

### Category: Restaking Protocol Security

**Rationale:** EigenLayer and liquid restaking protocols introduce compounding risks through slashing, AVS interactions, and liquidity withdrawal issues. Industry experts warn of cascading vulnerabilities.

#### 15.1 Cascading Slashing Risk
- **ID:** `cascading-slashing-risk`
- **Severity:** Critical
- **Description:** Detects patterns that amplify slashing across multiple AVS
- **Detects:**
  - Restaking without slashing risk isolation
  - Missing AVS-specific slashing limits
  - Lack of slashing event propagation handling
  - Inadequate operator collateral requirements

#### 15.2 AVS Malicious Governance
- **ID:** `avs-governance-attack`
- **Severity:** Critical
- **Description:** Identifies vulnerabilities to malicious AVS governance
- **Detects:**
  - Insufficient governance timelock delays
  - Missing operator exit mechanisms
  - Lack of emergency withdrawal before AVS changes
  - Inadequate slashing condition validation

#### 15.3 Withdrawal Queue Manipulation
- **ID:** `withdrawal-queue-manipulation`
- **Severity:** High
- **Description:** Detects manipulation of withdrawal queues in restaking
- **Detects:**
  - Missing withdrawal queue position validation
  - Inadequate withdrawal delay enforcement
  - Unsafe queue jumping mechanisms
  - Lack of withdrawal request authentication

#### 15.4 Liquid Restaking Token Depeg
- **ID:** `lrt-depeg-risk`
- **Severity:** High
- **Description:** Identifies conditions that can cause LRT token depegging
- **Detects:**
  - Missing redemption rate validation
  - Inadequate reserve ratio checks
  - Lack of emergency withdrawal caps
  - Unsafe oracle dependencies for pricing

#### 15.5 Operator Centralization Risk
- **ID:** `operator-centralization`
- **Severity:** Medium
- **Description:** Detects excessive centralization in operator selection
- **Detects:**
  - Single operator for multiple AVS
  - Missing operator diversification requirements
  - Inadequate operator performance monitoring
  - Lack of automatic operator rotation

#### 15.6 Restaking Loop Amplification
- **ID:** `restaking-loop-amplification`
- **Severity:** Critical
- **Description:** Detects dangerous recursive restaking patterns
- **Detects:**
  - Circular dependencies in restaking protocols
  - Missing recursion depth limits
  - Inadequate collateral ratio tracking
  - Unsafe derivative-on-derivative stacking

---

## Phase 16: ERC-4626 Vault Security (5 detectors)

### Category: Tokenized Vault Security

**Rationale:** The 2025 Cetus DEX hack ($223M loss) and ERC-4626 inflation attacks demonstrate critical vault security gaps.

#### 16.1 ERC-4626 Inflation Attack
- **ID:** `erc4626-inflation-attack`
- **Severity:** Critical
- **Description:** Detects vulnerability to share inflation attacks
- **Detects:**
  - Missing virtual shares/assets implementation
  - First depositor share manipulation risk
  - Inadequate minimum deposit requirements
  - Unsafe share calculation rounding

#### 16.2 Vault Donation Attack
- **ID:** `vault-donation-attack`
- **Severity:** High
- **Description:** Identifies vulnerabilities to donation-based attacks
- **Detects:**
  - Direct asset transfers inflating share price
  - Missing donation protection mechanisms
  - Inadequate totalAssets() calculation
  - Lack of share price manipulation detection

#### 16.3 Vault Withdrawal DOS
- **ID:** `vault-withdrawal-dos`
- **Severity:** High
- **Description:** Detects conditions that can lock withdrawals
- **Detects:**
  - Missing maxWithdraw implementation
  - Inadequate liquidity checks
  - Unsafe redeem failure handling
  - Lock period bypass vulnerabilities

#### 16.4 Vault Fee Manipulation
- **ID:** `vault-fee-manipulation`
- **Severity:** Medium
- **Description:** Identifies unsafe fee implementation in vaults
- **Detects:**
  - Missing fee cap limits
  - Immediate fee parameter updates
  - Inadequate fee calculation precision
  - Front-runnable fee changes

#### 16.5 Vault Reentrancy via Hooks
- **ID:** `vault-hook-reentrancy`
- **Severity:** High
- **Description:** Detects reentrancy through vault hook callbacks
- **Detects:**
  - External calls before state updates in deposit/withdraw
  - Missing reentrancy guards in hook implementations
  - Unsafe ERC-777/ERC-1363 token interactions
  - Vulnerable _beforeTokenTransfer/_afterTokenTransfer

---

## Phase 17: Token Standard Edge Cases (4 detectors)

### Category: Token Implementation Security

**Rationale:** Token standards have numerous edge cases and race conditions that remain exploitable.

#### 17.1 Approve Race Condition
- **ID:** `erc20-approve-race`
- **Severity:** Medium
- **Description:** Detects vulnerable approve() implementations
- **Detects:**
  - Missing increaseAllowance/decreaseAllowance
  - Unsafe approve() without zero check
  - Lack of race condition warnings
  - Missing Permit integration recommendations

#### 17.2 Infinite Approval Risk
- **ID:** `infinite-approval-risk`
- **Severity:** Low
- **Description:** Identifies contracts encouraging infinite approvals
- **Detects:**
  - Code encouraging uint256.max approvals
  - Missing approval amount validation
  - Lack of approval expiration
  - Inadequate allowance monitoring

#### 17.3 ERC-777 Reentrancy Hooks
- **ID:** `erc777-reentrancy`
- **Severity:** High
- **Description:** Detects reentrancy via ERC-777 hooks
- **Detects:**
  - Missing reentrancy protection with ERC-777
  - Unsafe tokensReceived implementation
  - State changes after token transfers
  - Vulnerable operator authorization

#### 17.4 ERC-721/1155 Callback Reentrancy
- **ID:** `nft-callback-reentrancy`
- **Severity:** High
- **Description:** Identifies reentrancy through NFT transfer callbacks
- **Detects:**
  - Unsafe onERC721Received/onERC1155Received
  - State changes after safeTransfer
  - Missing reentrancy guards in NFT contracts
  - Vulnerable batch transfer implementations

---

## Phase 18: DeFi Protocol-Specific (3 detectors)

### Category: DeFi Security

**Rationale:** Complex DeFi protocols have protocol-specific vulnerabilities beyond generic patterns.

#### 18.1 Uniswap V4 Hook Vulnerabilities
- **ID:** `uniswapv4-hook-issues`
- **Severity:** High
- **Description:** Detects security issues in Uniswap V4 hooks
- **Detects:**
  - Unsafe hook callback implementations
  - Missing return value validation
  - Inadequate hook access control
  - Vulnerable hook fee extraction

#### 18.2 AMM Constant Product Violation
- **ID:** `amm-k-invariant-violation`
- **Severity:** Critical
- **Description:** Identifies violations of AMM invariants
- **Detects:**
  - Breaking x*y=k formula
  - Missing invariant checks after swaps
  - Unsafe fee-on-transfer token handling
  - Inadequate reserve updates

#### 18.3 Lending Protocol Borrowing Bypass
- **ID:** `lending-borrow-bypass`
- **Severity:** Critical
- **Description:** Detects collateral and borrowing check bypasses
- **Detects:**
  - Missing collateral factor validation
  - Unsafe flash loan integration
  - Borrow limit bypass through reentrancy
  - Inadequate health factor checks

---

## Phase 19: Advanced Code Quality (2 detectors)

### Category: Code Quality Enhancements

**Rationale:** Complete the stub implementations from Phase 11 and add modern quality checks.

#### 19.1 Floating Pragma Detection
- **ID:** `floating-pragma`
- **Severity:** Low
- **Description:** Detects use of floating compiler versions
- **Detects:**
  - Use of ^0.8.0 style pragmas
  - Missing locked compiler versions
  - Pragma version too broad
  - Outdated compiler versions

#### 19.2 Unused State Variables
- **ID:** `unused-state-variables`
- **Severity:** Low
- **Description:** Identifies unused state variables wasting storage
- **Detects:**
  - State variables never read
  - Write-only state variables
  - Redundant state variable declarations
  - Legacy/deprecated variables

---

## Implementation Priority

### Critical Priority (Phases 13-15)
**Target:** Q1 2025
**Focus:** Cross-chain, account abstraction, and restaking - highest financial risk in 2025

1. Phase 13: Cross-Chain Intent & Bridge Security (8 detectors)
2. Phase 14: Account Abstraction & ERC-4337 (7 detectors)
3. Phase 15: Restaking & Liquid Staking (6 detectors)

### High Priority (Phase 16)
**Target:** Q2 2025
**Focus:** ERC-4626 vault security - recent high-value exploits

4. Phase 16: ERC-4626 Vault Security (5 detectors)

### Medium Priority (Phases 17-18)
**Target:** Q2-Q3 2025
**Focus:** Token standards and DeFi protocol-specific

5. Phase 17: Token Standard Edge Cases (4 detectors)
6. Phase 18: DeFi Protocol-Specific (3 detectors)

### Low Priority (Phase 19)
**Target:** Q3 2025
**Focus:** Complete code quality detectors

7. Phase 19: Advanced Code Quality (2 detectors)

---

## Summary Statistics

| Phase | Detectors | Severity Range | Implementation Effort |
|-------|-----------|----------------|---------------------|
| 13: Cross-Chain Intent | 8 | Medium - Critical | 3-4 weeks |
| 14: Account Abstraction | 7 | Medium - Critical | 3-4 weeks |
| 15: Restaking Security | 6 | Medium - Critical | 2-3 weeks |
| 16: ERC-4626 Vault | 5 | Medium - Critical | 2-3 weeks |
| 17: Token Standards | 4 | Medium - High | 2 weeks |
| 18: DeFi Specific | 3 | High - Critical | 2 weeks |
| 19: Code Quality | 2 | Low | 1 week |
| **Total** | **35** | **Low - Critical** | **15-19 weeks** |

**New Total Detector Count:** 71 (current) + 35 (proposed) = **106 detectors**

---

## Research References

1. **OWASP Smart Contract Top 10 (2025)** - Standard awareness document for Web3 vulnerabilities
2. **Cetus DEX Hack (May 2025)** - $223M loss due to overflow check, highlights vault security
3. **ERC-7683 Specification** - Cross-chain intent standard security considerations
4. **OpenZeppelin ERC-4337 Audit (2024)** - Identified bundler and paymaster vulnerabilities
5. **Sigma Prime Liquid Restaking Analysis** - Common vulnerabilities in restaking protocols
6. **Industry Expert Warnings (2025)** - Cascading risks in restaking and account abstraction

---

## Next Steps

1. **Review and Approve:** Stakeholder review of proposed detector additions
2. **Prioritize:** Confirm implementation priority based on threat landscape
3. **Resource Allocation:** Assign development resources for Phase 13-15
4. **Contract Collection:** Gather vulnerable contract examples for testing
5. **Benchmark Creation:** Develop test suites for new detector validation
6. **Documentation:** Create detector specifications with detailed examples

---

**Document Owner:** SolidityDefend Security Team
**Last Updated:** 2025-10-07
**Status:** Proposal - Pending Approval
