# DeFi Protocol Detectors

**Total:** 21 detectors

---

## AMM Invariant Manipulation

**ID:** `amm-invariant-manipulation`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description

Detects vulnerabilities in AMM invariant enforcement including K invariant violations, missing TWAP, and reserve manipulation

### Remediation

- Enforce K invariant (reserve0 * reserve1 >= k) after every swap to prevent reserve manipulation
- Make reserve update functions internal/private and only callable through validated swap paths
- Implement time-weighted average price (TWAP) using cumulative price observations to resist manipulation

### Source

`defi_advanced/amm_invariant_manipulation.rs`

---

## AMM Constant Product Violation

**ID:** `amm-k-invariant-violation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  

### Description

Detects violations of AMM invariants (x*y=k formula), including missing k validation, unsafe fee-on-transfer token handling, and inadequate reserve updates

### Source

`src/amm_k_invariant_violation.rs`

---

## AMM Liquidity Manipulation

**ID:** `amm-liquidity-manipulation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description

Detects vulnerabilities in AMM pools that allow liquidity manipulation attacks, including sandwich attacks and pool draining

### Vulnerable Patterns

- Swap functions using spot price without TWAP
- Price calculation based on current reserves

### Source

`src/amm_liquidity_manipulation.rs`

---

## JIT Liquidity Attacks

**ID:** `defi-jit-liquidity-attacks`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description

Detects lack of minimum liquidity lock periods and validates LP commitment to prevent sandwich attacks

### Source

`src/defi_jit_liquidity.rs`

---

## Liquidity Pool Manipulation

**ID:** `defi-liquidity-pool-manipulation`  
**Severity:** Critical  
**Categories:** DeFi, Oracle  

### Description

Detects missing K-value validation, price oracle manipulation, and flash loan attacks on AMM invariants

### Source

`src/defi_liquidity_pool_manipulation.rs`

---

## Yield Farming Exploits

**ID:** `defi-yield-farming-exploits`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description

Detects missing deposit/withdrawal fee validation, reward calculation errors, and share price manipulation

### Source

`src/defi_yield_farming.rs`

---

## Emergency Withdrawal Abuse

**ID:** `emergency-withdrawal-abuse`  
**Severity:** Medium  
**Categories:** DeFi, AccessControl  
**CWE:** CWE-841, CWE-863  

### Description

Detects emergency withdrawal functions that bypass lock periods or lose user rewards

### Vulnerable Patterns

- Explicit vulnerability comment about bypassing locks
- Explicit vulnerability comment about losing rewards
- Vulnerability comment about admin bypass

### Source

`src/emergency_withdrawal_abuse.rs`

---

## Intent Nonce Management

**ID:** `intent-nonce-management`  
**Severity:** High  
**Categories:** DeFi, CrossChain  

### Description

Detects improper nonce management in ERC-7683 intents that could lead to replay attacks

### Remediation

- Implement nonce validation: \
     \
     Option 1: Bitmap-based (allows out-of-order execution) \
     mapping(address => mapping(uint256 => bool)) public usedNonces; \
     \
     function openFor(...) external { \
      require(!usedNonces[order.user][order.nonce], \
- Validate nonce before execution: \
     require(!usedNonces[order.user][order.nonce], \

### Source

`erc7683/nonce_management.rs`

---

## Intent Solver Manipulation

**ID:** `intent-solver-manipulation`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description

Detects vulnerabilities where malicious solvers can manipulate intent execution for profit

### Remediation

- Implement solver whitelist: \
     \
     mapping(address => bool) public approvedSolvers; \
     \
     function approveSolver(address solver) external onlyOwner { \
      approvedSolvers[solver] = true; \
     } \
     \
     function fill(...) external { \
      require(approvedSolvers[msg.sender], \
- Add reentrancy protection: \
     \
     import \

### Source

`erc7683/solver_manipulation.rs`

---

## Lending Protocol Borrow Bypass

**ID:** `lending-borrow-bypass`  
**Severity:** Critical  
**Categories:** DeFi, AccessControl  

### Description

Detects collateral and borrowing check bypasses in lending protocols, including missing health factor validation, unsafe flash loan integration, and reentrancy vulnerabilities

### Source

`src/lending_borrow_bypass.rs`

---

## Lending Liquidation Abuse

**ID:** `lending-liquidation-abuse`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-1339  

### Description

Detects unfair liquidation mechanics in lending protocols that can be exploited for profit or griefing

### Vulnerable Patterns

- Spot price used for health factor calculation
- No liquidation cooldown or front-running protection
- Excessive liquidation bonus/incentive

### Source

`src/lending_liquidation_abuse.rs`

---

## Liquidity Bootstrapping Pool Abuse

**ID:** `liquidity-bootstrapping-abuse`  
**Severity:** Medium  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description

Detects vulnerabilities in LBP implementations where weight changes can be manipulated for unfair token distribution

### Vulnerable Patterns

- Weight update without rate limiting
- No maximum weight change per update
- Purchase function without per-address cap

### Source

`src/liquidity_bootstrapping_abuse.rs`

---

## Missing Slippage Protection

**ID:** `missing-slippage-protection`  
**Severity:** High  
**Categories:** DeFi, MEV  
**CWE:** CWE-20, CWE-682  

### Description

Detects DEX trades executed without minimum output amount protection, enabling sandwich attacks

### Vulnerable Patterns

- Direct zero in swap call

### Source

`src/slippage_protection.rs`

---

## Pool Donation Attack Enhanced

**ID:** `pool-donation-enhanced`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description

Detects advanced pool donation attacks including ERC-4626 share inflation and first-depositor manipulation vulnerabilities

### Remediation

- Mint initial dead shares or use virtual shares/assets in share calculation to prevent first-depositor manipulation
- Track balances internally instead of using balanceOf(), or use virtual assets/shares in calculations
- Enforce minimum deposit amount or minimum shares minted to prevent rounding attacks

### Source

`defi_advanced/pool_donation_enhanced.rs`

---

## Reward Calculation Manipulation

**ID:** `reward-calculation-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, Oracle  
**CWE:** CWE-20, CWE-682  

### Description

Detects reward calculations based on manipulable price sources or incentivizing price deviation

### Vulnerable Patterns

- Explicit vulnerability comment
- Uses current/spot price instead of TWAP
- Incentivi

### Source

`src/reward_calculation.rs`

---

## Uniswap V4 Hook Vulnerabilities

**ID:** `uniswapv4-hook-issues`  
**Severity:** High  
**Categories:** DeFi, ExternalCalls  

### Description

Detects security issues in Uniswap V4 hook implementations including unsafe callbacks, missing validation, access control issues, and fee extraction vulnerabilities

### Source

`src/uniswapv4_hook_issues.rs`

---

## Vault Donation Attack

**ID:** `vault-donation-attack`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description

Detects ERC4626 vaults vulnerable to price manipulation via direct token donations

### Source

`src/vault_donation_attack.rs`

---

## Vault Fee Manipulation

**ID:** `vault-fee-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, MEV  
**CWE:** CWE-362, CWE-829  

### Description

Detects ERC4626 vaults vulnerable to fee parameter front-running and manipulation attacks

### Source

`src/vault_fee_manipulation.rs`

---

## Vault Share Inflation Attack

**ID:** `vault-share-inflation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-1339  

### Description

Detects ERC4626 vault implementations vulnerable to share price manipulation by first depositor

### Source

`src/vault_share_inflation.rs`

---

## Vault Withdrawal DOS

**ID:** `vault-withdrawal-dos`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-400, CWE-770  

### Description

Detects ERC4626 vaults vulnerable to withdrawal denial-of-service attacks via queue manipulation or liquidity locks

### Source

`src/vault_withdrawal_dos.rs`

---

## Yield Farming Reward Manipulation

**ID:** `yield-farming-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, Logic  

### Description

Detects vulnerabilities in yield farming reward calculations that allow attackers to manipulate TVL or claim disproportionate rewards

### Remediation

- Implement time-weighted reward distribution based on staking duration, not just current TVL
- Add minimum staking duration requirement before allowing reward claims
- Initialize pool with minimum shares or dead shares to prevent first-depositor manipulation

### Source

`defi_advanced/yield_farming_manipulation.rs`

---

