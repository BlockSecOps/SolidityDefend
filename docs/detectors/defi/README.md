# Defi Detectors

**Total:** 15 detectors

---

## Amm K Invariant Violation

**ID:** `amm-k-invariant-violation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  

### Description



### Details


Detects violations of the AMM invariant (x*y=k formula) including:
- Breaking x*y=k formula
- Missing invariant checks after swaps
- Unsafe fee-on-transfer token handling
- Inadequate reserve updates
Check if function is an AMM swap function
Check for missing K invariant validation
Check for unsafe fee-on-transfer token handling

### Source

`crates/detectors/src/amm_k_invariant_violation.rs`

---

## Amm Liquidity Manipulation

**ID:** `amm-liquidity-manipulation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description



### Source

`crates/detectors/src/amm_liquidity_manipulation.rs`

---

## Defi Liquidity Pool Manipulation

**ID:** `defi-liquidity-pool-manipulation`  
**Severity:** Critical  
**Categories:** DeFi, Oracle  

### Description



### Details

DeFi Liquidity Pool Manipulation Detector

### Source

`crates/detectors/src/defi_liquidity_pool_manipulation.rs`

---

## Lending Borrow Bypass

**ID:** `lending-borrow-bypass`  
**Severity:** Critical  
**Categories:** DeFi, AccessControl  

### Description



### Details


Detects collateral and borrowing check bypasses including:
- Missing collateral factor validation
- Unsafe flash loan integration
- Borrow limit bypass through reentrancy
- Inadequate health factor checks
Check if function is a borrow function
Check if function is a flash loan function
Check for missing collateral factor validation
Check for health factor validation

### Source

`crates/detectors/src/lending_borrow_bypass.rs`

---

## Lending Liquidation Abuse

**ID:** `lending-liquidation-abuse`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-1339  

### Description



### Details

Check for liquidation abuse vulnerabilities

### Remediation

- Fix liquidation mechanism in '{}'. \
                    Use TWAP oracles for health factor calculations, implement liquidation cooldown periods, \
                    add liquidation incentive caps, validate collateral prices from multiple sources, \
                    and implement partial liquidation limits.

### Source

`crates/detectors/src/lending_liquidation_abuse.rs`

---

## Vault Share Inflation

**ID:** `vault-share-inflation`  
**Severity:** Critical  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-1339  

### Description



### Source

`crates/detectors/src/vault_share_inflation.rs`

---

## Amm Invariant Manipulation

**ID:** `amm-invariant-manipulation`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description



### Details

AMM Invariant Manipulation Detector

Detects vulnerabilities in Automated Market Maker (AMM) invariant enforcement:
1. Missing K invariant checks (x * y = k for constant product AMMs)
2. Unprotected reserve updates that bypass invariant validation
3. Price oracle manipulation via flash swaps
4. Missing TWAP (Time-Weighted Average Price) implementation
5. Reserve synchronization issues

The constant product formula (x * y = k) is fundamental to AMM security.
Any operation that bypasses or manipulates this invariant can lead to fund loss.

### Source

`crates/detectors/src/defi_advanced/amm_invariant_manipulation.rs`

---

## Defi Jit Liquidity Attacks

**ID:** `defi-jit-liquidity-attacks`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description



### Details

DeFi Just-In-Time (JIT) Liquidity Attacks Detector

### Source

`crates/detectors/src/defi_jit_liquidity.rs`

---

## Defi Yield Farming Exploits

**ID:** `defi-yield-farming-exploits`  
**Severity:** High  
**Categories:** DeFi, Logic  

### Description



### Details

DeFi Yield Farming Exploits Detector

### Source

`crates/detectors/src/defi_yield_farming.rs`

---

## Uniswapv4 Hook Issues

**ID:** `uniswapv4-hook-issues`  
**Severity:** High  
**Categories:** DeFi, ExternalCalls  

### Description



### Details


Detects security issues in Uniswap V4 hook implementations including:
- Unsafe hook callback implementations
- Missing return value validation
- Inadequate hook access control
- Vulnerable hook fee extraction
Check if function is a Uniswap V4 hook function
Check for unsafe hook callback implementations
Check for missing return value validation

### Source

`crates/detectors/src/uniswapv4_hook_issues.rs`

---

## Vault Donation Attack

**ID:** `vault-donation-attack`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-682, CWE-841  

### Description



### Source

`crates/detectors/src/vault_donation_attack.rs`

---

## Vault Withdrawal Dos

**ID:** `vault-withdrawal-dos`  
**Severity:** High  
**Categories:** DeFi, Logic  
**CWE:** CWE-400, CWE-770  

### Description



### Source

`crates/detectors/src/vault_withdrawal_dos.rs`

---

## Liquidity Bootstrapping Abuse

**ID:** `liquidity-bootstrapping-abuse`  
**Severity:** Medium  
**Categories:** DeFi, Logic  
**CWE:** CWE-841, CWE-682  

### Description



### Details

Check for LBP manipulation vulnerabilities

### Source

`crates/detectors/src/liquidity_bootstrapping_abuse.rs`

---

## Vault Fee Manipulation

**ID:** `vault-fee-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, MEV  
**CWE:** CWE-362, CWE-829  

### Description



### Source

`crates/detectors/src/vault_fee_manipulation.rs`

---

## Yield Farming Manipulation

**ID:** `yield-farming-manipulation`  
**Severity:** Medium  
**Categories:** DeFi, Logic  

### Description



### Details

Yield Farming Reward Manipulation Detector

Detects vulnerabilities in yield farming reward calculations that can be exploited:
1. TVL (Total Value Locked) manipulation to inflate rewards
2. Reward rate gaming through flash loans or quick deposits
3. Unprotected reward calculation that doesn't account for time-weighted positions
4. Missing checks for minimum staking duration

These vulnerabilities allow attackers to claim disproportionate rewards without
providing long-term liquidity to the protocol.

### Remediation

- Implement time-weighted reward distribution based on staking duration, not just current TVL

### Source

`crates/detectors/src/defi_advanced/yield_farming_manipulation.rs`

---

