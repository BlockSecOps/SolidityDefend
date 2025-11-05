# Restaking Detectors

**Total:** 5 detectors

---

## Lrt Share Inflation

**ID:** `lrt-share-inflation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

LRT Share Inflation Attack Detector

Detects ERC-4626-style first depositor attacks in Liquid Restaking Tokens where attackers
can deposit 1 wei, donate assets to inflate share price, causing subsequent depositors to
receive 0 shares and lose their deposits.

Severity: CRITICAL
Category: DeFi, Restaking, Vault

Real-World Exploit:
- Kelp DAO (November 2023) - Code4rena HIGH Severity
"Deposit Pool Vulnerable to 4626-style Vault Inflation Attack - Users Will Lose ALL Funds"
Attack: Deposit 1 wei → Donate 10,000 ETH → Victim deposits 1,000 ETH → Gets 0 shares

Vulnerabilities Detected:
1. No initial deposit lock (first deposit at 1:1 ratio)
2. totalAssets() uses balanceOf (includes donations)
3. No minimum shares check (can mint 0 shares)
4. No donation detection (balance before/after)
Checks deposit/mint functions for initial share lock

### Source

`crates/detectors/src/restaking/lrt_share_inflation.rs`

---

## Restaking Delegation Manipulation

**ID:** `restaking-delegation-manipulation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

Restaking Delegation Manipulation Detector

Detects improper delegation validation in restaking protocols where operators can
manipulate staker allocations without consent or where malicious operators can be selected.

Severity: CRITICAL
Category: DeFi, Restaking

Vulnerabilities Detected:
1. No operator whitelist/validation
2. Unconstrained allocation changes (no 14-day delay)
3. Missing delegation caps (centralization risk)
4. No undelegation mechanism

Real-World Context:
- EigenLayer: Operators can change allocations with 14-day delay
- Centralization: Few operators controlling majority of stake creates systemic risk
Checks delegation functions for operator validation

### Source

`crates/detectors/src/restaking/delegation_manipulation.rs`

---

## Restaking Slashing Conditions

**ID:** `restaking-slashing-conditions`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

Restaking Slashing Conditions Detector

Detects missing slashing protection, improper penalty calculation, and compound slashing
risks in restaking protocols. EigenLayer's slashing mechanism launched April 2025 creates
new attack surface where validators can lose 100% of stake for ANY AVS violation.

Severity: CRITICAL
Category: DeFi, Restaking

Vulnerabilities Detected:
1. No slashing policy validation (AVS can set 100% slashing)
2. Missing evidence validation
3. Compound slashing not prevented (multiple AVSs slash same stake)
4. No slashing appeal period

Real-World Context:
- EigenLayer slashing launched April 2025 - very new, high bug probability
- Validators can lose 100% of staked ETH if they breach any AVS rules
- Each AVS defines custom slashing policies
Checks slashing functions for evidence validation

### Source

`crates/detectors/src/restaking/slashing_conditions.rs`

---

## Restaking Withdrawal Delays

**ID:** `restaking-withdrawal-delays`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

Restaking Withdrawal Delays Detector

Detects missing withdrawal delay enforcement, queue manipulation, and liquidity lock
vulnerabilities in restaking protocols. EigenLayer requires 7-day delay; protocols that
bypass this or fail to maintain liquidity expose users to forced liquidations.

Severity: HIGH
Category: DeFi, Restaking

Real-World Incident:
- Renzo ezETH Depeg (April 2024) - $65M+ in liquidations
"Lack of support for withdrawals from the protocol, resulting in liquidations for
positions in derivative markets, leading to over $50 million in losses"

Vulnerabilities Detected:
1. Instant withdrawals (bypassing 7-day delay)
2. No withdrawal queue system
3. No liquidity reserve (100% restaked)
4. Withdrawal delay not propagated to users
Checks withdrawal functions for delay enforcement

### Source

`crates/detectors/src/restaking/withdrawal_delays.rs`

---

## Restaking Rewards Manipulation

**ID:** `restaking-rewards-manipulation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

Restaking Rewards Manipulation Detector

Detects reward calculation exploits, point system gaming, and unfair reward distribution
in restaking protocols. Operators control reward distribution, creating manipulation
opportunities.

Severity: MEDIUM
Category: DeFi, Restaking

Real-World Context:
- Renzo Airdrop Controversy: Farming via quick deposits/withdrawals
- Point systems without time-weighting vulnerable to Sybil attacks
- Operators can favor certain stakers in reward distribution

Vulnerabilities Detected:
1. Unfair reward distribution (not pro-rata)
2. Point system without Sybil protection
3. Rewards calculated using balanceOf (donation manipulation)
4. No reward rate limits
5. No early withdrawal penalty (farming prevention)
Checks reward distribution for proportional calculation

### Source

`crates/detectors/src/restaking/rewards_manipulation.rs`

---

