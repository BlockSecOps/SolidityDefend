# Flash Loans Detectors

**Total:** 7 detectors

---

## Flash Loan Governance Attack

**ID:** `flash-loan-governance-attack`  
**Severity:** Critical  
**Categories:** FlashLoan, DeFi  

### Description



### Details

Flash Loan Governance Attack Detector

Detects DAO takeover attacks via flash-borrowed governance tokens.
Prevents temporary voting power exploits to pass malicious proposals.

### Source

`crates/detectors/src/flashloan_enhanced/governance_attack.rs`

---

## Flash Loan Price Manipulation Advanced

**ID:** `flash-loan-price-manipulation-advanced`  
**Severity:** Critical  
**Categories:** FlashLoan, Oracle  

### Description



### Details

Flash Loan Price Manipulation Advanced Detector

Detects multi-protocol price manipulation chains using flash loans.
Addresses cascading liquidations and oracle manipulation across multiple pools.

### Source

`crates/detectors/src/flashloan_enhanced/price_manipulation_advanced.rs`

---

## Flash Loan Staking

**ID:** `flash-loan-staking`  
**Severity:** Critical  
**Categories:** FlashLoanAttacks, DeFi  
**CWE:** CWE-682, CWE-841  

### Description



### Details

Check if a function is vulnerable to flash loan staking attacks

### Source

`crates/detectors/src/flash_loan_staking.rs`

---

## Flashloan Price Oracle Manipulation

**ID:** `flashloan-price-oracle-manipulation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description



### Details

Flash Loan Price Oracle Manipulation Detector

Detects oracle manipulation vulnerabilities exploitable via flash loans:
- Single-source oracle (spot price from DEX) - Polter Finance $7M
- No TWAP (Time-Weighted Average Price)
- No multi-source validation
- Missing flash loan detection
- No price deviation checks

Severity: CRITICAL
Real Exploit: Polter Finance (2024) - $7M via flash-borrowed BOO tokens

### Source

`crates/detectors/src/flashloan/price_oracle_manipulation.rs`

---

## Flash Loan Collateral Swap

**ID:** `flash-loan-collateral-swap`  
**Severity:** High  
**Categories:** FlashLoan, DeFi  

### Description



### Details

Flash Loan Collateral Swap Detector

Detects flash loan manipulation of collateral ratios to trigger unfair
liquidations or create bad debt via collateral manipulation.

### Source

`crates/detectors/src/flashloan_enhanced/collateral_swap.rs`

---

## Flashloan Governance Attack

**ID:** `flashloan-governance-attack`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

Flash Loan Governance Attack Detector

Detects governance systems vulnerable to flash loan attacks:
- No snapshot-based voting (uses current balance) - Beanstalk $182M
- Instant execution without timelock - Compound Proposal 289
- No voting delay
- No quorum requirement

Severity: HIGH
Real Exploits: Shibarium $2.4M, Compound 499k COMP, Beanstalk $182M

### Source

`crates/detectors/src/flashloan/governance_attack.rs`

---

## Flashmint Token Inflation

**ID:** `flashmint-token-inflation`  
**Severity:** High  
**Categories:** DeFi  

### Description



### Details

Flash Mint Token Inflation Detector

Detects flash mint vulnerabilities:
- Uncapped flash mint amount (unlimited minting)
- No flash mint fee (free mints enable spam)
- No rate limiting (DoS via spam)

Severity: HIGH
Context: MakerDAO flash mint used in Euler $200M exploit

### Source

`crates/detectors/src/flashloan/flashmint_token_inflation.rs`

---

