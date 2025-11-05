# Flash Loan Detectors

**Total:** 9 detectors

---

## Flash Loan Collateral Swap

**ID:** `flash-loan-collateral-swap`  
**Severity:** High  
**Categories:** FlashLoan, DeFi  

### Description

Detects flash loan manipulation of collateral ratios

### Vulnerable Patterns

- Collateral value based on spot price
- Collateral swap without delay
- Liquidation based on single-block health factor

### Remediation

- Use time-weighted average price (TWAP) with 30+ minute window for collateral valuation
- Add minimum delay (e.g., 1 hour) between collateral changes and borrowing/liquidation

### Source

`flashloan_enhanced/collateral_swap.rs`

---

## Flash Loan Governance Attack

**ID:** `flash-loan-governance-attack`  
**Severity:** Critical  
**Categories:** FlashLoan, DeFi  

### Description

Detects DAO takeover via flash-borrowed governance tokens

### Vulnerable Patterns

- Voting power based on current token balance
- No vote delay between proposal and execution
- No minimum holding period for voting
- Quorum based on total supply (manipulable)

### Remediation

- Use snapshot-based voting (e.g., OpenZeppelin Governor with vote delay and checkpoints)
- Add minimum voting delay (e.g., 1 day) between proposal creation and voting period start
- Require minimum token holding period (e.g., 7 days) before tokens can be used for voting

### Source

`flashloan_enhanced/governance_attack.rs`

---

## Flash Loan Price Manipulation Advanced

**ID:** `flash-loan-price-manipulation-advanced`  
**Severity:** Critical  
**Categories:** FlashLoan, Oracle  

### Description

Detects multi-protocol price manipulation using flash loans

### Vulnerable Patterns

- Price fetched from single DEX during flash loan
- Multiple swaps in flash loan callback
- Liquidation triggered based on manipulated price
- Cross-protocol price dependency

### Remediation

- Use multi-source price oracle (Chainlink + TWAP) or disable price-sensitive operations during flash loans
- Limit number of swaps per transaction or use MEV-resistant execution (Flashbots, private mempool)
- Use time-weighted average price (TWAP) with minimum period (e.g., 30 minutes) for liquidation checks

### Source

`flashloan_enhanced/price_manipulation_advanced.rs`

---

## Flash Loan Reentrancy Combo

**ID:** `flash-loan-reentrancy-combo`  
**Severity:** Critical  
**Categories:** FlashLoan, Reentrancy  

### Description

Detects combined flash loan + reentrancy attacks (Penpie pattern)

### Vulnerable Patterns

- Flash loan callback without reentrancy guard
- State updated after flash loan repayment

### Remediation

- Add nonReentrant modifier to flash loan callback and all functions it calls

### Source

`flashloan_enhanced/reentrancy_combo.rs`

---

## Flash Loan Staking Attack

**ID:** `flash-loan-staking`  
**Severity:** Critical  
**Categories:** FlashLoanAttacks, DeFi  
**CWE:** CWE-682, CWE-841  

### Description

Detects staking/farming contracts vulnerable to flash loan attacks for reward extraction

### Vulnerable Patterns

- Reward calculation before state update (classic flash loan vulnerability)

### Source

`src/flash_loan_staking.rs`

---

## Flash Loan Callback Reentrancy

**ID:** `flashloan-callback-reentrancy`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects reentrancy vulnerabilities in flash loan callbacks

### Remediation

- Add nonReentrant modifier from OpenZeppelin

### Source

`flashloan/callback_reentrancy.rs`

---

## Flash Loan Governance Attack

**ID:** `flashloan-governance-attack`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects governance systems vulnerable to flash loan voting attacks

### Remediation

- Use EIP-5805 getPastVotes() with snapshot block
- Add timelock with queue() → execute() pattern (2+ days delay)

### Source

`flashloan/governance_attack.rs`

---

## Flash Loan Price Oracle Manipulation

**ID:** `flashloan-price-oracle-manipulation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects oracle manipulation vulnerabilities exploitable via flash loans

### Remediation

- Use TWAP oracle (Uniswap V3 observe()) or Chainlink with 30-minute average

### Source

`flashloan/price_oracle_manipulation.rs`

---

## Flash Mint Token Inflation Attack

**ID:** `flashmint-token-inflation`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects flash mint vulnerabilities allowing unlimited minting and spam

### Remediation

- Add MAX_FLASH_MINT constant and validate amount
- Add flash mint fee (e.g., 0.05% like MakerDAO)

### Source

`flashloan/flashmint_token_inflation.rs`

---

