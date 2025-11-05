# MEV Protection Detectors

**Total:** 16 detectors

---

## Auction Timing Manipulation

**ID:** `auction-timing-manipulation`  
**Severity:** High  
**Categories:** MEV, DeFi  
**CWE:** CWE-362, CWE-841  

### Description

Detects auction mechanisms with predictable timing, enabling MEV bot front-running

### Vulnerable Patterns

- Explicit vulnerability comment
- Uses block.timestamp for timing without randomization
- Missing access contr

### Source

`src/auction_timing.rs`

---

## Block Stuffing Vulnerable

**ID:** `block-stuffing-vulnerable`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-405  

### Description

Detects contracts vulnerable to block stuffing attacks where attackers fill blocks to prevent transaction inclusion

### Vulnerable Patterns

- Single-block deadline without grace period
- First-come-first-served with strict ordering
- Auction close without multi-block finalization

### Source

`src/block_stuffing_vulnerable.rs`

---

## CREATE2 Frontrunning Protection

**ID:** `create2-frontrunning`  
**Severity:** High  
**Categories:** Deployment, MEV, AccessControl  

### Description

Detects CREATE2 usage with predictable salts or missing authorization that could enable frontrunning and address collision attacks

### Vulnerable Patterns

- Predictable salt from msg.sender or simple counter
- Public CREATE2 deployment function without authorization
- Missing salt validation
- CREATE2 with initialization in same transaction

### Source

`src/create2_frontrunning.rs`

---

## Deadline Manipulation

**ID:** `deadline-manipulation`  
**Severity:** Medium  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-367  

### Description

Detects improper deadline handling that allows validators to hold and execute transactions at unfavorable times

### Vulnerable Patterns

- Deadline parameter without validation
- Allows very distant deadlines
- Swap/trade without deadline

### Source

`src/deadline_manipulation.rs`

---

## Front Running

**ID:** `front-running`  
**Severity:** Medium  
**Categories:** MEV  
**CWE:** CWE-362  

### Description

Vulnerable to front-running attacks

### Source

`src/mev.rs`

---

## Missing Front-Running Mitigation

**ID:** `front-running-mitigation`  
**Severity:** High  
**Categories:** MEV  
**CWE:** CWE-362, CWE-841  

### Description

Detects functions vulnerable to front-running attacks without proper MEV protection mechanisms

### Vulnerable Patterns

- Bid/auction functions without commit-reveal
- Swap/trade functions without slippage protection

### Source

`src/front_running_mitigation.rs`

---

## JIT Liquidity Sandwich

**ID:** `jit-liquidity-sandwich`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description

Detects vulnerability to just-in-time liquidity attacks where attackers add liquidity before swaps and remove immediately after to capture fees

### Remediation

- Add a minimum lock time for liquidity positions (e.g., 1 block or epoch-based system) to prevent JIT liquidity attacks

### Source

`defi_advanced/jit_liquidity_sandwich.rs`

---

## MEV Backrun Opportunities

**ID:** `mev-backrun-opportunities`  
**Severity:** Medium  
**Categories:** MEV, DeFi  

### Description

Detects backrunnable state changes creating MEV opportunities

### Vulnerable Patterns

- Reserve updates without delay
- Oracle price updates triggering actions
- Liquidation triggers without protection
- Rebalancing operations

### Remediation

- Add delay or use commit-reveal: lastUpdate = block.number; require(block.number > lastUpdate)
- Use private mempool or implement delay for critical price updates
- Add grace period before liquidation to reduce MEV opportunity
- Use batch auctions or time-weighted execution to reduce MEV extraction

### Source

`mev_enhanced/backrun_opportunities.rs`

---

## MEV Extractable Value

**ID:** `mev-extractable-value`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-841  

### Description

Detects contracts with extractable MEV through front-running, back-running, or transaction ordering manipulation

### Vulnerable Patterns

- Public function with value transfer without protection (TIGHTENED)

### Source

`src/mev_extractable_value.rs`

---

## MEV Priority Gas Auction

**ID:** `mev-priority-gas-auction`  
**Severity:** Medium  
**Categories:** MEV  

### Description

Detects PGA-vulnerable functions causing gas wars

### Vulnerable Patterns

- First-come-first-served minting
- Liquidation rewards to caller
- Arbitrage opportunities for anyone
- Time-sensitive operations

### Remediation

- Use commit-reveal, whitelist, or fair launch mechanism instead of FCFS
- Use Dutch auction for liquidation bonus or distribute rewards over time
- Capture MEV for protocol via auction mechanism or restrict to specific keepers
- Use commit-reveal or randomized selection instead of first-wins pattern

### Source

`mev_enhanced/priority_gas_auction.rs`

---

## MEV Sandwich Vulnerable Swaps

**ID:** `mev-sandwich-vulnerable-swaps`  
**Severity:** High  
**Categories:** MEV, DeFi  

### Description

Detects unprotected DEX swaps vulnerable to sandwich attacks

### Vulnerable Patterns

- Swap with zero or no minimum output
- No slippage parameter in swap function
- Large swaps without MEV protection
- Deadline too far in future

### Remediation

- Set minimum output: uint256 minOut = quote * (10000 - slippageBps) / 10000; swap(..., minOut)
- Add slippage protection parameter: function swap(..., uint256 minAmountOut)
- Use Flashbots/MEV-Share for large swaps or implement private transaction submission

### Source

`mev_enhanced/sandwich_vulnerable.rs`

---

## MEV Toxic Flow Exposure

**ID:** `mev-toxic-flow-exposure`  
**Severity:** Medium  
**Categories:** MEV, DeFi  

### Description

Detects AMM toxic flow risks from informed order flow

### Vulnerable Patterns

- No fee tier for toxic flow
- No trade size limits
- Instant arbitrage possible
- No JIT liquidity protection

### Remediation

- Implement dynamic fees that increase with volatility or trade size to discourage toxic flow
- Add maximum trade size as percentage of reserves: require(amountIn < reserves * maxBps / 10000)
- Add block delay or use time-weighted pricing to reduce instant arbitrage opportunities

### Source

`mev_enhanced/toxic_flow.rs`

---

## Sandwich Attack

**ID:** `sandwich-attack`  
**Severity:** Medium  
**Categories:** MEV  
**CWE:** CWE-362  

### Description

Vulnerable to sandwich attacks

### Source

`src/mev.rs`

---

## Missing Sandwich Attack Protection

**ID:** `sandwich-resistant-swap`  
**Severity:** High  
**Categories:** DeFi, MEV  
**CWE:** CWE-362, CWE-841  

### Description

Detects swap functions lacking protection against MEV sandwich attacks through front-running and back-running

### Vulnerable Patterns

- Missing slippage protection (amountOutMin)
- Missing deadline parameter

### Source

`src/sandwich_resistant_swap.rs`

---

## Timestamp Manipulation

**ID:** `timestamp-manipulation`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-367, CWE-829  

### Description

Detects dangerous dependencies on block.timestamp that miners can manipulate within bounds

### Source

`src/timestamp_manipulation.rs`

---

## Validator Front-Running

**ID:** `validator-front-running`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-841  

### Description

Detects vulnerabilities where validators can front-run user transactions for profit or extract MEV

### Vulnerable Patterns

- Validator selection visible before execution
- Reward distribution without anti-frontrun protection
- Staking without validator rotation

### Source

`src/validator_front_running.rs`

---

