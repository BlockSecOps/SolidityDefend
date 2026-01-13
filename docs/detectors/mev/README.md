# MEV Protection Detectors

**Total:** 28 detectors (16 base + 12 Phase 44 Advanced MEV)

---

## Phase 44: Advanced MEV & Front-Running (v1.8.1)

### Sandwich Conditional Swap

**ID:** `sandwich-conditional-swap`
**Severity:** Critical
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects conditional swap patterns vulnerable to sophisticated sandwich attacks with conditional execution. Covers weak slippage, conditional swaps, public swaps, and meaningless deadlines.

**Source:** `src/sandwich_conditional_swap.rs`

---

### JIT Liquidity Extraction

**ID:** `jit-liquidity-extraction`
**Severity:** Critical
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects just-in-time liquidity patterns where MEV searchers can extract value through liquidity manipulation including instant add/remove, concentrated liquidity, and same-block operations.

**Source:** `src/jit_liquidity_extraction.rs`

---

### Backrunning Opportunity

**ID:** `backrunning-opportunity`
**Severity:** High
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects state changes that can be profitably backrun by MEV searchers including price updates, liquidation triggers, reward distributions, and rebalance opportunities.

**Source:** `src/backrunning_opportunity.rs`

---

### Bundle Inclusion Leak

**ID:** `bundle-inclusion-leak`
**Severity:** High
**Categories:** MEV, Logic
**CWE:** CWE-200

Detects information leakage patterns that could reveal bundle contents to attackers through predictable nonces, intent leakage, leaky events, and timing leaks.

**Source:** `src/bundle_inclusion_leak.rs`

---

### Order Flow Auction Abuse

**ID:** `order-flow-auction-abuse`
**Severity:** High
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects order flow auction patterns vulnerable to manipulation where searchers can game the auction mechanism including unprotected bids, unfair settlement, and first-price auctions.

**Source:** `src/order_flow_auction_abuse.rs`

---

### Encrypted Mempool Timing Attack

**ID:** `encrypted-mempool-timing`
**Severity:** Medium
**Categories:** MEV, Logic
**CWE:** CWE-208

Detects timing vulnerabilities in encrypted mempool or commit-reveal implementations where transaction timing can leak information including gas timing leaks and deadline timing attacks.

**Source:** `src/encrypted_mempool_timing.rs`

---

### Cross-Domain MEV

**ID:** `cross-domain-mev`
**Severity:** High
**Categories:** MEV, L2
**CWE:** CWE-362

Detects MEV extraction opportunities across L1/L2 boundaries or between different rollups where timing differences enable arbitrage including sequencer MEV and cross-rollup arbitrage.

**Source:** `src/cross_domain_mev.rs`

---

### Liquidation MEV

**ID:** `liquidation-mev`
**Severity:** Critical
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects liquidation patterns vulnerable to MEV extraction where searchers can front-run liquidations or manipulate prices to trigger profitable liquidations including flash loan liquidations.

**Source:** `src/liquidation_mev.rs`

---

### Oracle Update MEV

**ID:** `oracle-update-mev`
**Severity:** High
**Categories:** MEV, Oracle
**CWE:** CWE-362

Detects oracle update patterns vulnerable to front-running where searchers can profit by trading before price updates including instant price usage and push oracle patterns.

**Source:** `src/oracle_update_mev.rs`

---

### Governance Proposal MEV

**ID:** `governance-proposal-mev`
**Severity:** High
**Categories:** MEV, AccessControl
**CWE:** CWE-362

Detects governance proposal patterns vulnerable to front-running where attackers can submit counter-proposals or acquire voting power before proposal execution including flash loan governance.

**Source:** `src/governance_proposal_mev.rs`

---

### Token Launch MEV

**ID:** `token-launch-mev`
**Severity:** Critical
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects token launch patterns vulnerable to sniping where MEV bots can front-run initial liquidity to buy tokens at launch price including presale transitions and fair launch issues.

**Source:** `src/token_launch_mev.rs`

---

### NFT Mint MEV

**ID:** `nft-mint-mev`
**Severity:** High
**Categories:** MEV, DeFi
**CWE:** CWE-362

Detects NFT mint patterns vulnerable to front-running where MEV bots can snipe rare tokens or front-run popular mints including predictable token IDs, reveal vulnerabilities, and batch mint issues.

**Source:** `src/nft_mint_mev.rs`

---

## Base MEV Detectors

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

