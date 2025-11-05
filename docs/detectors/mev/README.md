# Mev Detectors

**Total:** 14 detectors

---

## Create2 Frontrunning

**ID:** `create2-frontrunning`  
**Severity:** High  
**Categories:** Deployment, MEV, AccessControl  

### Description



### Details

CREATE2 Frontrunning Protection Detection

Detects contracts that use CREATE2 with predictable salts or lack proper authorization,
which can lead to frontrunning attacks and address collision exploits.

### Source

`crates/detectors/src/create2_frontrunning.rs`

---

## Front Running Mitigation

**ID:** `front-running-mitigation`  
**Severity:** High  
**Categories:** MEV  
**CWE:** CWE-362, CWE-841  

### Description



### Source

`crates/detectors/src/front_running_mitigation.rs`

---

## Jit Liquidity Sandwich

**ID:** `jit-liquidity-sandwich`  
**Severity:** High  
**Categories:** DeFi, MEV  

### Description



### Details

JIT Liquidity Sandwich Attack Detector

Detects vulnerability to just-in-time (JIT) liquidity attacks where an attacker:
1. Adds large liquidity immediately before a user's swap
2. Captures a significant portion of the trading fees
3. Removes liquidity immediately after

This is a sophisticated MEV strategy that exploits protocols without time-locks
on liquidity provision/removal.

### Source

`crates/detectors/src/defi_advanced/jit_liquidity_sandwich.rs`

---

## Mev Extractable Value

**ID:** `mev-extractable-value`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-841  

### Description



### Source

`crates/detectors/src/mev_extractable_value.rs`

---

## Mev Sandwich Vulnerable Swaps

**ID:** `mev-sandwich-vulnerable-swaps`  
**Severity:** High  
**Categories:** MEV, DeFi  

### Description



### Details

MEV Sandwich Vulnerable Swaps Detector

Detects unprotected DEX swaps vulnerable to sandwich attacks.
Missing slippage protection allows MEV bots to profit at user expense.

### Source

`crates/detectors/src/mev_enhanced/sandwich_vulnerable.rs`

---

## Sandwich Resistant Swap

**ID:** `sandwich-resistant-swap`  
**Severity:** High  
**Categories:** DeFi, MEV  
**CWE:** CWE-362, CWE-841  

### Description



### Source

`crates/detectors/src/sandwich_resistant_swap.rs`

---

## Validator Front Running

**ID:** `validator-front-running`  
**Severity:** High  
**Categories:** MEV, Logic  
**CWE:** CWE-362, CWE-841  

### Description



### Details

Check for validator front-running vulnerabilities

### Remediation

- Mitigate validator front-running in '{}'. \
                    Implement commit-reveal schemes, use threshold encryption, \
                    add validator rotation, implement fair sequencing service integration, \
                    use batch auctions instead of continuous, and add MEV redistribution mechanisms.

### Source

`crates/detectors/src/validator_front_running.rs`

---

## Mev Backrun Opportunities

**ID:** `mev-backrun-opportunities`  
**Severity:** Medium  
**Categories:** MEV, DeFi  

### Description



### Details

MEV Backrun Opportunities Detector

Detects backrunnable state changes that create MEV opportunities.
State changes that affect prices or balances can be exploited via backrunning.

### Source

`crates/detectors/src/mev_enhanced/backrun_opportunities.rs`

---

## Mev Priority Gas Auction

**ID:** `mev-priority-gas-auction`  
**Severity:** Medium  
**Categories:** MEV  

### Description



### Details

MEV Priority Gas Auction Detector

Detects PGA (Priority Gas Auction) vulnerable functions.
Gas wars occur when multiple parties compete for same opportunity.

### Remediation

- Use commit-reveal, whitelist, or fair launch mechanism instead of FCFS

### Source

`crates/detectors/src/mev_enhanced/priority_gas_auction.rs`

---

## Mev Toxic Flow Exposure

**ID:** `mev-toxic-flow-exposure`  
**Severity:** Medium  
**Categories:** MEV, DeFi  

### Description



### Details

MEV Toxic Flow Detector

Detects AMM toxic flow risks where informed traders extract value.
Adversarial order flow causes LPs to lose money to informed traders.

### Remediation

- Implement dynamic fees that increase with volatility or trade size to discourage toxic flow

### Source

`crates/detectors/src/mev_enhanced/toxic_flow.rs`

---

## Sandwich Attack

**ID:** `sandwich-attack`  
**Severity:** Medium  
**Categories:** MEV, MEV  
**CWE:** CWE-362, CWE-362  

### Description



### Details

Check if function is vulnerable to sandwich attacks

### Remediation

- Consider implementing commit-reveal schemes or using a decentralized oracle in function '{}'

### Source

`crates/detectors/src/mev.rs`

---

## Sandwich Attack

**ID:** `sandwich-attack`  
**Severity:** Medium  
**Categories:** MEV, MEV  
**CWE:** CWE-362, CWE-362  

### Description



### Details

Check if function is vulnerable to sandwich attacks

### Remediation

- Consider implementing commit-reveal schemes or using a decentralized oracle in function '{}'

### Source

`crates/detectors/src/mev.rs`

---

## Token Permit Front Running

**ID:** `token-permit-front-running`  
**Severity:** Medium  
**Categories:** DeFi  

### Description



### Details

Token Permit Front-Running Detector

Detects ERC-2612 permit griefing and front-running vulnerabilities.
Attackers can front-run permit transactions causing DOS or theft.

### Source

`crates/detectors/src/token_standards_extended/permit_front_running.rs`

---

## Front Running

**ID:** `front-running`
**Severity:** Medium
**Categories:** MEV

### Description

Vulnerable to front-running attacks.

### Details

Front-running is a type of MEV (Miner Extractable Value) attack where malicious actors observe pending transactions in the mempool and submit their own transactions with higher gas prices to be executed first. This allows them to profit from knowledge of upcoming transactions.

**Common Front-Running Vulnerabilities:**

1. **Price-Based Trades:** DEX swaps and token purchases where the attacker can buy before the victim
2. **Auction Bids:** On-chain auctions where bids are visible before execution
3. **Governance Votes:** Proposals where early votes can influence later voters
4. **NFT Mints:** Limited supply mints where attackers can claim items first
5. **Oracle Updates:** Price feed updates that can be exploited before application

**Attack Flow:**

1. Attacker monitors the mempool for profitable transactions
2. Attacker identifies a target transaction (e.g., large DEX swap)
3. Attacker submits their own transaction with higher gas price
4. Miner includes attacker's transaction first
5. Attacker profits, victim gets worse execution

**Example Vulnerable Code:**

```solidity
contract VulnerableAuction {
    uint public highestBid;
    address public highestBidder;

    // ❌ Vulnerable to front-running
    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");

        // Attacker can see this bid in mempool and submit higher bid
        highestBid = msg.value;
        highestBidder = msg.sender;
    }
}

contract VulnerableDEX {
    // ❌ No slippage protection - vulnerable to front-running
    function swap(address tokenIn, address tokenOut, uint amountIn) external {
        uint amountOut = getAmountOut(tokenIn, tokenOut, amountIn);
        // Attacker can front-run this swap and manipulate the price
        _executeSwap(tokenIn, tokenOut, amountIn, amountOut);
    }
}
```

**Types of Front-Running:**

- **Displacement:** Attacker's transaction replaces victim's transaction
- **Insertion:** Attacker inserts transaction before victim's
- **Suppression:** Attacker delays victim's transaction by filling blocks

### Remediation

**1. Use Commit-Reveal Schemes:**

```solidity
contract SecureAuction {
    mapping(address => bytes32) public commitments;
    mapping(address => uint) public bids;

    // ✅ Phase 1: Commit (hide bid amount)
    function commitBid(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
    }

    // ✅ Phase 2: Reveal (after commit phase ends)
    function revealBid(uint amount, bytes32 nonce) external payable {
        require(msg.value == amount, "Invalid amount");
        require(keccak256(abi.encodePacked(amount, nonce)) == commitments[msg.sender], "Invalid reveal");
        bids[msg.sender] = amount;
    }
}
```

**2. Add Slippage Protection:**

```solidity
contract SecureDEX {
    // ✅ User specifies minimum acceptable output
    function swap(
        address tokenIn,
        address tokenOut,
        uint amountIn,
        uint minAmountOut  // Slippage protection
    ) external {
        uint amountOut = getAmountOut(tokenIn, tokenOut, amountIn);
        require(amountOut >= minAmountOut, "Slippage too high");
        _executeSwap(tokenIn, tokenOut, amountIn, amountOut);
    }
}
```

**3. Use Deadline Parameters:**

```solidity
function swap(
    address tokenIn,
    address tokenOut,
    uint amountIn,
    uint minAmountOut,
    uint deadline  // Transaction expires after deadline
) external {
    require(block.timestamp <= deadline, "Transaction expired");
    // ... rest of swap logic
}
```

**4. Implement Batch Auctions:**

Instead of continuous trading, use batch auctions where all orders in a time window are executed at the same price.

**5. Use Private Mempools:**

- Flashbots Protect for Ethereum
- Private transaction relayers
- MEV-resistant ordering services

**6. Add Minimum Time Delays:**

```solidity
mapping(address => uint) public lastAction;

function sensitiveAction() external {
    require(block.timestamp >= lastAction[msg.sender] + MIN_DELAY, "Too soon");
    lastAction[msg.sender] = block.timestamp;
    // ... action logic
}
```

### Source

`crates/detectors/src/mev.rs`

---

