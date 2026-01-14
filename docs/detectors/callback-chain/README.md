# Callback Chain & Multicall Detectors

**Total:** 10 detectors (Phase 46 - v1.8.3)

---

## Phase 46: Callback Chains & Multicall Patterns (v1.8.3)

### Nested Callback Reentrancy

**ID:** `nested-callback-reentrancy`
**Severity:** Critical
**Categories:** Reentrancy, DeFi
**CWE:** CWE-841

Detects nested safe callbacks that can enable state corruption through chained reentrancy attacks. Covers onERC721Received triggering safeTransfer, flash loan callbacks with multiple external calls, and state changes in callback receivers.

**Source:** `src/nested_callback_reentrancy.rs`

---

### Callback In Callback Loop

**ID:** `callback-in-callback-loop`
**Severity:** High
**Categories:** Reentrancy, Logic
**CWE:** CWE-674

Detects recursive callback patterns that can be exploited through looped callback invocations leading to stack exhaustion or reentrancy. Covers safeTransfer/safeMint in loops, recursive callbacks, and unbounded callback iteration.

**Source:** `src/callback_in_callback_loop.rs`

---

### Multicall msg.value Reuse

**ID:** `multicall-msgvalue-reuse`
**Severity:** Critical
**Categories:** Logic, DeFi
**CWE:** CWE-837

Detects multicall/batch operations where msg.value can be reused across multiple calls, enabling ETH double-spending attacks. Covers payable multicall functions, delegatecall loops with msg.value, and untracked value in batch operations.

**Source:** `src/multicall_msgvalue_reuse.rs`

---

### Multicall Partial Revert

**ID:** `multicall-partial-revert`
**Severity:** High
**Categories:** Logic, DeFi
**CWE:** CWE-754

Detects multicall/batch operations where partial success can cause inconsistent state due to improper error handling. Covers try/catch patterns that continue on failure, success arrays without enforcement, and state changes before potential reverts.

**Source:** `src/multicall_partial_revert.rs`

---

### Batch Cross-Function Reentrancy

**ID:** `batch-cross-function-reentrancy`
**Severity:** Critical
**Categories:** Reentrancy, DeFi
**CWE:** CWE-841

Detects reentrancy vulnerabilities between functions called within a multicall/batch operation where one call can reenter another. Covers delegatecall multicall patterns, shared state functions, permit+transfer batching, and batchable swap functions with callbacks.

**Source:** `src/batch_cross_function_reentrancy.rs`

---

### Flash Callback Manipulation

**ID:** `flash-callback-manipulation`
**Severity:** High
**Categories:** DeFi, Logic
**CWE:** CWE-367

Detects flash loan callback patterns vulnerable to state manipulation through time-of-check-to-time-of-use (TOCTOU) attacks. Covers state reads before callback, swap/liquidity operations in callbacks, oracle reads in flash context, and unvalidated callback execution.

**Source:** `src/flash_callback_manipulation.rs`

---

### ERC721 SafeMint Callback

**ID:** `erc721-safemint-callback`
**Severity:** High
**Categories:** Reentrancy, DeFi
**CWE:** CWE-841

Detects ERC721 safeMint patterns vulnerable to callback exploitation through onERC721Received reentrancy attacks. Covers safeMint in loops, state updates after safeMint, payment handling around safeMint, and whitelist check bypasses.

**Source:** `src/erc721_safemint_callback.rs`

---

### ERC1155 Callback Reentrancy

**ID:** `erc1155-callback-reentrancy`
**Severity:** High
**Categories:** Reentrancy, DeFi
**CWE:** CWE-841

Detects ERC1155 callback patterns vulnerable to reentrancy through onERC1155Received and onERC1155BatchReceived callbacks. Covers state changes after safeTransfer, batch operations without guards, mint callbacks, and receiver implementations with external calls.

**Source:** `src/erc1155_callback_reentrancy.rs`

---

### Uniswap V4 Hook Callback

**ID:** `uniswap-v4-hook-callback`
**Severity:** High
**Categories:** DeFi, Reentrancy
**CWE:** CWE-841

Detects Uniswap V4 hook patterns vulnerable to callback exploitation, state manipulation, and reentrancy attacks. Covers hook state modifications, unvalidated pool hooks, external calls in hooks, dynamic fee manipulation, and improper BalanceDelta returns.

**Source:** `src/uniswap_v4_hook_callback.rs`

---

### Compound Callback Chain

**ID:** `compound-callback-chain`
**Severity:** High
**Categories:** DeFi, Reentrancy
**CWE:** CWE-841

Detects Compound-style lending protocol callback chain vulnerabilities through cToken interactions and market manipulation. Covers unprotected mint/redeem, borrow with market state read, liquidation callbacks, cToken operation chains, and comptroller interactions.

**Source:** `src/compound_callback_chain.rs`

---

## CWE Mappings

| CWE | Description | Detectors |
|-----|-------------|-----------|
| CWE-841 | Improper Enforcement of Behavioral Workflow | nested-callback-reentrancy, batch-cross-function-reentrancy, erc721-safemint-callback, erc1155-callback-reentrancy, uniswap-v4-hook-callback, compound-callback-chain |
| CWE-674 | Uncontrolled Recursion | callback-in-callback-loop |
| CWE-837 | Improper Enforcement of a Single, Unique Action | multicall-msgvalue-reuse |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | multicall-partial-revert |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | flash-callback-manipulation |

---

## Real-World Attack Examples

### Multicall msg.value Reuse (2023-2024)

Multiple DeFi protocols have been exploited through multicall patterns where msg.value is reused across batch operations. Attackers can deposit 1 ETH but have it credited multiple times through careful batch construction.

**Detectors that would catch this:**
- `multicall-msgvalue-reuse`
- `batch-cross-function-reentrancy`

### NFT Callback Exploits

ERC721 and ERC1155 callbacks have been exploited in numerous NFT projects to bypass mint limits, drain funds, or corrupt sale state through reentrancy during safeMint/safeTransfer operations.

**Detectors that would catch this:**
- `erc721-safemint-callback`
- `erc1155-callback-reentrancy`
- `nested-callback-reentrancy`

### Flash Loan Oracle Manipulation

Flash loan callbacks are frequently exploited to manipulate oracle prices within a single transaction, allowing attackers to borrow against inflated collateral or profit from price discrepancies.

**Detectors that would catch this:**
- `flash-callback-manipulation`
- `compound-callback-chain`

### Compound Fork Exploits

Many Compound forks have been exploited through callback chains in cToken operations, particularly during liquidation and market entry operations where multiple external calls create reentrancy opportunities.

**Detectors that would catch this:**
- `compound-callback-chain`
- `batch-cross-function-reentrancy`
