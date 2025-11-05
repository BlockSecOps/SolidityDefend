# Token Standard Detectors

**Total:** 10 detectors

---

## ERC-1155 Batch Validation

**ID:** `erc1155-batch-validation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects missing batch validation in ERC-1155 implementations

### Vulnerable Patterns

- safeBatchTransferFrom without array length validation
- balanceOfBatch without validation
- Custom batch functions without empty array check

### Remediation

- Add validation: require(ids.length == amounts.length, \
- Validate arrays: require(accounts.length == ids.length, \
- Add empty check: require(ids.length > 0, \

### Source

`token_standards_extended/batch_validation.rs`

---

## ERC-20 Approve Race Condition

**ID:** `erc20-approve-race`  
**Severity:** Medium  
**Categories:** Logic, DeFi  
**CWE:** CWE-362  

### Description

Detects ERC-20 approve functions vulnerable to front-running race conditions (SWC-114)

### Source

`src/erc20_approve_race.rs`

---

## Infinite Approval Risk

**ID:** `erc20-infinite-approval`  
**Severity:** Low  
**Categories:** Logic, DeFi  
**CWE:** CWE-284  

### Description

Detects contracts that accept or encourage unlimited ERC-20 approvals

### Source

`src/erc20_infinite_approval.rs`

---

## ERC-20 Transfer Return Bomb

**ID:** `erc20-transfer-return-bomb`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects return data bombs in ERC-20 token interactions

### Vulnerable Patterns

- Unchecked return data size from transfer
- Using low-level call for transfers without gas limit
- Copying return data without size check

### Remediation

- Check returndatasize() and reject if excessive (>64 bytes): require(returndatasize() <= 64)
- Specify gas limit for calls: token.call{gas: 100000}(abi.encodeWithSelector(...))
- Validate returndatasize before copying: require(returndatasize() <= MAX_SIZE)

### Source

`token_standards_extended/transfer_return_bomb.rs`

---

## ERC-721/1155 Callback Reentrancy

**ID:** `erc721-callback-reentrancy`  
**Severity:** High  
**Categories:** Reentrancy, Logic  
**CWE:** CWE-691, CWE-841  

### Description

Detects contracts vulnerable to reentrancy via ERC-721/1155 receiver callbacks

### Source

`src/erc721_callback_reentrancy.rs`

---

## ERC-721 Enumeration DOS

**ID:** `erc721-enumeration-dos`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects enumeration gas bombs in ERC-721 implementations

### Vulnerable Patterns

- tokenOfOwnerByIndex in unbounded loop
- totalSupply iteration without bounds
- No pagination in enumeration functions

### Remediation

- Add maximum iteration limit or use off-chain enumeration with pagination
- Avoid on-chain enumeration of entire collection; use events and off-chain indexing
- Add pagination parameters: function getTokens(uint256 offset, uint256 limit)

### Source

`token_standards_extended/enumeration_dos.rs`

---

## ERC-777 Reentrancy Hooks

**ID:** `erc777-reentrancy-hooks`  
**Severity:** High  
**Categories:** Reentrancy, DeFi  
**CWE:** CWE-691, CWE-841  

### Description

Detects contracts vulnerable to reentrancy via ERC-777 tokensReceived/tokensToSend callbacks

### Source

`src/erc777_reentrancy_hooks.rs`

---

## Token Decimal Confusion

**ID:** `token-decimal-confusion`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects decimal mismatch errors in multi-token systems

### Vulnerable Patterns

- Hardcoded decimal assumption (1e18)
- Price calculation without decimal normalization
- Multiple tokens without decimal tracking
- Decimal-sensitive operations without validation

### Remediation

- Call token.decimals() and normalize: uint256 decimals = token.decimals(); amount * 10**decimals
- Normalize decimals: amount * 10**token1.decimals() / 10**token2.decimals()
- Store decimals per token: mapping(address => uint8) public tokenDecimals

### Source

`token_standards_extended/decimal_confusion.rs`

---

## Token Permit Front-Running

**ID:** `token-permit-front-running`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects ERC-2612 permit griefing and front-running vulnerabilities

### Vulnerable Patterns

- permit() followed by transferFrom without try-catch
- No allowance check before permit
- Deadline too far in future
- Permit signature reuse protection missing
- Permit used in critical path without backup

### Remediation

- Use try-catch: try token.permit(...) {} catch {} or check allowance before permit
- Check allowance first: if (token.allowance(owner, spender) < amount) token.permit(...)
- Enforce maximum deadline: require(deadline <= block.timestamp + MAX_DEADLINE, \
- ERC-2612 includes nonces by default, but verify it

### Source

`token_standards_extended/permit_front_running.rs`

---

## Token Supply Manipulation

**ID:** `token-supply-manipulation`  
**Severity:** Critical  
**Categories:** Logic, AccessControl  
**CWE:** CWE-682, CWE-840  

### Description

Detects vulnerabilities in token supply management that allow unauthorized minting, burning, or supply manipulation

### Vulnerable Patterns

- Mint function without max supply cap
- Mint without access control

### Source

`src/token_supply_manipulation.rs`

---

