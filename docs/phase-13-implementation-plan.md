# Phase 13 Implementation Plan: Cross-Chain Intent & Bridge Security

**Phase:** 13
**Detectors:** 8
**Target Completion:** 3-4 weeks
**Priority:** Critical
**Dependencies:** Existing dataflow and CFG infrastructure

---

## Overview

Phase 13 introduces 8 detectors focused on cross-chain security, specifically addressing vulnerabilities in:
- ERC-7683 cross-chain intent specification
- Bridge contract security
- Cross-chain message verification
- Replay attack protection

---

## Detector Specifications

### 1. Settlement Contract Validation (`erc7683-settlement-validation`)

**Severity:** High
**CWE:** CWE-20 (Improper Input Validation)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable pattern - missing nonce check
function fillOrder(CrossChainOrder memory order, bytes memory signature) external {
    // MISSING: nonce validation
    _executeOrder(order);
}

// Vulnerable pattern - missing deadline check
function fillOrder(CrossChainOrder memory order, bytes memory signature) external {
    // MISSING: require(block.timestamp <= order.fillDeadline)
    _executeOrder(order);
}
```

**Implementation Approach:**
1. Identify functions implementing ERC-7683 `fillOrder` pattern
2. Check for presence of nonce validation:
   - Storage mapping read for order.nonce or order.user/order.orderHash
   - Comparison/require statement using nonce
3. Check for deadline validation:
   - `block.timestamp` comparison with order field
   - Require statement enforcing deadline
4. Validate settlement contract has proper token handling:
   - Use of Permit2 or SafeERC20
   - Check for direct approve() calls (vulnerable)

**Test Contracts:**
- `tests/contracts/phase13/erc7683/vulnerable_settlement.sol`
- `tests/contracts/phase13/erc7683/secure_settlement.sol`

**Expected False Positive Rate:** 5-10%

---

### 2. Cross-Chain Replay Attack (`erc7683-cross-chain-replay`)

**Severity:** Critical
**CWE:** CWE-294 (Authentication Bypass by Capture-replay)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - missing chain ID validation
function executeOrder(Order memory order, bytes memory proof) external {
    require(verifySignature(order, proof), "Invalid signature");
    // MISSING: require(order.chainId == block.chainid)
    _execute(order);
}

// Vulnerable - reusable order tracking
mapping(bytes32 => bool) public filled;
function fill(Order memory order) external {
    bytes32 orderHash = keccak256(abi.encode(order.user, order.amount));
    // VULNERABLE: Missing chain ID in hash
    require(!filled[orderHash], "Already filled");
    filled[orderHash] = true;
}
```

**Implementation Approach:**
1. Identify cross-chain order execution functions:
   - Functions with Order/CrossChainOrder struct parameters
   - Functions verifying signatures or proofs
2. Check for chain ID validation:
   - Presence of `block.chainid` comparison
   - Chain ID included in signature/proof verification
3. Verify order tracking includes chain context:
   - orderHash calculation includes chainid
   - Separate tracking per origin chain
4. Detect signature reuse across chains:
   - EIP-712 domain separator with chainId
   - Chain-specific nonce tracking

**Dataflow Analysis Requirements:**
- Taint tracking for order struct fields
- Verification that chainId flows into validation logic
- Signature verification must consume chainId parameter

**Test Contracts:**
- `tests/contracts/phase13/replay/missing_chainid.sol`
- `tests/contracts/phase13/replay/weak_nonce.sol`
- `tests/contracts/phase13/replay/secure_replay_protection.sol`

**Expected False Positive Rate:** 10-15%

---

### 3. Filler Front-Running Vulnerability (`erc7683-filler-frontrunning`)

**Severity:** High
**CWE:** CWE-362 (Concurrent Execution using Shared Resource)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - no slippage protection for filler
function fillOrder(Order memory order) external {
    uint256 amountOut = _swap(order.inputToken, order.outputToken, order.inputAmount);
    // VULNERABLE: No minimum output check for filler
    _transferToFiller(amountOut);
}

// Vulnerable - predictable execution
function executeFill(uint256 orderId) external {
    Order memory order = orders[orderId];
    // VULNERABLE: Filler can be front-run by checking public order queue
    _fill(order);
}
```

**Implementation Approach:**
1. Identify filler reward/payment logic:
   - Functions calculating filler compensation
   - Token transfers to msg.sender (filler)
2. Check for slippage protection:
   - Minimum output amount parameter
   - Price bounds validation
   - Require statements protecting filler amounts
3. Detect predictable execution patterns:
   - Public order queues without commit-reveal
   - Missing deadline/expiration on filler attempts
   - No competition mechanism for filler selection
4. CFG analysis for MEV opportunities:
   - External price feeds queried before filler payment
   - State changes between price check and transfer

**Dataflow Requirements:**
- Track flow from swap/exchange to filler payment
- Verify slippage parameters reach validation
- Identify external calls that create MEV windows

**Test Contracts:**
- `tests/contracts/phase13/mev/filler_frontrun.sol`
- `tests/contracts/phase13/mev/no_slippage_protection.sol`
- `tests/contracts/phase13/mev/secure_filler.sol`

**Expected False Positive Rate:** 15-20%

---

### 4. Oracle Dependency Risk (`erc7683-oracle-dependency`)

**Severity:** High
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - single oracle source
function validateCrossChainPrice(address token) internal view returns (uint256) {
    return priceOracle.getPrice(token); // Single source
}

// Vulnerable - no staleness check
function getPrice(address token) external view returns (uint256) {
    (uint256 price, uint256 timestamp) = oracle.latestRoundData();
    // MISSING: require(block.timestamp - timestamp < MAX_DELAY)
    return price;
}
```

**Implementation Approach:**
1. Identify oracle interactions in cross-chain contexts:
   - Functions calling external oracle contracts
   - Price feed queries used for cross-chain validation
2. Count unique oracle sources:
   - Single external call = vulnerable
   - Multiple oracle aggregation = secure
3. Check for staleness validation:
   - Timestamp comparison with `block.timestamp`
   - Require statement enforcing maximum age
4. Verify oracle failure handling:
   - Try-catch blocks around oracle calls
   - Fallback price sources
   - Circuit breaker patterns

**Semantic Analysis Requirements:**
- Resolve external contract types (is it an oracle?)
- Track oracle response through validation logic
- Identify missing error paths

**Test Contracts:**
- `tests/contracts/phase13/oracle/single_source.sol`
- `tests/contracts/phase13/oracle/no_staleness_check.sol`
- `tests/contracts/phase13/oracle/secure_oracle_multi.sol`

**Expected False Positive Rate:** 10-12%

---

### 5. Permit2 Integration Issues (`erc7683-unsafe-permit2`)

**Severity:** Medium
**CWE:** CWE-863 (Incorrect Authorization)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - using approve instead of Permit2
function deposit(address token, uint256 amount) external {
    IERC20(token).approve(address(this), amount); // VULNERABLE
    _deposit(token, amount);
}

// Vulnerable - missing witness data validation
function permitAndDeposit(PermitTransferFrom memory permit, bytes memory signature) external {
    // MISSING: witness data validation
    permit2.permitTransferFrom(permit, signature, address(this));
}
```

**Implementation Approach:**
1. Detect token approval patterns:
   - Direct `approve()` calls in cross-chain contexts
   - Flag when Permit2 should be used
2. Verify Permit2 signature validation:
   - Presence of `permitTransferFrom` or `permitBatchTransferFrom`
   - Witness data struct validation
3. Check permission scoping:
   - Time-limited approvals (deadline parameter)
   - Amount-limited permissions
   - Single-use nonces
4. Identify incorrect approval flow:
   - Approve-then-transfer pattern (vulnerable)
   - Permit-in-same-transaction pattern (secure)

**Symbol Resolution Requirements:**
- Identify Permit2 contract references
- Distinguish IERC20.approve from Permit2 patterns
- Type checking for Permit structs

**Test Contracts:**
- `tests/contracts/phase13/permit2/unsafe_approve.sol`
- `tests/contracts/phase13/permit2/missing_witness.sol`
- `tests/contracts/phase13/permit2/secure_permit2.sol`

**Expected False Positive Rate:** 8-10%

---

### 6. Bridge Token Minting Vulnerability (`bridge-token-mint-control`)

**Severity:** Critical
**CWE:** CWE-284 (Improper Access Control)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - missing access control
function mintWrapped(address to, uint256 amount) external {
    // MISSING: access control
    wrappedToken.mint(to, amount); // Anyone can mint!
}

// Vulnerable - no supply cap
function bridgeMint(address to, uint256 amount, bytes memory proof) external {
    require(verifyProof(proof), "Invalid proof");
    // MISSING: require(totalSupply() + amount <= maxSupply)
    _mint(to, amount);
}
```

**Implementation Approach:**
1. Identify bridge minting functions:
   - Functions calling token.mint()
   - Internal _mint() in bridge contracts
2. Verify access control:
   - onlyOwner, onlyRole, or similar modifier
   - Multi-sig or governance requirement
3. Check supply cap validation:
   - totalSupply comparison before minting
   - maxSupply or cap enforcement
4. Validate cross-chain proof verification:
   - Proof parameter present
   - Merkle or signature verification before mint
5. Detect locked-vs-minted balance tracking:
   - Ensure minted amount <= locked on origin chain

**Access Control Analysis:**
- Check modifier presence on mint functions
- Verify role-based permissions (MINTER_ROLE)
- Confirm multi-sig or timelock controls

**Test Contracts:**
- `tests/contracts/phase13/bridge/unprotected_mint.sol`
- `tests/contracts/phase13/bridge/no_supply_cap.sol`
- `tests/contracts/phase13/bridge/secure_bridge_mint.sol`

**Expected False Positive Rate:** 5%

---

### 7. Bridge Message Verification (`bridge-message-verification`)

**Severity:** Critical
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - weak signature validation
function executeMessage(Message memory message, bytes memory signature) external {
    require(validators[recoverSigner(message, signature)], "Invalid signer");
    // VULNERABLE: Only 1 signature required
    _execute(message);
}

// Vulnerable - missing merkle proof
function relayMessage(bytes memory data) external {
    // MISSING: Merkle proof verification
    _processMessage(data);
}
```

**Implementation Approach:**
1. Identify message relay/execute functions:
   - Functions processing cross-chain messages
   - Bridge message execution entry points
2. Check signature verification strength:
   - Single vs. multi-signature validation
   - Quorum requirements (M-of-N validation)
   - Signature uniqueness checks
3. Verify merkle proof validation:
   - MerkleProof.verify() calls
   - Root hash validation against stored commitment
4. Detect validator set management:
   - Validator addition/removal controls
   - Quorum threshold enforcement
   - Validator rotation mechanisms

**Cryptographic Verification:**
- ECDSA recover validation
- Merkle tree root verification
- Validator quorum calculation

**Test Contracts:**
- `tests/contracts/phase13/bridge/weak_signature.sol`
- `tests/contracts/phase13/bridge/missing_merkle_proof.sol`
- `tests/contracts/phase13/bridge/single_validator.sol`
- `tests/contracts/phase13/bridge/secure_multisig_bridge.sol`

**Expected False Positive Rate:** 8-10%

---

### 8. Chain-ID Validation (`missing-chainid-validation`)

**Severity:** High
**CWE:** CWE-346 (Origin Validation Error)

#### Detection Logic

**AST Patterns to Match:**
```solidity
// Vulnerable - signature without chain ID
function executeWithSignature(bytes memory data, bytes memory signature) external {
    bytes32 hash = keccak256(data); // MISSING: chain ID in hash
    address signer = ECDSA.recover(hash, signature);
    require(isAuthorized(signer), "Unauthorized");
    _execute(data);
}

// Vulnerable - missing EIP-712 domain separator
function permit(address owner, address spender, uint256 value, bytes memory sig) external {
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value));
    // MISSING: EIP-712 domain separator with chainId
    address signer = ECDSA.recover(structHash, sig);
}
```

**Implementation Approach:**
1. Detect signature verification patterns:
   - `ECDSA.recover()` or `ecrecover()` calls
   - Hash generation for signature verification
2. Check hash includes chain context:
   - `block.chainid` used in hash calculation
   - EIP-712 domain separator with chainId
3. Verify fork protection:
   - Chain ID checked in contract state
   - Network identification in cross-chain operations
4. Validate signature domain separation:
   - Different signatures required per chain
   - Chain-specific domain separators

**EIP-712 Compliance:**
- Detect EIP-712 domain separator construction
- Verify chainId parameter inclusion
- Check for DOMAIN_SEPARATOR caching issues

**Test Contracts:**
- `tests/contracts/phase13/chainid/missing_chainid_sig.sol`
- `tests/contracts/phase13/chainid/no_domain_separator.sol`
- `tests/contracts/phase13/chainid/secure_eip712.sol`

**Expected False Positive Rate:** 12-15%

---

## Implementation Tasks

### Week 1: Foundation & Infrastructure

**Tasks:**
- [ ] T13.1: Create Phase 13 detector module structure in `crates/detectors/src/phase13/`
- [ ] T13.2: Implement ERC-7683 AST pattern matchers for Order/CrossChainOrder structs
- [ ] T13.3: Add bridge-specific contract detection heuristics
- [ ] T13.4: Extend dataflow analysis for cross-chain taint sources
- [ ] T13.5: Create test contract collection (20+ vulnerable examples)

### Week 2: Core Detectors (1-4)

**Tasks:**
- [ ] T13.6: Implement detector #1: Settlement Contract Validation
  - Nonce validation detection
  - Deadline check detection
  - Token handling validation
- [ ] T13.7: Implement detector #2: Cross-Chain Replay Attack
  - Chain ID validation detection
  - Order tracking analysis
  - Signature domain checking
- [ ] T13.8: Implement detector #3: Filler Front-Running
  - Slippage protection detection
  - MEV vulnerability analysis
  - Execution predictability checks
- [ ] T13.9: Implement detector #4: Oracle Dependency Risk
  - Oracle source counting
  - Staleness check detection
  - Failure handling analysis

### Week 3: Advanced Detectors (5-8)

**Tasks:**
- [ ] T13.10: Implement detector #5: Permit2 Integration
  - Approval pattern detection
  - Permit2 usage validation
  - Permission scoping checks
- [ ] T13.11: Implement detector #6: Bridge Token Minting
  - Access control verification
  - Supply cap enforcement
  - Proof validation checks
- [ ] T13.12: Implement detector #7: Bridge Message Verification
  - Signature validation analysis
  - Merkle proof checking
  - Quorum validation
- [ ] T13.13: Implement detector #8: Chain-ID Validation
  - Signature hash analysis
  - EIP-712 compliance
  - Fork protection validation

### Week 4: Testing & Validation

**Tasks:**
- [ ] T13.14: Create comprehensive test suite for all 8 detectors
- [ ] T13.15: Benchmark detector performance on large codebases
- [ ] T13.16: Measure and optimize false positive rates
- [ ] T13.17: Integration testing with existing detector pipeline
- [ ] T13.18: Documentation: detector guides and remediation examples
- [ ] T13.19: SmartBugs validation for cross-chain category

---

## Testing Strategy

### Unit Tests
**Location:** `crates/detectors/tests/phase13/`

Each detector requires:
- 3-5 vulnerable contract examples (must detect)
- 2-3 secure contract examples (must not flag)
- 1-2 edge case contracts (boundary testing)

### Integration Tests
**Location:** `tests/integration/phase13/`

- Full pipeline execution with Phase 13 detectors
- Cross-detector interaction validation
- Performance benchmarking

### Validation Benchmarks

**Target Metrics:**
- **Precision:** >85% (minimize false positives)
- **Recall:** >90% (catch real vulnerabilities)
- **Performance:** <100ms per contract for all 8 detectors
- **False Positive Rate:** <15% average across detectors

---

## Technical Challenges

### Challenge 1: ERC-7683 Contract Detection

**Problem:** Identifying contracts implementing ERC-7683 without explicit interface declaration

**Solution:**
1. Heuristic-based detection:
   - Function signature matching (fillOrder, initiateSettlement)
   - Struct parameter analysis (CrossChainOrder, OriginSettlement)
2. Import analysis:
   - Detect imports from ERC-7683 libraries
   - Identify ISettlementContract interface usage

### Challenge 2: Cross-Chain Context Tracking

**Problem:** Determining if a contract operates in cross-chain context

**Solution:**
1. Bridge-specific keywords:
   - "bridge", "relay", "crosschain", "xchain" in contract names
2. Cross-chain function patterns:
   - Functions with chainId parameters
   - Multi-chain address mappings
3. External call analysis:
   - Calls to known bridge contracts
   - Message passing infrastructure

### Challenge 3: Signature Verification Analysis

**Problem:** Validating proper signature construction and verification

**Solution:**
1. EIP-712 pattern detection:
   - DOMAIN_SEPARATOR construction
   - TypeHash definitions
2. Hash input tracking:
   - Dataflow from block.chainid to signature hash
   - Verify chainId inclusion in signed data
3. Recovery validation:
   - Track recovered address usage
   - Verify authorization checks

---

## Dependencies

### Existing Infrastructure
- ✅ AST pattern matching framework
- ✅ Dataflow analysis with taint tracking
- ✅ Control flow graph construction
- ✅ Symbol resolution and type checking
- ✅ Detector registry and execution pipeline

### New Requirements
- ❌ ERC-7683 specific AST patterns
- ❌ Bridge contract heuristics
- ❌ Cross-chain taint sources
- ❌ EIP-712 signature validation analysis
- ❌ Merkle proof verification detection

---

## Success Criteria

### Functional Requirements
- [ ] All 8 detectors implemented and integrated
- [ ] Unit tests achieving >95% code coverage
- [ ] Integration tests passing with full pipeline
- [ ] Documentation complete with examples

### Quality Metrics
- [ ] Overall F1-score >85% on cross-chain benchmark
- [ ] False positive rate <15% per detector
- [ ] Performance <100ms per contract (8 detectors)
- [ ] Zero false negatives on critical vulnerabilities (bridge minting, message verification)

### Production Readiness
- [ ] Validated on 50+ real-world bridge contracts
- [ ] Benchmarked against known exploits (Nomad, Wormhole patterns)
- [ ] No degradation to existing detector performance
- [ ] Successfully integrated into CI/CD pipeline

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| High false positive rate | Medium | High | Extensive testing with real contracts, tunable confidence thresholds |
| ERC-7683 adoption too early | Low | Medium | Generalize patterns to bridge security, not just ERC-7683 specific |
| Performance degradation | Low | High | Parallel execution, early termination, performance profiling |
| Complex signature validation | Medium | Medium | Reuse existing cryptographic analysis, focus on common patterns |

---

## Deliverables

1. **Source Code**
   - 8 detector implementations in `crates/detectors/src/phase13/`
   - Supporting infrastructure for cross-chain analysis
   - Test suite with 50+ test contracts

2. **Documentation**
   - Detector specifications (this document)
   - User guide for cross-chain security scanning
   - Remediation examples for each vulnerability type

3. **Validation**
   - Benchmark results showing accuracy metrics
   - Performance profiling data
   - Comparison with existing tools (Slither, Mythril)

4. **Integration**
   - Updated detector registry with Phase 13 detectors
   - CLI support for Phase 13 filtering
   - SARIF output with cross-chain CWE mappings

---

**Document Owner:** SolidityDefend Core Team
**Created:** 2025-10-07
**Status:** Implementation Ready
**Next Review:** End of Week 2 (progress checkpoint)
