# Additional Detector Proposals: Phases 20-25

**Generated:** 2025-10-07
**Extension to:** additional-detectors-proposal.md (Phases 13-19)
**New Detectors:** 28 additional detectors across 6 new phases
**Total Target:** 134 detectors (71 current + 35 previous + 28 new)

---

## Executive Summary

Based on additional research into 2025 threat landscape, this document proposes **28 more detectors** across emerging vulnerability areas:

- Layer 2 security (rollups, bridges)
- Advanced proxy patterns (Diamond, metamorphic contracts)
- Transaction batching vulnerabilities
- EIP-3074 delegated transactions
- Token-bound accounts (ERC-6551)
- MEV protection mechanisms

---

## Phase 20: Layer 2 & Rollup Security (5 detectors)

### Category: L2 Bridge & Rollup Security

**Rationale:** L2 solutions dominate with >60% of L2 TVL. Bridge security is the most critical concern, with unique data availability and withdrawal challenges.

#### 20.1 L2 Bridge Message Validation
- **ID:** `l2-bridge-message-validation`
- **Severity:** Critical
- **Description:** Validates proper L1↔L2 message passing and verification
- **Detects:**
  - Missing merkle proof validation for L2→L1 messages
  - Weak signature verification on cross-layer messages
  - Missing nonce/sequence validation
  - Inadequate finality checks before execution
  - Replay vulnerabilities across L1/L2

**Vulnerability Example:**
```solidity
// Vulnerable - no merkle proof validation
function relayMessageFromL2(bytes memory message) external {
    // MISSING: Merkle proof validation against L2 state root
    _executeMessage(message);
}

// Vulnerable - no finality check
function withdrawFromL2(uint256 amount, bytes memory proof) external {
    // MISSING: require(isFinalized(proof.blockNumber))
    _withdraw(msg.sender, amount);
}
```

#### 20.2 Optimistic Rollup Challenge Period Bypass
- **ID:** `optimistic-challenge-bypass`
- **Severity:** Critical
- **Description:** Detects premature withdrawals before challenge period completion
- **Detects:**
  - Missing 7-day challenge period enforcement
  - Inadequate withdrawal delay validation
  - Challenge period manipulation
  - Fraud proof bypass vulnerabilities
  - Missing dispute resolution checks

**Vulnerability Example:**
```solidity
// Vulnerable - no challenge period check
function finalizeWithdrawal(bytes32 withdrawalHash) external {
    Withdrawal memory w = withdrawals[withdrawalHash];
    // MISSING: require(block.timestamp >= w.timestamp + CHALLENGE_PERIOD)
    _transfer(w.recipient, w.amount);
}
```

#### 20.3 ZK Proof Verification Bypass
- **ID:** `zk-proof-bypass`
- **Severity:** Critical
- **Description:** Identifies weak or missing ZK proof verification
- **Detects:**
  - Missing proof verification before state updates
  - Weak proof validation logic
  - Proof replay vulnerabilities
  - Public input manipulation
  - Prover bypass vulnerabilities (Polygon zkEVM style)

**Vulnerability Example:**
```solidity
// Vulnerable - no actual proof verification
function submitBatch(bytes calldata batchData, bytes calldata proof) external {
    // MISSING: require(verifyZKProof(proof, publicInputs))
    _processBatch(batchData); // Accepts any data!
}

// Vulnerable - proof replay
mapping(bytes32 => bool) public usedProofs;
function verifyAndExecute(bytes memory proof) external {
    // MISSING: usedProofs check
    require(zkVerifier.verify(proof), "Invalid proof");
    _execute();
}
```

#### 20.4 L2 Data Availability Failure
- **ID:** `l2-data-availability`
- **Severity:** High
- **Description:** Detects missing data availability guarantees
- **Detects:**
  - Missing data publication to L1
  - Inadequate data commitment mechanisms
  - Sequencer censorship vulnerabilities
  - Missing force inclusion mechanisms
  - Emergency exit without data availability

**Vulnerability Example:**
```solidity
// Vulnerable - no data availability commitment
function commitBatch(bytes32 stateRoot) external onlySequencer {
    // MISSING: Data publication or commitment
    batches.push(stateRoot); // Only state root, no data!
}

// Vulnerable - no force inclusion mechanism
contract Rollup {
    // MISSING: Users cannot force transaction inclusion
    // Sequencer can censor indefinitely
}
```

#### 20.5 L2 Fee Manipulation
- **ID:** `l2-fee-manipulation`
- **Severity:** Medium
- **Description:** Detects L2 fee calculation vulnerabilities
- **Detects:**
  - L1 gas price oracle manipulation
  - Dynamic fee calculation without bounds
  - Missing fee cap enforcement
  - Front-runnable fee parameter updates
  - Unfair fee distribution to sequencers

---

## Phase 21: Diamond Proxy & Advanced Upgrades (5 detectors)

### Category: ERC-2535 Diamond Proxy Security

**Rationale:** Diamond proxies are increasingly used for complex upgradeable systems. Trail of Bits identified critical storage collision and selector collision risks.

#### 21.1 Diamond Function Selector Collision
- **ID:** `diamond-selector-collision`
- **Severity:** High
- **Description:** Detects function selector collisions in diamond facets
- **Detects:**
  - Duplicate function selectors across facets
  - Missing selector uniqueness validation during upgrades
  - Selector override without explicit removal
  - Hash collision in function signatures
  - Missing collision prevention in diamondCut

**Vulnerability Example:**
```solidity
// Vulnerable - no selector collision check
function diamondCut(FacetCut[] memory cuts) external {
    for (uint i = 0; i < cuts.length; i++) {
        // MISSING: Check if selector already exists
        for (uint j = 0; j < cuts[i].functionSelectors.length; j++) {
            bytes4 selector = cuts[i].functionSelectors[j];
            selectorToFacet[selector] = cuts[i].facetAddress;
        }
    }
}
```

#### 21.2 Diamond Storage Collision
- **ID:** `diamond-storage-collision`
- **Severity:** Critical
- **Description:** Identifies storage slot collision risks in diamond facets
- **Detects:**
  - Missing Diamond Storage pattern usage
  - Unsafe storage variable declarations in facets
  - Storage slot conflicts between facets
  - Missing namespace isolation (hash-based storage)
  - Direct storage access without collision protection

**Vulnerability Example:**
```solidity
// Vulnerable - direct storage in facet (collision risk)
contract FacetA {
    uint256 public value; // Slot 0 - COLLISION RISK
    mapping(address => uint256) public balances; // Slot 1
}

contract FacetB {
    address public owner; // Slot 0 - COLLIDES with FacetA.value!
}

// Secure - Diamond Storage pattern
library LibDiamondStorage {
    bytes32 constant STORAGE_POSITION = keccak256("diamond.storage.facetA");

    struct Storage {
        uint256 value;
        mapping(address => uint256) balances;
    }

    function diamondStorage() internal pure returns (Storage storage ds) {
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}
```

#### 21.3 Diamond Initialization Reentrancy
- **ID:** `diamond-init-reentrancy`
- **Severity:** High
- **Description:** Detects reentrancy during diamond initialization
- **Detects:**
  - External calls during diamondCut initialization
  - Missing reentrancy guards in init functions
  - State changes after external calls in init
  - Unprotected initialization delegatecall
  - Multiple initialization vulnerabilities

#### 21.4 Diamond Loupe Function Integrity
- **ID:** `diamond-loupe-integrity`
- **Severity:** Medium
- **Description:** Validates diamond introspection functions (ERC-2535 Loupe)
- **Detects:**
  - Missing or incorrect loupe functions
  - Inconsistent facet/selector mappings
  - Stale facet information
  - Missing supportsInterface implementation
  - Incorrect facet address reporting

#### 21.5 Diamond Delegatecall to Zero Address
- **ID:** `diamond-delegatecall-zero`
- **Severity:** Critical
- **Description:** Detects delegatecall to non-existent or destructed facets
- **Detects:**
  - Missing address validation before delegatecall
  - Delegatecall to address(0)
  - Calls to selfdestructed facets
  - Missing existence checks (EXTCODESIZE)
  - Silent failure handling

**Vulnerability Example:**
```solidity
// Vulnerable - no facet existence check
fallback() external payable {
    address facet = selectorToFacet[msg.sig];
    // MISSING: require(facet != address(0))
    // MISSING: require(facet.code.length > 0)
    assembly {
        calldatacopy(0, 0, calldatasize())
        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
```

---

## Phase 22: Metamorphic Contracts & CREATE2 (4 detectors)

### Category: Contract Immutability & CREATE2 Security

**Rationale:** Metamorphic contracts can change bytecode at the same address using CREATE2 + SELFDESTRUCT, breaking immutability assumptions. a16z released a detector tool in 2024.

#### 22.1 Metamorphic Contract Detection
- **ID:** `metamorphic-contract-risk`
- **Severity:** Critical
- **Description:** Identifies contracts that can change bytecode via CREATE2 + SELFDESTRUCT
- **Detects:**
  - Presence of SELFDESTRUCT in contract or delegatecall targets
  - Contract deployed via CREATE2 (check deployer code)
  - Factory contracts using CREATE2 + SELFDESTRUCT pattern
  - Rug pull risk from bytecode replacement
  - Missing immutability guarantees

**Detection Logic:**
```solidity
// Pattern 1: Contract has SELFDESTRUCT
function detect() {
    if (contractCode.contains(SELFDESTRUCT_OPCODE)) {
        // Check if deployed by factory using CREATE2
        if (deployerUsedCREATE2) {
            // VULNERABLE: Can be redeployed with different code
        }
    }
}

// Pattern 2: Contract uses DELEGATECALL to destructible contract
function operate() external {
    // VULNERABLE if 'implementation' has SELFDESTRUCT
    implementation.delegatecall(msg.data);
}
```

#### 22.2 CREATE2 Address Prediction Frontrunning
- **ID:** `create2-frontrunning`
- **Severity:** Medium
- **Description:** Detects predictable CREATE2 addresses vulnerable to frontrunning
- **Detects:**
  - Predictable salt values (sequential, timestamp-based)
  - Missing msg.sender in salt calculation
  - Public CREATE2 factories without access control
  - Deterministic address calculation exposure
  - Missing nonce or randomness in salt

**Vulnerability Example:**
```solidity
// Vulnerable - predictable salt
uint256 public nonce;
function deploy() external {
    bytes32 salt = keccak256(abi.encode(nonce++)); // Predictable!
    address predicted = predictAddress(salt);
    // Attacker can frontrun and deploy first
}

// Secure - include msg.sender
function deploySecure() external {
    bytes32 salt = keccak256(abi.encode(msg.sender, nonce++));
    // Attacker cannot predict/frontrun
}
```

#### 22.3 SELFDESTRUCT Recipient Manipulation
- **ID:** `selfdestruct-recipient-manipulation`
- **Severity:** High
- **Description:** Detects unsafe SELFDESTRUCT recipient handling
- **Detects:**
  - SELFDESTRUCT with user-controlled recipient
  - Missing access control on destruction
  - Fund theft via SELFDESTRUCT
  - Emergency destruction without safeguards
  - Ether force-send attack vectors

#### 22.4 EXTCODESIZE Zero Check Bypass
- **ID:** `extcodesize-zero-bypass`
- **Severity:** Medium
- **Description:** Identifies reliance on EXTCODESIZE for security checks
- **Detects:**
  - Using EXTCODESIZE == 0 to detect EOAs
  - Missing awareness that contracts can call during construction
  - Security checks bypassable via constructor calls
  - Assumptions broken by CREATE2 deployed contracts
  - Missing alternative validation methods

**Vulnerability Example:**
```solidity
// Vulnerable - can be bypassed from constructor
modifier onlyEOA() {
    require(msg.sender.code.length == 0, "Contracts not allowed");
    _;
}

// Attack: Call from constructor
contract Attacker {
    constructor(Target target) {
        // msg.sender.code.length == 0 during construction!
        target.restrictedFunction();
    }
}
```

---

## Phase 23: Multicall & Batch Transaction Security (4 detectors)

### Category: Batch Transaction Vulnerabilities

**Rationale:** Multicall patterns are widely used but have critical vulnerabilities around msg.value reuse and partial reverts. OpenZeppelin documented payable multicall exploits.

#### 23.1 Payable Multicall msg.value Reuse
- **ID:** `multicall-msgvalue-reuse`
- **Severity:** Critical
- **Description:** Detects msg.value reuse in multicall/batch functions
- **Detects:**
  - Payable multicall reading msg.value multiple times
  - Missing value accounting across batched calls
  - Delegatecall with msg.value persistence
  - Token swap/purchase functions in multicall
  - Missing nonETHReuse protection

**Vulnerability Example:**
```solidity
// Vulnerable - msg.value can be reused
function multicall(bytes[] calldata data) external payable {
    for (uint i = 0; i < data.length; i++) {
        // VULNERABLE: Each delegatecall sees same msg.value
        (bool success,) = address(this).delegatecall(data[i]);
        require(success);
    }
}

// Example exploit
function swap() external payable {
    // Expects msg.value in ETH, gives tokens
    uint256 tokens = msg.value * RATE; // msg.value reused per call!
    _mint(msg.sender, tokens);
}

// Attacker calls: multicall([swap(), swap(), swap()])
// Sends 1 ETH, gets 3 ETH worth of tokens!
```

#### 23.2 Batch Transaction Partial Revert
- **ID:** `batch-partial-revert`
- **Severity:** High
- **Description:** Identifies inconsistent state from partial batch reverts
- **Detects:**
  - Missing atomic execution guarantees
  - Try-catch blocks allowing partial success
  - State changes before failed batch items
  - Missing full revert on any failure
  - Inconsistent batch execution semantics

**Vulnerability Example:**
```solidity
// Vulnerable - partial success allowed
function batchTransfer(address[] memory recipients, uint256[] memory amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        try this.transfer(recipients[i], amounts[i]) {
            // Success - continues
        } catch {
            // Failure - continues anyway!
            emit TransferFailed(recipients[i], amounts[i]);
        }
    }
}
```

#### 23.3 Multicall Cross-Function Reentrancy
- **ID:** `multicall-cross-function-reentrancy`
- **Severity:** High
- **Description:** Detects reentrancy between different functions in multicall
- **Detects:**
  - External calls in multicall without reentrancy guards
  - State dependencies across batched functions
  - Missing nonReentrant on multicall itself
  - Cross-function state manipulation
  - Callback attacks during batch execution

#### 23.4 Batch Nonce Manipulation
- **ID:** `batch-nonce-manipulation`
- **Severity:** Medium
- **Description:** Identifies nonce handling issues in batched transactions
- **Detects:**
  - Missing nonce increment in batch operations
  - Nonce reuse across batch items
  - Out-of-order execution without nonce validation
  - Missing nonce gap detection
  - Replay vulnerabilities in batches

---

## Phase 24: EIP-3074 Delegated Transaction Security (5 detectors)

### Category: AUTH/AUTHCALL Security

**Rationale:** EIP-3074 enables powerful transaction delegation but introduces new attack surfaces. Invoker contract security is critical, and upgradeable invokers are explicitly forbidden.

#### 24.1 Upgradeable Invoker Detection
- **ID:** `eip3074-upgradeable-invoker`
- **Severity:** Critical
- **Description:** Detects forbidden upgradeable invoker contracts
- **Detects:**
  - Proxy pattern in invoker contracts
  - Delegatecall-based upgradeability
  - Owner-controlled implementation changes
  - Missing immutability guarantees
  - Redeployment to same address vulnerability

**Vulnerability Example:**
```solidity
// CRITICAL VULNERABILITY - upgradeable invoker
contract InvokerProxy {
    address public implementation;

    function upgrade(address newImpl) external onlyOwner {
        implementation = newImpl; // FORBIDDEN!
    }

    fallback() external {
        implementation.delegatecall(msg.data);
    }
}
// If users sign over this address, owner can steal funds by upgrading!
```

#### 24.2 AUTH Commit Hash Validation
- **ID:** `eip3074-commit-validation`
- **Severity:** High
- **Description:** Validates proper commit hash verification in invokers
- **Detects:**
  - Missing commit hash computation
  - Using user-provided commit without validation
  - Unsafe parameter binding
  - Missing hash verification before AUTHCALL
  - Malicious parameter substitution risk

**Vulnerability Example:**
```solidity
// Vulnerable - trusts user's commit hash
function invoke(address to, bytes memory data, bytes32 commit) external {
    // VULNERABLE: Should compute commit ourselves!
    require(AUTH(commit), "Invalid auth");
    AUTHCALL(to, data);
}

// Secure - compute commit ourselves
function invokeSecure(address to, bytes memory data) external {
    bytes32 commit = keccak256(abi.encode(to, data, nonce++));
    require(AUTH(commit), "Invalid auth");
    AUTHCALL(to, data);
}
```

#### 24.3 AUTHCALL Replay Protection
- **ID:** `eip3074-replay-protection`
- **Severity:** Critical
- **Description:** Detects missing replay protection in AUTH operations
- **Detects:**
  - Missing nonce mechanism
  - Reusable signatures
  - Missing expiration timestamps
  - Cross-invoker replay vulnerabilities
  - Inadequate signature uniqueness

#### 24.4 AUTHCALL Call Depth Griefing
- **ID:** `eip3074-call-depth-griefing`
- **Severity:** Medium
- **Description:** Identifies call depth manipulation vulnerabilities
- **Detects:**
  - Sponsor-controlled call depth before invoker
  - Missing depth validation
  - Griefing attack vectors against sponsees
  - Inadequate gas forwarding
  - Call stack manipulation

#### 24.5 EIP-3074 Invoker Access Control
- **ID:** `eip3074-invoker-access`
- **Severity:** High
- **Description:** Validates invoker function access controls
- **Detects:**
  - Missing authorization checks in invoker
  - Unrestricted AUTHCALL usage
  - Missing whitelist/blacklist mechanisms
  - Inadequate function selector validation
  - Unrestricted target address calls

---

## Phase 25: Token-Bound Accounts ERC-6551 (5 detectors)

### Category: NFT Wallet Security

**Rationale:** ERC-6551 creates wallets for every NFT, introducing new attack surface. Security audits are paramount due to increased complexity and autonomous TBA actions.

#### 25.1 TBA Ownership Verification
- **ID:** `erc6551-ownership-verification`
- **Severity:** Critical
- **Description:** Validates proper NFT ownership verification in TBA operations
- **Detects:**
  - Missing NFT ownership check before TBA actions
  - Stale ownership cache
  - Ownership verification bypass
  - Missing reentrancy protection during ownership checks
  - NFT transfer front-running vulnerabilities

**Vulnerability Example:**
```solidity
// Vulnerable - no ownership verification
contract TokenBoundAccount {
    function executeCall(address to, bytes memory data) external {
        // MISSING: Verify msg.sender owns the bound NFT
        to.call(data);
    }
}

// Secure - verify ownership
function executeCallSecure(address to, bytes memory data) external {
    (uint256 chainId, address tokenContract, uint256 tokenId) = token();
    require(IERC721(tokenContract).ownerOf(tokenId) == msg.sender, "Not owner");
    to.call(data);
}
```

#### 25.2 TBA Autonomous Action Limits
- **ID:** `erc6551-autonomous-limits`
- **Severity:** High
- **Description:** Detects overly permissive autonomous TBA capabilities
- **Detects:**
  - Unlimited autonomous spending/transfer authority
  - Missing approval mechanisms for high-value actions
  - No owner confirmation for critical operations
  - Unrestricted smart contract interactions
  - Missing action allowlist/restrictions

**Vulnerability Example:**
```solidity
// Vulnerable - TBA can autonomously transfer all assets
contract TBA {
    function transferAll(address recipient) external {
        // VULNERABLE: No owner confirmation required!
        // Anyone who can call this can drain the TBA
        uint256 balance = address(this).balance;
        payable(recipient).transfer(balance);
    }
}
```

#### 25.3 TBA Signature Validation
- **ID:** `erc6551-signature-validation`
- **Severity:** High
- **Description:** Validates EIP-1271 signature verification in TBAs
- **Detects:**
  - Missing isValidSignature implementation
  - Weak signature validation logic
  - Missing NFT owner verification in signature check
  - EIP-1271 bypass vulnerabilities
  - Signature replay across TBAs

#### 25.4 TBA Registry Validation
- **ID:** `erc6551-registry-validation`
- **Severity:** Medium
- **Description:** Validates proper ERC-6551 registry usage
- **Detects:**
  - Using non-standard registry addresses
  - Missing registry existence checks
  - Incorrect account() implementation
  - CREATE2 salt manipulation
  - Account address prediction errors

#### 25.5 TBA Asset Recovery Mechanism
- **ID:** `erc6551-asset-recovery`
- **Severity:** High
- **Description:** Identifies missing emergency asset recovery mechanisms
- **Detects:**
  - No recovery mechanism if NFT is burned/destroyed
  - Locked assets without recovery path
  - Missing emergency withdrawal functions
  - Inadequate guardian/timelock mechanisms
  - Permanent asset lock scenarios

**Vulnerability Example:**
```solidity
// Vulnerable - assets locked if NFT burned
contract TBA {
    function token() public view returns (uint256, address, uint256) {
        return (chainId, tokenContract, tokenId);
    }

    // MISSING: What happens if NFT is burned?
    // Assets locked forever with no recovery!
}

// Secure - emergency recovery
function emergencyRecover(address recipient) external {
    (, address tokenContract, uint256 tokenId) = token();

    // Allow recovery if NFT is burned (owner == address(0))
    try IERC721(tokenContract).ownerOf(tokenId) returns (address owner) {
        require(owner == msg.sender, "Not owner");
    } catch {
        // NFT doesn't exist (burned), allow anyone to recover after timelock
        require(block.timestamp >= deploymentTime + RECOVERY_DELAY, "Too early");
    }

    payable(recipient).transfer(address(this).balance);
}
```

---

## Implementation Summary

### Total Proposed Expansion

| Document | Phases | Detectors | Timeline |
|----------|--------|-----------|----------|
| Original (Phases 13-19) | 7 | 35 | 15-19 weeks |
| **This Document (Phases 20-25)** | **6** | **28** | **12-15 weeks** |
| **Combined Total** | **13** | **63** | **27-34 weeks** |

### Grand Total Detector Count

- **Current:** 71 detectors (59 functional, 12 stubs)
- **Phase 13-19 Additions:** +35 detectors
- **Phase 20-25 Additions:** +28 detectors
- **New Total:** **134 detectors**

---

## Priority Assessment

### Critical (Immediate - Q1 2025)
**Phases 13-15** from original proposal remain highest priority:
- Cross-chain security (ERC-7683, bridges)
- Account abstraction (ERC-4337)
- Restaking protocols

### High (Q2 2025)
**Phases 16-17** from original + **Phase 20-22** from this proposal:
- ERC-4626 vaults
- Token standards
- **L2 & Rollup security** (Phase 20)
- **Diamond proxy security** (Phase 21)
- **Metamorphic contracts** (Phase 22)

### Medium (Q2-Q3 2025)
**Phases 18-19** from original + **Phase 23-25** from this proposal:
- DeFi protocol-specific
- Code quality completion
- **Multicall security** (Phase 23)
- **EIP-3074** (Phase 24)
- **ERC-6551 TBAs** (Phase 25)

---

## Research References

### Layer 2 Security
- **Olympix Medium (2024)** - Layer 2 unique challenges in rollups and sidechains
- **StarkWare Medium** - Optimistic rollup security vs capital efficiency dilemma
- **Polygon zkEVM** - Critical prover bypass vulnerability disclosure
- **L2 Market Data (2025)** - >60% TVL in L2s, Optimistic dominating

### Diamond Proxy
- **Trail of Bits (2020)** - "Good idea, bad design" critique of ERC-2535
- **CertiK** - Diamond proxy best practices and security
- **OpenZeppelin Decision** - Not including ERC-2535 due to complexity concerns

### Metamorphic Contracts
- **a16z Crypto (2024)** - Metamorphic smart contract detector tool release
- **MixBytes** - Metamorphic contracts and EVM code immutability analysis
- **CREATE2 Security Analysis** - Address prediction and frontrunning risks

### Multicall Security
- **OpenZeppelin** - Payable multicall msg.value reuse vulnerability documentation
- **Solidity Docs** - Security considerations for delegatecall and msg.value
- **RareSkills** - Cross-function reentrancy in multicall patterns

### EIP-3074
- **EIP-3074 Specification** - Explicit security considerations and invoker requirements
- **Ethereum Magicians Forum** - Security discussion and upgrade concerns
- **MyCrypto Blog** - EIP-3074 quality of life improvements and risks

### ERC-6551
- **Tokenbound Documentation** - Security FAQ and implementation guides
- **GoldRush Guide** - Complete ERC-6551 security analysis
- **CleevioX** - Token-bound accounts attack surface analysis

---

## Testing Requirements

Each phase requires comprehensive test contracts:

**Phase 20 (L2 Security):** 40+ L2 bridge and rollup contracts
**Phase 21 (Diamond):** 25+ diamond proxy implementations
**Phase 22 (Metamorphic):** 20+ CREATE2/SELFDESTRUCT contracts
**Phase 23 (Multicall):** 30+ multicall/batch implementations
**Phase 24 (EIP-3074):** 15+ invoker contract examples
**Phase 25 (ERC-6551):** 20+ token-bound account contracts

**Total:** 150+ additional test contracts

---

## Success Criteria

### Coverage Metrics
- **134 total detectors** (71 + 35 + 28)
- **100% coverage** of OWASP Top 10 (2025)
- **100% coverage** of major 2025 standards (ERC-7683, ERC-4337, ERC-6551, EIP-3074)
- **Complete L2 security coverage** (Optimistic, ZK, bridges)
- **Advanced proxy patterns** (Diamond, metamorphic)

### Quality Metrics
- **F1-Score:** Maintain 85%+ overall
- **False Positive Rate:** <15% per detector
- **Performance:** <200ms per contract (all 134 detectors)
- **Zero False Negatives:** On known 2024-2025 exploits

---

**Document Owner:** SolidityDefend Security Research Team
**Created:** 2025-10-07
**Status:** Research Complete - Pending Approval
**Related:** additional-detectors-proposal.md (Phases 13-19)
