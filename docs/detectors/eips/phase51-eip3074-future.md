# Phase 51: EIP-3074 & Future Standards Detectors

**Added in:** v1.9.1 (2026-01-15)
**Total Detectors:** 8
**Categories:** EIP Security, Cross-Chain, Upgradeable

---

## Overview

Phase 51 adds 8 detectors for emerging Ethereum standards:
- **EIP-3074** (AUTH/AUTHCALL) - Account abstraction via sponsored transactions
- **EIP-4844** (Proto-Danksharding) - Blob transactions for L2 data availability
- **EIP-6780** (Selfdestruct Changes) - Post-Cancun selfdestruct behavior
- **PUSH0** (EIP-3855) - Cross-chain bytecode compatibility

---

## Detector Summary

| Detector ID | Severity | Description | CWE |
|-------------|----------|-------------|-----|
| `eip3074-upgradeable-invoker` | Critical | Forbidden upgradeable invoker contracts | CWE-284 |
| `eip3074-commit-validation` | High | Improper commit hash verification | CWE-345 |
| `eip3074-replay-attack` | High | Missing replay protection in AUTH | CWE-294 |
| `eip3074-invoker-authorization` | High | Missing invoker authorization checks | CWE-862 |
| `eip4844-blob-validation` | High | Blob transaction validation issues | CWE-20 |
| `eip3074-call-depth-griefing` | Medium | Call depth manipulation attacks | CWE-400 |
| `eip6780-selfdestruct-change` | Medium | Post-Cancun selfdestruct behavior | CWE-670 |
| `push0-stack-assumption` | Low | PUSH0 cross-chain compatibility | CWE-682 |

---

## EIP-3074 Detectors

### eip3074-upgradeable-invoker (Critical)

**Description:** EIP-3074 explicitly forbids upgradeable invoker contracts. Users sign AUTH messages trusting specific invoker code - upgradeable invokers break this trust model.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Upgradeable invoker breaks trust model
contract VulnerableInvoker is UUPSUpgradeable {
    function executeAuth(address target, bytes calldata data) external {
        assembly {
            let authorized := auth(target, commit)
            // User trusted v1 code, now running v2
        }
    }
}
```

**Remediation:**
```solidity
// SECURE: Non-upgradeable invoker
contract SecureInvoker {
    // immutable = cannot be upgraded
    function executeAuth(address target, bytes calldata data) external {
        assembly {
            let authorized := auth(target, commit)
        }
    }
}
```

---

### eip3074-commit-validation (High)

**Description:** AUTH commit hash must include all transaction parameters to prevent manipulation.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Incomplete commit - missing nonce, deadline, chainId
bytes32 commit = keccak256(abi.encode(to));
```

**Required Parameters:**
- `to` - Target address
- `value` - ETH value
- `data` - Calldata
- `nonce` - Replay protection
- `deadline` - Time limit
- `chainId` - Chain replay protection
- `invoker` - Invoker address

**Secure Pattern:**
```solidity
bytes32 commit = keccak256(abi.encode(
    to, value, data, nonce, deadline, block.chainid, address(this)
));
```

---

### eip3074-replay-attack (High)

**Description:** AUTH signatures can be replayed without proper protection mechanisms.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No nonce, no deadline, no chainId
function invoke(address to, bytes calldata data, bytes calldata sig) external {
    assembly { auth(to, commit) }  // Can be replayed forever
}
```

**Secure Pattern:**
```solidity
mapping(address => uint256) public nonces;

function invoke(
    address to,
    bytes calldata data,
    uint256 nonce,
    uint256 deadline,
    bytes calldata sig
) external {
    require(block.timestamp <= deadline, "Expired");
    require(nonce == nonces[msg.sender]++, "Invalid nonce");

    bytes32 commit = keccak256(abi.encode(
        to, data, nonce, deadline, block.chainid
    ));
    assembly { auth(to, commit) }
}
```

---

### eip3074-invoker-authorization (High)

**Description:** Missing authorization checks on who can use the invoker and what targets/functions are allowed.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Anyone can call, any target
function execute(address to, bytes calldata data) external {
    assembly { authcall(gas(), to, 0, ...) }
}
```

**Secure Pattern:**
```solidity
mapping(address => bool) public allowedTargets;
mapping(bytes4 => bool) public allowedSelectors;

function execute(address to, bytes calldata data) external onlyAuthorized {
    require(allowedTargets[to], "Invalid target");
    require(allowedSelectors[bytes4(data)], "Invalid function");
    assembly { authcall(gas(), to, 0, ...) }
}
```

---

### eip3074-call-depth-griefing (Medium)

**Description:** AUTHCALL can fail if invoked at high call depth due to EVM 1024 call depth limit.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No depth check
function execute(address to, bytes calldata data) external {
    assembly {
        let success := authcall(gas(), to, 0, ...)
        if iszero(success) { revert(0, 0) }  // May fail at depth 1024
    }
}
```

**Secure Pattern:**
```solidity
function execute(address to, bytes calldata data) external {
    require(gasleft() > 100000, "Insufficient gas/depth");
    assembly {
        let success := authcall(sub(gas(), 10000), to, 0, ...)
    }
}
```

---

## EIP-4844 Detector

### eip4844-blob-validation (High)

**Description:** Blob transactions require proper validation of versioned hashes and KZG proofs.

**Vulnerable Patterns:**
```solidity
// VULNERABLE: No version prefix validation
function processBlobData(bytes32 versionedHash) external {
    // Missing: require(versionedHash >> 248 == 0x01)
    emit BlobProcessed(versionedHash);
}

// VULNERABLE: BLOBHASH without validation
function getBlobHash(uint256 index) external view returns (bytes32) {
    bytes32 hash;
    assembly { hash := blobhash(index) }
    return hash;  // Should validate version
}
```

**Secure Pattern:**
```solidity
address constant KZG_PRECOMPILE = address(0x0a);

function processBlobData(bytes32 versionedHash) external {
    // Validate version prefix (0x01 for KZG)
    require(uint8(versionedHash[0]) == 0x01, "Invalid version");

    // Verify via point evaluation precompile
    (bool success, ) = KZG_PRECOMPILE.staticcall(
        abi.encode(versionedHash, z, y, commitment, proof)
    );
    require(success, "KZG verification failed");
}
```

---

## EIP-6780 Detector

### eip6780-selfdestruct-change (Medium)

**Description:** Post-Cancun (Dencun upgrade, March 2024), SELFDESTRUCT only deletes code if called in the same transaction as contract creation. ETH transfer still works.

**Affected Patterns:**

1. **Metamorphic Contracts (Broken)**
```solidity
// VULNERABLE: CREATE2 + selfdestruct no longer works
contract MetamorphicFactory {
    function destroyAndRedeploy(bytes32 salt) external {
        existing.selfdestruct();  // Code NOT deleted
        create2(..., salt);       // FAILS - address occupied
    }
}
```

2. **Emergency Destroy (Changed Behavior)**
```solidity
// CHANGED: Code remains after selfdestruct
function emergencyDestroy() external onlyOwner {
    selfdestruct(payable(owner));
    // ETH sent, but code still exists
}
```

3. **extcodesize Checks (May Fail)**
```solidity
// VULNERABLE: extcodesize > 0 after selfdestruct
function isDestroyed() external view returns (bool) {
    return address(target).code.length == 0;  // Will be false
}
```

**Secure Alternatives:**
```solidity
// Use pausable pattern instead of destroy
bool public active = true;

function deactivate() external onlyOwner {
    active = false;
}

function isActive() external view returns (bool) {
    return active;  // Use state flag, not extcodesize
}
```

---

## PUSH0 Detector

### push0-stack-assumption (Low)

**Description:** Solidity >=0.8.20 generates PUSH0 opcode (EIP-3855), which is only available on Shanghai+ chains. Pre-Shanghai chains will reject this bytecode.

**Affected Scenarios:**
- Cross-chain deployments to pre-Shanghai chains (BSC, some L2s)
- Gas calculations assuming PUSH1 0 cost (3 gas) vs PUSH0 (2 gas)

**Detection Criteria:**
- Contract uses `pragma solidity >=0.8.20`
- AND has cross-chain indicators (block.chainid, LayerZero, Axelar, etc.)

**Vulnerable Pattern:**
```solidity
pragma solidity ^0.8.20;  // Generates PUSH0

contract CrossChainBridge {
    function send(uint256 destChain) external {
        // May fail on pre-Shanghai chains
    }
}
```

**Secure Pattern:**
```solidity
// Option 1: Use older Solidity
pragma solidity ^0.8.19;

// Option 2: Specify EVM version in foundry.toml
// [profile.default]
// evm_version = "paris"
```

---

## Testing

All Phase 51 detectors have been comprehensively tested:

| Detector | Test Findings | Test Contracts |
|----------|---------------|----------------|
| eip6780-selfdestruct-change | 20 | 5 |
| push0-stack-assumption | 15 | 4 |
| eip3074-replay-attack | 9 | 3 |
| eip3074-invoker-authorization | 8 | 3 |
| eip3074-call-depth-griefing | 8 | 2 |
| eip4844-blob-validation | 5 | 3 |
| eip3074-upgradeable-invoker | 2 | 1 |
| eip3074-commit-validation | 2 | 2 |

**Total:** 69 findings across test contracts

---

## References

- [EIP-3074: AUTH and AUTHCALL opcodes](https://eips.ethereum.org/EIPS/eip-3074)
- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)
- [EIP-6780: SELFDESTRUCT only in same transaction](https://eips.ethereum.org/EIPS/eip-6780)
- [EIP-3855: PUSH0 instruction](https://eips.ethereum.org/EIPS/eip-3855)
