# EIP-3074 AUTH/AUTHCALL Detectors

**Detector IDs:** `eip3074-*`
**Total Detectors:** 5
**Added in:** v1.9.1 (2026-01-15)
**Categories:** EIP Security, Account Abstraction

---

## Overview

EIP-3074 introduces two new EVM opcodes - AUTH and AUTHCALL - that enable sponsored transactions and account abstraction at the protocol level. AUTH validates a signature over a commit hash, setting the authorized account context. AUTHCALL then executes calls on behalf of the authorized account.

While powerful, EIP-3074 introduces significant security considerations:

- **Trust Model**: Users sign messages trusting specific invoker contract code
- **Replay Risks**: Signatures can be replayed without proper protection
- **Authorization Scope**: Broad permissions can lead to unauthorized actions
- **Call Depth Limits**: AUTHCALL inherits the 1024 call depth limit

These detectors identify common vulnerabilities in EIP-3074 invoker implementations.

---

## Detector Summary

| Detector ID | Severity | Description | CWE |
|-------------|----------|-------------|-----|
| `eip3074-upgradeable-invoker` | Critical | Forbidden upgradeable invoker contracts | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| `eip3074-commit-validation` | High | Improper commit hash verification | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) |
| `eip3074-replay-attack` | High | Missing replay protection in AUTH | [CWE-294](https://cwe.mitre.org/data/definitions/294.html) |
| `eip3074-invoker-authorization` | High | Missing invoker authorization checks | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| `eip3074-call-depth-griefing` | Medium | Call depth manipulation attacks | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |

---

## Detailed Detector Documentation

### eip3074-upgradeable-invoker

**Severity:** Critical
**CWE:** [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

#### Description

EIP-3074 explicitly forbids upgradeable invoker contracts. When users sign AUTH messages, they are trusting the specific invoker contract code at the time of signing. If the invoker is upgradeable, the contract owner could modify the code to perform malicious actions using previously signed authorizations.

This is a fundamental violation of the EIP-3074 trust model and can lead to complete loss of user funds.

#### Detection Criteria

- Contract uses AUTH opcode (assembly `auth()` instruction)
- Contract inherits from upgradeable patterns:
  - `UUPSUpgradeable`
  - `TransparentUpgradeableProxy`
  - `Initializable` with upgrade functions
  - Diamond proxy patterns
- Contract has `upgradeTo` or similar upgrade functions

#### Vulnerable Code Pattern

```solidity
// VULNERABLE: Upgradeable invoker breaks user trust
contract VulnerableInvoker is UUPSUpgradeable, Initializable {
    function initialize() external initializer {
        // initialization
    }

    function executeAuth(
        address target,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 commit = keccak256(abi.encode(target, data));
        assembly {
            // User signed trusting v1 code
            // After upgrade, v2 code runs with their signature
            let authorized := auth(target, commit)
            if iszero(authorized) { revert(0, 0) }
        }
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

#### Secure Code Pattern

```solidity
// SECURE: Non-upgradeable invoker preserves trust model
contract SecureInvoker {
    // No inheritance from upgradeable contracts
    // No upgrade functions
    // Contract code is immutable after deployment

    function executeAuth(
        address target,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 commit = keccak256(abi.encode(target, data));
        assembly {
            let authorized := auth(target, commit)
            if iszero(authorized) { revert(0, 0) }
        }
    }
}
```

#### Remediation

1. **Never make invoker contracts upgradeable** - This is a hard requirement from the EIP
2. Deploy new invoker versions as separate contracts
3. Users must explicitly migrate to new invoker versions
4. Consider using immutable deployment patterns (CREATE2 with deterministic addresses)

---

### eip3074-commit-validation

**Severity:** High
**CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

#### Description

The AUTH opcode validates a signature over a commit hash. If the commit hash does not include all relevant transaction parameters, attackers can manipulate unsigned fields to redirect funds or change the transaction behavior.

#### Detection Criteria

- AUTH commit hash construction is missing required fields:
  - `to` (target address)
  - `value` (ETH amount)
  - `data` (calldata)
  - `nonce` (replay protection)
  - `deadline` (time limit)
  - `chainId` (cross-chain replay protection)
  - `invoker` (invoker address binding)

#### Vulnerable Code Pattern

```solidity
// VULNERABLE: Incomplete commit - missing critical parameters
contract IncompleteCommitInvoker {
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Missing: nonce, deadline, chainId, invoker address
        bytes32 commit = keccak256(abi.encode(to));

        assembly {
            let authorized := auth(to, commit)
            // Attacker can change value, data without invalidating signature
        }
    }
}
```

#### Secure Code Pattern

```solidity
// SECURE: Complete commit hash with all parameters
contract SecureCommitInvoker {
    mapping(address => uint256) public nonces;

    bytes32 public constant DOMAIN_SEPARATOR = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256("SecureInvoker"),
        keccak256("1"),
        block.chainid,
        address(this)
    ));

    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Expired");
        require(nonce == nonces[msg.sender], "Invalid nonce");

        // Complete commit with all parameters
        bytes32 commit = keccak256(abi.encode(
            to,           // Target address
            value,        // ETH value
            keccak256(data), // Calldata hash
            nonce,        // Replay protection
            deadline,     // Time limit
            block.chainid, // Chain replay protection
            address(this) // Invoker binding
        ));

        nonces[msg.sender]++;

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }
            let success := authcall(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
```

#### Remediation

1. Always include all seven required parameters in the commit hash
2. Use EIP-712 structured data for better UX and verification
3. Hash calldata to keep commit size manageable
4. Validate all parameters before AUTH execution

---

### eip3074-replay-attack

**Severity:** High
**CWE:** [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

#### Description

AUTH signatures without proper replay protection can be reused multiple times. This allows attackers to replay valid signatures to execute unauthorized transactions repeatedly.

#### Detection Criteria

- AUTH usage without nonce tracking
- AUTH usage without deadline validation
- AUTH usage without chainId in commit
- Missing signature invalidation after use

#### Vulnerable Code Pattern

```solidity
// VULNERABLE: No replay protection - signatures can be reused forever
contract ReplayableInvoker {
    function invoke(
        address to,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 commit = keccak256(abi.encode(to, data));

        assembly {
            // This signature can be replayed indefinitely
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }
            authcall(gas(), to, 0, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
```

#### Secure Code Pattern

```solidity
// SECURE: Comprehensive replay protection
contract ReplayProtectedInvoker {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedSignatures;

    function invoke(
        address to,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Time-based protection
        require(block.timestamp <= deadline, "Signature expired");

        // Nonce-based protection
        require(nonce == nonces[msg.sender], "Invalid nonce");
        nonces[msg.sender]++;

        // Construct commit with replay protection
        bytes32 commit = keccak256(abi.encode(
            to,
            data,
            nonce,
            deadline,
            block.chainid,
            address(this)
        ));

        // Signature uniqueness check
        bytes32 sigHash = keccak256(abi.encodePacked(v, r, s));
        require(!usedSignatures[sigHash], "Signature already used");
        usedSignatures[sigHash] = true;

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }
            authcall(gas(), to, 0, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
```

#### Remediation

1. **Always use nonces** - Incrementing nonces prevent signature reuse
2. **Add deadlines** - Time-limited signatures reduce exposure window
3. **Include chainId** - Prevents cross-chain replay attacks
4. **Consider signature tracking** - Additional layer of protection

---

### eip3074-invoker-authorization

**Severity:** High
**CWE:** [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

#### Description

Invoker contracts that allow unrestricted targets or function calls can be exploited to perform actions the user did not intend. Without proper authorization checks, a malicious actor could use the invoker to call arbitrary contracts.

#### Detection Criteria

- AUTHCALL without target address validation
- AUTHCALL without function selector filtering
- Missing caller authorization
- Unrestricted `to` parameter

#### Vulnerable Code Pattern

```solidity
// VULNERABLE: No restrictions on target or function
contract UnrestrictedInvoker {
    function execute(
        address to,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 commit = keccak256(abi.encode(to, data));

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }
            // Anyone can call any contract with any function
            authcall(gas(), to, 0, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
```

#### Secure Code Pattern

```solidity
// SECURE: Restricted targets and functions
contract RestrictedInvoker {
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;
    mapping(address => bool) public authorizedCallers;

    modifier onlyAuthorized() {
        require(authorizedCallers[msg.sender], "Unauthorized caller");
        _;
    }

    function execute(
        address to,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external onlyAuthorized {
        // Validate target
        require(allowedTargets[to], "Target not allowed");

        // Validate function selector
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            require(allowedSelectors[selector], "Function not allowed");
        }

        bytes32 commit = keccak256(abi.encode(to, data, block.chainid, address(this)));

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }
            let success := authcall(gas(), to, 0, add(data, 0x20), mload(data), 0, 0)
            if iszero(success) { revert(0, 0) }
        }
    }

    function addAllowedTarget(address target) external onlyOwner {
        allowedTargets[target] = true;
    }

    function addAllowedSelector(bytes4 selector) external onlyOwner {
        allowedSelectors[selector] = true;
    }
}
```

#### Remediation

1. **Whitelist allowed targets** - Only permit calls to known, trusted contracts
2. **Filter function selectors** - Restrict which functions can be called
3. **Implement caller authorization** - Control who can use the invoker
4. **Consider role-based access** - Different users may have different permissions

---

### eip3074-call-depth-griefing

**Severity:** Medium
**CWE:** [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

#### Description

AUTHCALL is subject to the EVM's 1024 call depth limit. An attacker can pre-populate the call stack to near the limit before invoking the invoker contract, causing AUTHCALL to fail even with sufficient gas.

#### Detection Criteria

- AUTHCALL without call depth checks
- Missing gas stipend validation
- No minimum gas requirements
- Reliance on AUTHCALL success without depth consideration

#### Vulnerable Code Pattern

```solidity
// VULNERABLE: No call depth protection
contract DepthVulnerableInvoker {
    function execute(
        address to,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 commit = keccak256(abi.encode(to, data));

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }

            // May fail at high call depth even with enough gas
            let success := authcall(gas(), to, 0, add(data, 0x20), mload(data), 0, 0)
            if iszero(success) { revert(0, 0) }
        }
    }
}
```

#### Secure Code Pattern

```solidity
// SECURE: Call depth and gas protection
contract DepthProtectedInvoker {
    uint256 public constant MIN_GAS_REQUIRED = 100000;
    uint256 public constant GAS_BUFFER = 10000;

    function execute(
        address to,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Ensure sufficient gas for execution
        require(gasleft() >= MIN_GAS_REQUIRED, "Insufficient gas");

        bytes32 commit = keccak256(abi.encode(to, data));

        assembly {
            let authorized := auth(to, commit)
            if iszero(authorized) { revert(0, 0) }

            // Reserve gas buffer for post-call operations
            let gasToUse := sub(gas(), GAS_BUFFER)

            let success := authcall(gasToUse, to, 0, add(data, 0x20), mload(data), 0, 0)

            // Handle failure gracefully
            if iszero(success) {
                // Return failure data
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    // Allow users to check if execution is likely to succeed
    function estimateGasRequired(
        address to,
        bytes calldata data
    ) external view returns (uint256) {
        // Estimate based on target and data
        return MIN_GAS_REQUIRED + data.length * 16;
    }
}
```

#### Remediation

1. **Check available gas** - Require minimum gas before AUTHCALL
2. **Reserve gas buffer** - Ensure gas for post-call operations
3. **Handle failures gracefully** - Propagate error data on failure
4. **Consider gas estimation** - Help users provide adequate gas

---

## Testing

All EIP-3074 detectors have been validated with test contracts:

| Detector | Test Findings | Test Contracts |
|----------|---------------|----------------|
| `eip3074-upgradeable-invoker` | 2 | 1 |
| `eip3074-commit-validation` | 2 | 2 |
| `eip3074-replay-attack` | 9 | 3 |
| `eip3074-invoker-authorization` | 8 | 3 |
| `eip3074-call-depth-griefing` | 8 | 2 |

**Total:** 29 findings across test contracts

---

## Best Practices

### Invoker Contract Design

1. **Immutability** - Never make invoker contracts upgradeable
2. **Minimal Scope** - Limit what the invoker can do
3. **Complete Commits** - Include all parameters in commit hash
4. **Comprehensive Replay Protection** - Use nonces, deadlines, and chainId
5. **Authorization Layers** - Restrict targets, functions, and callers
6. **Gas Management** - Handle call depth and gas limits

### User Protection

1. **Signature Review** - Always show users what they are signing
2. **Deadline Enforcement** - Use short expiration times
3. **Revocation** - Allow users to invalidate pending signatures
4. **Audit Trail** - Log all invoker executions

---

## References

### EIP Specification
- [EIP-3074: AUTH and AUTHCALL opcodes](https://eips.ethereum.org/EIPS/eip-3074)

### Security Resources
- [EIP-3074 Security Considerations](https://eips.ethereum.org/EIPS/eip-3074#security-considerations)
- [Account Abstraction Security Best Practices](https://ethereum.org/en/developers/docs/accounts/)

### Related Detectors
- `eip7702-*` - EIP-7702 account delegation detectors
- `signature-malleability` - Signature manipulation vulnerabilities
- `cross-chain-replay` - Cross-chain replay attack detection

---

**Last Updated:** 2026-01-26
**Detector Version:** 1.0.0
**Source:** `crates/detectors/src/eip3074/`
