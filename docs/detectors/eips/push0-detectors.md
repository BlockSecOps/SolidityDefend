# PUSH0 Cross-Chain Compatibility Detector

**Detector ID:** `push0-stack-assumption`
**Total Detectors:** 1
**Added in:** v1.9.1 (2026-01-15)
**Categories:** EIP Security, Cross-Chain

---

## Overview

EIP-3855 introduced the PUSH0 opcode in the Shanghai upgrade (April 2023), which pushes the constant value 0 onto the stack. This opcode is more gas-efficient than the previous pattern of using PUSH1 0x00 (3 gas vs 2 gas).

Starting with Solidity 0.8.20, the compiler generates PUSH0 by default when targeting the Shanghai EVM version or later. This creates a cross-chain compatibility issue:

**Problem:** Contracts compiled with Solidity >= 0.8.20 (default EVM target) produce bytecode containing PUSH0, which will fail to deploy or execute on chains that have not yet implemented the Shanghai upgrade.

**Affected Chains (as of 2024):**
- Some Layer 2 rollups with older EVM versions
- Alternative EVM-compatible chains (BSC, older forks)
- Private/enterprise Ethereum networks
- Testnets running pre-Shanghai software

---

## Detector Summary

| Detector ID | Severity | Description | CWE |
|-------------|----------|-------------|-----|
| `push0-stack-assumption` | Low | PUSH0 cross-chain bytecode compatibility | [CWE-682](https://cwe.mitre.org/data/definitions/682.html) |

---

## Detailed Detector Documentation

### push0-stack-assumption

**Severity:** Low
**CWE:** [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)

#### Description

This detector identifies contracts that may have cross-chain deployment issues due to PUSH0 opcode usage. It flags:

1. **Solidity version >= 0.8.20** combined with cross-chain patterns
2. **Missing EVM version specification** in compiler configuration
3. **Cross-chain bridge or messaging contracts** using modern Solidity

The severity is Low because:
- The contract works correctly on Shanghai+ chains
- The issue only manifests on specific target chains
- It is a deployment/configuration issue rather than a logic vulnerability

#### Detection Criteria

- `pragma solidity ^0.8.20` or higher version specification
- Combined with indicators of cross-chain intent:
  - `block.chainid` usage or comparisons
  - LayerZero, Axelar, Wormhole, or similar bridge integrations
  - `ILayerZeroEndpoint`, `IAxelarGateway`, etc. interfaces
  - Function names like `crossChain*`, `bridge*`, `relay*`
  - Multi-chain deployment scripts or comments

#### Vulnerable Code Patterns

**Pattern 1: Cross-Chain Contract with Modern Solidity**

```solidity
// POTENTIALLY INCOMPATIBLE: Solidity 0.8.20+ generates PUSH0
pragma solidity ^0.8.20;

import "@layerzerolabs/contracts/interfaces/ILayerZeroEndpoint.sol";

contract CrossChainBridge {
    ILayerZeroEndpoint public endpoint;
    mapping(uint16 => bytes) public trustedRemotes;

    function sendCrossChain(
        uint16 destChainId,
        address to,
        uint256 amount
    ) external payable {
        // This contract may fail to deploy on pre-Shanghai chains
        bytes memory payload = abi.encode(to, amount);
        endpoint.send{value: msg.value}(
            destChainId,
            trustedRemotes[destChainId],
            payload,
            payable(msg.sender),
            address(0),
            bytes("")
        );
    }
}
```

**Pattern 2: Multi-Chain Token**

```solidity
// POTENTIALLY INCOMPATIBLE: Uses chainId for multi-chain logic
pragma solidity ^0.8.21;

contract MultiChainToken {
    string public name = "MultiChain Token";
    string public symbol = "MCT";

    mapping(address => uint256) public balanceOf;

    // Chain-specific configuration
    mapping(uint256 => address) public chainBridges;

    function bridgeOut(uint256 destChain, uint256 amount) external {
        require(chainBridges[destChain] != address(0), "Chain not supported");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;

        // Will compile to bytecode with PUSH0
        // May not deploy on all target chains
        emit BridgeInitiated(block.chainid, destChain, msg.sender, amount);
    }

    event BridgeInitiated(
        uint256 sourceChain,
        uint256 destChain,
        address sender,
        uint256 amount
    );
}
```

**Pattern 3: Axelar Integration**

```solidity
// POTENTIALLY INCOMPATIBLE: Axelar gateway on multiple chains
pragma solidity ^0.8.22;

import "@axelar-network/contracts/interfaces/IAxelarGateway.sol";
import "@axelar-network/contracts/interfaces/IAxelarExecutable.sol";

contract AxelarBridge is IAxelarExecutable {
    constructor(address gateway_) IAxelarExecutable(gateway_) {}

    function sendToChain(
        string calldata destChain,
        string calldata destAddress,
        bytes calldata payload
    ) external payable {
        // Bytecode contains PUSH0
        // Deployment may fail on chains without Shanghai
        gateway.callContract(destChain, destAddress, payload);
    }
}
```

#### Secure Code Patterns

**Pattern 1: Use Older Solidity Version**

```solidity
// COMPATIBLE: Solidity 0.8.19 does not generate PUSH0
pragma solidity ^0.8.19;

import "@layerzerolabs/contracts/interfaces/ILayerZeroEndpoint.sol";

contract CompatibleBridge {
    ILayerZeroEndpoint public endpoint;
    mapping(uint16 => bytes) public trustedRemotes;

    function sendCrossChain(
        uint16 destChainId,
        address to,
        uint256 amount
    ) external payable {
        // Bytecode uses PUSH1 0x00 instead of PUSH0
        // Compatible with all EVM chains
        bytes memory payload = abi.encode(to, amount);
        endpoint.send{value: msg.value}(
            destChainId,
            trustedRemotes[destChainId],
            payload,
            payable(msg.sender),
            address(0),
            bytes("")
        );
    }
}
```

**Pattern 2: Specify EVM Version in Foundry**

```solidity
// Contract can use modern Solidity features
pragma solidity ^0.8.24;

// Configure in foundry.toml to target Paris EVM (pre-Shanghai)
```

```toml
# foundry.toml
[profile.default]
solc_version = "0.8.24"
evm_version = "paris"  # Pre-Shanghai, no PUSH0

[profile.mainnet]
evm_version = "shanghai"  # Full Shanghai support

[profile.legacy]
evm_version = "paris"  # For chains without Shanghai
```

**Pattern 3: Specify EVM Version in Hardhat**

```solidity
pragma solidity ^0.8.24;
// Use hardhat.config.js to control EVM version
```

```javascript
// hardhat.config.js
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      evmVersion: "paris", // No PUSH0 in bytecode
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  // For different chains
  networks: {
    mainnet: {
      // Uses Shanghai by default
    },
    legacyChain: {
      // May need paris EVM version
    }
  }
};
```

**Pattern 4: Conditional Compilation**

```solidity
// COMPATIBLE: Different contracts for different chains
pragma solidity ^0.8.19;  // Base version for legacy chains

// For Shanghai+ chains, compile with:
// solc --evm-version shanghai ...

contract UniversalBridge {
    // Core logic works on all chains
    function bridge(address to, uint256 amount) external {
        // Implementation
    }
}
```

---

## Remediation Guidelines

### Option 1: Use Solidity < 0.8.20

The simplest solution for maximum compatibility:

```solidity
// Maximum compatibility - no PUSH0
pragma solidity ^0.8.19;
```

### Option 2: Specify EVM Version

Keep modern Solidity but target older EVM:

**Foundry:**
```toml
[profile.default]
evm_version = "paris"
```

**Hardhat:**
```javascript
solidity: {
  settings: {
    evmVersion: "paris"
  }
}
```

**Remix:**
Select "paris" in compiler settings.

**solc CLI:**
```bash
solc --evm-version paris Contract.sol
```

### Option 3: Chain-Specific Builds

Maintain separate builds for different chain targets:

```bash
# Shanghai+ chains (Ethereum mainnet, etc.)
forge build --evm-version shanghai

# Legacy chains (some L2s, BSC, etc.)
forge build --evm-version paris --out out-legacy
```

### Option 4: Document Chain Requirements

If PUSH0 is intentional, document the chain requirements:

```solidity
pragma solidity ^0.8.24;

/**
 * @title ModernBridge
 * @notice This contract requires Shanghai EVM (PUSH0 opcode)
 * @dev Supported chains: Ethereum mainnet, Arbitrum One, Optimism
 * @dev NOT supported: BSC (as of 2024), older L2 chains
 */
contract ModernBridge {
    // ...
}
```

---

## EVM Version Reference

| EVM Version | PUSH0 Support | Notes |
|-------------|---------------|-------|
| `homestead` | No | Very old |
| `byzantium` | No | Pre-Constantinople |
| `constantinople` | No | 2019 |
| `petersburg` | No | 2019 |
| `istanbul` | No | 2019 |
| `berlin` | No | 2021 |
| `london` | No | 2021 |
| `paris` | No | 2022 (Merge) |
| `shanghai` | **Yes** | 2023 (EIP-3855) |
| `cancun` | **Yes** | 2024 (Dencun) |

---

## Testing

The detector has been validated with test cases:

| Test Scenario | Findings | Contracts |
|---------------|----------|-----------|
| Cross-chain with 0.8.20+ | 6 | 2 |
| LayerZero integration | 4 | 1 |
| Chain ID usage patterns | 5 | 1 |

**Total:** 15 findings across 4 test contracts

---

## Best Practices

### For Cross-Chain Developers

1. **Always check target chain EVM versions** before deployment
2. **Use the lowest common denominator** for multi-chain contracts
3. **Maintain chain compatibility matrices** in documentation
4. **Test deployments on all target chains** before mainnet

### For Protocol Developers

1. **Specify EVM version explicitly** in build configuration
2. **Document chain requirements** in contract NatSpec
3. **Consider chain-specific builds** for optimization
4. **Monitor chain upgrades** for compatibility changes

### Gas Considerations

- PUSH0: 2 gas
- PUSH1 0x00: 3 gas
- Difference: 1 gas per zero push

For gas-sensitive applications on Shanghai+ chains, using PUSH0 (Solidity >= 0.8.20) provides minor gas savings.

---

## Chain Compatibility Status

### Chains with Shanghai/PUSH0 Support (2024)

- Ethereum Mainnet
- Arbitrum One
- Optimism
- Polygon PoS
- Base
- Most major L2s

### Chains Requiring Verification

- BNB Smart Chain (check current EVM version)
- Avalanche C-Chain (check current EVM version)
- Fantom Opera (check current EVM version)
- Private/enterprise chains (varies)

### Recommendation

Always verify target chain compatibility before deployment:

```bash
# Check if chain supports PUSH0
# Deploy test contract with PUSH0 and verify execution
cast call --rpc-url $RPC_URL ...
```

---

## References

### EIP Specification
- [EIP-3855: PUSH0 instruction](https://eips.ethereum.org/EIPS/eip-3855)

### Solidity Documentation
- [Solidity 0.8.20 Release Notes](https://soliditylang.org/blog/2023/05/10/solidity-0.8.20-release-announcement/)
- [EVM Version Pragma](https://docs.soliditylang.org/en/latest/using-the-compiler.html#setting-the-evm-version-to-target)

### Build Tool Documentation
- [Foundry EVM Version](https://book.getfoundry.sh/reference/config/solidity-compiler#evm_version)
- [Hardhat EVM Version](https://hardhat.org/hardhat-runner/docs/advanced/building-and-testing#setting-the-evm-version)

### Related Detectors
- `cross-chain-*` - Cross-chain validation detectors
- `erc7683-*` - Cross-chain intent detectors

---

**Last Updated:** 2026-01-26
**Detector Version:** 1.0.0
**Source:** `crates/detectors/src/push0/stack_assumption.rs`
