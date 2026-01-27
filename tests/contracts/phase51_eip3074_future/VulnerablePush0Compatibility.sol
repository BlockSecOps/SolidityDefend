// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerablePush0CrossChain
 * @notice VULNERABLE: Uses Solidity >=0.8.20 for cross-chain deployment
 * @dev Should trigger: push0-stack-assumption (Low)
 *
 * Solidity >=0.8.20 generates PUSH0 opcode which is only available
 * on Shanghai+ chains. Pre-Shanghai chains will reject this bytecode.
 */
contract VulnerablePush0CrossChain {
    mapping(uint256 => bool) public supportedChains;

    event CrossChainMessage(uint256 indexed destChain, bytes data);

    constructor() {
        // Multi-chain deployment intent
        supportedChains[1] = true;      // Ethereum Mainnet (Shanghai+)
        supportedChains[56] = true;     // BSC (may not support PUSH0)
        supportedChains[137] = true;    // Polygon
        supportedChains[42161] = true;  // Arbitrum
    }

    // This contract uses block.chainid - indicates cross-chain use
    function sendMessage(uint256 destChain, bytes calldata data) external {
        require(supportedChains[destChain], "Chain not supported");
        require(destChain != block.chainid, "Same chain");
        emit CrossChainMessage(destChain, data);
    }

    function getChainId() external view returns (uint256) {
        return block.chainid;
    }
}

/**
 * @title VulnerableGasCalculation
 * @notice VULNERABLE: Assembly gas calculations assume old PUSH1 0 cost
 * @dev Should trigger: push0-stack-assumption (Low)
 */
contract VulnerableGasCalculation {
    // VULNERABLE: Gas calculation may be wrong with PUSH0
    function estimateGas(uint256 iterations) external pure returns (uint256) {
        uint256 gasNeeded;
        assembly {
            // Old: PUSH1 0 costs 3 gas
            // New: PUSH0 costs 2 gas
            // This calculation assumes old cost
            gasNeeded := mul(iterations, 3)
        }
        return gasNeeded;
    }

    // VULNERABLE: Complex stack operations with hardcoded gas
    function complexOperation() external view returns (uint256) {
        uint256 result;
        assembly {
            // Complex stack operations
            let a := mload(0x40)
            let b := dup1
            let c := swap1

            // Gas calculation assuming PUSH1 costs
            result := add(mul(gas(), 3), gasleft())
        }
        return result;
    }
}

/**
 * @title VulnerableEvmVersion
 * @notice VULNERABLE: Pre-Shanghai EVM version specified
 * @dev Should trigger: push0-stack-assumption (Low)
 */
contract VulnerableEvmVersion {
    // evmVersion: paris - PUSH0 not available
    // This contract may have issues if compiled with Shanghai+ default

    function useVerbatim() external pure returns (uint256) {
        uint256 result;
        assembly {
            // verbatim may need updating for PUSH0
            result := verbatim_0i_1o(hex"600060005260206000f3")
        }
        return result;
    }
}

/**
 * @title LayerZeroBridge
 * @notice VULNERABLE: Cross-chain bridge using >=0.8.20
 * @dev Should trigger: push0-stack-assumption (Low)
 */
contract LayerZeroBridge {
    address public endpoint;

    mapping(uint16 => bytes) public trustedRemote;

    constructor(address _endpoint) {
        endpoint = _endpoint;
    }

    // LayerZero integration - cross-chain
    function setTrustedRemote(uint16 srcChain, bytes calldata path) external {
        trustedRemote[srcChain] = path;
    }

    function send(
        uint16 destChain,
        bytes calldata payload,
        address payable refundAddress
    ) external payable {
        // Cross-chain send - may fail on chains without PUSH0
        (bool success,) = endpoint.call{value: msg.value}(
            abi.encodeWithSignature(
                "send(uint16,bytes,bytes,address,address,bytes)",
                destChain,
                trustedRemote[destChain],
                payload,
                refundAddress,
                address(0),
                ""
            )
        );
        require(success, "Send failed");
    }
}

/**
 * @title AxelarBridge
 * @notice Another cross-chain bridge example
 */
contract AxelarBridge {
    address public gateway;

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function callContract(
        string calldata destChain,
        string calldata destAddress,
        bytes calldata payload
    ) external {
        // Axelar cross-chain call
        (bool success,) = gateway.call(
            abi.encodeWithSignature(
                "callContract(string,string,bytes)",
                destChain,
                destAddress,
                payload
            )
        );
        require(success, "Call failed");
    }
}
