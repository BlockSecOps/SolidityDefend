// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title L2ProxyVulnerable
 * @notice Test contract for L2 (Optimism/Arbitrum) proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. cross-chain-replay - Cross-chain signature replay
 * 2. l2-message-validation - Missing L2 message validation
 * 3. gas-limit-issues - Gas forwarding issues
 *
 * TEST CATEGORY: proxy
 * SEVERITY: critical/high
 */

contract L2ProxyVulnerable {
    address public l1Contract;
    address public implementation;
    mapping(bytes32 => bool) public executedMessages;

    constructor(address _l1Contract, address _implementation) {
        l1Contract = _l1Contract;
        implementation = _implementation;
    }

    // VULNERABILITY 1: No chain ID validation for cross-chain messages
    // Expected: cross-chain-replay (CRITICAL)
    function relayMessage(
        address target,
        bytes memory data,
        bytes32 messageHash,
        bytes memory signature
    ) public {
        // VULNERABILITY: No chain ID check!
        // Message from L1 can be replayed on other L2s

        bytes32 hash = keccak256(abi.encode(target, data, messageHash));
        address signer = recoverSigner(hash, signature);

        // VULNERABILITY 2: No validation that signer is l1Contract
        // Expected: missing-signature-validation (HIGH)

        (bool success,) = target.call(data);
        require(success, "Call failed");
    }

    // VULNERABILITY 3: No nonce/replay protection
    // Expected: missing-nonce-validation (CRITICAL)
    function executeL1Message(bytes memory message) public {
        // VULNERABILITY: Message can be executed multiple times!
        bytes32 messageHash = keccak256(message);

        // Should check: require(!executedMessages[messageHash])
        // But doesn't!

        (bool success,) = implementation.delegatecall(message);
        require(success, "Execution failed");
    }

    // VULNERABILITY 4: Gas forwarding without limits
    // Expected: gas-griefing (MEDIUM)
    function forwardCall(address target, bytes memory data) public payable {
        // Forwards all gas - can cause griefing
        (bool success,) = target.call{gas: gasleft()}(data);
        require(success, "Forward failed");
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
