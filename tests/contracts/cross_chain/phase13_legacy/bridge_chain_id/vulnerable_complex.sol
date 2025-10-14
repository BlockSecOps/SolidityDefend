// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Complex Vulnerable Cross-Chain Relay
/// @notice This demonstrates a more sophisticated bridge with other validations but missing chain-ID checks
/// @dev Should trigger: missing-chainid-validation detector

contract CrossChainRelay {
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => bool) public authorizedRelayers;
    uint256 public lastNonce;
    address public admin;

    event MessageExecuted(bytes32 indexed messageHash, uint256 nonce);
    event RelayerAuthorized(address indexed relayer);

    modifier onlyAuthorized() {
        require(authorizedRelayers[msg.sender], "Not authorized");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        authorizedRelayers[msg.sender] = true;
    }

    /// @notice Execute a cross-chain message with multiple validations but NO chain-ID check
    /// @dev VULNERABILITY: Has nonce, signature, and replay protection but missing chain-ID validation
    function executeMessage(
        bytes32 messageHash,
        uint256 nonce,
        bytes calldata payload,
        bytes calldata signature
    ) external onlyAuthorized {
        // Good: Replay protection
        require(!processedMessages[messageHash], "Already processed");

        // Good: Nonce validation
        require(nonce > lastNonce, "Invalid nonce");

        // Good: Signature verification
        require(_verifySignature(messageHash, signature), "Invalid signature");

        // VULNERABILITY: Missing chain-ID validation
        // Should have: require(destinationChainId == block.chainid, "Wrong chain");

        // Mark as processed
        processedMessages[messageHash] = true;
        lastNonce = nonce;

        // Execute the payload
        (bool success,) = address(this).call(payload);
        require(success, "Execution failed");

        emit MessageExecuted(messageHash, nonce);
    }

    /// @notice Process bridged message with partial chain-ID handling
    /// @dev VULNERABILITY: Chain-ID included in hash but no runtime validation
    function receiveMessage(
        bytes32 messageHash,
        bytes calldata message,
        uint256 sourceChainId,
        uint256 targetChainId,
        bytes calldata signature
    ) external onlyAuthorized {
        // VULNERABILITY: Chain-ID is hashed but never compared to block.chainid
        bytes32 hash = keccak256(abi.encodePacked(
            message,
            sourceChainId,
            targetChainId
        ));
        require(hash == messageHash, "Invalid hash");

        // Missing: require(targetChainId == block.chainid, "Wrong target chain");

        require(_verifySignature(hash, signature), "Invalid signature");
        require(!processedMessages[hash], "Already processed");

        processedMessages[hash] = true;

        _processMessage(message);

        emit MessageExecuted(hash, lastNonce++);
    }

    function authorizeRelayer(address relayer) external onlyAdmin {
        authorizedRelayers[relayer] = true;
        emit RelayerAuthorized(relayer);
    }

    function _verifySignature(bytes32 hash, bytes calldata signature) internal pure returns (bool) {
        // Simplified signature verification
        return signature.length == 65;
    }

    function _processMessage(bytes calldata message) internal {
        // Internal message processing
    }
}
