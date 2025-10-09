// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Secure Bridge Token
/// @notice Proper access control, message validation, AND amount limits
/// @dev Should NOT trigger bridge-token-mint-control detector

contract SecureBridgeToken {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processedMessages;
    uint256 public totalSupply;
    address public bridge;
    uint256 public constant MAX_MINT_AMOUNT = 1000000 ether;

    event Minted(address indexed to, uint256 amount);

    modifier onlyBridge() {
        require(msg.sender == bridge, "Only bridge");
        _;
    }

    constructor(address _bridge) {
        bridge = _bridge;
    }

    /// @notice Secure mint with access control, validation, and limits
    /// @dev SECURE: Has all three protections
    function mint(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes calldata proof
    ) external onlyBridge {
        // SECURE: Message validation
        require(verifyMessage(messageHash, proof), "Invalid message");
        require(!processedMessages[messageHash], "Already processed");

        // SECURE: Amount limits
        require(amount <= MAX_MINT_AMOUNT, "Exceeds max mint");

        // Mark as processed
        processedMessages[messageHash] = true;

        // Mint tokens
        balances[to] += amount;
        totalSupply += amount;

        emit Minted(to, amount);
    }

    function verifyMessage(bytes32, bytes calldata) internal pure returns (bool) {
        return true;
    }
}
