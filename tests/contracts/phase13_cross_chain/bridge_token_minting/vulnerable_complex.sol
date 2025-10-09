// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Bridge Token with Access Control but Missing Validation & Limits
/// @notice Has access control but missing message validation and amount limits
/// @dev Should trigger multiple findings from bridge-token-mint-control detector

contract BridgeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public bridge;

    event Minted(address indexed to, uint256 amount);

    modifier onlyBridge() {
        require(msg.sender == bridge, "Only bridge");
        _;
    }

    constructor(address _bridge) {
        bridge = _bridge;
    }

    /// @notice Mint with access control but NO message validation
    /// @dev VULNERABILITY: Missing cross-chain message verification
    function mint(address to, uint256 amount) external onlyBridge {
        balances[to] += amount;
        totalSupply += amount;
        emit Minted(to, amount);
    }

    /// @notice Mint with access control and message verification but NO limits
    /// @dev VULNERABILITY: Missing maximum mint amount limits
    function mintVerified(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes calldata signature
    ) external onlyBridge {
        require(verifyMessage(messageHash, signature), "Invalid message");

        balances[to] += amount;
        totalSupply += amount;
        emit Minted(to, amount);
    }

    function verifyMessage(bytes32, bytes calldata) internal pure returns (bool) {
        return true;
    }
}
