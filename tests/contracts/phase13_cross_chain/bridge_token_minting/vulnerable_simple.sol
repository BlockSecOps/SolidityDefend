// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Bridge Token - No Access Control
/// @notice Demonstrates completely unrestricted token minting
/// @dev Should trigger: bridge-token-mint-control detector

contract VulnerableBridgeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Minted(address indexed to, uint256 amount);

    /// @notice Mint tokens WITHOUT any access control
    /// @dev VULNERABILITY: Anyone can mint unlimited tokens!
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
        emit Minted(to, amount);
    }

    /// @notice Issue tokens WITHOUT access control
    /// @dev VULNERABILITY: Unrestricted token issuance
    function issueTokens(address recipient, uint256 value) external {
        balances[recipient] += value;
        totalSupply += value;
    }
}
