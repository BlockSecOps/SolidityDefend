// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bridge {
    mapping(address => bool) public authorized;

    modifier onlyAuthorized() {
        require(authorized[msg.sender], "Not authorized");
        _;
    }

    function receiveMessage(
        bytes calldata message,
        uint256 sourceChainId,
        uint256 targetChainId
    ) external onlyAuthorized {
        bytes32 hash = keccak256(abi.encodePacked(message, sourceChainId, targetChainId));
        _processMessage(message);
    }

    function _processMessage(bytes calldata message) internal {}
}
