// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bridge {
    function receiveMessage(
        bytes calldata message,
        uint256 sourceChainId,
        uint256 targetChainId
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(message, sourceChainId, targetChainId));
        _processMessage(message);
    }

    function _processMessage(bytes calldata message) internal {}
}
