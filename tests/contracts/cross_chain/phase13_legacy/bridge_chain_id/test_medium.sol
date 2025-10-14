// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bridge {
    function receiveMessage(
        bytes32 messageHash,
        bytes calldata message,
        uint256 chainId
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(message, chainId));
        require(hash == messageHash, "Invalid hash");
        _processMessage(message);
    }

    function _processMessage(bytes calldata message) internal {}
}
