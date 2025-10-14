// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bridge {
    function executeWithProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external {
        require(verifyMerkleProof(root, leaf, proof), "Invalid");
        _execute();
    }

    function verifyMerkleProof(bytes32, bytes32, bytes32[] calldata) internal pure returns (bool) {
        return true;
    }

    function _execute() internal {}
}
