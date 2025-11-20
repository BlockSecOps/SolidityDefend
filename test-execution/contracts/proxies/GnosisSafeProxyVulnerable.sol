// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title GnosisSafeProxyVulnerable
 * @notice Test contract for Gnosis Safe proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. signature-replay - Signature can be replayed
 * 2. missing-nonce-validation - No nonce tracking
 * 3. threshold-bypass - Threshold can be changed without proper validation
 *
 * TEST CATEGORY: proxy
 * SEVERITY: critical
 */

contract GnosisSafeProxyVulnerable {
    address public singleton;
    mapping(address => bool) public owners;
    uint256 public threshold;
    uint256 public nonce;

    constructor(address _singleton, address[] memory _owners, uint256 _threshold) {
        singleton = _singleton;
        threshold = _threshold;
        for (uint256 i = 0; i < _owners.length; i++) {
            owners[_owners[i]] = true;
        }
    }

    // VULNERABILITY 1: No signature replay protection
    // Expected: signature-replay (CRITICAL)
    function executeTransaction(
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signatures
    ) public returns (bool) {
        // VULNERABILITY: No nonce check!
        // Same transaction can be executed multiple times

        bytes32 txHash = keccak256(abi.encode(to, value, data));

        // Simplified signature check (vulnerable)
        address signer = recoverSigner(txHash, signatures);
        require(owners[signer], "Not an owner");

        (bool success,) = to.call{value: value}(data);
        return success;
    }

    // VULNERABILITY 2: Threshold can be set to 0
    // Expected: invalid-threshold (HIGH)
    function changeThreshold(uint256 _threshold) public {
        // No validation that threshold > 0!
        // No check that threshold <= owner count!
        threshold = _threshold;
    }

    // VULNERABILITY 3: Owner can be added without multi-sig
    // Expected: missing-access-control (CRITICAL)
    function addOwner(address owner) public {
        // No multi-sig validation!
        owners[owner] = true;
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
        address _singleton = singleton;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
