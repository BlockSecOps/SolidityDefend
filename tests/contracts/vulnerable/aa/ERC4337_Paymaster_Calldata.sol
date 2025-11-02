// SPDX-License-Identifier: MIT
// Based on: ERC-4337 Malformed Calldata Vulnerability (March 2023/2025)
// Reference: NIOLabs discovery - VerifyingPaymaster vulnerability
pragma solidity ^0.8.20;

/**
 * @title ERC-4337 VerifyingPaymaster Calldata Vulnerability
 * @notice Paymaster vulnerable to malformed calldata manipulation
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: UserOperation fields can be altered after signature
 * Should trigger: aa-nonce-management-advanced, aa-user-operation-replay detectors
 *
 * Attack Vector:
 * 1. Paymaster signs UserOp for specific purpose (e.g., gasless mint)
 * 2. UserOp hash generated using .offset fields in calldata
 * 3. Attacker modifies initCode or callData after signature
 * 4. Hash verification passes due to calldata encoding inconsistency
 * 5. Operation executes with different behavior than signed
 * 6. Paymaster sponsors unintended transaction
 */
contract VerifyingPaymaster_Vulnerable {
    address public verifyingSigner;
    mapping(address => uint256) public senderNonce;

    constructor(address _verifyingSigner) {
        verifyingSigner = _verifyingSigner;
    }

    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;      // VULNERABLE: Can be modified after signature
        bytes callData;      // VULNERABLE: Can be modified after signature
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    /**
     * @notice Validate paymaster sponsorship
     * @dev VULNERABLE: Hash calculation uses .offset, allowing manipulation
     */
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,  // VULNERABLE: Pre-calculated hash may not match actual data
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // VULNERABLE: No re-calculation of hash from actual calldata
        // Trusts the provided userOpHash blindly

        // Extract paymaster data
        require(userOp.paymasterAndData.length >= 20 + 65, "Invalid paymaster data");

        bytes memory paymasterData = userOp.paymasterAndData[20:];
        (uint48 validUntil, uint48 validAfter, bytes memory signature) = abi.decode(
            paymasterData,
            (uint48, uint48, bytes)
        );

        // VULNERABLE: Verifies signature against provided hash,
        // not against actual UserOperation data
        bytes32 hash = keccak256(abi.encode(
            userOpHash,  // VULNERABLE: Uses pre-calculated hash
            validUntil,
            validAfter
        ));

        address recovered = _recoverSigner(hash, signature);
        require(recovered == verifyingSigner, "Invalid signature");

        // VULNERABLE: No validation that initCode/callData matches signed intent
        // Attacker can modify these fields after getting signature

        // VULNERABLE: No proper nonce management
        // Global nonce instead of per-user per-key nonces

        return ("", _packValidationData(false, validUntil, validAfter));
    }

    /**
     * @notice Post-operation hook
     * @dev VULNERABLE: No verification of actual execution vs signed intent
     */
    function postOp(
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        // VULNERABLE: Can't verify if executed operation matched signed operation
        // Malformed calldata attack already succeeded
    }

    function _recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(hash, v, r, s);
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }
}

/**
 * Expected Detection:
 * - aa-nonce-management-advanced: Multiple findings
 *   - No per-user nonce validation
 *   - No nonce increment
 *   - Global nonce vulnerable to replay
 *
 * - aa-user-operation-replay: Critical findings
 *   - UserOp hash not recalculated from actual data
 *   - initCode and callData can be modified post-signature
 *   - No chain ID validation
 *   - Missing replay protection
 */
