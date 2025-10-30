// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title LegitimatePermitToken
 * @notice Properly implemented ERC-2612 permit token with security best practices
 * @dev This contract should NOT trigger false positives from permit-signature-exploit detector
 *
 * Security Measures:
 * 1. Deadline validation (prevents expired signatures)
 * 2. Nonce management (prevents replay attacks)
 * 3. Domain separator (prevents cross-chain replay)
 * 4. EIP-712 typed data (prevents signature malleability)
 * 5. Signature validation (prevents invalid signatures)
 */

contract LegitimatePermitToken {
    // ERC-20 state
    string public constant name = "Legitimate Permit Token";
    string public constant symbol = "LPT";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ERC-2612 permit state
    mapping(address => uint256) public nonces;
    bytes32 public immutable DOMAIN_SEPARATOR;

    // EIP-712 type hashes
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;

        // Compute domain separator for EIP-712
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice ERC-2612 permit function with proper security validation
     * @param owner Token owner granting approval
     * @param spender Address receiving approval
     * @param value Amount to approve
     * @param deadline Signature expiration timestamp
     * @param v Signature v component
     * @param r Signature r component
     * @param s Signature s component
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // CRITICAL: Validate deadline to prevent expired signature replay
        require(block.timestamp <= deadline, "Permit: signature expired");

        // Build EIP-712 structured data hash
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonces[owner],
                deadline
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                structHash
            )
        );

        // Recover signer from signature
        address recoveredAddress = ecrecover(digest, v, r, s);

        // CRITICAL: Validate signature
        require(recoveredAddress != address(0), "Permit: invalid signature");
        require(recoveredAddress == owner, "Permit: unauthorized");

        // CRITICAL: Increment nonce to prevent replay
        nonces[owner]++;

        // Grant approval
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    /**
     * @notice Get current nonce for permit (prevents replay)
     * @param owner Address to check
     * @return Current nonce
     */
    function getNonce(address owner) external view returns (uint256) {
        return nonces[owner];
    }

    // Standard ERC-20 functions
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }
}

/**
 * EXPECTED RESULTS:
 * ================
 * This ERC-2612 permit token implements all security best practices and should NOT trigger:
 *
 * ✅ permit-signature-exploit: Validates deadline (block.timestamp <= deadline)
 * ✅ permit-signature-exploit: Increments nonce after use (prevents replay)
 * ✅ permit-signature-exploit: Uses domain separator (prevents cross-chain replay)
 * ✅ permit-signature-exploit: Validates recovered address == owner
 * ✅ permit-signature-exploit: Uses EIP-712 structured data (prevents malleability)
 *
 * Expected Findings: 0 (Zero false positives)
 */
