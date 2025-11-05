// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DelegationChainAttack
 * @notice EIP-7702 Delegation Chain and Composability Attacks
 *
 * VULNERABILITY: Complex delegation chains and cross-contract exploitation
 * EIP: EIP-7702 (Pectra upgrade, expected 2025)
 *
 * BACKGROUND:
 * EIP-7702 allows EOAs to delegate code execution. When multiple contracts
 * interact in complex ways with delegated EOAs, new attack vectors emerge:
 * - Delegation chains (A delegates to B, calls C, C checks A)
 * - Re-delegation attacks (delegated code delegates again)
 * - Cross-contract state manipulation
 * - Identity confusion attacks
 *
 * ATTACK PATTERNS:
 * 1. Delegation chain confusion (who is actually executing?)
 * 2. Re-delegation to bypass restrictions
 * 3. Cross-contract delegation coordination
 * 4. Identity spoofing via delegation
 * 5. Delegation in callback context
 *
 * TESTED DETECTORS:
 * - eip7702-delegation-chain
 * - eip7702-redelegation
 * - eip7702-identity-confusion
 * - eip7702-callback-delegation
 */

/**
 * @title VaultWithIdentityCheck
 * @notice Vault that checks msg.sender identity
 */
contract VaultWithIdentityCheck {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isAuthorized;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function authorize(address user) external {
        require(msg.sender == owner, "Not owner");
        isAuthorized[user] = true;
    }

    /**
     * @notice VULNERABILITY 1: Identity check breaks with delegation
     * @dev With EIP-7702, msg.sender could be EOA with delegated code
     */
    function withdraw(uint256 amount) external {
        // VULNERABLE: Assumes msg.sender is EOA or known contract
        // With EIP-7702, msg.sender could be EOA executing attacker's code
        require(isAuthorized[msg.sender] || msg.sender == owner, "Not authorized");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 2: Callback assumes caller identity
     */
    function withdrawWithCallback(uint256 amount, bytes calldata data) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        // VULNERABLE: Callback to msg.sender (could be delegated EOA)
        (bool success, ) = msg.sender.call{value: amount}(data);
        require(success, "Callback failed");
    }

    receive() external payable {}
}

/**
 * @title DelegationProxy
 * @notice Proxy contract for delegation
 */
contract DelegationProxy {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABILITY 3: Delegation chain confusion
     * @dev EOA delegates to this proxy, which delegates to implementation
     *      Creates confusion about who is actually executing
     */
    fallback() external payable {
        address impl = implementation;

        // VULNERABLE: Double delegation
        // 1. EOA delegates to this contract (EIP-7702)
        // 2. This contract delegates to implementation (delegatecall)
        // Result: Execution context is confusing

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /**
     * @notice VULNERABILITY 4: Admin can be bypassed via delegation
     */
    function setImplementation(address newImpl) external {
        // VULNERABLE: Checks msg.sender == admin
        // With EIP-7702, attacker's EOA could delegate to become "admin"
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
    }

    receive() external payable {}
}

/**
 * @title ReDelegationAttack
 * @notice Demonstrates re-delegation attack pattern
 */
contract ReDelegationAttack {
    address public attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice VULNERABILITY 5: Re-delegation to bypass restrictions
     * @dev When EOA delegates to this contract, this contract can:
     *      1. Execute with EOA's identity (msg.sender = EOA)
     *      2. Delegate again to another contract
     *      3. Bypass checks that only look at immediate caller
     */
    function executeWithReDelegation(address target, bytes calldata data) external returns (bytes memory) {
        // First delegation: EOA → this contract (via EIP-7702)
        // msg.sender = EOA address
        // code = this contract's code

        // Second delegation: Call another contract
        // That contract sees msg.sender = EOA (not this contract!)
        (bool success, bytes memory result) = target.call(data);
        require(success, "Re-delegation failed");

        // ATTACK: Can also drain funds during re-delegation
        if (address(this).balance > 0) {
            payable(attacker).transfer(address(this).balance);
        }

        return result;
    }

    /**
     * @notice VULNERABILITY 6: Recursive delegation
     */
    function recursiveDelegate(address target, bytes calldata data, uint256 depth) external {
        if (depth == 0) {
            return;
        }

        // VULNERABLE: Each recursion level can set state
        // or perform actions with delegated identity
        (bool success, ) = target.call(data);
        require(success, "Recursive call failed");

        // Recurse with delegated identity
        this.recursiveDelegate(target, data, depth - 1);
    }
}

/**
 * @title CrossContractDelegation
 * @notice Cross-contract delegation coordination attack
 */
contract CrossContractDelegation {
    mapping(address => uint256) public delegationFlags;

    /**
     * @notice VULNERABILITY 7: Cross-contract delegation coordination
     * @dev Multiple EOAs can delegate to this contract and coordinate
     */
    function coordinatedAttack(
        address[] calldata targets,
        bytes[] calldata data
    ) external {
        require(targets.length == data.length, "Length mismatch");

        // Set delegation flag for this EOA
        delegationFlags[msg.sender] = 1;

        // Execute coordinated calls
        for (uint256 i = 0; i < targets.length; i++) {
            // VULNERABLE: All calls execute with msg.sender = delegating EOA
            // Can coordinate attacks across multiple contracts
            (bool success, ) = targets[i].call(data[i]);
            require(success, "Coordinated call failed");
        }

        delegationFlags[msg.sender] = 0;
    }

    /**
     * @notice VULNERABILITY 8: Delegation state can be checked by other contracts
     */
    function isDelegating(address account) external view returns (bool) {
        // VULNERABLE: Leaks information about delegation state
        // Other contracts can change behavior based on this
        return delegationFlags[account] > 0;
    }
}

/**
 * @title CallbackDelegation
 * @notice Delegation attacks in callback context
 */
contract CallbackDelegation {
    address public targetVault;

    constructor(address _targetVault) {
        targetVault = _targetVault;
    }

    /**
     * @notice VULNERABILITY 9: Delegation during callback
     * @dev When contract calls back to EOA, EOA delegates during callback
     */
    function initiateWithdrawal(uint256 amount) external {
        // Call vault to withdraw
        (bool success, ) = targetVault.call(
            abi.encodeWithSignature("withdrawWithCallback(uint256,bytes)", amount, "")
        );
        require(success, "Withdrawal failed");
    }

    /**
     * @notice Callback hook - executed when vault calls back
     * @dev If EOA delegates to this contract, callback runs with delegated code
     */
    receive() external payable {
        // VULNERABLE: During callback, can execute arbitrary code
        // with vault's msg.sender context

        // Could re-enter vault with different parameters
        // Could manipulate state before vault completes its operation
        // Could call other contracts with vault's authority
    }

    /**
     * @notice VULNERABILITY 10: Callback can trigger new delegation
     */
    function callbackWithDelegation(address newTarget, bytes calldata data) external payable {
        // During callback, initiate new delegation chain
        (bool success, ) = newTarget.call(data);
        require(success, "Callback delegation failed");
    }
}

/**
 * @title IdentitySpoofing
 * @notice Identity spoofing via delegation
 */
contract IdentitySpoofing {
    /**
     * @notice VULNERABILITY 11: Impersonate authorized EOA
     * @dev Attacker's EOA delegates to this contract, then calls protected functions
     */
    function impersonateAndCall(address target, bytes calldata data) external returns (bytes memory) {
        // When attacker's EOA delegates to this contract:
        // - msg.sender = attacker's EOA
        // - code = this contract's code
        //
        // If target checks msg.sender for authorization:
        // - Target sees msg.sender = attacker's EOA
        // - Target doesn't know code is delegated!
        //
        // ATTACK: If attacker can trick authorized EOA to delegate,
        // can impersonate them

        (bool success, bytes memory result) = target.call(data);
        require(success, "Impersonation call failed");

        return result;
    }

    /**
     * @notice VULNERABILITY 12: Signature replay with delegation
     * @dev Sign message with EOA, then delegate to execute
     */
    function executeWithSignature(
        address target,
        bytes calldata data,
        bytes calldata signature
    ) external {
        // Verify signature (msg.sender signed this)
        bytes32 hash = keccak256(data);
        address signer = recoverSigner(hash, signature);
        require(signer == msg.sender, "Invalid signature");

        // VULNERABLE: Execute with signature verification passed
        // But actual execution code is delegated (could be malicious)
        (bool success, ) = target.call(data);
        require(success, "Execution failed");
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(hash, v, r, s);
    }
}

/**
 * @title DelegationGasManipulation
 * @notice Gas manipulation via delegation
 */
contract DelegationGasManipulation {
    /**
     * @notice VULNERABILITY 13: Gas estimation breaks with delegation
     * @dev Gas estimation doesn't account for delegated code complexity
     */
    function expensiveOperation(uint256 iterations) external {
        // VULNERABLE: If EOA delegates to this contract:
        // - Gas estimation sees simple EOA call
        // - Actual execution is expensive loop
        // - Can cause out-of-gas for unprepared callers

        for (uint256 i = 0; i < iterations; i++) {
            // Expensive computation
            uint256 result = 0;
            for (uint256 j = 0; j < 100; j++) {
                result += uint256(keccak256(abi.encodePacked(i, j)));
            }
        }
    }

    /**
     * @notice VULNERABILITY 14: Gas griefing via delegation
     */
    function gasGrief(address target, bytes calldata data) external {
        // VULNERABLE: Can delegate to contract that consumes all gas
        // Caller's transaction fails but attacker still gets paid

        uint256 startGas = gasleft();

        // Call target
        (bool success, ) = target.call{gas: startGas - 10000}(data);

        // ATTACK: Consume remaining gas
        while (gasleft() > 100) {
            // Waste gas
        }

        require(success, "Call failed");
    }
}

/**
 * @title DelegationMultiSig
 * @notice MultiSig vulnerabilities with delegation
 */
contract DelegationMultiSig {
    address[] public signers;
    uint256 public threshold;
    mapping(bytes32 => uint256) public confirmations;

    constructor(address[] memory _signers, uint256 _threshold) {
        signers = _signers;
        threshold = _threshold;
    }

    /**
     * @notice VULNERABILITY 15: MultiSig bypass via delegation
     * @dev If signers delegate their EOAs, can bypass multisig checks
     */
    function executeMultiSig(
        address target,
        bytes calldata data,
        bytes[] calldata signatures
    ) external {
        bytes32 txHash = keccak256(abi.encode(target, data));

        // Verify signatures
        uint256 validSignatures = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(txHash, signatures[i]);
            if (isSigner(signer)) {
                validSignatures++;
            }
        }

        require(validSignatures >= threshold, "Insufficient signatures");

        // VULNERABLE: Execute even if signers have delegated their EOAs
        // Delegated code could be malicious, but signatures are valid!
        (bool success, ) = target.call(data);
        require(success, "Execution failed");
    }

    function isSigner(address account) internal view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == account) {
                return true;
            }
        }
        return false;
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(hash, v, r, s);
    }
}
