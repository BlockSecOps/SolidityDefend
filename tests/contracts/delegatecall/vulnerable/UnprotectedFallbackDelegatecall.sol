// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UnprotectedFallbackDelegatecall
 * @notice VULNERABLE: Fallback/receive functions with unprotected delegatecall
 * @dev This contract demonstrates vulnerabilities in fallback/receive functions
 *      that perform delegatecall without proper access controls or validation.
 *
 * Vulnerability: CWE-284 (Improper Access Control), CWE-829 (Untrusted Control Sphere)
 * Severity: CRITICAL
 * Impact: Complete contract takeover, fund theft, unauthorized operations
 *
 * Fallback/receive functions are automatically called when:
 * - Contract receives ETH with no data (receive)
 * - Contract receives call to non-existent function (fallback)
 * - Contract receives ETH with data (fallback)
 *
 * If these functions perform unprotected delegatecall, anyone can:
 * 1. Trigger arbitrary code execution
 * 2. Bypass access controls
 * 3. Manipulate contract state
 * 4. Drain funds
 *
 * Real-world impact:
 * - Proxy contracts with unprotected fallback are common attack vectors
 * - Multiple DeFi protocols exploited via fallback delegatecall
 * - Transparent proxy pattern specifically addresses this vulnerability
 */

/**
 * @notice VULNERABLE: Basic unprotected fallback with delegatecall
 */
contract UnprotectedFallback {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    /**
     * @notice CRITICAL: Anyone can trigger delegatecall via fallback
     */
    fallback() external payable {
        address impl = implementation;

        // VULNERABLE: No access control, anyone can call!
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @notice VULNERABLE: Fallback allows admin function shadowing
 */
contract FunctionShadowing {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice Admin-only upgrade function
     */
    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "Only admin");
        implementation = newImplementation;
    }

    /**
     * @notice VULNERABLE: Fallback can shadow admin functions
     * @dev If implementation has upgradeTo(), it shadows this contract's version!
     */
    fallback() external payable {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Receive function with delegatecall
 */
contract ReceiveDelegatecall {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Receive delegates to implementation
     * @dev Anyone sending ETH triggers delegatecall!
     */
    receive() external payable {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Fallback with weak access control
 */
contract WeakFallbackProtection {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABLE: Only checks msg.value, not caller
     */
    fallback() external payable {
        // INSUFFICIENT: Anyone can call with 0 value
        require(msg.value == 0, "No ETH allowed");

        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Fallback with blacklist instead of whitelist
 */
contract BlacklistFallback {
    address public implementation;
    mapping(address => bool) public blocked;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function blockAddress(address user) external {
        blocked[user] = true;
    }

    /**
     * @notice VULNERABLE: Blacklist is insufficient (should use whitelist)
     */
    fallback() external payable {
        // WEAK: Blacklist can be bypassed via contract creation
        require(!blocked[msg.sender], "Blocked");

        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Fallback allows state corruption via storage collision
 */
contract StorageCorruption {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1
    uint256 public balance;         // Slot 2

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABLE: Delegatecall can corrupt proxy storage
     */
    fallback() external payable {
        address impl = implementation;

        // If implementation uses slots 0-2, it corrupts proxy state!
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function deposit() external payable {
        balance += msg.value;
    }
}

/**
 * @notice MALICIOUS IMPLEMENTATION - For attack demonstration
 */
contract MaliciousImplementation {
    address public implementation;  // Matches proxy slot 0
    address public admin;           // Matches proxy slot 1

    /**
     * @notice Attack: Corrupt proxy's implementation variable
     */
    function attack() external {
        // This overwrites proxy's implementation (slot 0)!
        implementation = msg.sender;
    }

    /**
     * @notice Attack: Steal admin role
     */
    function becomeAdmin() external {
        // This overwrites proxy's admin (slot 1)!
        admin = msg.sender;
    }

    /**
     * @notice Attack: Drain funds
     */
    function drain() external {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @notice ATTACK DEMONSTRATION
 */
contract FallbackAttack {
    /**
     * @notice Exploit unprotected fallback
     */
    function exploit(address proxy) external {
        // Call non-existent function to trigger fallback
        (bool success, ) = proxy.call(abi.encodeWithSignature("attack()"));
        require(success, "Attack failed");

        // Verify we corrupted the proxy
        UnprotectedFallback target = UnprotectedFallback(payable(proxy));
        // implementation variable now points to attacker
    }
}

/**
 * @notice VULNERABLE: Fallback with no implementation validation
 */
contract NoImplementationValidation {
    address public implementation;

    /**
     * @notice Anyone can set implementation!
     */
    function setImplementation(address newImpl) external {
        implementation = newImpl;  // No validation or access control
    }

    /**
     * @notice VULNERABLE: Delegates to unvalidated implementation
     */
    fallback() external payable {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Multiple fallback delegates (incorrect pattern)
 */
contract MultipleFallbacks {
    address public implementation1;
    address public implementation2;

    constructor(address impl1, address impl2) {
        implementation1 = impl1;
        implementation2 = impl2;
    }

    /**
     * @notice CONFUSED: Which implementation to use?
     */
    fallback() external payable {
        // VULNERABLE: Logic is unclear and unprotected
        address impl = msg.value > 0 ? implementation1 : implementation2;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Fallback with reentrancy risk
 */
contract ReentrancyFallback {
    address public implementation;
    uint256 public balance;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        uint256 amount = balance;
        balance = 0;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABLE: Fallback can trigger reentrancy
     */
    fallback() external payable {
        address impl = implementation;

        // If implementation calls back to proxy, reentrancy!
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice VULNERABLE: Fallback with gas manipulation
 */
contract GasManipulation {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: No gas checks for delegatecall
     */
    fallback() external payable {
        address impl = implementation;

        // VULNERABLE: Delegatecall forwards all available gas
        // Attacker can cause OOG or grief
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
