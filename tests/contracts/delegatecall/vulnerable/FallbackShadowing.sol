// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FallbackShadowing
 * @notice VULNERABLE: Fallback function shadows implementation functions
 * @dev This contract demonstrates the vulnerability where a fallback function's
 *      selector matching logic can unintentionally shadow functions in the
 *      implementation contract, causing calls to be misrouted.
 *
 * Vulnerability: CWE-670 (Always-Incorrect Control Flow Implementation)
 * Severity: MEDIUM
 * Impact: Function calls routed incorrectly, state corruption, DOS
 *
 * Fallback function shadowing occurs when:
 * 1. Proxy uses fallback to delegate calls
 * 2. Proxy defines functions with same selector as implementation
 * 3. Fallback logic doesn't properly route selectors
 * 4. Critical functions become unreachable
 *
 * Real-world impact:
 * - Multiple proxy implementations with misrouted calls
 * - Functions intended for implementation executed in proxy context
 * - Critical functions made unreachable
 * - State corruption due to incorrect delegation
 *
 * Attack scenario:
 * 1. User calls function expecting implementation logic
 * 2. Fallback intercepts call and executes proxy logic instead
 * 3. Expected state changes don't occur
 * 4. Contract behavior becomes unpredictable
 */

/**
 * @notice VULNERABLE: Proxy with function that shadows implementation
 */
contract VulnerableProxyWithShadowing {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABLE: This function shadows the implementation's upgrade function
     * @dev Anyone can call this, but it does nothing useful
     */
    function upgradeImplementation(address newImpl) external {
        // VULNERABLE: This shadows the real upgradeImplementation in the implementation!
        // Users might call this thinking they're upgrading, but nothing happens
        // The real upgrade function in implementation is unreachable
    }

    /**
     * @notice VULNERABLE: Fallback delegates to implementation
     * @dev But some functions are shadowed by proxy functions
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

    receive() external payable {}
}

/**
 * @notice Implementation contract with upgrade function
 */
contract ImplementationWithUpgrade {
    address public implementation;
    address public admin;
    uint256 public value;

    /**
     * @notice Real upgrade function that should be called
     * @dev This function is shadowed by proxy and unreachable!
     */
    function upgradeImplementation(address newImpl) external {
        require(msg.sender == admin, "Only admin");
        implementation = newImpl;
    }

    function setValue(uint256 newValue) external {
        value = newValue;
    }
}

/**
 * @notice VULNERABLE: Proxy with admin function shadowing
 */
contract AdminFunctionShadowing {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Proxy-level transferOwnership shadows implementation
     * @dev This only changes proxy owner, not implementation owner!
     */
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
        // Implementation's transferOwnership is unreachable!
    }

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
 * @notice VULNERABLE: Incorrect selector routing in fallback
 */
contract IncorrectSelectorRouting {
    address public implementation;

    // Function selector for withdraw()
    bytes4 private constant WITHDRAW_SELECTOR = 0x3ccfd60b;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Fallback with broken selector routing
     * @dev Attempts to handle withdraw specially but breaks routing
     */
    fallback() external payable {
        bytes4 selector = msg.sig;

        // VULNERABLE: Special case for withdraw, but implementation also has withdraw!
        if (selector == WITHDRAW_SELECTOR) {
            // This executes in proxy context, shadows implementation's withdraw
            revert("Withdrawals disabled");
        }

        // Other calls delegated normally
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
 * @notice VULNERABLE: Receive function shadowing payable fallback
 */
contract ReceiveShadowing {
    address public implementation;
    uint256 public receivedCount;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Receive function intercepts ETH transfers
     * @dev This shadows any receive logic in implementation
     */
    receive() external payable {
        receivedCount++;
        // Implementation's receive function never executes!
    }

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
 * @notice VULNERABLE: Multiple function shadowing
 */
contract MultipleFunctionShadowing {
    address public implementation;
    address public admin;
    bool public paused;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABLE: Pause function in proxy shadows implementation
     */
    function pause() external {
        require(msg.sender == admin, "Only admin");
        paused = true;
        // Implementation's pause function is unreachable!
    }

    /**
     * @notice VULNERABLE: Unpause function in proxy shadows implementation
     */
    function unpause() external {
        require(msg.sender == admin, "Only admin");
        paused = false;
        // Implementation's unpause function is unreachable!
    }

    /**
     * @notice VULNERABLE: getAdmin shadows implementation's getAdmin
     */
    function getAdmin() external view returns (address) {
        return admin;
        // Implementation's getAdmin is unreachable!
    }

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
 * @notice VULNERABLE: Initialization function shadowing
 */
contract InitializationShadowing {
    address public implementation;
    bool public initialized;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Initialize in proxy shadows implementation's initialize
     * @dev This could prevent proper implementation initialization
     */
    function initialize() external {
        require(!initialized, "Already initialized");
        initialized = true;
        // Implementation's initialize is unreachable!
    }

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
 * @notice VULNERABLE: Storage getter shadowing
 */
contract StorageGetterShadowing {
    address public implementation;
    uint256 public version;

    constructor(address _implementation) {
        implementation = _implementation;
        version = 1;
    }

    /**
     * @notice VULNERABLE: getVersion in proxy shadows implementation
     * @dev Returns proxy version instead of implementation version
     */
    function getVersion() external view returns (uint256) {
        return version;
        // Implementation's getVersion is unreachable!
    }

    /**
     * @notice VULNERABLE: getImplementation shadows implementation's function
     */
    function getImplementation() external view returns (address) {
        return implementation;
        // Implementation might have its own getImplementation!
    }

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
 * @notice VULNERABLE: Fallback with hardcoded selector checks
 */
contract HardcodedSelectorShadowing {
    address public implementation;

    // Hardcoded selectors that are intercepted
    bytes4 private constant ADMIN_SELECTOR = 0xf851a440; // admin()
    bytes4 private constant OWNER_SELECTOR = 0x8da5cb5b; // owner()

    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABLE: Fallback intercepts specific selectors
     * @dev Hardcoded checks shadow implementation functions
     */
    fallback() external payable {
        bytes4 selector = msg.sig;

        // VULNERABLE: These selectors are intercepted and never reach implementation
        if (selector == ADMIN_SELECTOR || selector == OWNER_SELECTOR) {
            assembly {
                mstore(0, sload(admin.slot))
                return(0, 32)
            }
        }

        // Other calls delegated
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
