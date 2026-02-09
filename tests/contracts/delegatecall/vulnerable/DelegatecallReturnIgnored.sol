// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DelegatecallReturnIgnored
 * @notice VULNERABLE: Delegatecall without checking return value
 * @dev This contract demonstrates the critical vulnerability of performing
 *      delegatecall operations without validating the return value.
 *
 * Vulnerability: CWE-252 (Unchecked Return Value)
 * Severity: HIGH
 * Impact: Silent failures, state corruption, fund loss, incorrect state assumptions
 *
 * When delegatecall return value is ignored:
 * 1. Failures go unnoticed and execution continues
 * 2. Contract assumes operation succeeded when it failed
 * 3. State may be partially updated or corrupted
 * 4. Critical operations may fail silently
 *
 * Real-world impact:
 * - Silent failures in proxy upgrades
 * - Partial state updates causing corruption
 * - Failed critical operations treated as successful
 * - Fund transfers that fail without notice
 *
 * Attack scenario:
 * 1. Attacker provides malicious target that reverts
 * 2. Contract performs delegatecall without checking return
 * 3. Operation fails but contract continues as if successful
 * 4. Contract state becomes corrupted or inconsistent
 */

/**
 * @notice VULNERABLE: Direct delegatecall without checking return
 */
contract IgnoredReturnDelegatecall {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    /**
     * @notice CRITICAL VULNERABILITY: Delegatecall return value not checked
     * @dev If delegatecall fails, execution continues without error
     */
    function execute(bytes calldata data) external {
        // VULNERABLE: Return value ignored!
        implementation.delegatecall(data);
        // If delegatecall failed, we'll never know
        // Contract continues as if everything succeeded
    }

    /**
     * @notice VULNERABLE: Statement-position delegatecall
     */
    function executeStatement(bytes memory data) external {
        // VULNERABLE: Used as statement, return not captured
        implementation.delegatecall(data);
    }
}

/**
 * @notice VULNERABLE: Delegatecall in proxy upgrade without validation
 */
contract VulnerableProxyUpgrade {
    address public implementation;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Upgrade without checking delegatecall success
     */
    function upgrade(address newImpl, bytes memory initData) external {
        require(msg.sender == owner, "Only owner");

        implementation = newImpl;

        // VULNERABLE: Initialization delegatecall not checked
        if (initData.length > 0) {
            newImpl.delegatecall(initData);
            // If initialization fails, proxy is in broken state!
        }
    }
}

/**
 * @notice VULNERABLE: Batch operations without return checking
 */
contract BatchDelegatecallIgnored {
    address public libraryAddr;

    constructor(address _library) {
        libraryAddr = _library;
    }

    /**
     * @notice VULNERABLE: Batch calls without checking any returns
     */
    function batchExecute(bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            // VULNERABLE: Each call's return value ignored
            libraryAddr.delegatecall(data[i]);
            // If one fails, we continue to the next
        }
        // No way to know if any calls failed
    }
}

/**
 * @notice VULNERABLE: Return captured but not validated
 */
contract CapturedButNotChecked {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Return value assigned but never checked
     */
    function execute(bytes calldata data) external returns (bool) {
        (bool success, ) = implementation.delegatecall(data);
        // VULNERABLE: success captured but never validated
        // Just returned to caller who might also ignore it
        return success;
    }

    /**
     * @notice VULNERABLE: Only data returned, not success
     */
    function executeForData(bytes calldata data) external returns (bytes memory) {
        (, bytes memory result) = implementation.delegatecall(data);
        // VULNERABLE: success not captured, only data
        // If delegatecall failed, result is empty but we don't know
        return result;
    }
}

/**
 * @notice VULNERABLE: Conditional execution without checking return
 */
contract ConditionalDelegatecallIgnored {
    address public implementation;
    bool public paused;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Delegatecall in conditional without checking
     */
    function executeWhenActive(bytes calldata data) external {
        require(!paused, "Paused");

        // VULNERABLE: Return not checked
        implementation.delegatecall(data);

        // If call failed, we don't know and can't handle it
    }
}

/**
 * @notice VULNERABLE: Delegatecall in loop without checking
 */
contract LoopDelegatecallIgnored {
    address[] public implementations;

    function addImplementation(address impl) external {
        implementations.push(impl);
    }

    /**
     * @notice VULNERABLE: Loop delegates without checking any returns
     */
    function executeAll(bytes calldata data) external {
        for (uint256 i = 0; i < implementations.length; i++) {
            // VULNERABLE: Each delegatecall return ignored
            implementations[i].delegatecall(data);
        }
        // No way to know if all succeeded or some failed
    }
}

/**
 * @notice VULNERABLE: Assembly delegatecall without success check
 */
contract AssemblyDelegatecallIgnored {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Assembly delegatecall result not validated
     */
    function execute(bytes calldata data) external {
        address impl = implementation;

        // VULNERABLE: result not checked
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            // result is available but never checked
            return(0, returndatasize())
        }
    }

    /**
     * @notice VULNERABLE: Assembly delegatecall continues on failure
     */
    function executeNoCheck(bytes calldata data) external {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            // VULNERABLE: Always returns, even if result == 0 (failure)
            return(0, returndatasize())
        }
    }
}

/**
 * @notice VULNERABLE: Try-catch without handling failure
 */
contract TryCatchNoHandling {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Try-catch with empty catch
     */
    function executeWithEmptyCatch(bytes calldata data) external {
        try this.internalDelegatecall(data) {
            // Success path
        } catch {
            // VULNERABLE: Catch block is empty, failure ignored
            // Contract continues as if nothing happened
        }
    }

    function internalDelegatecall(bytes calldata data) external {
        implementation.delegatecall(data);
    }
}

/**
 * @notice VULNERABLE: Event emission without return check
 */
contract EventEmittedWithoutCheck {
    address public implementation;

    event Executed(bytes data);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Event emitted regardless of success
     */
    function execute(bytes calldata data) external {
        // VULNERABLE: Delegatecall return not checked
        implementation.delegatecall(data);

        // Event emitted even if delegatecall failed!
        emit Executed(data);
    }
}

/**
 * @notice VULNERABLE: State change after unchecked delegatecall
 */
contract StateChangeAfterIgnoredReturn {
    address public implementation;
    uint256 public counter;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: State updated regardless of delegatecall result
     */
    function execute(bytes calldata data) external {
        // VULNERABLE: Return not checked
        implementation.delegatecall(data);

        // DANGEROUS: State updated even if delegatecall failed
        counter++;
    }
}

/**
 * @notice VULNERABLE: Payment after unchecked delegatecall
 */
contract PaymentAfterIgnoredReturn {
    address public implementation;
    mapping(address => uint256) public balances;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Payment sent regardless of delegatecall success
     */
    function executeAndPay(bytes calldata data, address payable recipient, uint256 amount) external {
        // VULNERABLE: Delegatecall return not checked
        implementation.delegatecall(data);

        // DANGEROUS: Payment sent even if delegatecall failed
        recipient.transfer(amount);
    }
}

/**
 * @notice VULNERABLE: Modifier with unchecked delegatecall
 */
contract ModifierWithIgnoredReturn {
    address public validator;

    /**
     * @notice VULNERABLE: Modifier delegates without checking
     */
    modifier validate(bytes memory data) {
        // VULNERABLE: Delegatecall in modifier without check
        validator.delegatecall(data);
        // Modifier continues even if validation failed!
        _;
    }

    function executeWithValidation(bytes memory validationData, bytes memory action)
        external
        validate(validationData)
    {
        // This executes even if validation delegatecall failed
    }
}

/**
 * @notice VULNERABLE: Constructor with unchecked delegatecall
 */
contract ConstructorIgnoredReturn {
    address public implementation;

    /**
     * @notice VULNERABLE: Constructor delegates without checking
     */
    constructor(address _implementation, bytes memory initData) {
        implementation = _implementation;

        if (initData.length > 0) {
            // VULNERABLE: Initialization delegatecall not checked
            _implementation.delegatecall(initData);
            // Contract deployed even if initialization failed!
        }
    }
}

/**
 * @notice VULNERABLE: Fallback with unchecked delegatecall
 */
contract FallbackIgnoredReturn {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Fallback delegates without checking
     */
    fallback() external payable {
        address impl = implementation;
        // VULNERABLE: No check on delegatecall success
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            // Returns even if result == 0 (failure)
            return(0, returndatasize())
        }
    }
}
