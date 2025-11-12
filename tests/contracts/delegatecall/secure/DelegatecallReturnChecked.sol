// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DelegatecallReturnChecked
 * @notice SECURE: Delegatecall with proper return value validation
 * @dev This contract demonstrates secure patterns for performing delegatecall
 *      operations with proper return value checking and error handling.
 *
 * Security Pattern: Always validate delegatecall return values
 * Benefits: Detect failures, prevent silent errors, maintain state consistency
 * Compliance: CWE-252 prevention, Solidity best practices
 *
 * Best practices:
 * 1. Always capture delegatecall return value (bool success, bytes memory data)
 * 2. Check success before proceeding
 * 3. Use require() or revert() on failure
 * 4. Handle return data appropriately
 * 5. Emit events only after successful operations
 */

/**
 * @notice SECURE: Delegatecall with require check
 */
contract CheckedDelegatecall {
    address public implementation;
    address public owner;

    event ExecutionSuccess(bytes data);
    event ExecutionFailed(bytes data, bytes reason);

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Delegatecall with require validation
     * @dev Reverts if delegatecall fails
     */
    function execute(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);

        // SECURE: Check return value
        require(success, "Delegatecall failed");

        emit ExecutionSuccess(data);
    }

    /**
     * @notice SECURE: Delegatecall with custom error message
     */
    function executeWithMessage(bytes calldata data, string memory errorMsg) external {
        (bool success, ) = implementation.delegatecall(data);

        // SECURE: Custom error message on failure
        require(success, errorMsg);
    }

    /**
     * @notice SECURE: Delegatecall with return data on failure
     */
    function executeWithRevert(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);

        // SECURE: Bubble up the revert reason
        if (!success) {
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }
    }
}

/**
 * @notice SECURE: Proxy upgrade with validation
 */
contract SecureProxyUpgrade {
    address public implementation;
    address public owner;

    event Upgraded(address indexed newImplementation);
    event InitializationFailed(address indexed implementation, bytes reason);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Upgrade with delegatecall validation
     */
    function upgrade(address newImpl, bytes memory initData) external {
        require(msg.sender == owner, "Only owner");
        require(newImpl != address(0), "Invalid implementation");

        implementation = newImpl;

        // SECURE: Check initialization if provided
        if (initData.length > 0) {
            (bool success, bytes memory returnData) = newImpl.delegatecall(initData);

            // Revert upgrade if initialization fails
            require(success, "Initialization failed");
        }

        emit Upgraded(newImpl);
    }

    /**
     * @notice SECURE: Upgrade with graceful initialization failure handling
     */
    function upgradeWithFallback(address newImpl, bytes memory initData) external {
        require(msg.sender == owner, "Only owner");

        address oldImpl = implementation;
        implementation = newImpl;

        if (initData.length > 0) {
            (bool success, bytes memory returnData) = newImpl.delegatecall(initData);

            // SECURE: Rollback if initialization fails
            if (!success) {
                implementation = oldImpl;
                emit InitializationFailed(newImpl, returnData);
                revert("Initialization failed, upgrade rolled back");
            }
        }

        emit Upgraded(newImpl);
    }
}

/**
 * @notice SECURE: Batch operations with return checking
 */
contract BatchDelegatecallChecked {
    address public library;

    event BatchExecutionComplete(uint256 successCount, uint256 failureCount);
    event CallFailed(uint256 indexed index, bytes data, bytes reason);

    constructor(address _library) {
        library = _library;
    }

    /**
     * @notice SECURE: Batch with all-or-nothing semantics
     */
    function batchExecute(bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory returnData) = library.delegatecall(data[i]);

            // SECURE: Revert entire batch if one fails
            if (!success) {
                emit CallFailed(i, data[i], returnData);
                revert("Batch execution failed");
            }
        }
    }

    /**
     * @notice SECURE: Batch with partial success allowed
     */
    function batchExecutePartial(bytes[] calldata data) external returns (bool[] memory results) {
        results = new bool[](data.length);
        uint256 successCount = 0;
        uint256 failureCount = 0;

        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory returnData) = library.delegatecall(data[i]);

            // SECURE: Track each result
            results[i] = success;

            if (success) {
                successCount++;
            } else {
                failureCount++;
                emit CallFailed(i, data[i], returnData);
            }
        }

        emit BatchExecutionComplete(successCount, failureCount);
    }
}

/**
 * @notice SECURE: Conditional execution with validation
 */
contract ConditionalDelegatecallChecked {
    address public implementation;
    bool public paused;

    event Executed(bytes data);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Delegatecall with validation
     */
    function executeWhenActive(bytes calldata data) external {
        require(!paused, "Paused");

        (bool success, bytes memory returnData) = implementation.delegatecall(data);

        // SECURE: Validate delegatecall succeeded
        if (!success) {
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        emit Executed(data);
    }
}

/**
 * @notice SECURE: Assembly delegatecall with success check
 */
contract AssemblyDelegatecallChecked {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Assembly delegatecall with result validation
     */
    function execute(bytes calldata data) external {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            // SECURE: Check result and revert on failure
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /**
     * @notice SECURE: Assembly with explicit failure handling
     */
    function executeWithCheck(bytes calldata data) external returns (bool) {
        address impl = implementation;
        bool success;

        assembly {
            calldatacopy(0, 0, calldatasize())
            success := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
        }

        // SECURE: Return success to caller for further handling
        require(success, "Delegatecall failed");
        return success;
    }
}

/**
 * @notice SECURE: Try-catch with proper error handling
 */
contract TryCatchWithHandling {
    address public implementation;

    event ExecutionFailed(bytes reason);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Try-catch with error handling
     */
    function executeWithTryCatch(bytes calldata data) external {
        try this.internalDelegatecall(data) {
            // Success path
        } catch Error(string memory reason) {
            // SECURE: Handle error with reason
            emit ExecutionFailed(bytes(reason));
            revert(reason);
        } catch (bytes memory lowLevelData) {
            // SECURE: Handle low-level errors
            emit ExecutionFailed(lowLevelData);
            revert("Low-level call failed");
        }
    }

    function internalDelegatecall(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);
        require(success, string(returnData));
    }
}

/**
 * @notice SECURE: State changes only after successful delegatecall
 */
contract StateChangeAfterCheck {
    address public implementation;
    uint256 public counter;

    event Executed(uint256 newCounter);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Update state only after successful delegatecall
     */
    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);

        // SECURE: Only update state if delegatecall succeeded
        require(success, "Delegatecall failed");

        counter++;
        emit Executed(counter);
    }
}

/**
 * @notice SECURE: Payment only after successful delegatecall
 */
contract PaymentAfterCheck {
    address public implementation;

    event PaymentSent(address indexed recipient, uint256 amount);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Send payment only after successful delegatecall
     */
    function executeAndPay(bytes calldata data, address payable recipient, uint256 amount) external {
        (bool success, ) = implementation.delegatecall(data);

        // SECURE: Only pay if delegatecall succeeded
        require(success, "Delegatecall failed");

        recipient.transfer(amount);
        emit PaymentSent(recipient, amount);
    }
}

/**
 * @notice SECURE: Modifier with delegatecall validation
 */
contract ModifierWithCheck {
    address public validator;

    /**
     * @notice SECURE: Modifier validates delegatecall success
     */
    modifier validate(bytes memory data) {
        (bool success, bytes memory result) = validator.delegatecall(data);

        // SECURE: Only proceed if validation succeeded
        require(success && abi.decode(result, (bool)), "Validation failed");
        _;
    }

    function executeWithValidation(bytes memory validationData, bytes memory action)
        external
        validate(validationData)
    {
        // This only executes if validation succeeded
    }
}

/**
 * @notice SECURE: Constructor with delegatecall validation
 */
contract ConstructorWithCheck {
    address public implementation;
    bool public initialized;

    /**
     * @notice SECURE: Constructor validates initialization delegatecall
     */
    constructor(address _implementation, bytes memory initData) {
        implementation = _implementation;

        if (initData.length > 0) {
            (bool success, ) = _implementation.delegatecall(initData);

            // SECURE: Deployment fails if initialization fails
            require(success, "Initialization failed");
            initialized = true;
        }
    }
}

/**
 * @notice SECURE: Fallback with delegatecall validation
 */
contract FallbackWithCheck {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Fallback checks delegatecall result
     */
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            // SECURE: Revert on failure, return on success
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice SECURE: Return data extraction with validation
 */
contract ReturnDataHandling {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Extract and validate return data
     */
    function executeForData(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = implementation.delegatecall(data);

        // SECURE: Only return data if call succeeded
        require(success, "Delegatecall failed");

        return result;
    }

    /**
     * @notice SECURE: Decode return data with validation
     */
    function executeForValue(bytes calldata data) external returns (uint256) {
        (bool success, bytes memory result) = implementation.delegatecall(data);

        // SECURE: Validate before decoding
        require(success, "Delegatecall failed");
        require(result.length >= 32, "Invalid return data");

        return abi.decode(result, (uint256));
    }
}
