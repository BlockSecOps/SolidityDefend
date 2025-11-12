// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ConstructorDelegatecall
 * @notice VULNERABLE: Delegatecall in constructor
 * @dev This contract demonstrates the risks of performing delegatecall during
 *      contract construction, which can lead to unexpected initialization behavior.
 *
 * Vulnerability: CWE-665 (Improper Initialization)
 * Severity: MEDIUM
 * Impact: Storage corruption, failed initialization, deployment of broken contracts
 *
 * Constructor delegatecall risks:
 * 1. Storage layout mismatches during initialization
 * 2. Reentrancy during construction
 * 3. User-controlled constructor parameters
 * 4. Failed delegatecall leaving contract in broken state
 *
 * Real-world impact:
 * - Proxy contracts with broken initialization
 * - Factories deploying corrupted contracts
 * - Front-running constructor calls
 *
 * Attack scenario:
 * 1. Attacker provides malicious init address
 * 2. Constructor delegatecalls to attacker's contract
 * 3. Attacker's code corrupts storage during construction
 * 4. Contract deploys in broken/exploitable state
 */

/**
 * @notice VULNERABLE: Constructor with unchecked delegatecall
 */
contract UncheckedConstructorDelegatecall {
    address public owner;
    uint256 public value;

    /**
     * @notice VULNERABLE: Delegatecall in constructor without checking
     */
    constructor(address initLogic, bytes memory initData) {
        // VULNERABLE: If delegatecall fails, contract still deploys!
        initLogic.delegatecall(initData);

        owner = msg.sender;
    }
}

/**
 * @notice VULNERABLE: User-controlled constructor delegatecall
 */
contract UserControlledConstructorDelegatecall {
    address public implementation;
    bool public initialized;

    /**
     * @notice VULNERABLE: User controls delegatecall target in constructor
     */
    constructor(address userProvidedLogic, bytes memory data) {
        // VULNERABLE: User can provide malicious address!
        (bool success, ) = userProvidedLogic.delegatecall(data);
        require(success, "Init failed");

        implementation = userProvidedLogic;
        initialized = true;
    }
}

/**
 * @notice VULNERABLE: Constructor delegatecall with storage corruption risk
 */
contract StorageCorruptionConstructor {
    address public admin;  // Slot 0
    uint256 public value;  // Slot 1
    bool public active;    // Slot 2

    /**
     * @notice VULNERABLE: Delegatecall can corrupt storage layout
     */
    constructor(address initContract) {
        // VULNERABLE: initContract can write to any storage slot!
        (bool success, ) = initContract.delegatecall(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Init failed");

        admin = msg.sender;
    }
}

/**
 * @notice VULNERABLE: Proxy with constructor delegatecall
 */
contract VulnerableProxyConstructor {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    /**
     * @notice VULNERABLE: Constructor delegates without validation
     */
    constructor(address _implementation, bytes memory _data) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _implementation)
        }

        // VULNERABLE: Delegatecall during construction
        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            // VULNERABLE: No rollback if initialization fails!
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly { impl := sload(slot) }

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
 * @notice VULNERABLE: Factory with constructor delegatecall
 */
contract VulnerableFactory {
    event ContractCreated(address newContract);

    /**
     * @notice VULNERABLE: Creates contracts with delegatecall init
     */
    function createContract(address initLogic, bytes memory initData) external returns (address) {
        VulnerableInitContract newContract = new VulnerableInitContract(initLogic, initData);
        emit ContractCreated(address(newContract));
        return address(newContract);
    }
}

contract VulnerableInitContract {
    address public creator;
    address public initLogic;

    constructor(address _initLogic, bytes memory initData) {
        creator = msg.sender;
        initLogic = _initLogic;

        // VULNERABLE: Delegatecall in constructor
        (bool success, ) = _initLogic.delegatecall(initData);
        require(success, "Init failed");
    }
}

/**
 * @notice VULNERABLE: Clone factory with delegatecall init
 */
contract VulnerableCloneFactory {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Clones initialize via delegatecall
     */
    function clone(bytes memory initData) external returns (address) {
        address instance = createClone(implementation);

        // VULNERABLE: Delegatecall to user-influenced implementation
        (bool success, ) = instance.call(
            abi.encodeWithSignature("initialize(bytes)", initData)
        );
        require(success, "Init failed");

        return instance;
    }

    function createClone(address target) internal returns (address result) {
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, clone, 0x37)
        }
    }
}

/**
 * @notice VULNERABLE: Reentrancy during constructor
 */
contract ReentrancyConstructorDelegatecall {
    address public token;
    uint256 public balance;

    /**
     * @notice VULNERABLE: Constructor delegates which could reenter
     */
    constructor(address initContract) payable {
        // VULNERABLE: initContract could call back during construction!
        (bool success, ) = initContract.delegatecall{value: msg.value}(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Init failed");

        balance = address(this).balance;
    }

    function withdraw() external {
        payable(msg.sender).transfer(balance);
        balance = 0;
    }
}

/**
 * @notice VULNERABLE: Multiple constructor delegatecalls
 */
contract MultipleConstructorDelegatecalls {
    address public moduleA;
    address public moduleB;
    bool public initializedA;
    bool public initializedB;

    /**
     * @notice VULNERABLE: Multiple delegatecalls in constructor
     */
    constructor(address _moduleA, address _moduleB) {
        // VULNERABLE: First delegatecall
        (bool successA, ) = _moduleA.delegatecall(
            abi.encodeWithSignature("initA()")
        );
        require(successA, "Init A failed");
        initializedA = true;
        moduleA = _moduleA;

        // VULNERABLE: Second delegatecall (could interact with first's state)
        (bool successB, ) = _moduleB.delegatecall(
            abi.encodeWithSignature("initB()")
        );
        require(successB, "Init B failed");
        initializedB = true;
        moduleB = _moduleB;
    }
}

/**
 * @notice VULNERABLE: Constructor with delegatecall loop
 */
contract ConstructorDelegatecallLoop {
    address[] public initializers;
    bool public fullyInitialized;

    /**
     * @notice VULNERABLE: Loops through delegatecalls in constructor
     */
    constructor(address[] memory _initializers) {
        initializers = _initializers;

        for (uint256 i = 0; i < _initializers.length; i++) {
            // VULNERABLE: Each delegatecall could corrupt state
            (bool success, ) = _initializers[i].delegatecall(
                abi.encodeWithSignature("initialize(uint256)", i)
            );
            require(success, "Init failed");
        }

        fullyInitialized = true;
    }
}

/**
 * @notice VULNERABLE: Conditional constructor delegatecall
 */
contract ConditionalConstructorDelegatecall {
    address public logic;
    bool public useCustomInit;

    /**
     * @notice VULNERABLE: Conditional delegatecall based on parameter
     */
    constructor(bool _useCustomInit, address customLogic) {
        useCustomInit = _useCustomInit;

        if (_useCustomInit) {
            // VULNERABLE: User controls whether delegatecall happens
            (bool success, ) = customLogic.delegatecall(
                abi.encodeWithSignature("customInit()")
            );
            require(success, "Custom init failed");
            logic = customLogic;
        }
    }
}

/**
 * @notice VULNERABLE: Constructor delegatecall with ETH transfer
 */
contract ConstructorDelegatecallWithValue {
    address public implementation;
    uint256 public initialBalance;

    /**
     * @notice VULNERABLE: Delegatecall with value in constructor
     */
    constructor(address _implementation) payable {
        // VULNERABLE: Sending ETH during delegatecall in constructor
        (bool success, ) = _implementation.delegatecall{value: msg.value}(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Init failed");

        implementation = _implementation;
        initialBalance = address(this).balance;
    }
}

/**
 * @notice ATTACK CONTRACT - Malicious initializer
 */
contract MaliciousInitializer {
    /**
     * @notice Malicious init that corrupts storage
     */
    function initialize() external {
        // Corrupt first storage slot (usually owner/admin)
        assembly {
            sstore(0, caller())  // Set slot 0 to attacker
            sstore(1, 0xdead)    // Corrupt slot 1
        }
    }

    /**
     * @notice Malicious init that reenters
     */
    function initWithReentry() external {
        // Could call back to constructor's contract
        (bool success, ) = msg.sender.call(
            abi.encodeWithSignature("someFunction()")
        );
        require(success);
    }
}

/**
 * @notice VULNERABLE: Diamond proxy with constructor delegatecall
 */
contract VulnerableDiamondConstructor {
    struct FacetCut {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    bytes32 private constant DIAMOND_STORAGE_POSITION =
        keccak256("diamond.standard.diamond.storage");

    /**
     * @notice VULNERABLE: Constructor delegates to init diamond
     */
    constructor(FacetCut[] memory _cuts, address _init, bytes memory _calldata) {
        // Add facets
        for (uint256 i = 0; i < _cuts.length; i++) {
            // ... facet setup ...
        }

        // VULNERABLE: Delegatecall during construction
        if (_init != address(0)) {
            (bool success, ) = _init.delegatecall(_calldata);
            require(success, "Diamond init failed");
        }
    }
}

/**
 * @notice VULNERABLE: Beacon with constructor delegatecall
 */
contract VulnerableBeaconConstructor {
    address public beacon;

    /**
     * @notice VULNERABLE: Constructor gets implementation and delegates
     */
    constructor(address _beacon, bytes memory _data) {
        beacon = _beacon;

        if (_data.length > 0) {
            address implementation = IBeacon(_beacon).implementation();

            // VULNERABLE: Delegatecall in constructor
            (bool success, ) = implementation.delegatecall(_data);
            require(success, "Init failed");
        }
    }
}

interface IBeacon {
    function implementation() external view returns (address);
}
