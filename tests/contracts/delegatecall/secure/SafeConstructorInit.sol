// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SafeConstructorInit
 * @notice SECURE: Safe initialization patterns without constructor delegatecall
 * @dev This contract demonstrates secure alternatives to delegatecall in constructors.
 *
 * Security Pattern: Separate initialization from construction
 * Benefits: Predictable initialization, no storage corruption risk, atomic operations
 * Compliance: Proxy initialization best practices
 *
 * Best practices:
 * 1. Avoid delegatecall in constructors
 * 2. Use initialize() pattern for proxies
 * 3. Set immutable values in constructor
 * 4. Validate all initialization parameters
 * 5. Use initializer modifier for reentrancy protection
 */

/**
 * @notice SECURE: Direct initialization in constructor (no delegatecall)
 */
contract DirectConstructorInit {
    address public owner;
    uint256 public value;
    bool public initialized;

    event Initialized(address owner, uint256 value);

    /**
     * @notice SECURE: Direct initialization, no delegatecall
     */
    constructor(uint256 _value) {
        owner = msg.sender;
        value = _value;
        initialized = true;

        emit Initialized(owner, value);
    }
}

/**
 * @notice SECURE: Proxy with post-deployment initialization
 */
contract SecureProxyInit {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bool private initialized;

    /**
     * @notice SECURE: Constructor only sets immutable data
     */
    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");

        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _implementation)
        }
    }

    /**
     * @notice SECURE: Initialize called after deployment (not in constructor)
     */
    function initialize(bytes calldata data) external {
        require(!initialized, "Already initialized");

        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly { impl := sload(slot) }

        (bool success, ) = impl.delegatecall(data);
        require(success, "Initialization failed");

        initialized = true;
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
 * @notice SECURE: Initializable base contract pattern
 */
abstract contract Initializable {
    bool private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(
            _initializing || !_initialized,
            "Already initialized"
        );

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }

    modifier onlyInitializing() {
        require(_initializing, "Not initializing");
        _;
    }
}

/**
 * @notice SECURE: Contract using initializable pattern
 */
contract SecureInitializableContract is Initializable {
    address public owner;
    uint256 public value;

    event Initialized(address owner, uint256 value);

    constructor() {
        // SECURE: Constructor is empty or minimal
    }

    /**
     * @notice SECURE: Initialization done post-deployment
     */
    function initialize(address _owner, uint256 _value) external initializer {
        owner = _owner;
        value = _value;

        emit Initialized(_owner, _value);
    }
}

/**
 * @notice SECURE: Factory with safe initialization
 */
contract SecureFactory {
    event ContractCreated(address indexed newContract, address indexed creator);

    /**
     * @notice SECURE: Creates and initializes in two steps
     */
    function createContract(uint256 value) external returns (address) {
        // SECURE: Create with direct constructor params
        SecureInitContract newContract = new SecureInitContract(msg.sender, value);

        emit ContractCreated(address(newContract), msg.sender);
        return address(newContract);
    }
}

contract SecureInitContract {
    address public creator;
    uint256 public value;

    /**
     * @notice SECURE: Direct parameter initialization
     */
    constructor(address _creator, uint256 _value) {
        creator = _creator;
        value = _value;
    }
}

/**
 * @notice SECURE: Clone factory with safe initialization
 */
contract SecureCloneFactory {
    address public immutable implementation;

    event CloneCreated(address indexed clone);

    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Clone then call initialize (not delegatecall)
     */
    function clone(bytes memory initData) external returns (address instance) {
        instance = createClone(implementation);

        // SECURE: Regular call to initialize, not delegatecall
        (bool success, ) = instance.call(
            abi.encodeWithSignature("initialize(bytes)", initData)
        );
        require(success, "Initialization failed");

        emit CloneCreated(instance);
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
 * @notice SECURE: UUPS proxy with proper initialization
 */
contract SecureUUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    /**
     * @notice SECURE: Constructor sets implementation, no delegatecall
     */
    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");

        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _implementation)
        }
    }

    /**
     * @notice SECURE: Initialization via fallback after deployment
     */
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

    receive() external payable {}
}

/**
 * @notice SECURE: Beacon proxy with safe initialization
 */
contract SecureBeaconProxy {
    address public immutable beacon;
    bool private initialized;

    constructor(address _beacon) {
        require(_beacon != address(0), "Invalid beacon");
        beacon = _beacon;
    }

    /**
     * @notice SECURE: Initialize after deployment
     */
    function initialize(bytes calldata data) external {
        require(!initialized, "Already initialized");

        address implementation = IBeacon(beacon).implementation();
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Initialization failed");

        initialized = true;
    }

    fallback() external payable {
        address implementation = IBeacon(beacon).implementation();

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

interface IBeacon {
    function implementation() external view returns (address);
}

/**
 * @notice SECURE: Diamond with safe initialization
 */
contract SecureDiamondProxy {
    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
        bytes4[] functionSelectors;
        bool initialized;
    }

    bytes32 private constant DIAMOND_STORAGE_POSITION =
        keccak256("diamond.standard.diamond.storage");

    /**
     * @notice SECURE: Constructor only sets up facets
     */
    constructor(address[] memory facets, bytes4[][] memory selectors) {
        require(facets.length == selectors.length, "Length mismatch");

        DiamondStorage storage ds = diamondStorage();

        for (uint256 i = 0; i < facets.length; i++) {
            address facet = facets[i];
            require(facet != address(0), "Invalid facet");

            for (uint256 j = 0; j < selectors[i].length; j++) {
                bytes4 selector = selectors[i][j];

                ds.selectorToFacetAndPosition[selector].facetAddress = facet;
                ds.selectorToFacetAndPosition[selector].functionSelectorPosition =
                    uint96(ds.functionSelectors.length);
                ds.functionSelectors.push(selector);
            }
        }
    }

    /**
     * @notice SECURE: Initialize called separately after deployment
     */
    function initialize(address initContract, bytes calldata initData) external {
        DiamondStorage storage ds = diamondStorage();
        require(!ds.initialized, "Already initialized");

        (bool success, ) = initContract.delegatecall(initData);
        require(success, "Initialization failed");

        ds.initialized = true;
    }

    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;
        require(facet != address(0), "Function does not exist");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}

/**
 * @notice SECURE: Two-step initialization pattern
 */
contract TwoStepInitialization {
    address public owner;
    address public implementation;
    bool public phase1Complete;
    bool public phase2Complete;

    event Phase1Complete();
    event Phase2Complete();

    /**
     * @notice SECURE: Constructor does phase 1
     */
    constructor(address _owner) {
        require(_owner != address(0), "Invalid owner");
        owner = _owner;
        phase1Complete = true;

        emit Phase1Complete();
    }

    /**
     * @notice SECURE: Phase 2 done after deployment
     */
    function initializePhase2(address _implementation) external {
        require(msg.sender == owner, "Only owner");
        require(phase1Complete, "Phase 1 not complete");
        require(!phase2Complete, "Already initialized");

        implementation = _implementation;
        phase2Complete = true;

        emit Phase2Complete();
    }
}

/**
 * @notice SECURE: Immutable constructor pattern
 */
contract ImmutableConstructorInit {
    address public immutable owner;
    uint256 public immutable createdAt;
    address public immutable factory;

    /**
     * @notice SECURE: All immutable values set in constructor
     */
    constructor(address _owner, uint256 _value) {
        owner = _owner;
        createdAt = block.timestamp;
        factory = msg.sender;
    }
}
