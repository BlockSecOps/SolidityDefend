// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ImmutableLibraryDelegatecall
 * @notice SECURE: Delegatecall to immutable library addresses
 * @dev This contract demonstrates secure patterns for delegatecall to libraries
 *      using immutable addresses that cannot be changed after deployment.
 *
 * Security Pattern: Immutable library references
 * Benefits: Code integrity, no substitution attacks, predictable behavior
 * Compliance: Best practices for library delegation
 *
 * Best practices:
 * 1. Use immutable keyword for library addresses
 * 2. Set library address in constructor only
 * 3. Use constant for compile-time known addresses
 * 4. Document library version/hash
 * 5. Verify library code before deployment
 */

/**
 * @notice SECURE: Immutable library address
 */
contract ImmutableLibraryDelegatecall {
    address public immutable mathLibrary;  // SECURE: Cannot be changed!

    event LibraryExecuted(bytes data, bytes result);

    constructor(address _library) {
        require(_library != address(0), "Invalid library");
        // SECURE: Set once in constructor, immutable forever
        mathLibrary = _library;
    }

    /**
     * @notice SECURE: Uses immutable library address
     */
    function calculate(bytes calldata data) external returns (uint256) {
        // SECURE: Library address is immutable
        (bool success, bytes memory result) = mathLibrary.delegatecall(data);
        require(success, "Library call failed");

        emit LibraryExecuted(data, result);
        return abi.decode(result, (uint256));
    }
}

/**
 * @notice SECURE: Multiple immutable libraries
 */
contract MultipleImmutableLibraries {
    address public immutable mathLibrary;
    address public immutable stringLibrary;
    address public immutable arrayLibrary;

    constructor(
        address _math,
        address _string,
        address _array
    ) {
        require(_math != address(0), "Invalid math library");
        require(_string != address(0), "Invalid string library");
        require(_array != address(0), "Invalid array library");

        // SECURE: All libraries set once and immutable
        mathLibrary = _math;
        stringLibrary = _string;
        arrayLibrary = _array;
    }

    function executeMath(bytes memory data) external returns (bytes memory) {
        (bool success, bytes memory result) = mathLibrary.delegatecall(data);
        require(success, "Math library failed");
        return result;
    }

    function executeString(bytes memory data) external returns (bytes memory) {
        (bool success, bytes memory result) = stringLibrary.delegatecall(data);
        require(success, "String library failed");
        return result;
    }

    function executeArray(bytes memory data) external returns (bytes memory) {
        (bool success, bytes memory result) = arrayLibrary.delegatecall(data);
        require(success, "Array library failed");
        return result;
    }
}

/**
 * @notice SECURE: Constant library address (compile-time known)
 */
contract ConstantLibraryDelegatecall {
    // SECURE: Known at compile time, truly immutable
    address public constant MATH_LIBRARY = 0x1234567890123456789012345678901234567890;

    function calculate(bytes memory data) external returns (uint256) {
        // SECURE: Uses constant address
        (bool success, bytes memory result) = MATH_LIBRARY.delegatecall(data);
        require(success, "Library call failed");
        return abi.decode(result, (uint256));
    }
}

/**
 * @notice SECURE: Immutable library with version tracking
 */
contract VersionedImmutableLibrary {
    address public immutable library;
    string public constant LIBRARY_VERSION = "1.0.0";
    bytes32 public constant LIBRARY_CODE_HASH = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;

    constructor(address _library) {
        require(_library != address(0), "Invalid library");

        // SECURE: Verify library code hash
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(_library)
        }
        require(codeHash == LIBRARY_CODE_HASH, "Library code mismatch");

        library = _library;
    }

    function execute(bytes memory data) external returns (bytes memory) {
        (bool success, bytes memory result) = library.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }
}

/**
 * @notice SECURE: Immutable proxy (UUPS pattern)
 * @dev Upgrades handled in implementation, not proxy
 */
contract ImmutableUUPSProxy {
    // SECURE: Implementation set once, upgrades in implementation
    address public immutable initialImplementation;

    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation, bytes memory _data) {
        require(_implementation != address(0), "Invalid implementation");

        initialImplementation = _implementation;
        _setImplementation(_implementation);

        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        address impl = _getImplementation();
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

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, newImplementation) }
    }
}

/**
 * @notice SECURE: Beacon pattern with immutable beacon
 */
contract ImmutableBeaconProxy {
    address public immutable beacon;  // SECURE: Beacon address immutable

    constructor(address _beacon, bytes memory _data) {
        require(_beacon != address(0), "Invalid beacon");
        beacon = _beacon;

        if (_data.length > 0) {
            (bool success, ) = _getImplementation().delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        address impl = _getImplementation();
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

    function _getImplementation() internal view returns (address) {
        return IBeacon(beacon).implementation();
    }
}

interface IBeacon {
    function implementation() external view returns (address);
}

/**
 * @notice SECURE: Diamond with immutable diamond cut
 * @dev Uses EIP-2535 with immutable core
 */
contract ImmutableDiamondProxy {
    bytes32 private constant DIAMOND_STORAGE_POSITION =
        keccak256("diamond.standard.diamond.storage");

    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
        bytes4[] functionSelectors;
    }

    constructor(address[] memory _facets, bytes4[][] memory _selectors) {
        require(_facets.length == _selectors.length, "Length mismatch");

        DiamondStorage storage ds = diamondStorage();

        for (uint256 i = 0; i < _facets.length; i++) {
            address facet = _facets[i];
            require(facet != address(0), "Invalid facet");

            for (uint256 j = 0; j < _selectors[i].length; j++) {
                bytes4 selector = _selectors[i][j];

                // SECURE: Selectors set once at deployment
                ds.selectorToFacetAndPosition[selector].facetAddress = facet;
                ds.selectorToFacetAndPosition[selector].functionSelectorPosition =
                    uint96(ds.functionSelectors.length);
                ds.functionSelectors.push(selector);
            }
        }
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
 * @notice SECURE: Library with integrity check
 */
contract IntegrityCheckedLibrary {
    address public immutable library;
    bytes32 public immutable expectedCodeHash;

    event IntegrityVerified(address library, bytes32 codeHash);

    constructor(address _library, bytes32 _expectedCodeHash) {
        require(_library != address(0), "Invalid library");

        // SECURE: Verify code hash at deployment
        bytes32 actualCodeHash;
        assembly {
            actualCodeHash := extcodehash(_library)
        }
        require(actualCodeHash == _expectedCodeHash, "Code hash mismatch");

        library = _library;
        expectedCodeHash = _expectedCodeHash;

        emit IntegrityVerified(_library, actualCodeHash);
    }

    function execute(bytes memory data) external returns (bytes memory) {
        // SECURE: Library is immutable and verified
        (bool success, bytes memory result) = library.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }

    /**
     * @notice Allows anyone to verify library integrity
     */
    function verifyIntegrity() external view returns (bool) {
        bytes32 currentCodeHash;
        assembly {
            currentCodeHash := extcodehash(sload(library.slot))
        }
        return currentCodeHash == expectedCodeHash;
    }
}

/**
 * @notice SECURE: Immutable library registry pattern
 */
contract ImmutableLibraryRegistry {
    struct LibraryInfo {
        address libraryAddress;
        string version;
        bytes32 codeHash;
    }

    mapping(string => LibraryInfo) public immutableLibraries;
    bool public initialized;

    /**
     * @notice SECURE: Initialize once pattern
     */
    function initialize(
        string[] memory names,
        address[] memory addresses,
        string[] memory versions,
        bytes32[] memory codeHashes
    ) external {
        require(!initialized, "Already initialized");
        require(names.length == addresses.length, "Length mismatch");

        for (uint256 i = 0; i < names.length; i++) {
            immutableLibraries[names[i]] = LibraryInfo({
                libraryAddress: addresses[i],
                version: versions[i],
                codeHash: codeHashes[i]
            });
        }

        initialized = true;
    }

    function executeLibrary(string memory name, bytes memory data) external returns (bytes memory) {
        LibraryInfo memory lib = immutableLibraries[name];
        require(lib.libraryAddress != address(0), "Library not found");

        // SECURE: Library address cannot change after initialization
        (bool success, bytes memory result) = lib.libraryAddress.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }
}

/**
 * @notice SECURE: Example math library
 */
contract SecureMathLibrary {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    function multiply(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }
}
