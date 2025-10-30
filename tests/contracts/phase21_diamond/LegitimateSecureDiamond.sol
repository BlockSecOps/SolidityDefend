// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title LegitimateSecureDiamond
 * @notice Properly implemented EIP-2535 Diamond Proxy following all best practices
 * @dev This contract should NOT trigger false positives from Phase 21 detectors
 *
 * Best Practices Implemented:
 * 1. Proper diamond storage pattern (no collisions)
 * 2. Function selector collision prevention
 * 3. Initialization reentrancy protection
 * 4. EIP-2535 loupe compliance
 * 5. Safe delegatecall with zero address checks
 */

// Diamond Storage Pattern (Proper - No Collisions)
library LibDiamondStorage {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition;
    }

    struct FacetFunctionSelectors {
        bytes4[] functionSelectors;
        uint256 facetAddressPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
        mapping(address => FacetFunctionSelectors) facetFunctionSelectors;
        address[] facetAddresses;
        mapping(bytes4 => bool) supportedInterfaces;
        address contractOwner;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }
}

// Initialization with Reentrancy Protection
library LibDiamondInit {
    bytes32 constant INIT_STORAGE_POSITION = keccak256("diamond.init.storage");

    struct InitStorage {
        bool initialized;
        bool initializing;
    }

    function initStorage() internal pure returns (InitStorage storage s) {
        bytes32 position = INIT_STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }

    modifier initializer() {
        InitStorage storage s = initStorage();
        require(!s.initialized, "Already initialized");
        require(!s.initializing, "Initialization in progress");

        s.initializing = true;
        _;
        s.initializing = false;
        s.initialized = true;
    }
}

// EIP-2535 Loupe Interface (Compliant)
interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function facets() external view returns (Facet[] memory facets_);
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory facetFunctionSelectors_);
    function facetAddresses() external view returns (address[] memory facetAddresses_);
    function facetAddress(bytes4 _functionSelector) external view returns (address facetAddress_);
}

// Diamond Cut Interface
interface IDiamondCut {
    enum FacetCutAction {Add, Replace, Remove}

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    function diamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external;
}

contract SecureDiamond is IDiamondLoupe {
    using LibDiamondStorage for LibDiamondStorage.DiamondStorage;

    constructor(address _contractOwner, address _diamondCutFacet) payable {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        ds.contractOwner = _contractOwner;

        // Add the diamondCut external function from the diamondCutFacet
        // Zero address check prevents delegatecall to zero
        require(_diamondCutFacet != address(0), "Diamond cut facet cannot be zero address");

        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = IDiamondCut.diamondCut.selector;
        addFunctions(_diamondCutFacet, functionSelectors);

        // Add EIP-165 support
        ds.supportedInterfaces[type(IDiamondLoupe).interfaceId] = true;
        ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
    }

    // Proper function selector management (prevents collisions)
    function addFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        require(_functionSelectors.length > 0, "No selectors provided");
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        require(_facetAddress != address(0), "Cannot add functions from zero address");

        uint96 selectorPosition = uint96(ds.facetFunctionSelectors[_facetAddress].functionSelectors.length);

        // Check for selector collisions before adding
        for (uint256 i = 0; i < _functionSelectors.length; i++) {
            bytes4 selector = _functionSelectors[i];

            // Prevent selector collision
            address oldFacetAddress = ds.selectorToFacetAndPosition[selector].facetAddress;
            require(oldFacetAddress == address(0), "Function selector collision detected");

            ds.facetFunctionSelectors[_facetAddress].functionSelectors.push(selector);
            ds.selectorToFacetAndPosition[selector].facetAddress = _facetAddress;
            ds.selectorToFacetAndPosition[selector].functionSelectorPosition = selectorPosition;
            selectorPosition++;
        }

        if (ds.facetFunctionSelectors[_facetAddress].functionSelectors.length == _functionSelectors.length) {
            ds.facetAddresses.push(_facetAddress);
            ds.facetFunctionSelectors[_facetAddress].facetAddressPosition = ds.facetAddresses.length - 1;
        }
    }

    // EIP-2535 Loupe Implementation (Compliant)
    function facets() external view override returns (Facet[] memory facets_) {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        uint256 numFacets = ds.facetAddresses.length;
        facets_ = new Facet[](numFacets);

        for (uint256 i = 0; i < numFacets; i++) {
            address facetAddress_ = ds.facetAddresses[i];
            facets_[i].facetAddress = facetAddress_;
            facets_[i].functionSelectors = ds.facetFunctionSelectors[facetAddress_].functionSelectors;
        }
    }

    function facetFunctionSelectors(address _facet) external view override returns (bytes4[] memory facetFunctionSelectors_) {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        facetFunctionSelectors_ = ds.facetFunctionSelectors[_facet].functionSelectors;
    }

    function facetAddresses() external view override returns (address[] memory facetAddresses_) {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        facetAddresses_ = ds.facetAddresses;
    }

    function facetAddress(bytes4 _functionSelector) external view override returns (address facetAddress_) {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        facetAddress_ = ds.selectorToFacetAndPosition[_functionSelector].facetAddress;
    }

    // Safe delegatecall with zero address check
    fallback() external payable {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;

        // Prevent delegatecall to zero address (Security best practice)
        require(facet != address(0), "Diamond: Function does not exist");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}

// Example Facet with Proper Initialization
contract ExampleFacet {
    using LibDiamondInit for LibDiamondInit.InitStorage;

    // Initialization function with reentrancy protection
    function init() external LibDiamondInit.initializer {
        // Safe initialization logic
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        // Initialize facet-specific storage
    }

    function exampleFunction() external pure returns (string memory) {
        return "Example function";
    }
}

/**
 * EXPECTED RESULTS:
 * ================
 * This contract follows all EIP-2535 Diamond Proxy best practices and should NOT trigger:
 *
 * ✅ diamond-storage-collision: Uses proper diamond storage pattern with unique slots
 * ✅ diamond-selector-collision: Checks for collisions before adding selectors
 * ✅ diamond-init-reentrancy: Uses initializer modifier with reentrancy protection
 * ✅ diamond-loupe-violation: Implements all required loupe functions correctly
 * ✅ diamond-delegatecall-zero: Checks facet address != 0 before delegatecall
 *
 * Expected Findings: 0 (Zero false positives)
 */
