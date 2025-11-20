// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableDiamond
 * @notice Test contract for Diamond Pattern (EIP-2535) vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. function-selector-collision - Function selectors may collide across facets
 * 2. unprotected-diamond-cut - Anyone can add/remove/replace facets
 * 3. storage-collision - Facets may have conflicting storage layouts
 * 4. delegatecall-to-untrusted - Unsafe delegatecall to facets
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical
 * REFERENCE: EIP-2535 Diamond Standard
 */

contract VulnerableDiamond {
    // Diamond storage
    struct FacetAddressAndSelectorPosition {
        address facetAddress;
        uint16 selectorPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndSelectorPosition) facetAddressAndSelectorPosition;
        bytes4[] selectors;
        address owner;
    }

    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    constructor(address _owner) {
        DiamondStorage storage ds = diamondStorage();
        ds.owner = _owner;
    }

    // VULNERABILITY 1: No function selector collision check
    // Expected: function-selector-collision (CRITICAL)
    function addFunction(bytes4 selector, address facet) public {
        // VULNERABILITY 2: No access control
        // Expected: missing-access-control (CRITICAL)
        DiamondStorage storage ds = diamondStorage();

        // VULNERABILITY: No check if selector already exists!
        // Multiple facets could have same selector!
        ds.facetAddressAndSelectorPosition[selector].facetAddress = facet;
        ds.facetAddressAndSelectorPosition[selector].selectorPosition = uint16(ds.selectors.length);
        ds.selectors.push(selector);
    }

    // VULNERABILITY 3: Anyone can remove functions
    // Expected: missing-access-control (CRITICAL)
    function removeFunction(bytes4 selector) public {
        DiamondStorage storage ds = diamondStorage();
        delete ds.facetAddressAndSelectorPosition[selector];
    }

    // VULNERABILITY 4: Anyone can replace facets (diamond cut)
    // Expected: unprotected-diamond-cut (CRITICAL)
    function replaceFacet(bytes4 selector, address newFacet) public {
        DiamondStorage storage ds = diamondStorage();
        ds.facetAddressAndSelectorPosition[selector].facetAddress = newFacet;
    }

    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.facetAddressAndSelectorPosition[msg.sig].facetAddress;

        // VULNERABILITY 5: No check if facet exists
        // Expected: missing-contract-existence-check (HIGH)
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
}

/**
 * @title DiamondFacet1
 * @notice First diamond facet with storage
 */
contract DiamondFacet1 {
    // VULNERABILITY 6: Storage collision between facets
    // Expected: proxy-storage-collision (CRITICAL)
    address public owner; // Slot 0
    uint256 public value1; // Slot 1

    function setValue1(uint256 _value) public {
        value1 = _value;
    }
}

/**
 * @title DiamondFacet2
 * @notice Second diamond facet with conflicting storage
 */
contract DiamondFacet2 {
    // VULNERABILITY: Same storage layout as Facet1 - COLLISION!
    address public admin; // Slot 0 - COLLIDES with owner
    uint256 public value2; // Slot 1 - COLLIDES with value1

    function setValue2(uint256 _value) public {
        value2 = _value;
    }
}
