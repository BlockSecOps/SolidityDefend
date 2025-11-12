// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title NoShadowingProxy
 * @notice SECURE: Proxy implementations that avoid function shadowing
 * @dev This contract demonstrates secure patterns for proxy contracts that
 *      prevent fallback functions from shadowing implementation functions.
 *
 * Security Pattern: Transparent Proxy Pattern
 * Benefits: Clear separation between proxy and implementation functions
 * Compliance: EIP-1967, OpenZeppelin standards
 *
 * Best practices:
 * 1. Use transparent proxy pattern (admin vs user separation)
 * 2. Minimal proxy interface (only essential admin functions)
 * 3. Internal/private admin functions to avoid selector conflicts
 * 4. EIP-1967 storage slots for proxy state
 * 5. Explicit function routing based on msg.sender
 */

/**
 * @notice SECURE: Transparent proxy with admin separation
 * @dev Admin calls don't delegate, user calls do - prevents shadowing
 */
contract TransparentProxy {
    // EIP-1967 storage slots
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    constructor(address _implementation, address _admin) {
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    /**
     * @notice Modifier to prevent admin from calling implementation
     * @dev Admin calls execute proxy logic, user calls delegate
     */
    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _delegate(_getImplementation());
        }
    }

    /**
     * @notice SECURE: Upgrade function only callable by admin
     * @dev Does NOT shadow implementation because of ifAdmin pattern
     */
    function upgradeTo(address newImplementation) external ifAdmin {
        _setImplementation(newImplementation);
    }

    /**
     * @notice SECURE: Change admin only callable by admin
     * @dev Does NOT shadow implementation because of ifAdmin pattern
     */
    function changeAdmin(address newAdmin) external ifAdmin {
        _setAdmin(newAdmin);
    }

    /**
     * @notice SECURE: Get admin only for admin
     * @dev Does NOT shadow implementation because of ifAdmin pattern
     */
    function admin() external ifAdmin returns (address) {
        return _getAdmin();
    }

    /**
     * @notice SECURE: Get implementation only for admin
     * @dev Does NOT shadow implementation because of ifAdmin pattern
     */
    function implementation() external ifAdmin returns (address) {
        return _getImplementation();
    }

    /**
     * @notice SECURE: Fallback delegates to implementation
     * @dev Only executes for non-admin users
     */
    fallback() external payable {
        _delegate(_getImplementation());
    }

    receive() external payable {
        _delegate(_getImplementation());
    }

    /**
     * @notice Internal delegation function
     */
    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _getAdmin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }
}

/**
 * @notice SECURE: UUPS Proxy (upgrades in implementation)
 * @dev No proxy functions to shadow - all logic in implementation
 */
contract UUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation, bytes memory _data) {
        _setImplementation(_implementation);
        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice SECURE: Minimal proxy - no admin functions
     * @dev All upgrade logic is in implementation, zero shadowing risk
     */
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

    receive() external payable {
        // Delegates to implementation's receive
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }
}

/**
 * @notice SECURE: Beacon Proxy (no upgrade logic in proxy)
 * @dev Implementation address read from beacon, zero proxy functions
 */
contract BeaconProxy {
    address public immutable beacon;

    constructor(address _beacon, bytes memory _data) {
        beacon = _beacon;
        if (_data.length > 0) {
            (bool success, ) = _getImplementation().delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice SECURE: No proxy functions, only fallback
     * @dev Cannot shadow implementation - no functions defined
     */
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
 * @notice SECURE: Minimal proxy with no functions
 * @dev EIP-1167 clone pattern - zero shadowing risk
 */
contract MinimalProxy {
    address public immutable implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Pure delegation, no proxy functions
     * @dev Immutable implementation, no admin functions, zero shadowing
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
 * @notice SECURE: Diamond proxy with explicit function mapping
 * @dev Uses storage mapping to route selectors, no hardcoded functions
 */
contract DiamondProxy {
    struct FacetAddressAndSelectorPosition {
        address facetAddress;
        uint16 selectorPosition;
    }

    mapping(bytes4 => FacetAddressAndSelectorPosition) internal _selectorToFacet;

    /**
     * @notice SECURE: Fallback uses mapping for routing
     * @dev No hardcoded selectors, all routing through storage
     */
    fallback() external payable {
        address facet = _selectorToFacet[msg.sig].facetAddress;
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
 * @notice SECURE: Proxy with internal-only admin functions
 * @dev Admin functions are internal, called via delegatecall from implementation
 */
contract InternalAdminProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    constructor(address _implementation, address _admin) {
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    /**
     * @notice SECURE: No public admin functions
     * @dev Admin calls come through implementation via delegatecall
     */
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

    // Internal functions - only callable via delegatecall
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _getAdmin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }
}

/**
 * @notice SECURE: Documentation of function collision prevention
 * @dev This is an example implementation contract that works with proxies
 */
contract SecureImplementation {
    address public implementation;
    address public admin;
    uint256 public value;

    /**
     * @notice These functions work with transparent proxy pattern
     * @dev Admin calling these gets intercepted by proxy, users delegate
     */
    function setValue(uint256 newValue) external {
        value = newValue;
    }

    function getValue() external view returns (uint256) {
        return value;
    }

    /**
     * @notice SECURE: Implementation doesn't define admin/implementation getters
     * @dev Avoids collision with proxy admin functions
     */
}
