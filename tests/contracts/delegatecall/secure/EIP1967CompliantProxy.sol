// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EIP1967CompliantProxy
 * @notice SECURE: Proxy using EIP-1967 standard storage slots
 * @dev This contract demonstrates the correct way to avoid storage collisions
 *      by using deterministic, pseudo-random storage slots as defined in EIP-1967.
 *
 * Security features:
 * 1. EIP-1967 compliant storage slots (impossible to collide accidentally)
 * 2. Storage gaps in upgradeable contracts
 * 3. Proper initialization patterns
 * 4. Namespaced storage for complex implementations
 *
 * EIP-1967 defines specific slots:
 * - Implementation: keccak256("eip1967.proxy.implementation") - 1
 * - Admin: keccak256("eip1967.proxy.admin") - 1
 * - Beacon: keccak256("eip1967.proxy.beacon") - 1
 *
 * These slots are chosen to:
 * - Be deterministic (same across all chains)
 * - Be pseudo-random (unlikely to collide with sequential storage)
 * - Be standardized (tooling can detect them)
 *
 * References:
 * - EIP-1967: https://eips.ethereum.org/EIPS/eip-1967
 * - OpenZeppelin implementation
 */

/**
 * @notice SECURE PROXY - EIP-1967 compliant
 */
contract EIP1967CompliantProxy {
    /**
     * @notice EIP-1967 Storage Slots
     * @dev These are calculated as:
     *      bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
     *
     * Slot values (for reference):
     * - Implementation: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
     * - Admin: 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
     */
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    constructor(address _implementation, address _admin) {
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    /**
     * @notice Upgrade to new implementation (admin only)
     */
    function upgradeTo(address newImplementation) external {
        require(msg.sender == _getAdmin(), "Only admin");
        require(newImplementation != address(0), "Invalid implementation");
        require(_isContract(newImplementation), "Must be contract");

        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @notice Change admin
     */
    function changeAdmin(address newAdmin) external {
        require(msg.sender == _getAdmin(), "Only admin");
        require(newAdmin != address(0), "Invalid admin");

        address previousAdmin = _getAdmin();
        _setAdmin(newAdmin);
        emit AdminChanged(previousAdmin, newAdmin);
    }

    /**
     * @notice Get current implementation
     */
    function implementation() public view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    /**
     * @notice Get current admin
     */
    function admin() public view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    /**
     * @notice Internal: Set implementation address
     */
    function _setImplementation(address newImplementation) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    /**
     * @notice Internal: Set admin address
     */
    function _setAdmin(address newAdmin) private {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    /**
     * @notice Internal: Get admin (avoiding public function shadowing)
     */
    function _getAdmin() private view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    /**
     * @notice Check if address is contract
     */
    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @notice Fallback with admin protection (Transparent Proxy pattern)
     */
    fallback() external payable {
        require(msg.sender != _getAdmin(), "Admin cannot fallback");
        _delegate(implementation());
    }

    receive() external payable {
        require(msg.sender != _getAdmin(), "Admin cannot receive");
        _delegate(implementation());
    }

    /**
     * @notice Internal: Delegate execution
     */
    function _delegate(address impl) private {
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
 * @notice SECURE IMPLEMENTATION - With storage gaps
 */
contract SecureImplementationV1 {
    // NO storage variables at top!
    // All storage goes after gap

    /**
     * @notice Storage gap to allow future variable additions
     * @dev Reserves 50 slots for future use in upgrades
     */
    uint256[50] private __gap;

    // Actual storage variables come AFTER the gap
    address public owner;
    uint256 public value;
    mapping(address => uint256) public balances;

    /**
     * @notice Initialize implementation (called once)
     */
    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }

    /**
     * @notice Business logic functions
     */
    function setValue(uint256 newValue) external {
        require(msg.sender == owner, "Only owner");
        value = newValue;
    }
}

/**
 * @notice SECURE IMPLEMENTATION V2 - Upgraded version
 * @dev Can safely add new variables without collision
 */
contract SecureImplementationV2 is SecureImplementationV1 {
    // V1 used: gap[50] + owner + value + balances = 53 slots
    // We can now add new variables safely

    uint256 public newFeature;      // Safe: slot 53
    address public newAddress;      // Safe: slot 54

    // Still maintain gap for future V3
    uint256[48] private __gapV2;   // Reduced gap

    function setNewFeature(uint256 _newFeature) external {
        require(msg.sender == owner, "Only owner");
        newFeature = _newFeature;
    }
}

/**
 * @notice NAMESPACED STORAGE PATTERN
 * @dev Advanced pattern using Diamond Storage for complex contracts
 */
contract NamespacedStorage {
    /**
     * @notice Storage struct for specific feature
     */
    struct TokenStorage {
        mapping(address => uint256) balances;
        uint256 totalSupply;
        string name;
        string symbol;
    }

    /**
     * @notice Calculate storage slot for namespace
     * @dev Uses hash of namespace string
     */
    function _getTokenStorage() private pure returns (TokenStorage storage s) {
        bytes32 position = keccak256("myproject.token.storage");
        assembly {
            s.slot := position
        }
    }

    /**
     * @notice Example usage
     */
    function getBalance(address account) external view returns (uint256) {
        TokenStorage storage s = _getTokenStorage();
        return s.balances[account];
    }
}

/**
 * @notice DIAMOND STORAGE PATTERN (EIP-2535)
 * @dev Each facet gets its own storage namespace
 */
library LibDiamond {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) selectorToFacet;
        address contractOwner;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }
}

/**
 * @notice UNSTRUCTURED STORAGE PATTERN
 * @dev Used by OpenZeppelin for Initializable, Ownable, etc.
 */
contract UnstructuredStorage {
    /**
     * @notice Store value at specific slot
     */
    function _setSlot(bytes32 slot, address value) private {
        assembly {
            sstore(slot, value)
        }
    }

    /**
     * @notice Load value from specific slot
     */
    function _getSlot(bytes32 slot) private view returns (address value) {
        assembly {
            value := sload(slot)
        }
    }

    /**
     * @notice Example: Store owner at custom slot
     */
    function setOwner(address newOwner) external {
        bytes32 ownerSlot = keccak256("mycontract.owner");
        _setSlot(ownerSlot, newOwner);
    }

    function getOwner() public view returns (address) {
        bytes32 ownerSlot = keccak256("mycontract.owner");
        return _getSlot(ownerSlot);
    }
}

/**
 * @notice STORAGE LAYOUT VALIDATOR
 * @dev Helper contract to validate storage layouts match
 */
library StorageSlotValidator {
    /**
     * @notice Verify EIP-1967 slot calculation
     */
    function verifyImplementationSlot() internal pure returns (bool) {
        bytes32 calculatedSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        bytes32 expectedSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        return calculatedSlot == expectedSlot;
    }

    /**
     * @notice Verify Admin slot calculation
     */
    function verifyAdminSlot() internal pure returns (bool) {
        bytes32 calculatedSlot = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
        bytes32 expectedSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        return calculatedSlot == expectedSlot;
    }
}

/**
 * @notice COMPARISON: Storage Layouts
 */
/**
 * VULNERABLE:
 * Slot 0: implementation
 * Slot 1: admin
 * Slot 2: ... (sequential)
 *
 * SECURE (EIP-1967):
 * Slot 0x360894...: implementation (pseudo-random)
 * Slot 0xb53127...: admin (pseudo-random)
 * Slot 0-N: Available for implementation's variables
 *
 * Result: No collision possible!
 */
