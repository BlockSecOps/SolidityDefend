// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title LegitimateUpgradeableStorage
 * @notice Properly implemented upgradeable contract with safe storage layout
 * @dev This contract should NOT trigger false positives from storage-layout-upgrade detector
 *
 * Security Measures:
 * 1. Append-only storage layout (never reorder or remove)
 * 2. Storage gaps for future variables
 * 3. Namespaced storage pattern (EIP-1967)
 * 4. Proper initialization pattern
 * 5. Version tracking
 */

/**
 * @title StorageV1
 * @notice Version 1 of storage layout - Initial implementation
 */
contract StorageV1 {
    // SLOT 0
    address public owner;

    // SLOT 1
    uint256 public value;

    // SLOT 2
    mapping(address => uint256) public balances;

    // SLOT 3-52: Storage gap for future versions (50 slots)
    // This prevents storage collisions when adding new variables
    uint256[50] private __gap;

    event ValueUpdated(uint256 oldValue, uint256 newValue);
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }

    function setValue(uint256 _value) external {
        require(msg.sender == owner, "Only owner");
        uint256 oldValue = value;
        value = _value;
        emit ValueUpdated(oldValue, _value);
    }

    function setBalance(address account, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        balances[account] = amount;
    }
}

/**
 * @title StorageV2
 * @notice Version 2 of storage layout - Proper upgrade (append-only)
 * @dev Demonstrates correct storage layout preservation
 */
contract StorageV2 {
    // ✅ PRESERVED FROM V1 (CRITICAL: Never reorder or change these!)
    // SLOT 0
    address public owner;

    // SLOT 1
    uint256 public value;

    // SLOT 2
    mapping(address => uint256) public balances;

    // SLOT 3-52: Storage gap REDUCED by 2 (we're adding 2 new variables)
    uint256[48] private __gap;

    // ✅ NEW VARIABLES APPENDED (using gap slots 51-52)
    // SLOT 53 (was gap slot 50)
    uint256 public version;

    // SLOT 54 (was gap slot 51)
    uint256 public totalSupply;

    // New events
    event VersionUpdated(uint256 oldVersion, uint256 newVersion);
    event TotalSupplyUpdated(uint256 amount);

    function initializeV2() external {
        require(version == 0, "Already initialized V2");
        version = 2;
        emit VersionUpdated(0, 2);
    }

    function setValue(uint256 _value) external {
        require(msg.sender == owner, "Only owner");
        uint256 oldValue = value;
        value = _value;
        emit ValueUpdated(oldValue, _value);
    }

    function setBalance(address account, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        balances[account] = amount;
    }

    // New function using new storage
    function setTotalSupply(uint256 _totalSupply) external {
        require(msg.sender == owner, "Only owner");
        totalSupply = _totalSupply;
        emit TotalSupplyUpdated(_totalSupply);
    }

    event ValueUpdated(uint256 oldValue, uint256 newValue);
}

/**
 * @title NamespacedStorage
 * @notice Upgradeable contract using EIP-1967 namespaced storage pattern
 * @dev Uses keccak256 hash for storage slot isolation
 */
contract NamespacedStorage {
    // EIP-1967 standard storage slots
    bytes32 private constant IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    // Custom namespaced storage
    bytes32 private constant DATA_STORAGE_SLOT = keccak256("app.storage.data");

    struct DataStorage {
        uint256 value;
        address owner;
        mapping(address => uint256) balances;
        uint256 version;
    }

    /**
     * @notice Get data storage using namespaced slot
     * @return ds Data storage struct
     */
    function dataStorage() internal pure returns (DataStorage storage ds) {
        bytes32 slot = DATA_STORAGE_SLOT;
        assembly {
            ds.slot := slot
        }
    }

    /**
     * @notice Initialize with proper namespacing
     * @param _owner Initial owner
     */
    function initialize(address _owner) external {
        DataStorage storage ds = dataStorage();
        require(ds.owner == address(0), "Already initialized");
        ds.owner = _owner;
        ds.version = 1;
    }

    /**
     * @notice Upgrade to V2 with same storage namespace (safe)
     */
    function upgradeToV2() external {
        DataStorage storage ds = dataStorage();
        require(ds.owner == msg.sender, "Only owner");
        require(ds.version == 1, "Already upgraded");
        ds.version = 2;
    }

    /**
     * @notice Set value using namespaced storage
     * @param _value New value
     */
    function setValue(uint256 _value) external {
        DataStorage storage ds = dataStorage();
        require(ds.owner == msg.sender, "Only owner");
        ds.value = _value;
    }

    /**
     * @notice Get current version
     * @return Current version number
     */
    function getVersion() external view returns (uint256) {
        DataStorage storage ds = dataStorage();
        return ds.version;
    }
}

/**
 * @title ProxyImplementationV1
 * @notice Implementation contract V1 for transparent proxy pattern
 */
contract ProxyImplementationV1 {
    // Storage layout for proxy pattern
    address public implementation; // Proxy sets this
    address public admin;          // Proxy sets this

    // Implementation-specific storage starts here
    uint256 public counter;
    mapping(address => uint256) public userScores;

    function increment() external {
        counter++;
    }

    function setScore(address user, uint256 score) external {
        userScores[user] = score;
    }
}

/**
 * @title ProxyImplementationV2
 * @notice Implementation contract V2 - Safe upgrade (append-only)
 */
contract ProxyImplementationV2 {
    // ✅ PRESERVED: Exact same layout as V1
    address public implementation;
    address public admin;
    uint256 public counter;
    mapping(address => uint256) public userScores;

    // ✅ NEW: Appended variables only
    uint256 public totalScore;
    bool public paused;

    function increment() external {
        require(!paused, "Paused");
        counter++;
    }

    function setScore(address user, uint256 score) external {
        require(!paused, "Paused");
        userScores[user] = score;
        totalScore += score;
    }

    function setPaused(bool _paused) external {
        paused = _paused;
    }
}

/**
 * EXPECTED RESULTS:
 * ================
 * These contracts demonstrate proper upgradeable storage patterns and should NOT trigger:
 *
 * ✅ storage-layout-upgrade: StorageV1 → StorageV2 uses append-only pattern
 * ✅ storage-layout-upgrade: Uses storage gaps to prevent collisions
 * ✅ storage-layout-upgrade: NamespacedStorage uses EIP-1967 pattern
 * ✅ storage-layout-upgrade: ProxyImplementationV1 → V2 preserves layout
 * ✅ storage-layout-upgrade: No variable reordering or deletion
 *
 * Expected Findings: 0 (Zero false positives)
 */
