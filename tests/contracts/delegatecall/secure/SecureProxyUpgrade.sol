// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureProxyUpgrade
 * @notice SECURE: Proxy upgrade with proper access control
 * @dev This contract demonstrates the correct way to implement proxy upgrades
 *      with multiple layers of security.
 *
 * Security features:
 * 1. Access control on upgrade function (onlyOwner)
 * 2. Implementation validation
 * 3. Upgrade event emission for transparency
 * 4. EIP-1967 compliant storage slots
 * 5. Optional: Timelock for upgrade execution
 *
 * Follows patterns from:
 * - OpenZeppelin TransparentUpgradeableProxy
 * - OpenZeppelin UUPSUpgradeable
 * - EIP-1967: Standard Proxy Storage Slots
 */
contract SecureProxyUpgrade {
    // EIP-1967 standard storage slot for implementation
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    // EIP-1967 standard storage slot for admin
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    address public owner;
    mapping(address => uint256) public balances;

    // Events for transparency
    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @notice Access control modifier
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    /**
     * @notice Admin-only modifier for critical functions
     */
    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Only admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        _setAdmin(msg.sender);
    }

    /**
     * @notice SECURE: Upgrade function with access control
     * @param newImplementation Address of the new implementation
     */
    function upgradeTo(address newImplementation) external onlyAdmin {
        // Access control: Only admin can upgrade
        require(msg.sender == _getAdmin(), "Unauthorized");

        // Validation: Ensure implementation is a contract
        require(newImplementation != address(0), "Invalid implementation");
        require(_isContract(newImplementation), "Implementation must be a contract");

        // Additional validation: Prevent upgrade to same implementation
        address currentImpl = implementation();
        require(newImplementation != currentImpl, "Already using this implementation");

        // Update implementation
        _setImplementation(newImplementation);

        // Emit event for transparency
        emit Upgraded(newImplementation);
    }

    /**
     * @notice SECURE: Upgrade with additional validation
     * @dev Calls implementation's initialization after upgrade
     * @param newImplementation Address of the new implementation
     * @param data Calldata to pass to new implementation's initialize()
     */
    function upgradeToAndCall(
        address newImplementation,
        bytes memory data
    ) external payable onlyAdmin {
        upgradeTo(newImplementation);

        // Call initialize on new implementation if data provided
        if (data.length > 0) {
            (bool success, ) = newImplementation.delegatecall(data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice Change admin (owner of upgrade rights)
     * @dev Should be protected and ideally use timelock
     */
    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid admin address");

        address previousAdmin = _getAdmin();
        _setAdmin(newAdmin);

        emit AdminChanged(previousAdmin, newAdmin);
    }

    /**
     * @notice Get current implementation address
     */
    function implementation() public view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
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
     * @notice Get current admin address
     */
    function _getAdmin() private view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
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
     * @notice Check if address is a contract
     */
    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @notice Fallback function that delegates to implementation
     * @dev Admin calls do NOT delegate (Transparent Proxy pattern)
     */
    fallback() external payable {
        // Transparent proxy pattern: admin calls don't delegate
        if (msg.sender == _getAdmin()) {
            return;
        }

        address impl = implementation();
        require(impl != address(0), "Implementation not set");

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
 * @title SecureProxyWithTimelock
 * @notice EXTRA SECURE: Proxy with timelock for upgrades
 * @dev Adds delay before upgrades can be executed (governance)
 */
contract SecureProxyWithTimelock is SecureProxyUpgrade {
    uint256 public constant UPGRADE_DELAY = 2 days;

    struct PendingUpgrade {
        address implementation;
        uint256 executeAfter;
        bool executed;
    }

    mapping(bytes32 => PendingUpgrade) public pendingUpgrades;

    event UpgradeProposed(bytes32 indexed upgradeId, address implementation, uint256 executeAfter);
    event UpgradeExecuted(bytes32 indexed upgradeId, address implementation);
    event UpgradeCancelled(bytes32 indexed upgradeId);

    /**
     * @notice Propose an upgrade (starts timelock)
     */
    function proposeUpgrade(address newImplementation) external onlyAdmin returns (bytes32) {
        require(newImplementation != address(0), "Invalid implementation");
        require(_isContract(newImplementation), "Must be contract");

        bytes32 upgradeId = keccak256(abi.encode(newImplementation, block.timestamp));
        uint256 executeAfter = block.timestamp + UPGRADE_DELAY;

        pendingUpgrades[upgradeId] = PendingUpgrade({
            implementation: newImplementation,
            executeAfter: executeAfter,
            executed: false
        });

        emit UpgradeProposed(upgradeId, newImplementation, executeAfter);
        return upgradeId;
    }

    /**
     * @notice Execute pending upgrade after timelock
     */
    function executeUpgrade(bytes32 upgradeId) external onlyAdmin {
        PendingUpgrade storage pending = pendingUpgrades[upgradeId];

        require(pending.implementation != address(0), "Upgrade not found");
        require(!pending.executed, "Already executed");
        require(block.timestamp >= pending.executeAfter, "Timelock not expired");

        pending.executed = true;
        _setImplementation(pending.implementation);

        emit UpgradeExecuted(upgradeId, pending.implementation);
        emit Upgraded(pending.implementation);
    }

    /**
     * @notice Cancel pending upgrade
     */
    function cancelUpgrade(bytes32 upgradeId) external onlyAdmin {
        PendingUpgrade storage pending = pendingUpgrades[upgradeId];

        require(pending.implementation != address(0), "Upgrade not found");
        require(!pending.executed, "Already executed");

        delete pendingUpgrades[upgradeId];

        emit UpgradeCancelled(upgradeId);
    }
}
