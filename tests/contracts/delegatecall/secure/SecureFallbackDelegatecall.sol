// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureFallbackDelegatecall
 * @notice SECURE: Properly protected fallback/receive functions with delegatecall
 * @dev This contract demonstrates secure patterns for fallback/receive functions
 *      that perform delegatecall operations.
 *
 * Security principles:
 * 1. Transparent Proxy Pattern - Admin cannot call implementation functions
 * 2. Access control on fallback/receive
 * 3. EIP-1967 compliant storage slots (no storage collision)
 * 4. Immutable implementation (when possible)
 * 5. Function selector validation
 * 6. Reentrancy protection
 *
 * Patterns demonstrated:
 * - Transparent proxy with admin protection
 * - UUPS proxy with self-upgrading logic
 * - Beacon proxy with centralized upgrades
 * - Immutable implementation proxy
 * - Function selector whitelist
 */

/**
 * @notice SECURE: Transparent Proxy Pattern (OpenZeppelin style)
 * @dev Admin cannot access implementation functions (prevents function shadowing)
 */
contract TransparentProxy {
    /**
     * @dev EIP-1967 compliant storage slots
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
     * @notice SECURE: Admin functions (admin cannot trigger fallback)
     */
    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }

    function upgradeTo(address newImplementation) external ifAdmin {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    function changeAdmin(address newAdmin) external ifAdmin {
        address previousAdmin = _getAdmin();
        _setAdmin(newAdmin);
        emit AdminChanged(previousAdmin, newAdmin);
    }

    function admin() external ifAdmin returns (address) {
        return _getAdmin();
    }

    function implementation() external ifAdmin returns (address) {
        return _getImplementation();
    }

    /**
     * @notice SECURE: Fallback with admin protection
     * @dev Admin calls are blocked from reaching implementation
     */
    fallback() external payable {
        // SECURE: If admin calls, revert (prevents function shadowing)
        require(msg.sender != _getAdmin(), "Admin cannot fallback");
        _fallback();
    }

    receive() external payable {
        require(msg.sender != _getAdmin(), "Admin cannot receive");
        _fallback();
    }

    /**
     * @notice Internal: Delegate to implementation
     */
    function _fallback() private {
        address impl = _getImplementation();
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

    function _getImplementation() private view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) private {
        require(_isContract(newImplementation), "Must be contract");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _getAdmin() private view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "Invalid admin");
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

/**
 * @notice SECURE: UUPS Proxy (Universal Upgradeable Proxy Standard)
 * @dev Upgrade logic is in implementation, not proxy
 */
contract UUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    event Upgraded(address indexed implementation);

    constructor(address _implementation, bytes memory _data) {
        _setImplementation(_implementation);

        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice SECURE: Fallback delegates to implementation
     * @dev Upgrade logic is in implementation (no admin in proxy)
     */
    fallback() external payable {
        address impl = _getImplementation();
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

    receive() external payable {
        // Forward to fallback
        assembly {
            calldatacopy(0, 0, calldatasize())
            let impl := sload(IMPLEMENTATION_SLOT.slot)
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function _getImplementation() private view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) private {
        require(_isContract(newImplementation), "Must be contract");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
        emit Upgraded(newImplementation);
    }

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

/**
 * @notice SECURE: Beacon Proxy
 * @dev Implementation address comes from separate beacon contract
 */
contract BeaconProxy {
    address public immutable beacon;

    event BeaconUpgraded(address indexed beacon);

    constructor(address _beacon, bytes memory _data) {
        require(_isContract(_beacon), "Beacon must be contract");
        beacon = _beacon;

        if (_data.length > 0) {
            address impl = IBeacon(_beacon).implementation();
            (bool success, ) = impl.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice SECURE: Implementation comes from immutable beacon
     */
    fallback() external payable {
        address impl = IBeacon(beacon).implementation();
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

    receive() external payable {
        address impl = IBeacon(beacon).implementation();
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

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

interface IBeacon {
    function implementation() external view returns (address);
}

/**
 * @notice SECURE: Immutable Implementation Proxy
 * @dev Implementation cannot be changed after deployment
 */
contract ImmutableProxy {
    address public immutable implementation;

    constructor(address _implementation, bytes memory _data) {
        require(_isContract(_implementation), "Must be contract");
        implementation = _implementation;

        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    /**
     * @notice SECURE: Delegates to immutable implementation
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

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

/**
 * @notice SECURE: Function Selector Whitelist
 * @dev Only allows specific function selectors to be delegated
 */
contract SelectorWhitelist {
    address public owner;
    address public implementation;
    mapping(bytes4 => bool) public allowedSelectors;

    event SelectorAdded(bytes4 indexed selector);
    event SelectorRemoved(bytes4 indexed selector);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    function addSelector(bytes4 selector) external onlyOwner {
        allowedSelectors[selector] = true;
        emit SelectorAdded(selector);
    }

    function removeSelector(bytes4 selector) external onlyOwner {
        allowedSelectors[selector] = false;
        emit SelectorRemoved(selector);
    }

    /**
     * @notice SECURE: Only delegates whitelisted function selectors
     */
    fallback() external payable {
        bytes4 selector = msg.sig;
        require(allowedSelectors[selector], "Selector not allowed");

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
 * @notice SECURE: Reentrancy Protected Fallback
 */
contract ReentrancyGuardedProxy {
    address public implementation;
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "Reentrant call");
        locked = 2;
        _;
        locked = 1;
    }

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice SECURE: Reentrancy guard on fallback
     */
    fallback() external payable nonReentrant {
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

    receive() external payable nonReentrant {}
}

/**
 * @notice SECURE: Multi-sig Protected Fallback
 */
contract MultiSigFallback {
    address public implementation;
    address[] public signers;
    mapping(address => bool) public isSigner;

    constructor(address _implementation, address[] memory _signers) {
        require(_signers.length >= 2, "Need multiple signers");
        implementation = _implementation;

        for (uint256 i = 0; i < _signers.length; i++) {
            signers.push(_signers[i]);
            isSigner[_signers[i]] = true;
        }
    }

    /**
     * @notice SECURE: Only signers can trigger fallback
     */
    fallback() external payable {
        require(isSigner[msg.sender], "Not authorized");

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

    receive() external payable {
        require(isSigner[msg.sender], "Not authorized");
    }
}

/**
 * @notice SECURE: Pausable Fallback
 */
contract PausableProxy {
    address public owner;
    address public implementation;
    bool public paused;

    event Paused();
    event Unpaused();

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused();
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    /**
     * @notice SECURE: Can be paused in emergency
     */
    fallback() external payable whenNotPaused {
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

    receive() external payable whenNotPaused {}
}
