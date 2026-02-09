// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureDelegatecall
 * @notice SECURE: Properly controlled delegatecall implementations
 * @dev This contract demonstrates secure patterns for delegatecall usage.
 *
 * Security principles:
 * 1. Never allow user input to directly control delegatecall target
 * 2. Use whitelisting for allowed targets
 * 3. Implement strict access controls
 * 4. Use immutable or admin-only target addresses
 * 5. Validate targets before delegatecall
 * 6. Consider using libraries instead of delegatecall
 *
 * Patterns demonstrated:
 * - Immutable implementation addresses
 * - Whitelist-based target selection
 * - Multi-sig controlled updates
 * - Library-based execution
 * - Enumerated target selection
 * - Timelock protection
 */

/**
 * @notice SECURE: Immutable delegatecall target
 */
contract ImmutableTarget {
    address public immutable implementation;
    address public owner;

    event Executed(address indexed target, bytes data, bytes result);

    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");
        require(_isContract(_implementation), "Must be contract");

        implementation = _implementation;
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Only delegates to immutable implementation
     */
    function execute(bytes calldata data) external payable returns (bytes memory) {
        // SECURE: Target is immutable and set at deployment
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Execution failed");

        emit Executed(implementation, data, result);
        return result;
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
 * @notice SECURE: Whitelist-based delegatecall
 */
contract WhitelistBased {
    address public owner;
    mapping(address => bool) public whitelistedLibraries;
    address[] public libraryList;

    event LibraryWhitelisted(address indexed libraryAddr, bool status);
    event Executed(address indexed libraryAddr, bytes data);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Add library to whitelist (owner only)
     */
    function whitelistLibrary(address lib) external onlyOwner {
        require(lib != address(0), "Invalid address");
        require(_isContract(lib), "Must be contract");
        require(!whitelistedLibraries[lib], "Already whitelisted");

        whitelistedLibraries[lib] = true;
        libraryList.push(lib);

        emit LibraryWhitelisted(lib, true);
    }

    /**
     * @notice Remove library from whitelist (owner only)
     */
    function removeLibrary(address lib) external onlyOwner {
        require(whitelistedLibraries[lib], "Not whitelisted");

        whitelistedLibraries[lib] = false;
        emit LibraryWhitelisted(lib, false);
    }

    /**
     * @notice SECURE: Only delegates to whitelisted libraries
     * @dev Users can only choose FROM the whitelist, not arbitrary addresses
     */
    function executeLibrary(address lib, bytes calldata data) external returns (bytes memory) {
        // SECURE: Validate library is whitelisted
        require(whitelistedLibraries[lib], "Library not whitelisted");

        (bool success, bytes memory result) = lib.delegatecall(data);
        require(success, "Library call failed");

        emit Executed(lib, data);
        return result;
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
 * @notice SECURE: Enum-based target selection
 */
contract EnumBasedSelection {
    enum Library {
        Math,
        String,
        Array
    }

    address public owner;
    mapping(Library => address) public libraries;

    event LibraryUpdated(Library indexed lib, address implementation);
    event Executed(Library indexed lib, bytes data);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Set library implementation (owner only)
     */
    function setLibrary(Library lib, address implementation) external onlyOwner {
        require(implementation != address(0), "Invalid address");
        require(_isContract(implementation), "Must be contract");

        libraries[lib] = implementation;
        emit LibraryUpdated(lib, implementation);
    }

    /**
     * @notice SECURE: User selects enum, not address
     * @dev Enum limits choices to predefined set
     */
    function executeLibrary(Library lib, bytes calldata data) external returns (bytes memory) {
        address target = libraries[lib];
        require(target != address(0), "Library not set");

        // SECURE: Target is controlled by owner-set mapping, not user
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");

        emit Executed(lib, data);
        return result;
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
 * @notice SECURE: Multi-sig controlled delegatecall
 */
contract MultiSigControlled {
    address public owner1;
    address public owner2;
    address public implementation;

    mapping(bytes32 => bool) public proposalApprovals;
    mapping(bytes32 => address) public proposedImplementations;

    event ProposalCreated(bytes32 indexed proposalId, address newImplementation);
    event ProposalApproved(bytes32 indexed proposalId, address approver);
    event ImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    constructor(address _owner1, address _owner2, address _implementation) {
        require(_owner1 != address(0) && _owner2 != address(0), "Invalid owners");
        require(_owner1 != _owner2, "Owners must differ");
        require(_isContract(_implementation), "Must be contract");

        owner1 = _owner1;
        owner2 = _owner2;
        implementation = _implementation;
    }

    /**
     * @notice Propose new implementation (any owner)
     */
    function proposeImplementation(address newImpl) external returns (bytes32) {
        require(msg.sender == owner1 || msg.sender == owner2, "Only owners");
        require(_isContract(newImpl), "Must be contract");

        bytes32 proposalId = keccak256(abi.encodePacked(newImpl, block.timestamp));
        proposedImplementations[proposalId] = newImpl;

        emit ProposalCreated(proposalId, newImpl);
        return proposalId;
    }

    /**
     * @notice Approve and execute proposal (other owner)
     */
    function approveImplementation(bytes32 proposalId) external {
        require(msg.sender == owner1 || msg.sender == owner2, "Only owners");
        require(proposedImplementations[proposalId] != address(0), "Invalid proposal");
        require(!proposalApprovals[proposalId], "Already approved");

        proposalApprovals[proposalId] = true;
        address newImpl = proposedImplementations[proposalId];

        emit ProposalApproved(proposalId, msg.sender);

        // Update implementation
        address oldImpl = implementation;
        implementation = newImpl;

        emit ImplementationUpdated(oldImpl, newImpl);
    }

    /**
     * @notice SECURE: Delegates to multi-sig controlled implementation
     */
    function execute(bytes calldata data) external returns (bytes memory) {
        address target = implementation;
        require(target != address(0), "No implementation");

        // SECURE: Implementation requires multi-sig to change
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");

        return result;
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
 * @notice SECURE: Timelock-protected delegatecall
 */
contract TimelockProtected {
    address public owner;
    address public implementation;
    address public pendingImplementation;
    uint256 public implementationTimestamp;
    uint256 public constant TIMELOCK_DURATION = 2 days;

    event ImplementationProposed(address indexed newImpl, uint256 executeTime);
    event ImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _implementation) {
        require(_isContract(_implementation), "Must be contract");

        owner = msg.sender;
        implementation = _implementation;
    }

    /**
     * @notice Propose new implementation with timelock
     */
    function proposeImplementation(address newImpl) external onlyOwner {
        require(_isContract(newImpl), "Must be contract");
        require(newImpl != implementation, "Same implementation");

        pendingImplementation = newImpl;
        implementationTimestamp = block.timestamp + TIMELOCK_DURATION;

        emit ImplementationProposed(newImpl, implementationTimestamp);
    }

    /**
     * @notice Execute pending implementation after timelock
     */
    function executeProposal() external onlyOwner {
        require(pendingImplementation != address(0), "No pending proposal");
        require(block.timestamp >= implementationTimestamp, "Timelock not expired");

        address oldImpl = implementation;
        implementation = pendingImplementation;

        // Clear pending
        pendingImplementation = address(0);
        implementationTimestamp = 0;

        emit ImplementationUpdated(oldImpl, implementation);
    }

    /**
     * @notice SECURE: Delegates to timelock-protected implementation
     */
    function execute(bytes calldata data) external returns (bytes memory) {
        address target = implementation;
        require(target != address(0), "No implementation");

        // SECURE: Implementation changes have 2-day delay
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");

        return result;
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
 * @notice SECURE: Library-based approach (no delegatecall needed)
 */
library SecureMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    function multiply(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }
}

contract LibraryBasedApproach {
    /**
     * @notice SECURE: Use Solidity libraries instead of delegatecall
     * @dev Libraries are statically linked at compile time
     */
    function calculate(uint256 a, uint256 b) external pure returns (uint256) {
        // SECURE: No delegatecall needed - library code is linked
        return SecureMath.add(SecureMath.multiply(a, b), 10);
    }
}

/**
 * @notice SECURE: Diamond pattern with controlled facets
 */
contract SecureDiamond {
    address public owner;
    mapping(bytes4 => address) public selectorToFacet;

    event FacetUpdated(bytes4 indexed selector, address indexed facet);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Add or update facet (owner only)
     */
    function setFacet(bytes4 selector, address facet) external onlyOwner {
        require(facet != address(0), "Invalid facet");
        require(_isContract(facet), "Must be contract");

        selectorToFacet[selector] = facet;
        emit FacetUpdated(selector, facet);
    }

    /**
     * @notice SECURE: Fallback delegates to owner-controlled facets
     */
    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0), "Function not found");

        // SECURE: Facet address is controlled by owner, not user input
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
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

/**
 * @notice SECURE: Registry-based with contract verification
 */
contract RegistryBased {
    address public owner;
    address public registry;

    event RegistryUpdated(address indexed oldRegistry, address indexed newRegistry);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _registry) {
        require(_registry != address(0), "Invalid registry");
        owner = msg.sender;
        registry = _registry;
    }

    function setRegistry(address newRegistry) external onlyOwner {
        require(newRegistry != address(0), "Invalid registry");
        address old = registry;
        registry = newRegistry;
        emit RegistryUpdated(old, newRegistry);
    }

    /**
     * @notice SECURE: Query registry for approved implementation
     */
    function execute(bytes32 implementationId, bytes calldata data) external returns (bytes memory) {
        // Query trusted registry for implementation address
        address target = IRegistry(registry).getImplementation(implementationId);
        require(target != address(0), "Implementation not found");

        // SECURE: Target comes from trusted registry, not user
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");

        return result;
    }
}

interface IRegistry {
    function getImplementation(bytes32 id) external view returns (address);
}
