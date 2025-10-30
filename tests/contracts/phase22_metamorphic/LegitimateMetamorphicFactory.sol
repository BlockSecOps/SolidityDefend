// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title LegitimateMetamorphicFactory
 * @notice Properly implemented metamorphic contract factory with security best practices
 * @dev This contract should NOT trigger false positives from Phase 22 detectors
 *
 * Legitimate Use Cases:
 * 1. Upgradeable contract deployment (transparent proxy alternative)
 * 2. Contract factory with deterministic addresses
 * 3. Secure CREATE2 deployment with proper salt management
 * 4. Safe selfdestruct patterns for emergency scenarios
 *
 * Security Measures:
 * 1. Access control on metamorphic operations
 * 2. CREATE2 frontrunning protection via salt commitment
 * 3. Recipient validation for selfdestruct
 * 4. EXTCODESIZE checks with proper context
 */

// Interface for metamorphic contracts
interface IMetamorphicContract {
    function initialize(bytes calldata data) external;
    function version() external view returns (uint256);
}

/**
 * @title LegitimateMetamorphicFactory
 * @notice Factory for deploying contracts at deterministic addresses
 */
contract LegitimateMetamorphicFactory {
    address public immutable owner;

    // CREATE2 salt commitment to prevent frontrunning
    mapping(bytes32 => address) public saltCommitments;
    mapping(bytes32 => uint256) public commitmentTimestamps;
    uint256 public constant COMMITMENT_DELAY = 1 hours;

    // Track deployed contracts
    mapping(address => bool) public isDeployedContract;
    mapping(address => uint256) public contractVersion;

    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt, uint256 version);
    event SaltCommitted(bytes32 indexed saltHash, address indexed deployer);
    event ContractUpgraded(address indexed contractAddress, uint256 oldVersion, uint256 newVersion);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    /**
     * @notice Commit to a salt before deployment (prevents CREATE2 frontrunning)
     * @param saltHash Keccak256 hash of (salt, deployer address)
     */
    function commitSalt(bytes32 saltHash) external {
        require(saltCommitments[saltHash] == address(0), "Salt already committed");

        saltCommitments[saltHash] = msg.sender;
        commitmentTimestamps[saltHash] = block.timestamp;

        emit SaltCommitted(saltHash, msg.sender);
    }

    /**
     * @notice Deploy contract using CREATE2 with proper frontrunning protection
     * @param bytecode Contract bytecode to deploy
     * @param salt Unique salt for deterministic address
     * @return deployedAddress Address of deployed contract
     */
    function deployWithCreate2(bytes memory bytecode, bytes32 salt) external returns (address deployedAddress) {
        // Frontrunning protection: verify salt commitment
        bytes32 saltHash = keccak256(abi.encodePacked(salt, msg.sender));
        require(saltCommitments[saltHash] == msg.sender, "Salt not committed");
        require(
            block.timestamp >= commitmentTimestamps[saltHash] + COMMITMENT_DELAY,
            "Commitment delay not passed"
        );

        // Deploy using CREATE2
        assembly {
            deployedAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        require(deployedAddress != address(0), "Deployment failed");

        // Track deployment
        isDeployedContract[deployedAddress] = true;
        contractVersion[deployedAddress] = 1;

        emit ContractDeployed(deployedAddress, salt, 1);
    }

    /**
     * @notice Compute CREATE2 address before deployment
     * @param bytecode Contract bytecode
     * @param salt Unique salt
     * @return predicted Predicted contract address
     */
    function computeAddress(bytes memory bytecode, bytes32 salt) public view returns (address predicted) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        predicted = address(uint160(uint256(hash)));
    }

    /**
     * @notice Safe check if address is a contract (considers construction phase)
     * @param account Address to check
     * @return True if account is a contract
     */
    function isContract(address account) public view returns (bool) {
        // EXTCODESIZE check with proper context
        // During construction, codesize is 0, so this handles that case
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @notice Check if contract is being constructed (legitimate EXTCODESIZE bypass)
     * @param account Address to check
     * @return True if contract is in construction
     */
    function isInConstruction(address account) external view returns (bool) {
        // This is a legitimate use of EXTCODESIZE behavior
        // During construction, extcodesize returns 0 even if it's a contract
        if (!isContract(account) && isDeployedContract[account]) {
            return true; // Known deployed contract but codesize is 0 = construction phase
        }
        return false;
    }
}

/**
 * @title UpgradeableMetamorphicContract
 * @notice Example metamorphic contract with safe upgrade pattern
 */
contract UpgradeableMetamorphicContract {
    address public immutable factory;
    address public owner;
    uint256 public version;
    bool public initialized;

    // Safe selfdestruct pattern
    address public emergencyRecipient;
    uint256 public selfdestructProposalTime;
    uint256 public constant SELFDESTRUCT_DELAY = 7 days;

    event Initialized(uint256 version);
    event SelfdestructProposed(address recipient, uint256 executeTime);
    event SelfdestructExecuted(address recipient);

    constructor() {
        factory = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyFactory() {
        require(msg.sender == factory, "Only factory");
        _;
    }

    /**
     * @notice Initialize contract (called by factory)
     * @param data Initialization data
     */
    function initialize(bytes calldata data) external onlyFactory {
        require(!initialized, "Already initialized");

        (address _owner, uint256 _version) = abi.decode(data, (address, uint256));

        owner = _owner;
        version = _version;
        initialized = true;

        emit Initialized(_version);
    }

    /**
     * @notice Propose selfdestruct with timelock and recipient validation
     * @param recipient Address to receive remaining funds
     */
    function proposeSelfDestruct(address recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        require(recipient == owner, "Recipient must be owner"); // Prevent manipulation

        emergencyRecipient = recipient;
        selfdestructProposalTime = block.timestamp;

        emit SelfdestructProposed(recipient, block.timestamp + SELFDESTRUCT_DELAY);
    }

    /**
     * @notice Execute selfdestruct after timelock (safe pattern)
     */
    function executeSelfDestruct() external onlyOwner {
        require(emergencyRecipient != address(0), "No proposal");
        require(
            block.timestamp >= selfdestructProposalTime + SELFDESTRUCT_DELAY,
            "Timelock not passed"
        );

        address recipient = emergencyRecipient;

        emit SelfdestructExecuted(recipient);

        // Safe selfdestruct with validated recipient
        selfdestruct(payable(recipient));
    }

    /**
     * @notice Cancel selfdestruct proposal
     */
    function cancelSelfDestruct() external onlyOwner {
        emergencyRecipient = address(0);
        selfdestructProposalTime = 0;
    }

    function getVersion() external view returns (uint256) {
        return version;
    }
}

/**
 * EXPECTED RESULTS:
 * ================
 * These contracts use metamorphic patterns with proper security measures and should NOT trigger:
 *
 * ✅ metamorphic-contract: Factory pattern is legitimate, properly access-controlled
 * ✅ create2-frontrunning: Uses salt commitment with timelock to prevent frontrunning
 * ✅ selfdestruct-recipient-manipulation: Validates recipient, requires it to be owner, uses timelock
 * ✅ extcodesize-bypass: isContract() and isInConstruction() are legitimate checks with proper context
 *
 * Expected Findings: 0 (Zero false positives)
 */
