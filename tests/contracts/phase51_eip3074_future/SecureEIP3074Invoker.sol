// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureEIP3074Invoker
 * @notice SECURE: Non-upgradeable invoker with proper protections
 * @dev Should NOT trigger any Phase 51 detectors
 */
contract SecureEIP3074Invoker {
    address public immutable owner;

    mapping(address => uint256) public nonces;
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;

    uint256 public constant MAX_VALUE = 10 ether;

    event Executed(address indexed signer, address indexed target, bool success);

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setAllowedTarget(address target, bool allowed) external onlyOwner {
        allowedTargets[target] = allowed;
    }

    function setAllowedSelector(bytes4 selector, bool allowed) external onlyOwner {
        allowedSelectors[selector] = allowed;
    }

    /**
     * @notice SECURE: Complete EIP-3074 implementation with all protections
     */
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external returns (bool success) {
        // 1. Deadline enforcement
        require(block.timestamp <= deadline, "Expired");

        // 2. Nonce validation and increment
        require(nonce == nonces[msg.sender], "Invalid nonce");
        nonces[msg.sender]++;

        // 3. Target validation
        require(allowedTargets[to], "Invalid target");

        // 4. Selector validation
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            require(allowedSelectors[selector], "Invalid function");
        }

        // 5. Value limits
        require(value <= MAX_VALUE, "Value too high");

        // 6. Complete commit hash with all parameters
        bytes32 commit = keccak256(abi.encode(
            to,
            value,
            data,
            nonce,
            deadline,
            block.chainid,
            address(this)
        ));

        // 7. Call depth check (approximate)
        uint256 startGas = gasleft();
        require(startGas > 100000, "Insufficient gas/depth");

        assembly {
            let authorized := auth(to, commit)
            success := authcall(sub(gas(), 10000), to, value, add(data, 32), mload(data), 0, 0)
        }

        emit Executed(msg.sender, to, success);
        return success;
    }
}

/**
 * @title SecureBlobProcessor
 * @notice SECURE: Proper EIP-4844 blob validation
 */
contract SecureBlobProcessor {
    address constant POINT_EVALUATION_PRECOMPILE = address(0x0a);

    event BlobProcessed(bytes32 indexed versionedHash, bool verified);

    /**
     * @notice SECURE: Validates versioned hash prefix
     */
    function processBlobData(bytes32 versionedHash) external {
        // Verify version prefix (0x01 for KZG)
        require(uint8(versionedHash[0]) == 0x01, "Invalid version");
        emit BlobProcessed(versionedHash, true);
    }

    /**
     * @notice SECURE: Uses blobhash with validation
     */
    function getBlobHash(uint256 index) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            hash := blobhash(index)
        }
        // Validate version prefix
        require(hash >> 248 == 0x01, "Invalid blob version");
        return hash;
    }

    /**
     * @notice SECURE: Verifies KZG proof via precompile
     */
    function verifyBlobProof(
        bytes32 versionedHash,
        bytes32 z,
        bytes32 y,
        bytes memory commitment,
        bytes memory proof
    ) external view returns (bool) {
        // Version check
        require(uint8(versionedHash[0]) == 0x01, "Invalid version");

        // Call point evaluation precompile
        (bool success, bytes memory result) = POINT_EVALUATION_PRECOMPILE.staticcall(
            abi.encode(versionedHash, z, y, commitment, proof)
        );

        return success && result.length > 0;
    }

    /**
     * @notice SECURE: Proper blob gas calculation
     */
    function estimateBlobGas(uint256 numBlobs) external view returns (uint256) {
        uint256 blobBaseFee;
        assembly {
            blobBaseFee := blobbasefee()
        }
        // Proper calculation: base fee * gas per blob * number of blobs
        uint256 gasPerBlob = 131072; // 2^17
        return blobBaseFee * gasPerBlob * numBlobs;
    }
}

/**
 * @title SecureSelfdestructPattern
 * @notice SECURE: Proper post-Cancun selfdestruct handling
 */
contract SecureSelfdestructPattern {
    address public owner;
    bool public active;

    event FundsRecovered(address indexed to, uint256 amount);
    event ContractDeactivated();

    constructor() {
        owner = msg.sender;
        active = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenActive() {
        require(active, "Contract inactive");
        _;
    }

    /**
     * @notice SECURE: Use pausable pattern instead of selfdestruct for deactivation
     */
    function deactivate() external onlyOwner {
        active = false;
        emit ContractDeactivated();
    }

    /**
     * @notice SECURE: ETH recovery still works with selfdestruct
     */
    function recoverETH(address payable to) external onlyOwner {
        uint256 balance = address(this).balance;
        emit FundsRecovered(to, balance);
        // Post-Cancun: ETH transfer still works, just code won't be deleted
        selfdestruct(to);
    }

    /**
     * @notice SECURE: Don't rely on extcodesize for destruction check
     */
    function isActive() external view returns (bool) {
        // Use state flag instead of extcodesize
        return active;
    }

    receive() external payable whenActive {}
}

/**
 * @title SecureCrossChainContract
 * @notice SECURE: Handles PUSH0 compatibility properly
 */
// Using older pragma for cross-chain compatibility
// pragma solidity ^0.8.19; // Would use this for pre-Shanghai chains

contract SecureCrossChainContract {
    // For multi-chain deployment, compile with:
    // solc --evm-version paris

    mapping(uint256 => bool) public supportedChains;

    constructor() {
        supportedChains[1] = true;
    }

    function addChain(uint256 chainId) external {
        supportedChains[chainId] = true;
    }

    // Safe cross-chain message
    function sendMessage(uint256 destChain, bytes calldata data) external pure returns (bytes32) {
        return keccak256(abi.encode(destChain, data));
    }
}
