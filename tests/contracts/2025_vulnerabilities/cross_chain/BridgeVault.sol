// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title BridgeVault
 * @dev Cross-chain bridge contract with modern vulnerabilities
 *
 * VULNERABILITIES:
 * 1. Signature replay attacks across chains
 * 2. Chain ID manipulation vulnerabilities
 * 3. Race conditions in cross-chain message verification
 * 4. Insufficient validation of bridge operators
 * 5. Time-based oracle manipulation
 * 6. Cross-chain MEV extraction
 * 7. Liquidity sandwich attacks during bridging
 * 8. Validator set manipulation
 * 9. Emergency pause bypass
 * 10. Double spending via chain reorganization
 */
contract BridgeVault is Ownable, Pausable {

    struct BridgeRequest {
        address user;
        address token;
        uint256 amount;
        uint256 targetChain;
        address targetAddress;
        uint256 nonce;
        uint256 deadline;
        bytes32 requestHash;
    }

    struct ValidatorSignature {
        address validator;
        bytes signature;
        uint256 timestamp;
    }

    // VULNERABILITY: No chain ID in mapping, allows cross-chain replay
    mapping(bytes32 => bool) public processedRequests;
    mapping(address => uint256) public userNonces;
    mapping(address => bool) public validators;
    mapping(uint256 => uint256) public chainGasLimits;
    mapping(address => mapping(uint256 => uint256)) public userChainNonces;

    // VULNERABILITY: Single admin controls validator set
    address[] public validatorsList;
    uint256 public requiredSignatures;
    uint256 public constant MAX_VALIDATORS = 100;
    uint256 public bridgeFee = 100; // 1%

    // VULNERABILITY: Time-based validation window
    uint256 public validationWindow = 300; // 5 minutes
    uint256 public emergencyDelay = 3600; // 1 hour

    // VULNERABILITY: Mutable chain configuration
    mapping(uint256 => bool) public supportedChains;
    mapping(uint256 => address) public chainBridgeAddresses;

    event BridgeInitiated(
        bytes32 indexed requestHash,
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 targetChain
    );

    event BridgeCompleted(
        bytes32 indexed requestHash,
        address indexed user,
        uint256 amount
    );

    modifier onlyValidator() {
        require(validators[msg.sender], "Not a validator");
        _;
    }

    modifier validChain(uint256 chainId) {
        require(supportedChains[chainId], "Unsupported chain");
        _;
    }

    constructor(address[] memory _validators, uint256 _requiredSignatures) Ownable(msg.sender) {
        require(_validators.length <= MAX_VALIDATORS, "Too many validators");
        require(_requiredSignatures <= _validators.length, "Invalid signature requirement");
        require(_requiredSignatures > 0, "Must require at least one signature");

        for (uint256 i = 0; i < _validators.length; i++) {
            validators[_validators[i]] = true;
            validatorsList.push(_validators[i]);
        }
        requiredSignatures = _requiredSignatures;
    }

    /**
     * @dev Initiate bridge transfer - VULNERABLE to multiple attacks
     */
    function initiateBridge(
        address token,
        uint256 amount,
        uint256 targetChain,
        address targetAddress,
        uint256 deadline
    ) external payable whenNotPaused validChain(targetChain) {
        require(amount > 0, "Invalid amount");
        require(deadline > block.timestamp, "Deadline passed");
        require(targetAddress != address(0), "Invalid target address");

        // VULNERABILITY: No validation of target chain bridge address
        // VULNERABILITY: Using predictable nonce generation
        uint256 nonce = userNonces[msg.sender]++;

        // VULNERABILITY: Hash doesn't include chain ID, enabling replay attacks
        bytes32 requestHash = keccak256(abi.encodePacked(
            msg.sender,
            token,
            amount,
            targetChain,
            targetAddress,
            nonce,
            deadline
            // Missing: block.chainid to prevent cross-chain replay
        ));

        require(!processedRequests[requestHash], "Request already processed");

        // VULNERABILITY: Fee calculation susceptible to overflow/underflow
        uint256 fee = (amount * bridgeFee) / 10000;
        uint256 bridgeAmount = amount - fee;

        // Transfer tokens to vault
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // VULNERABILITY: State update after external call
        processedRequests[requestHash] = true;

        emit BridgeInitiated(requestHash, msg.sender, token, bridgeAmount, targetChain);
    }

    /**
     * @dev Complete bridge transfer with validator signatures - VULNERABLE
     */
    function completeBridge(
        BridgeRequest calldata request,
        ValidatorSignature[] calldata signatures
    ) external whenNotPaused {
        require(signatures.length >= requiredSignatures, "Insufficient signatures");
        require(request.deadline > block.timestamp, "Request expired");

        // VULNERABILITY: No verification that request came from supported chain
        bytes32 requestHash = keccak256(abi.encodePacked(
            request.user,
            request.token,
            request.amount,
            request.targetChain,
            request.targetAddress,
            request.nonce,
            request.deadline
        ));

        require(request.requestHash == requestHash, "Invalid request hash");
        require(!processedRequests[requestHash], "Already processed");

        // VULNERABILITY: Signature validation doesn't prevent replay attacks
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            require(validators[signatures[i].validator], "Invalid validator");

            // VULNERABILITY: No timestamp validation allows old signatures
            require(
                block.timestamp - signatures[i].timestamp <= validationWindow,
                "Signature too old"
            );

            bytes32 messageHash = getMessageHash(request);
            address signer = recoverSigner(messageHash, signatures[i].signature);
            require(signer == signatures[i].validator, "Invalid signature");

            // VULNERABILITY: No check for duplicate signers
            signers[i] = signer;
        }

        // VULNERABILITY: State update allows reentrancy
        processedRequests[requestHash] = true;

        // VULNERABILITY: No slippage protection during token transfer
        uint256 availableBalance = IERC20(request.token).balanceOf(address(this));
        require(availableBalance >= request.amount, "Insufficient vault balance");

        IERC20(request.token).transfer(request.targetAddress, request.amount);

        emit BridgeCompleted(requestHash, request.user, request.amount);
    }

    /**
     * @dev Emergency withdraw - VULNERABLE to admin abuse
     */
    function emergencyWithdraw(
        address token,
        uint256 amount,
        address to
    ) external onlyOwner {
        // VULNERABILITY: No time lock, immediate withdrawal possible
        // VULNERABILITY: No validation of withdrawal legitimacy
        IERC20(token).transfer(to, amount);
    }

    /**
     * @dev Update validator set - VULNERABLE to centralization
     */
    function updateValidators(
        address[] calldata newValidators,
        uint256 newRequiredSignatures
    ) external onlyOwner {
        // VULNERABILITY: Immediate validator set change without timelock
        require(newValidators.length <= MAX_VALIDATORS, "Too many validators");
        require(newRequiredSignatures <= newValidators.length, "Invalid requirement");

        // Clear existing validators
        for (uint256 i = 0; i < validatorsList.length; i++) {
            validators[validatorsList[i]] = false;
        }
        delete validatorsList;

        // VULNERABILITY: No validation of new validators
        for (uint256 i = 0; i < newValidators.length; i++) {
            validators[newValidators[i]] = true;
            validatorsList.push(newValidators[i]);
        }

        requiredSignatures = newRequiredSignatures;
    }

    /**
     * @dev Add supported chain - VULNERABLE to misconfiguration
     */
    function addSupportedChain(
        uint256 chainId,
        address bridgeAddress
    ) external onlyOwner {
        // VULNERABILITY: No validation of chain ID or bridge address
        supportedChains[chainId] = true;
        chainBridgeAddresses[chainId] = bridgeAddress;
    }

    /**
     * @dev Update bridge fee - VULNERABLE to immediate changes
     */
    function updateBridgeFee(uint256 newFee) external onlyOwner {
        // VULNERABILITY: No maximum fee limit, could be set to 100%
        // VULNERABILITY: No timelock for fee changes
        bridgeFee = newFee;
    }

    /**
     * @dev Get message hash for signing
     */
    function getMessageHash(BridgeRequest memory request) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(request))
        ));
    }

    /**
     * @dev Recover signer from signature
     */
    function recoverSigner(bytes32 messageHash, bytes memory signature) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @dev Pause contract - VULNERABLE to admin abuse
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Get validator count
     */
    function getValidatorCount() external view returns (uint256) {
        return validatorsList.length;
    }

    /**
     * @dev Check if chain is supported
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return supportedChains[chainId];
    }

    // VULNERABILITY: Fallback function accepts Ether without validation
    receive() external payable {
        // Could be exploited for unexpected ETH handling
    }

    // VULNERABILITY: Fallback allows arbitrary calls
    fallback() external payable {
        // Dangerous fallback that could be exploited
    }
}