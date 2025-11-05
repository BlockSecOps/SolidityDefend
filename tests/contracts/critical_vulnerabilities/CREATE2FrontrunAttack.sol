// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CREATE2FrontrunAttack
 * @notice Demonstrates CREATE2 frontrunning vulnerabilities
 *
 * VULNERABILITY: CREATE2 frontrunning and address prediction attacks
 * SEVERITY: Critical
 * CATEGORY: Frontrunning / MEV
 *
 * BACKGROUND:
 * CREATE2 allows deploying contracts to deterministic addresses based on:
 * - Deployer address
 * - Salt value
 * - Contract bytecode
 *
 * This determinism creates attack vectors:
 * 1. Frontrunning: Attacker sees deployment tx and deploys malicious contract first
 * 2. Phishing: Attacker deploys fake contract at expected address
 * 3. Fund theft: Attacker captures funds sent to "future" address
 *
 * REAL-WORLD CASES:
 * - Tornado Cash governance attack (2020)
 * - Uniswap V3 pool initialization attacks
 * - Cross-chain bridge deployment frontrunning
 *
 * TESTED DETECTORS:
 * - create2-frontrunning
 * - front-running
 * - missing-access-control
 */

/**
 * @title VulnerableFactory
 * @notice Factory vulnerable to CREATE2 frontrunning
 */
contract VulnerableFactory {
    event ContractDeployed(address indexed contractAddress, bytes32 salt);

    /**
     * @notice VULNERABILITY 1: Unprotected CREATE2 deployment
     * @dev Anyone can frontrun and deploy to the same address first
     */
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
        address addr;

        // VULNERABLE: No access control, no nonce, predictable address
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        require(addr != address(0), "Deployment failed");
        emit ContractDeployed(addr, salt);

        return addr;
    }

    /**
     * @notice VULNERABILITY 2: Public address prediction
     * @dev Allows anyone to compute future deployment addresses
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash)
        external
        view
        returns (address)
    {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }

    /**
     * @notice VULNERABILITY 3: Accepts funds for "future" contracts
     * @dev Funds can be stolen by frontrunning deployment
     */
    function fundFutureContract(bytes32 salt, bytes32 bytecodeHash)
        external
        payable
    {
        address futureAddr = this.computeAddress(salt, bytecodeHash);

        // VULNERABLE: Sending funds to address that doesn't exist yet
        payable(futureAddr).transfer(msg.value);
    }
}

/**
 * @title VulnerableWallet
 * @notice Simple wallet that will be deployed via CREATE2
 */
contract VulnerableWallet {
    address public owner;

    constructor(address _owner) payable {
        owner = _owner;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

/**
 * @title MaliciousWallet
 * @notice Attacker's fake wallet with same bytecode structure
 */
contract MaliciousWallet {
    address public owner;

    constructor(address _owner) payable {
        // MALICIOUS: Set attacker as owner instead of intended owner
        owner = tx.origin; // Attacker's address
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

/**
 * @title CREATE2Attacker
 * @notice Demonstrates CREATE2 frontrunning attack
 */
contract CREATE2Attacker {
    VulnerableFactory public factory;

    constructor(address _factory) {
        factory = VulnerableFactory(_factory);
    }

    /**
     * @notice ATTACK 1: Frontrun deployment and steal address
     */
    function frontrunDeployment(
        bytes32 salt,
        bytes memory maliciousBytecode
    ) external returns (address) {
        // Attacker sees victim's deployment tx in mempool
        // Attacker submits same deployment with higher gas
        // Attacker's contract gets deployed to intended address first

        return factory.deploy(salt, maliciousBytecode);
    }

    /**
     * @notice ATTACK 2: Pre-compute address and steal funds
     */
    function stealPreFundedContract(
        bytes32 salt,
        bytes memory maliciousBytecode,
        bytes32 bytecodeHash
    ) external returns (address) {
        // Step 1: Victim calls fundFutureContract()
        // Step 2: Attacker frontruns and deploys malicious contract
        // Step 3: Attacker's contract receives the funds
        // Step 4: Attacker withdraws funds

        address maliciousAddr = factory.deploy(salt, maliciousBytecode);

        // Funds are already at this address, sent by victim
        // Withdraw to attacker
        MaliciousWallet(payable(maliciousAddr)).withdraw();

        return maliciousAddr;
    }

    /**
     * @notice ATTACK 3: Deploy at predicted address before victim
     */
    function deployAtPredictedAddress(
        bytes32 victimSalt,
        address victimAddress
    ) external payable returns (address) {
        // Attacker knows:
        // - Factory address
        // - Salt victim will use
        // - Bytecode victim will deploy

        // Deploy malicious contract first
        bytes memory maliciousBytecode = abi.encodePacked(
            type(MaliciousWallet).creationCode,
            abi.encode(msg.sender)
        );

        return factory.deploy(victimSalt, maliciousBytecode);
    }
}

/**
 * @title CrossChainDeploymentVulnerable
 * @notice Vulnerable cross-chain CREATE2 deployment
 */
contract CrossChainDeploymentVulnerable {
    mapping(uint256 => address) public deployedContracts; // chainId => address

    event CrossChainDeployment(uint256 indexed chainId, address contractAddress);

    /**
     * @notice VULNERABILITY 4: Cross-chain CREATE2 without verification
     * @dev Assumes same address across chains, vulnerable to frontrunning
     */
    function deployCrossChain(
        bytes32 salt,
        bytes memory bytecode,
        uint256[] memory chainIds
    ) external returns (address predictedAddress) {
        // VULNERABLE: Assumes deployment will succeed on all chains
        // Attacker can frontrun on some chains but not others

        predictedAddress = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(bytecode)
        )))));

        // Record deployment (but doesn't verify!)
        for (uint256 i = 0; i < chainIds.length; i++) {
            deployedContracts[chainIds[i]] = predictedAddress;
            emit CrossChainDeployment(chainIds[i], predictedAddress);
        }

        // VULNERABLE: Doesn't actually deploy on other chains
        // Doesn't verify deployment succeeded
        // Attacker can deploy malicious contract on other chains
    }

    /**
     * @notice VULNERABILITY 5: Trust cross-chain deployments without proof
     */
    function trustCrossChainAddress(uint256 chainId)
        external
        view
        returns (address)
    {
        // VULNERABLE: No verification of actual deployment
        return deployedContracts[chainId];
    }
}

/**
 * @title SecureFactory
 * @notice Demonstrates proper CREATE2 protections
 */
contract SecureFactory {
    address public owner;
    mapping(bytes32 => bool) public saltUsed;
    mapping(address => bool) public isDeployed;

    uint256 private nonce; // Additional entropy

    event ContractDeployed(
        address indexed contractAddress,
        bytes32 salt,
        address deployer
    );

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Protected CREATE2 deployment
     */
    function deploySecure(bytes32 userSalt, bytes memory bytecode)
        external
        returns (address)
    {
        // MITIGATION 1: Access control
        // require(msg.sender == owner, "Not authorized");

        // MITIGATION 2: Add nonce to salt for unpredictability
        bytes32 actualSalt = keccak256(abi.encodePacked(
            userSalt,
            msg.sender,
            nonce++
        ));

        // MITIGATION 3: Prevent salt reuse
        require(!saltUsed[actualSalt], "Salt already used");
        saltUsed[actualSalt] = true;

        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), actualSalt)
        }

        require(addr != address(0), "Deployment failed");

        // MITIGATION 4: Track deployments
        isDeployed[addr] = true;

        emit ContractDeployed(addr, actualSalt, msg.sender);
        return addr;
    }

    /**
     * @notice SECURE: Verify deployment before funding
     */
    function deployAndFund(bytes32 salt, bytes memory bytecode)
        external
        payable
        returns (address)
    {
        // MITIGATION 5: Deploy first, then fund
        address addr = this.deploySecure(salt, bytecode);

        // MITIGATION 6: Verify deployment succeeded
        require(isDeployed[addr], "Deployment not verified");

        // Now safe to fund
        payable(addr).transfer(msg.value);

        return addr;
    }

    /**
     * @notice SECURE: Don't expose address computation publicly
     * @dev Only owner can predict addresses
     */
    function computeAddress(
        bytes32 userSalt,
        bytes32 bytecodeHash,
        address deployer,
        uint256 deploymentNonce
    ) external view returns (address) {
        require(msg.sender == owner, "Not authorized");

        bytes32 actualSalt = keccak256(abi.encodePacked(
            userSalt,
            deployer,
            deploymentNonce
        ));

        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            actualSalt,
            bytecodeHash
        )))));
    }
}

/**
 * @title CREATE2WithCommitReveal
 * @notice Secure CREATE2 using commit-reveal scheme
 */
contract CREATE2WithCommitReveal {
    struct Commitment {
        bytes32 commitHash;
        uint256 timestamp;
        address committer;
    }

    mapping(bytes32 => Commitment) public commitments;
    uint256 public constant REVEAL_DELAY = 10 minutes;

    event Committed(bytes32 indexed commitId, address committer);
    event Revealed(bytes32 indexed commitId, address contractAddress);

    /**
     * @notice SECURE: Commit to deployment parameters
     */
    function commit(bytes32 commitHash) external {
        bytes32 commitId = keccak256(abi.encodePacked(msg.sender, commitHash));

        require(commitments[commitId].timestamp == 0, "Already committed");

        commitments[commitId] = Commitment({
            commitHash: commitHash,
            timestamp: block.timestamp,
            committer: msg.sender
        });

        emit Committed(commitId, msg.sender);
    }

    /**
     * @notice SECURE: Reveal and deploy after delay
     */
    function reveal(
        bytes32 salt,
        bytes memory bytecode,
        bytes32 secret
    ) external returns (address) {
        bytes32 commitHash = keccak256(abi.encodePacked(salt, bytecode, secret));
        bytes32 commitId = keccak256(abi.encodePacked(msg.sender, commitHash));

        Commitment memory c = commitments[commitId];

        // Verify commitment
        require(c.timestamp != 0, "No commitment found");
        require(c.committer == msg.sender, "Not committer");
        require(c.commitHash == commitHash, "Invalid reveal");
        require(block.timestamp >= c.timestamp + REVEAL_DELAY, "Too early");

        // Deploy
        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        require(addr != address(0), "Deployment failed");

        // Clean up
        delete commitments[commitId];

        emit Revealed(commitId, addr);
        return addr;
    }
}
