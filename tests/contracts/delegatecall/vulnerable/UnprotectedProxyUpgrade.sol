// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UnprotectedProxyUpgrade
 * @notice VULNERABLE: Proxy upgrade function without access control
 * @dev This contract demonstrates a critical vulnerability where anyone can upgrade
 *      the implementation contract, potentially taking control of the proxy.
 *
 * Vulnerability: CWE-284 (Improper Access Control)
 * Severity: CRITICAL
 * Impact: Complete takeover of proxy contract
 *
 * Real-world exploits:
 * - Wormhole Bridge ($320M) - Attacker upgraded implementation to malicious contract
 * - Audius ($6M) - Unprotected delegatecall allowed arbitrary code execution
 *
 * Attack scenario:
 * 1. Attacker deploys malicious implementation contract
 * 2. Attacker calls upgradeTo() with malicious contract address
 * 3. All subsequent calls to proxy execute attacker's code
 * 4. Attacker drains all funds, steals user data, etc.
 */
contract UnprotectedProxyUpgrade {
    // Storage slot for implementation address (EIP-1967)
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Upgrade function without access control
     * @dev Anyone can call this and change the implementation!
     */
    function upgradeTo(address newImplementation) external {
        // CRITICAL BUG: No access control check!
        // Should have: require(msg.sender == owner, "Only owner");

        require(newImplementation != address(0), "Invalid address");

        // Update implementation address
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
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
     * @notice Fallback function that delegates to implementation
     */
    fallback() external payable {
        address impl = implementation();
        require(impl != address(0), "Implementation not set");

        assembly {
            // Copy msg.data
            calldatacopy(0, 0, calldatasize())

            // Delegate call to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)

            // Copy return data
            returndatacopy(0, 0, returndatasize())

            // Return or revert
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @title MaliciousImplementation
 * @notice Example of malicious implementation that attacker could deploy
 */
contract MaliciousImplementation {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    address public owner;
    mapping(address => uint256) public balances;

    /**
     * @notice Malicious function that steals all funds
     */
    function steal() external {
        // Transfer all ETH to attacker
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice Malicious function that gives attacker owner privileges
     */
    function takeOwnership() external {
        owner = msg.sender;
    }

    /**
     * @notice Drain a specific user's balance
     */
    function drainBalance(address user) external {
        uint256 amount = balances[user];
        balances[user] = 0;
        payable(msg.sender).transfer(amount);
    }
}

/**
 * @title LegitimateImplementation
 * @notice Example of what the intended implementation should look like
 */
contract LegitimateImplementation {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
