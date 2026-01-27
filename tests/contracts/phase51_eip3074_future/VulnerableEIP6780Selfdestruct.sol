// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableMetamorphicContract
 * @notice VULNERABLE: Relies on CREATE2 + selfdestruct for metamorphic pattern
 * @dev Should trigger: eip6780-selfdestruct-change (Medium)
 *
 * Post-Cancun (Dencun upgrade), SELFDESTRUCT only deletes code if called
 * in the same transaction as creation. This breaks metamorphic patterns.
 */
contract VulnerableMetamorphicContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Destroy function expects code deletion
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
        // Post-Cancun: Code will NOT be deleted
        // CREATE2 redeploy will fail
    }

    // VULNERABLE: Redeploy pattern broken post-Cancun
    function redeploy(bytes memory newCode) external {
        require(msg.sender == owner, "Not owner");
        // This pattern no longer works:
        // 1. selfdestruct() - code NOT deleted post-Cancun
        // 2. CREATE2 with same salt - will fail (address occupied)
    }
}

/**
 * @title VulnerableEmergencyDestroy
 * @notice VULNERABLE: Emergency selfdestruct assumes code deletion
 * @dev Should trigger: eip6780-selfdestruct-change (Medium)
 */
contract VulnerableEmergencyDestroy {
    address public owner;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Emergency function expects code deletion for security
    function emergencyDestroy() external onlyOwner {
        // Intended: Remove contract completely in emergency
        // Post-Cancun: ETH transferred but code remains
        selfdestruct(payable(owner));
    }

    // VULNERABLE: Kill function for upgrade pattern
    function kill() external onlyOwner {
        selfdestruct(payable(owner));
        // code will be deleted - WRONG assumption post-Cancun
    }

    // VULNERABLE: Reset function expecting code cleanup
    function reset() external onlyOwner {
        selfdestruct(payable(owner));
        // contract destroyed - WRONG assumption
    }
}

/**
 * @title VulnerableExtcodesizeCheck
 * @notice VULNERABLE: Uses extcodesize to verify selfdestruct
 * @dev Should trigger: eip6780-selfdestruct-change (Medium)
 */
contract VulnerableExtcodesizeCheck {
    address public targetContract;

    function setTarget(address _target) external {
        targetContract = _target;
    }

    // VULNERABLE: Checks if contract was destroyed via extcodesize
    function isContractDestroyed() external view returns (bool) {
        uint256 size;
        address target = targetContract;
        assembly {
            size := extcodesize(target)
        }
        // Post-Cancun: This will return non-zero even after selfdestruct
        return size == 0;
    }

    // VULNERABLE: Logic depends on contract destruction
    function executeIfDestroyed() external {
        require(this.isContractDestroyed(), "Contract still exists");
        // This logic may never execute post-Cancun
    }
}

/**
 * @title MetamorphicFactory
 * @notice VULNERABLE: Factory for metamorphic contracts using CREATE2
 * @dev Should trigger: eip6780-selfdestruct-change (Medium)
 */
contract MetamorphicFactory {
    event Deployed(address indexed addr, bytes32 salt);
    event Destroyed(address indexed addr);

    mapping(bytes32 => address) public deployments;

    // Deploy using CREATE2
    function deploy(bytes memory code, bytes32 salt) external returns (address) {
        address addr;
        assembly {
            addr := create2(0, add(code, 32), mload(code), salt)
        }
        require(addr != address(0), "Deploy failed");
        deployments[salt] = addr;
        emit Deployed(addr, salt);
        return addr;
    }

    // VULNERABLE: Expects redeploy to work after destroy
    function destroyAndRedeploy(bytes32 salt, bytes memory newCode) external {
        address existing = deployments[salt];
        require(existing != address(0), "Not deployed");

        // Call selfdestruct on existing contract
        (bool success,) = existing.call(abi.encodeWithSignature("destroy()"));
        require(success, "Destroy failed");
        emit Destroyed(existing);

        // Try to redeploy - WILL FAIL post-Cancun (address still occupied)
        address newAddr;
        assembly {
            newAddr := create2(0, add(newCode, 32), mload(newCode), salt)
        }
        // newAddr will be 0 because address is still occupied
        require(newAddr != address(0), "Redeploy failed");
        deployments[salt] = newAddr;
    }
}
