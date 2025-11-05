// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TransientComposability
 * @notice EIP-1153 Cross-Contract Composability Issues
 *
 * VULNERABILITY: Transient storage breaks composability assumptions
 * EIP: EIP-1153 (Cancun upgrade, March 2024)
 *
 * BACKGROUND:
 * Transient storage is transaction-scoped, not call-scoped. This creates composability
 * issues when contracts interact in complex ways within the same transaction.
 *
 * PROBLEM:
 * Contract A sets transient storage → Contract B reads it → Unexpected behavior
 * Flash loan protocols, DEX aggregators, and vault strategies are particularly vulnerable.
 *
 * TESTED DETECTORS:
 * - transient-storage-composability
 * - transient-storage-state-leak
 */

contract VaultA {
    mapping(address => uint256) public balances;
    uint256 private operationLock; // Simulates transient storage (EIP-1153)

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @notice VULNERABILITY 1: Transient storage leaks to external contracts
     */
    function withdrawAndCall(uint256 amount, address target, bytes calldata data) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Set transient storage
        operationLock = 1;

        // VULNERABLE: External call while transient storage is set
        // Target contract can read this transient state
        (bool success, ) = target.call(data);
        require(success, "Call failed");

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);

        operationLock = 0;
    }

    function isLocked() external view returns (uint256) {
        return operationLock;
    }
}

contract VaultB {
    mapping(address => uint256) public balances;
    VaultA public vaultA;
    uint256 private crossVaultFlag; // Simulates transient storage (EIP-1153)

    constructor(address _vaultA) {
        vaultA = VaultA(_vaultA);
    }

    /**
     * @notice VULNERABILITY 2: Reads transient storage from another contract
     * @dev Creates unexpected dependencies and race conditions
     */
    function depositWithBonus() external payable {
        // VULNERABLE: Reading transient storage from VaultA
        // This creates hidden dependency on VaultA's internal state
        uint256 vaultALock = vaultA.isLocked();

        // Decision based on another contract's transient state
        uint256 bonus = vaultALock > 0 ? msg.value / 10 : 0;

        balances[msg.sender] += msg.value + bonus;
    }

    /**
     * @notice VULNERABILITY 3: Transient storage coordination attack
     */
    function exploitCrossVault(uint256 amountA) external {
        // Set transient flag
        crossVaultFlag = 1;

        // Call VaultA which will see this flag through transient storage pollution
        bytes memory data = abi.encodeWithSignature("depositWithBonus()");
        vaultA.withdrawAndCall(amountA, address(this), data);

        crossVaultFlag = 0;
    }

    receive() external payable {
        // During callback, we have access to transient storage
        // Can manipulate state before VaultA completes its operation
    }
}

/**
 * @title FlashLoanProviderTransient
 * @notice Flash loan protocol using transient storage
 */
contract FlashLoanProviderTransient {
    uint256 private flashLoanActive; // Simulates transient storage (EIP-1153)
    uint256 public poolBalance = 1000 ether;

    /**
     * @notice VULNERABILITY 4: Flash loan with transient storage indicator
     * @dev Borrower can detect flash loan context via transient storage
     */
    function flashLoan(uint256 amount, address borrower, bytes calldata data) external {
        require(amount <= poolBalance, "Insufficient liquidity");

        // Set transient indicator
        flashLoanActive = 1;

        // Send funds
        (bool success, ) = borrower.call{value: amount}(data);
        require(success, "Borrower call failed");

        // Check repayment
        require(address(this).balance >= poolBalance, "Flash loan not repaid");

        flashLoanActive = 0;
    }

    function isFlashLoanActive() external view returns (bool) {
        return flashLoanActive == 1;
    }

    receive() external payable {}
}

/**
 * @title DEXAggregatorTransient
 * @notice DEX aggregator that can exploit transient storage
 */
contract DEXAggregatorTransient {
    FlashLoanProviderTransient public flashLoan;

    constructor(address _flashLoan) {
        flashLoan = FlashLoanProviderTransient(_flashLoan);
    }

    /**
     * @notice VULNERABILITY 5: DEX swap behavior changes during flash loan
     * @dev Flash loan detection via transient storage enables price manipulation
     */
    function swap(uint256 amountIn) external payable returns (uint256) {
        // VULNERABLE: Check if we're in a flash loan context
        // This shouldn't be detectable, but transient storage leaks it
        bool inFlashLoan = flashLoan.isFlashLoanActive();

        // Different pricing if in flash loan (price manipulation)
        uint256 rate = inFlashLoan ? 90 : 100; // 10% worse rate during flash loan
        uint256 amountOut = (amountIn * rate) / 100;

        return amountOut;
    }
}

/**
 * @title MultiCallTransient
 * @notice Multicall contract vulnerable to transient state pollution
 */
contract MultiCallTransient {
    uint256 private currentCallIndex; // Simulates transient storage (EIP-1153)

    struct Call {
        address target;
        bytes data;
    }

    /**
     * @notice VULNERABILITY 6: Transient storage pollutes multicall execution
     * @dev Each call in batch can see/modify transient state from previous calls
     */
    function aggregate(Call[] calldata calls) external returns (bytes[] memory results) {
        results = new bytes[](calls.length);

        for (uint256 i = 0; i < calls.length; i++) {
            // VULNERABLE: Set transient storage that next call can see
            currentCallIndex = i;

            (bool success, bytes memory result) = calls[i].target.call(calls[i].data);
            require(success, "Call failed");

            results[i] = result;
        }

        currentCallIndex = 0;
    }

    function getCurrentCallIndex() external view returns (uint256) {
        return currentCallIndex;
    }
}

/**
 * @title TransientStorageOracle
 * @notice Oracle that uses transient storage for caching
 */
contract TransientStorageOracle {
    uint256 private cachedPrice; // Simulates transient storage (EIP-1153)
    uint256 private cacheTimestamp; // Simulates transient storage (EIP-1153)

    /**
     * @notice VULNERABILITY 7: Transient cache can be manipulated
     * @dev External contracts can set transient storage to poison cache
     */
    function getPrice() external view returns (uint256) {
        // VULNERABLE: Reads from transient storage that could be set by caller
        // in previous call within same transaction
        if (cachedPrice > 0 && block.timestamp == cacheTimestamp) {
            return cachedPrice; // Return potentially manipulated cache
        }

        // Fetch real price (simplified)
        return 100 ether;
    }

    function setPriceCache(uint256 price) external {
        // VULNERABLE: Anyone can set transient cache
        // This affects getPrice() calls in the same transaction
        cachedPrice = price;
        cacheTimestamp = block.timestamp;
    }
}
