// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TransientReentrancy
 * @notice EIP-1153 Transient Storage Reentrancy Vulnerability Test
 *
 * VULNERABILITY: Transient storage reentrancy attack
 * EIP: EIP-1153 (Cancun upgrade, March 2024)
 *
 * BACKGROUND:
 * EIP-1153 introduces transient storage (TSTORE/TLOAD) which is cleared after each transaction.
 * While gas-efficient for reentrancy guards, it creates NEW attack vectors when combined
 * with external calls that can now set transient state.
 *
 * ATTACK SCENARIO:
 * 1. Attacker calls withdraw()
 * 2. During external call (transfer), attacker's fallback is triggered
 * 3. In fallback, attacker sets transient storage flags
 * 4. These flags affect subsequent logic in the same transaction
 * 5. Attacker can coordinate multi-step attacks using transient state
 *
 * REAL-WORLD CONTEXT:
 * Post-Cancun (March 2024), protocols using transient storage for reentrancy guards
 * must be aware that even low-gas calls (transfer, send) can now manipulate transient state.
 *
 * TESTED DETECTORS:
 * - transient-storage-reentrancy
 * - transient-storage-misuse
 * - transient-reentrancy-guard
 */

contract TransientReentrancy {
    mapping(address => uint256) public balances;

    // Transient storage slot for reentrancy guard
    // In real Solidity 0.8.24+, this would use: uint256 transient private locked;
    // For testing, we simulate with a regular variable that represents transient behavior
    uint256 private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event TransientStateSet(uint256 value);

    /**
     * @notice VULNERABLE: Uses transient storage for reentrancy guard
     * @dev While transient storage auto-clears, external calls can SET transient state
     */
    modifier nonReentrant() {
        require(locked == 0, "Reentrant call");
        locked = 1;
        _;
        locked = 0; // Cleared at end of transaction in real transient storage
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice VULNERABILITY 1: Transient reentrancy via external call
     * @dev External call can set transient storage, affecting later logic
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: External call before state update
        // Attacker's fallback can set transient storage flags
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // VULNERABLE: State update after external call
        // Transient flags set during call can affect this logic
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 2: Transient state coordination
     * @dev Multiple functions can read/write transient state in same transaction
     */
    function withdrawWithBonus(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Check transient storage flag (could be set by attacker in previous call)
        uint256 bonusFlag = getTransientBonus();
        uint256 totalAmount = bonusFlag > 0 ? amount + bonusFlag : amount;

        (bool success, ) = msg.sender.call{value: totalAmount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // Only deduct original amount!
        emit Withdrawal(msg.sender, totalAmount);
    }

    /**
     * @notice VULNERABILITY 3: Transient storage can be manipulated
     * @dev External contracts can set transient storage that affects this contract
     */
    function getTransientBonus() public view returns (uint256) {
        // In real implementation, this would read from transient storage
        // Attacker could set this during callback
        return locked; // Simplified for testing
    }

    /**
     * @notice VULNERABILITY 4: Low-gas external calls can set transient state
     * @dev Post-EIP-1153, even transfer() can modify transient storage
     */
    function withdrawSafe(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount; // State update first (CEI pattern)

        // STILL VULNERABLE: Even with CEI, transfer can set transient state
        // that affects other calls in the same transaction
        payable(msg.sender).transfer(amount);

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 5: Transient storage pollution
     * @dev Transient storage can be polluted by previous calls in same transaction
     */
    function batchWithdraw(address[] calldata users, uint256[] calldata amounts) external {
        require(users.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            // VULNERABLE: Each iteration can pollute transient storage
            // affecting subsequent iterations
            _withdrawInternal(users[i], amounts[i]);
        }
    }

    function _withdrawInternal(address user, uint256 amount) private {
        require(balances[user] >= amount, "Insufficient balance");

        // Transient storage check (could be polluted by previous iteration)
        if (locked == 0) {
            locked = 1;

            (bool success, ) = user.call{value: amount}("");
            require(success, "Transfer failed");

            balances[user] -= amount;
            locked = 0;
        }
    }

    /**
     * @notice VULNERABILITY 6: Cross-contract transient state sharing
     * @dev Multiple contracts can share transient state in same transaction
     */
    function withdrawViaHelper(address helper, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: Helper contract can set transient storage
        // that this contract reads
        (bool success, bytes memory data) = helper.call(
            abi.encodeWithSignature("processWithdrawal(address,uint256)", msg.sender, amount)
        );
        require(success, "Helper failed");

        // Decision based on helper's response (which could be manipulated via transient storage)
        uint256 processedAmount = abi.decode(data, (uint256));

        (success, ) = msg.sender.call{value: processedAmount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}

/**
 * @title AttackerContract
 * @notice Simulates attacker exploiting transient storage
 */
contract AttackerContract {
    TransientReentrancy public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = TransientReentrancy(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    /**
     * @notice Attacker's fallback - sets transient storage during callback
     */
    receive() external payable {
        // In real attack, this would set transient storage flags
        // that affect the victim contract's subsequent logic
        attackCount++;

        // Could attempt reentrancy or set transient state
        if (attackCount == 1) {
            // Try to manipulate transient storage
            // In real implementation, would use TSTORE opcode
        }
    }
}
