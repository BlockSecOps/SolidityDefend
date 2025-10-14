// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault_FeeManipulation
 * @notice VULNERABLE: ERC-4626 vault with manipulable fee parameters
 *
 * VULNERABILITY: Fee manipulation and front-running
 *
 * Attack scenario:
 * 1. Admin sees large pending deposit transaction
 * 2. Admin front-runs with setFee() to increase fee to 50%
 * 3. User's deposit executes with 50% fee instead of expected 1%
 * 4. Admin extracts massive value, then lowers fee back
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault_FeeManipulation {
    IERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    address public owner;

    // VULNERABILITY: Fee can be changed instantly without timelock
    uint256 public performanceFee = 100; // 1% in basis points
    uint256 public constant FEE_DENOMINATOR = 10000;

    event Deposit(address indexed user, uint256 assets, uint256 shares, uint256 fee);
    event FeeUpdated(uint256 newFee);  // Missing effective time

    constructor(address _asset) {
        asset = IERC20(_asset);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /**
     * @notice VULNERABLE: Set performance fee
     * @dev Multiple vulnerabilities in fee setting
     *
     * VULNERABILITY: Multiple issues
     * - Unprotected fee update without timelock. Fee changes take effect immediately, enabling front-running attacks
     * - No maximum fee limit enforced. Admin can set arbitrarily high fees to extract all user value
     * - Fee updates controlled by single admin without multi-sig. Single point of failure for fee manipulation
     * - Instant fee updates without gradual ramping. Large fee changes can shock users without warning
     */
    function setFee(uint256 newFee) public onlyOwner {
        // VULNERABILITY: Unprotected fee update without timelock. Fee changes take effect immediately,
        // enabling front-running attacks
        performanceFee = newFee;

        // VULNERABILITY: Fee update without event emission. Users cannot detect fee changes
        // before they take effect
        // emit FeeUpdated(newFee); // Commented out to show vulnerability

        // VULNERABILITY: No maximum fee limit enforced. Admin can set arbitrarily high fees
        // to extract all user value

        // VULNERABILITY: Fee updates controlled by single admin without multi-sig.
        // Single point of failure for fee manipulation

        // VULNERABILITY: Instant fee updates without gradual ramping.
        // Large fee changes can shock users without warning
    }

    /**
     * @notice VULNERABLE: Deposit with fee
     * @dev Fee calculated at deposit time, subject to front-running
     *
     * VULNERABILITY: Front-runnable fee-dependent operation
     * - Fee can be changed in same block before user transaction executes
     */
    function deposit(uint256 assets) public returns (uint256 shares) {
        // VULNERABILITY: Front-runnable fee-dependent operation. Fee can be changed in same block
        // before user transaction executes
        uint256 fee = (assets * performanceFee) / FEE_DENOMINATOR;
        uint256 netAssets = assets - fee;

        shares = totalSupply == 0 ? netAssets : (netAssets * totalSupply) / asset.balanceOf(address(this));

        balanceOf[msg.sender] += shares;
        totalSupply += shares;

        require(asset.transferFrom(msg.sender, address(this), assets));

        // Send fee to owner
        if (fee > 0) {
            require(asset.transfer(owner, fee));
        }

        emit Deposit(msg.sender, assets, shares, fee);
    }

    /**
     * @notice Get current fee
     */
    function getFee() public view returns (uint256) {
        return performanceFee;
    }

    function withdraw(uint256 shares) public {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        uint256 assets = (shares * asset.balanceOf(address(this))) / totalSupply;

        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;

        require(asset.transfer(msg.sender, assets));
    }
}
