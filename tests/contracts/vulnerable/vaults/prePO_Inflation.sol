// SPDX-License-Identifier: MIT
// Based on: prePO Code4rena audit - High severity inflation attack
// Reference: Code4rena audit findings 2024
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title prePO-style Inflation Attack Vulnerability
 * @notice Collateral vault vulnerable to classic ERC-4626 inflation attack
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: First depositor attack via donation
 * Should trigger: vault-share-inflation, vault-donation-attack detectors
 *
 * Attack Scenario:
 * 1. Vault is empty (0 shares, 0 assets)
 * 2. Attacker deposits 1 wei → receives 1 share
 * 3. Attacker donates 10,000 tokens directly to vault
 * 4. Exchange rate: 10,001 tokens / 1 share
 * 5. Victim deposits 5,000 tokens
 * 6. Victim receives: 5,000 * 1 / 10,001 = 0 shares (rounds down)
 * 7. Victim's 5,000 tokens are stuck
 * 8. Attacker redeems 1 share for 15,001 tokens (profit: 5,000 tokens)
 */
contract prePO_Collateral_Vulnerable is ERC20 {
    IERC20 public immutable baseToken;

    // VULNERABILITY: No minimum deposit
    // VULNERABILITY: No virtual shares
    // VULNERABILITY: No dead shares (initial burn)
    uint256 public constant MIN_DEPOSIT = 0; // Should be > 0!

    constructor(IERC20 _baseToken) ERC20("prePO Collateral", "preUSDC") {
        baseToken = _baseToken;
    }

    /**
     * @notice Deposit base tokens for collateral shares
     * @dev VULNERABLE: Classic ERC-4626 inflation attack vector
     */
    function deposit(uint256 amount, address recipient) external returns (uint256 shares) {
        require(amount > MIN_DEPOSIT, "Below minimum");  // VULNERABLE: MIN_DEPOSIT is 0!

        // VULNERABLE: totalSupply check allows 1 wei first deposit
        if (totalSupply() == 0) {
            shares = amount;  // 1:1 ratio for first deposit
        } else {
            // VULNERABLE: Uses contract balance (manipulable via donations)
            uint256 totalBaseToken = baseToken.balanceOf(address(this));
            shares = (amount * totalSupply()) / totalBaseToken;

            // VULNERABLE: Integer rounding can result in 0 shares
            // If shares == 0, user loses their deposit!
        }

        // VULNERABLE: Allows minting 0 shares (user loses funds)
        require(baseToken.transferFrom(msg.sender, address(this), amount));
        _mint(recipient, shares);
    }

    /**
     * @notice Redeem collateral shares for base tokens
     */
    function withdraw(uint256 shares) external returns (uint256 amount) {
        require(shares > 0, "Zero shares");

        uint256 totalBaseToken = baseToken.balanceOf(address(this));
        amount = (shares * totalBaseToken) / totalSupply();

        _burn(msg.sender, shares);
        require(baseToken.transfer(msg.sender, amount));
    }

    /**
     * @notice Preview deposit amount to shares
     * @dev VULNERABLE: Can be manipulated by donations
     */
    function previewDeposit(uint256 amount) public view returns (uint256) {
        if (totalSupply() == 0) return amount;

        // VULNERABLE: Direct balance check
        uint256 totalBaseToken = baseToken.balanceOf(address(this));
        return (amount * totalSupply()) / totalBaseToken;
    }

    // VULNERABILITY: No protection against direct transfers
    // Anyone can transfer tokens directly to inflate share price
}

/**
 * Expected Detection:
 * - vault-share-inflation: Critical finding
 *   - No minimum deposit enforcement (MIN_DEPOSIT = 0)
 *   - No virtual shares offset
 *   - No dead shares mechanism
 *   - First deposit can be 1 wei
 *   - Allows minting 0 shares
 *
 * - vault-donation-attack: High finding
 *   - Uses balanceOf for totalAssets (donation-vulnerable)
 *   - No internal accounting
 *   - Exchange rate manipulable via direct transfers
 */
