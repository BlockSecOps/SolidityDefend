// SPDX-License-Identifier: MIT
// Based on: Code4rena KelpDAO contest - High severity inflation attack
// Reference: https://code4rena.com/reports/2024-kelpdao
pragma solidity ^0.8.20;

/**
 * @title KelpDAO-style Inflation Attack Vulnerability
 * @notice Simplified version demonstrating inflation attack vulnerability
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: First depositor can inflate share price to steal subsequent deposits
 * Should trigger: vault-share-inflation detector
 *
 * Attack Vector:
 * 1. Attacker deposits 1 wei (receives 1 share)
 * 2. Attacker donates large amount directly to vault (not through deposit)
 * 3. Share price inflates: totalAssets / totalShares = (1 + donation) / 1
 * 4. Victim deposits X tokens
 * 5. Victim receives: X * totalShares / totalAssets ≈ 0 shares (rounds down)
 * 6. Attacker redeems their 1 share for all assets
 */
contract KelpDAO_Vulnerable_Vault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // VULNERABILITY: No inflation protection (no virtual shares, dead shares, or minimum deposit)

    function deposit(uint256 amount) external {
        uint256 sharesToMint;

        if (totalShares == 0) {
            // First deposit: 1:1 ratio
            // VULNERABLE: Attacker can deposit 1 wei
            sharesToMint = amount;
        } else {
            // Subsequent deposits use current exchange rate
            // VULNERABLE: Can be manipulated by direct transfers
            uint256 totalAssets = address(this).balance;
            sharesToMint = (amount * totalShares) / totalAssets;
            // VULNERABLE: Integer division rounds down, can result in 0 shares
        }

        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;

        // Accept ETH deposit (simplified)
        require(msg.value == amount, "Incorrect ETH amount");
    }

    function redeem(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");

        uint256 totalAssets = address(this).balance;
        uint256 assetAmount = (shareAmount * totalAssets) / totalShares;

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        payable(msg.sender).transfer(assetAmount);
    }

    // VULNERABILITY: Anyone can donate to inflate share price
    receive() external payable {
        // Accepts direct transfers without minting shares
        // This allows inflation attacks
    }

    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (address(this).balance * 1e18) / totalShares;
    }
}

/**
 * Expected Detection:
 * - vault-share-inflation: Critical finding
 *   - No virtual shares offset
 *   - No dead shares (initial burn)
 *   - No minimum deposit requirement
 *   - Vulnerable to first depositor attack
 */
