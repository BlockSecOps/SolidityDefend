// SPDX-License-Identifier: MIT
// Based on: Code4rena GoGoPool ggAVAX - High severity first depositor attack
// Reference: GoGoPool audit findings 2024
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title GoGoPool ggAVAX-style First Depositor Attack
 * @notice ERC-4626 vault vulnerable to share price manipulation
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: Malicious first depositor can steal funds from subsequent depositors
 * Should trigger: vault-share-inflation, vault-donation-attack detectors
 *
 * Attack Steps:
 * 1. Attacker is first depositor with 1 token
 * 2. Attacker transfers large amount (e.g., 10,000 tokens) directly to vault
 * 3. Exchange rate becomes: 10,001 tokens / 1 share = 10,001:1
 * 4. Victim deposits 10,000 tokens
 * 5. Victim receives: 10,000 * 1 / 10,001 = 0 shares (rounds down)
 * 6. Victim's tokens are stuck in vault
 * 7. Attacker withdraws 1 share for all 20,001 tokens
 */
contract ggAVAX_Vulnerable is ERC20 {
    IERC20 public immutable asset; // AVAX or wAVAX

    constructor(IERC20 _asset) ERC20("GoGoPool AVAX", "ggAVAX") {
        asset = _asset;
    }

    // VULNERABILITY: Standard ERC-4626 pattern without inflation protection
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // VULNERABLE: No minimum deposit check
        // VULNERABLE: No virtual shares offset

        uint256 supply = totalSupply();

        if (supply == 0) {
            // VULNERABLE: First deposit gets 1:1 ratio
            shares = assets;
        } else {
            // VULNERABLE: Uses current balance (can be manipulated)
            uint256 totalAssets = asset.balanceOf(address(this));
            shares = (assets * supply) / totalAssets;

            // VULNERABLE: Integer division can round to 0
            // If shares == 0, user loses their deposit!
        }

        // VULNERABLE: Allows 0 share mints
        require(asset.transferFrom(msg.sender, address(this), assets));
        _mint(receiver, shares);
    }

    function withdraw(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        if (msg.sender != owner) {
            uint256 allowed = allowance(owner, msg.sender);
            require(allowed >= shares, "Insufficient allowance");
            _approve(owner, msg.sender, allowed - shares);
        }

        uint256 totalAssets = asset.balanceOf(address(this));
        assets = (shares * totalAssets) / totalSupply();

        _burn(owner, shares);
        require(asset.transfer(receiver, assets));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) return assets;

        // VULNERABLE: Direct balance check allows donation attacks
        return (assets * supply) / asset.balanceOf(address(this));
    }
}

/**
 * Expected Detection:
 * - vault-share-inflation: Critical finding
 *   - No inflation protection mechanism
 *   - First depositor can manipulate exchange rate
 *   - Integer rounding can result in 0 shares
 *
 * - vault-donation-attack: High finding
 *   - totalAssets based on balance (manipulable via transfers)
 *   - No internal accounting to prevent donations
 */
