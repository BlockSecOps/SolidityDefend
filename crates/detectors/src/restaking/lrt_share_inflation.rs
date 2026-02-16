//! LRT Share Inflation Attack Detector
//!
//! Detects ERC-4626-style first depositor attacks in Liquid Restaking Tokens where attackers
//! can deposit 1 wei, donate assets to inflate share price, causing subsequent depositors to
//! receive 0 shares and lose their deposits.
//!
//! Severity: CRITICAL
//! Category: DeFi, Restaking, Vault
//!
//! Real-World Exploit:
//! - Kelp DAO (November 2023) - Code4rena HIGH Severity
//!   "Deposit Pool Vulnerable to 4626-style Vault Inflation Attack - Users Will Lose ALL Funds"
//!   Attack: Deposit 1 wei → Donate 10,000 ETH → Victim deposits 1,000 ETH → Gets 0 shares
//!
//! Vulnerabilities Detected:
//! 1. No initial deposit lock (first deposit at 1:1 ratio)
//! 2. totalAssets() uses balanceOf (includes donations)
//! 3. No minimum shares check (can mint 0 shares)
//! 4. No donation detection (balance before/after)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::restaking::classification::*;
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct LRTShareInflationDetector {
    base: BaseDetector,
}

impl LRTShareInflationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("lrt-share-inflation".to_string()),
                "LRT Share Inflation Attack".to_string(),
                "Detects ERC-4626-style first depositor attacks in liquid restaking tokens where attackers can steal deposits".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Checks deposit/mint functions for initial share lock
    fn check_initial_share_lock(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check deposit/mint/stake functions
        if !func_name_lower.contains("deposit")
            && !func_name_lower.contains("mint")
            && !func_name_lower.contains("stake")
        {
            return findings;
        }

        // Check if function has first deposit logic
        if !has_first_deposit_logic(function, ctx) {
            return findings;
        }

        // Check for initial share lock (OpenZeppelin pattern)
        if !has_initial_share_lock(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No initial share lock in '{}' - vulnerable to inflation attack (Kelp DAO exploit)",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Implement initial share lock (OpenZeppelin ERC-4626 pattern):\n\
                 \n\
                 uint256 private constant INITIAL_SHARE_LOCK = 1000;\n\
                 bool private initialized;\n\
                 \n\
                 function deposit(uint256 assets) external returns (uint256 shares) {\n\
                     // ... balance checks\n\
                     \n\
                     if (!initialized) {\n\
                         // First deposit: lock initial shares to prevent inflation\n\
                         shares = assets;\n\
                         _mint(address(0), INITIAL_SHARE_LOCK);  // Lock to 0x0\n\
                         _mint(msg.sender, shares - INITIAL_SHARE_LOCK);\n\
                         initialized = true;\n\
                     } else {\n\
                         shares = (assets * totalSupply()) / _totalTrackedAssets;\n\
                         require(shares > 0, \"Zero shares\");\n\
                         _mint(msg.sender, shares);\n\
                     }\n\
                     \n\
                     _totalTrackedAssets += assets;\n\
                 }\n\
                 \n\
                 This prevents attacker from depositing 1 wei and inflating share price.\n\
                 \n\
                 Reference: https://code4rena.com/reports/2023-11-kelp (Kelp DAO exploit)".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks deposit functions for minimum shares validation
    fn check_minimum_shares(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check deposit/mint functions
        if !func_name_lower.contains("deposit") && !func_name_lower.contains("mint") {
            return findings;
        }

        // Check for minimum shares check
        if !checks_minimum_shares(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "No minimum shares check in '{}' - can mint 0 shares (rounding attack)",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Validate minimum shares minted:\n\
                 \n\
                 function deposit(uint256 assets) external returns (uint256 shares) {\n\
                     shares = convertToShares(assets);\n\
                     \n\
                     // Prevent zero shares (rounding attack)\n\
                     require(shares > 0, \"Zero shares - deposit amount too small\");\n\
                     \n\
                     _mint(msg.sender, shares);\n\
                     _totalTrackedAssets += assets;\n\
                 }\n\
                 \n\
                 This prevents victim from depositing assets but receiving 0 shares."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks deposit functions for donation detection
    fn check_donation_detection(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check deposit functions
        if !func_name_lower.contains("deposit") {
            return findings;
        }

        // Check for donation detection
        if !has_donation_detection(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No donation detection in '{}' - attacker can inflate share price via direct transfer",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Detect donations via balance before/after comparison:\n\
                 \n\
                 function deposit(uint256 assets) external returns (uint256 shares) {\n\
                     // Capture balance before transfer\n\
                     uint256 balanceBefore = asset.balanceOf(address(this));\n\
                     \n\
                     asset.transferFrom(msg.sender, address(this), assets);\n\
                     \n\
                     // Verify actual deposit amount (detect donations)\n\
                     uint256 balanceAfter = asset.balanceOf(address(this));\n\
                     uint256 actualDeposit = balanceAfter - balanceBefore;\n\
                     \n\
                     require(\n\
                         actualDeposit == assets,\n\
                         \"Donation detected - unexpected balance increase\"\n\
                     );\n\
                     \n\
                     // Calculate shares based on tracked assets, not balanceOf\n\
                     shares = (assets * totalSupply()) / _totalTrackedAssets;\n\
                     _mint(msg.sender, shares);\n\
                     \n\
                     _totalTrackedAssets += actualDeposit;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks totalAssets() implementation for balanceOf usage
    fn check_total_assets_implementation(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find totalAssets function
        let functions = ctx.get_functions();
        let total_assets_func = functions.iter().find(|f| {
            let name = f.name.name.to_lowercase();
            name == "totalassets" || name == "total_assets"
        });

        if let Some(func) = total_assets_func {
            // Check if it uses balanceOf
            if uses_balance_of(func, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        "totalAssets() uses balanceOf - vulnerable to donation manipulation"
                            .to_string(),
                        func.name.location.start().line() as u32,
                        0,
                        20,
                        Severity::Critical,
                    )
                    .with_fix_suggestion(
                        "Use tracked assets instead of balanceOf:\n\
                     \n\
                     // BAD: Includes donations\n\
                     function totalAssets() public view returns (uint256) {\n\
                         return asset.balanceOf(address(this));  // VULNERABLE\n\
                     }\n\
                     \n\
                     // GOOD: Only counts legitimate deposits\n\
                     uint256 private _totalTrackedAssets;\n\
                     \n\
                     function totalAssets() public view returns (uint256) {\n\
                         return _totalTrackedAssets;  // SECURE\n\
                     }\n\
                     \n\
                     function deposit(uint256 assets) external {\n\
                         // ...\n\
                         _totalTrackedAssets += assets;  // Track explicitly\n\
                     }\n\
                     \n\
                     function withdraw(uint256 shares) external {\n\
                         uint256 assets = convertToAssets(shares);\n\
                         _totalTrackedAssets -= assets;  // Decrement on withdrawal\n\
                         // ...\n\
                     }\n\
                     \n\
                     This prevents attacker from inflating totalAssets via direct transfer."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        findings
    }

    /// Checks for tracked assets storage variable
    fn check_tracked_assets_storage(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract is LRT
        if !is_lrt_contract(ctx) {
            return findings;
        }

        // Check for tracked assets variable
        if !has_tracked_assets_storage(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No tracked assets variable - should track deposits explicitly instead of using balanceOf".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Add tracked assets storage:\n\
                 \n\
                 // Track total assets explicitly (don't rely on balanceOf)\n\
                 uint256 private _totalTrackedAssets;\n\
                 \n\
                 function deposit(uint256 assets) external {\n\
                     // ... deposit logic\n\
                     _totalTrackedAssets += assets;\n\
                 }\n\
                 \n\
                 function withdraw(uint256 shares) external {\n\
                     uint256 assets = convertToAssets(shares);\n\
                     _totalTrackedAssets -= assets;\n\
                     // ... withdrawal logic\n\
                 }\n\
                 \n\
                 function totalAssets() public view returns (uint256) {\n\
                     return _totalTrackedAssets;  // Use tracked, not balanceOf\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for minimum deposit amount
    fn check_minimum_deposit(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // Only check LRT contracts
        if !is_lrt_contract(ctx) {
            return findings;
        }

        // Check for minimum deposit constant
        let has_min_deposit = source_lower.contains("min_deposit")
            || source_lower.contains("mindeposit")
            || source_lower.contains("minimum_deposit");

        if !has_min_deposit {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No minimum deposit amount - allows dust deposits that can be exploited".to_string(),
                1,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Define minimum deposit amount:\n\
                 \n\
                 uint256 public constant MIN_DEPOSIT = 1e15;  // 0.001 ETH\n\
                 \n\
                 function deposit(uint256 assets) external returns (uint256 shares) {\n\
                     require(assets >= MIN_DEPOSIT, \"Deposit amount too small\");\n\
                     \n\
                     // ... rest of deposit logic\n\
                 }\n\
                 \n\
                 This prevents attackers from depositing tiny amounts (1 wei) for inflation attacks.".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for LRTShareInflationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LRTShareInflationDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // Only run on LRT contracts (Liquid Restaking Tokens / ERC-4626 vaults)
        if !is_lrt_contract(ctx) && !is_erc4626_vault(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip pure ERC-4626 vaults that aren't LRT-specific.
        // The vault-share-inflation detector already covers generic ERC-4626 vaults.
        // This detector should only fire on actual LRT/restaking contracts to avoid duplicates.
        if !is_lrt_contract(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong LRT protocol protections (return early)
        if vault_patterns::has_lrt_peg_protection(ctx) {
            // LRT peg protection includes share inflation protection
            return Ok(findings);
        }

        if vault_patterns::has_inflation_protection(ctx) {
            // Comprehensive inflation protection (dead shares, virtual shares, minimum deposit)
            return Ok(findings);
        }

        // FP Reduction: For contracts that also qualify as ERC-4626 vaults,
        // skip all share inflation checks (already covered by vault-share-inflation).
        // This prevents duplicate findings on the same contract.
        if is_erc4626_vault(ctx) {
            return Ok(findings);
        }

        // Check each deposit function for vulnerabilities (LRT-only contracts)
        for function in ctx.get_functions() {
            findings.extend(self.check_initial_share_lock(function, ctx));
            findings.extend(self.check_minimum_shares(function, ctx));
            findings.extend(self.check_donation_detection(function, ctx));
        }

        // Contract-level checks
        findings.extend(self.check_total_assets_implementation(ctx));
        findings.extend(self.check_tracked_assets_storage(ctx));
        findings.extend(self.check_minimum_deposit(ctx));

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {

    // Test cases would go here
    // Should cover:
    // 1. No initial share lock (Kelp DAO exploit)
    // 2. totalAssets uses balanceOf
    // 3. No minimum shares check
    // 4. No donation detection
    // 5. No tracked assets variable
    // 6. No false positives on OpenZeppelin ERC-4626 implementation
}
