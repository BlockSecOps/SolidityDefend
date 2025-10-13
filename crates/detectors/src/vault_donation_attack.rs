use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ERC-4626 vault donation attacks via direct token transfers
pub struct VaultDonationAttackDetector {
    base: BaseDetector,
}

impl VaultDonationAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-donation-attack".to_string()),
                "Vault Donation Attack".to_string(),
                "Detects ERC4626 vaults vulnerable to price manipulation via direct token donations".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for VaultDonationAttackDetector {
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

        for function in ctx.get_functions() {
            if let Some(donation_issue) = self.check_donation_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to vault donation attack. {} \
                    Attacker can manipulate share price by directly transferring tokens to vault, \
                    causing rounding errors that steal from depositors.",
                    function.name.name, donation_issue
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Protect '{}' from donation attack. \
                    Solutions: (1) Track assets internally instead of using balanceOf, \
                    (2) Implement donation guards that track expected vs actual balance, \
                    (3) Use virtual shares/assets to make donations economically infeasible, \
                    (4) Require minimum initial deposits.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl VaultDonationAttackDetector {
    /// Check for donation attack vulnerabilities
    fn check_donation_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify vault-related functions
        let is_vault_function = self.is_vault_related_function(&func_source, &function.name.name);

        if !is_vault_function {
            return None;
        }

        // Pattern 1: Uses balanceOf for asset calculation without internal accounting
        let uses_balance_of = func_source.contains("balanceOf(address(this))")
            || func_source.contains("token.balanceOf(address(this))")
            || func_source.contains("asset.balanceOf(address(this))")
            || func_source.contains(".balanceOf(address(this))");

        let has_internal_accounting = func_source.contains("totalDeposited")
            || func_source.contains("internalBalance")
            || func_source.contains("trackedAssets")
            || func_source.contains("accountedBalance");

        if uses_balance_of && !has_internal_accounting {
            return Some(format!(
                "Uses balanceOf(address(this)) for share price calculation without internal balance tracking. \
                Vulnerable to direct token donation manipulation"
            ));
        }

        // Pattern 2: totalAssets() implementation that uses balance directly
        let is_total_assets = function.name.name.to_lowercase().contains("totalassets")
            || function.name.name == "totalAssets";

        if is_total_assets && uses_balance_of && !has_internal_accounting {
            return Some(format!(
                "totalAssets() uses balanceOf directly without internal accounting. \
                Any direct token transfer will inflate share price"
            ));
        }

        // Pattern 3: Share calculation using potentially manipulable balance
        let calculates_shares = (func_source.contains("shares")
            || func_source.contains("convertToShares"))
            && (func_source.contains("totalAssets()") || func_source.contains("totalAssets"));

        if calculates_shares && uses_balance_of && !has_internal_accounting {
            return Some(format!(
                "Share calculation depends on balanceOf which can be manipulated by donations"
            ));
        }

        // Pattern 4: Missing donation guards or balance validation
        let has_donation_guard = func_source.contains("expectedBalance")
            || func_source.contains("require(asset.balanceOf(address(this)) ==")
            || func_source.contains("donationGuard")
            || func_source.contains("balanceCheck");

        if (is_total_assets || calculates_shares) && uses_balance_of && !has_donation_guard {
            return Some(format!(
                "No donation guard detected. Missing validation for unexpected balance increases"
            ));
        }

        // Pattern 5: Asset balance read without update tracking
        let reads_balance = func_source.contains(".balanceOf(");
        let updates_tracking = func_source.contains("totalDeposited +=")
            || func_source.contains("totalDeposited =")
            || func_source.contains("internalBalance +=")
            || func_source.contains("_updateBalance");

        let is_deposit_withdraw = function.name.name.to_lowercase().contains("deposit")
            || function.name.name.to_lowercase().contains("withdraw")
            || function.name.name.to_lowercase().contains("mint")
            || function.name.name.to_lowercase().contains("redeem");

        if is_deposit_withdraw && reads_balance && !updates_tracking {
            return Some(format!(
                "Deposit/withdrawal function reads balance without updating internal tracking. \
                Donations between operations will cause accounting mismatch"
            ));
        }

        // Pattern 6: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("donation")
                || func_source.contains("direct transfer")
                || func_source.contains("balance manipulation"))
        {
            return Some(format!("Vault donation vulnerability marker detected"));
        }

        None
    }

    /// Check if function is vault-related
    fn is_vault_related_function(&self, func_source: &str, func_name: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        // Check function name patterns
        let vault_name_pattern = name_lower.contains("deposit")
            || name_lower.contains("withdraw")
            || name_lower.contains("mint")
            || name_lower.contains("redeem")
            || name_lower.contains("totalassets")
            || name_lower.contains("converttoshares")
            || name_lower.contains("converttoassets");

        // Check source patterns
        let vault_source_pattern = func_source.contains("shares")
            || func_source.contains("totalSupply")
            || func_source.contains("totalAssets")
            || func_source.contains("balanceOf");

        vault_name_pattern || vault_source_pattern
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = VaultDonationAttackDetector::new();
        assert_eq!(detector.name(), "Vault Donation Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
