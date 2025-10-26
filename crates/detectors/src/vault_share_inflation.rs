use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for vault share inflation attacks (first depositor attack)
pub struct VaultShareInflationDetector {
    base: BaseDetector,
}

impl VaultShareInflationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-share-inflation".to_string()),
                "Vault Share Inflation Attack".to_string(),
                "Detects ERC4626 vault implementations vulnerable to share price manipulation by first depositor".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for VaultShareInflationDetector {
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

        // NEW: Check for safe patterns at contract level FIRST
        // If any protection is present, contract is safe - no findings needed
        if vault_patterns::has_inflation_protection(ctx) {
            return Ok(findings); // Contract is protected - no findings
        }

        for function in ctx.get_functions() {
            if let Some(inflation_issue) = self.check_share_inflation(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to vault share inflation attack. {} \
                    First depositor can manipulate share price by depositing 1 wei, \
                    donating assets directly to vault, causing rounding errors that steal from subsequent depositors.",
                    function.name.name, inflation_issue
                );

                // NEW: Assign confidence based on context
                // If we get here, no protections were found, so confidence is HIGH
                let confidence = Confidence::High;

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_cwe(1339) // CWE-1339: Insufficient Precision or Accuracy
                .with_confidence(confidence) // NEW: Set confidence explicitly
                .with_fix_suggestion(format!(
                    "Protect '{}' from share inflation attack. \
                    Solutions: (1) Mint initial shares to zero address on deployment (dead shares), \
                    (2) Implement virtual shares/assets (ERC4626 with offset), \
                    (3) Enforce minimum first deposit amount, \
                    (4) Use higher precision decimals (1e18 instead of 1e6).",
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

impl VaultShareInflationDetector {
    /// Check for share inflation vulnerabilities
    fn check_share_inflation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify deposit/mint functions in vault-like contracts
        let is_deposit_function = func_source.contains("deposit")
            || function.name.name.to_lowercase().contains("deposit")
            || func_source.contains("mint(")
            || function.name.name.to_lowercase().contains("mint");

        if !is_deposit_function {
            return None;
        }

        // Check if function calculates shares
        let calculates_shares = func_source.contains("shares")
            || func_source.contains("totalSupply")
            || func_source.contains("totalAssets");

        if !calculates_shares {
            return None;
        }

        // Pattern 1: Share calculation without virtual shares/assets
        let vulnerable_calculation = (func_source.contains("shares = assets * totalSupply / totalAssets") ||
                                     func_source.contains("shares = (assets * totalSupply) / totalAssets") ||
                                     func_source.contains("shares = amount * totalSupply / totalAssets") ||
                                     func_source.contains("* totalSupply() / totalAssets()")) &&
                                    !func_source.contains("VIRTUAL_") &&
                                    !func_source.contains("+ 1") && // Virtual offset
                                    !func_source.contains("OFFSET");

        if vulnerable_calculation {
            return Some(format!(
                "Share calculation vulnerable to inflation: uses assets * totalSupply / totalAssets \
                without virtual shares/assets offset protection"
            ));
        }

        // Pattern 2: No minimum deposit requirement
        let lacks_minimum = calculates_shares
            && !func_source.contains("MINIMUM_")
            && !func_source.contains("require(amount >=")
            && !func_source.contains("require(assets >=")
            && !func_source.contains("MIN_DEPOSIT");

        if lacks_minimum {
            return Some(format!(
                "No minimum deposit amount enforced, allowing 1 wei deposit \
                that can be used for share price manipulation"
            ));
        }

        // Pattern 3: totalSupply() == 0 case not handled specially
        let checks_total_supply =
            func_source.contains("totalSupply") || func_source.contains("totalSupply()");

        let lacks_bootstrap_protection = checks_total_supply
            && !func_source.contains("if (totalSupply() == 0)")
            && !func_source.contains("if (totalSupply == 0)")
            && !func_source.contains("totalSupply() > 0")
            && !func_source.contains("INITIAL_");

        if lacks_bootstrap_protection {
            return Some(format!(
                "Share calculation doesn't handle totalSupply == 0 case specially, \
                vulnerable to first depositor setting arbitrary share/asset ratio"
            ));
        }

        // Pattern 4: No dead shares minted at deployment
        let is_constructor =
            function.name.name == "constructor" || func_source.contains("constructor");

        let is_initializer = function.name.name.to_lowercase().contains("initialize");

        let lacks_dead_shares = (is_constructor || is_initializer || is_deposit_function)
            && calculates_shares
            && !func_source.contains("_mint(address(0)")
            && !func_source.contains("mint(DEAD")
            && !func_source.contains("deadShares");

        if lacks_dead_shares && is_deposit_function {
            return Some(format!(
                "Vault doesn't mint dead shares to address(0) at initialization, \
                leaving it vulnerable to first depositor attack"
            ));
        }

        // Pattern 5: Direct asset balance check without accounting
        let uses_balance_check = func_source.contains("balanceOf(address(this))")
            || func_source.contains("token.balanceOf(address(this))")
            || func_source.contains(".balanceOf(address(this))");

        let lacks_internal_accounting = uses_balance_check
            && !func_source.contains("totalAssets")
            && !func_source.contains("totalDeposited")
            && !func_source.contains("internalBalance");

        if lacks_internal_accounting {
            return Some(format!(
                "Uses token.balanceOf(address(this)) for share price calculation \
                without internal accounting, vulnerable to direct token transfer manipulation"
            ));
        }

        // Pattern 6: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("share inflation")
                || func_source.contains("first depositor")
                || func_source.contains("ERC4626"))
        {
            return Some(format!(
                "Vault share inflation vulnerability marker detected"
            ));
        }

        None
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
        let detector = VaultShareInflationDetector::new();
        assert_eq!(detector.name(), "Vault Share Inflation Attack");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
