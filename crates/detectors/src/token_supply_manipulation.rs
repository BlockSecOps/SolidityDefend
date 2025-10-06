use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for token supply manipulation vulnerabilities
pub struct TokenSupplyManipulationDetector {
    base: BaseDetector,
}

impl TokenSupplyManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-supply-manipulation".to_string()),
                "Token Supply Manipulation".to_string(),
                "Detects vulnerabilities in token supply management that allow unauthorized minting, burning, or supply manipulation".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for TokenSupplyManipulationDetector {
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
            if let Some(supply_issue) = self.check_token_supply_manipulation(function, ctx) {
                let message = format!(
                    "Function '{}' has token supply manipulation vulnerability. {} \
                    Improper supply controls can lead to unlimited minting, hyperinflation, or complete token devaluation.",
                    function.name.name,
                    supply_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_cwe(840) // CWE-840: Business Logic Errors
                .with_fix_suggestion(format!(
                    "Fix token supply controls in '{}'. \
                    Implement maximum supply cap, add minting rate limits, \
                    require multi-signature for minting, add supply change events, \
                    validate burn amounts, and implement supply monitoring.",
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

impl TokenSupplyManipulationDetector {
    /// Check for token supply manipulation vulnerabilities
    fn check_token_supply_manipulation(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check if function affects token supply
        let affects_supply = func_source.contains("mint") ||
                            func_source.contains("burn") ||
                            func_source.contains("totalSupply") ||
                            func_source.contains("_mint") ||
                            func_source.contains("_burn") ||
                            function.name.name.to_lowercase().contains("mint") ||
                            function.name.name.to_lowercase().contains("burn");

        if !affects_supply {
            return None;
        }

        // Pattern 1: Mint function without max supply cap
        let is_mint = func_source.contains("mint") ||
                     func_source.contains("_mint") ||
                     function.name.name.to_lowercase().contains("mint");

        let no_supply_cap = is_mint &&
                           !func_source.contains("maxSupply") &&
                           !func_source.contains("MAX_SUPPLY") &&
                           !func_source.contains("cap()");

        if no_supply_cap {
            return Some(format!(
                "Mint function lacks maximum supply cap, \
                enables unlimited token minting and hyperinflation"
            ));
        }

        // Pattern 2: Mint without access control
        let lacks_access_control = is_mint &&
                                   !func_source.contains("onlyOwner") &&
                                   !func_source.contains("onlyMinter") &&
                                   !func_source.contains("hasRole") &&
                                   !func_source.contains("require(msg.sender");

        if lacks_access_control {
            return Some(format!(
                "Mint function lacks proper access control, \
                anyone can mint unlimited tokens"
            ));
        }

        // Pattern 3: No minting rate limit
        let has_rate_limit = func_source.contains("lastMint") ||
                            func_source.contains("mintRate") ||
                            func_source.contains("cooldown") ||
                            func_source.contains("block.timestamp");

        let no_rate_limit = is_mint &&
                           !has_rate_limit &&
                           func_source.contains("amount");

        if no_rate_limit {
            return Some(format!(
                "Mint function has no rate limit, \
                single transaction can mint excessive tokens"
            ));
        }

        // Pattern 4: Burn without balance check
        let is_burn = func_source.contains("burn") ||
                     func_source.contains("_burn") ||
                     function.name.name.to_lowercase().contains("burn");

        let no_balance_check = is_burn &&
                              !func_source.contains("balanceOf") &&
                              !func_source.contains("require") &&
                              func_source.contains("amount");

        if no_balance_check {
            return Some(format!(
                "Burn function doesn't check balance before burning, \
                can underflow balances or total supply"
            ));
        }

        // Pattern 5: TotalSupply can be manipulated directly
        let modifies_total_supply = func_source.contains("totalSupply =") ||
                                   func_source.contains("totalSupply +=") ||
                                   func_source.contains("totalSupply -=");

        let direct_manipulation = modifies_total_supply &&
                                 !is_mint &&
                                 !is_burn;

        if direct_manipulation {
            return Some(format!(
                "Function directly modifies totalSupply variable, \
                bypasses mint/burn controls for supply manipulation"
            ));
        }

        // Pattern 6: Mint doesn't update totalSupply
        let updates_balance = func_source.contains("balanceOf[") ||
                             func_source.contains("_balances[");

        let doesnt_update_supply = is_mint &&
                                  updates_balance &&
                                  !func_source.contains("totalSupply");

        if doesnt_update_supply {
            return Some(format!(
                "Mint function updates balance but not totalSupply, \
                creates discrepancy between balances and reported supply"
            ));
        }

        // Pattern 7: No supply change events
        let emits_event = func_source.contains("emit");

        let no_supply_event = (is_mint || is_burn) &&
                             !emits_event;

        if no_supply_event {
            return Some(format!(
                "Supply-changing operation doesn't emit event, \
                off-chain systems cannot track supply changes"
            ));
        }

        // Pattern 8: Mint to zero address
        let mints_to_address = is_mint &&
                              (func_source.contains("address to") ||
                               func_source.contains("address recipient"));

        let no_zero_check = mints_to_address &&
                           !func_source.contains("require(to != address(0)") &&
                           !func_source.contains("require(recipient != address(0)");

        if no_zero_check {
            return Some(format!(
                "Mint function doesn't validate recipient address, \
                tokens can be minted to zero address (burned)"
            ));
        }

        // Pattern 9: Rebasing without proper controls
        let is_rebasing = func_source.contains("rebase") ||
                         func_source.contains("_rebase") ||
                         function.name.name.to_lowercase().contains("rebase");

        let uncontrolled_rebase = is_rebasing &&
                                 !func_source.contains("maxRebase") &&
                                 !func_source.contains("rebaseCap");

        if uncontrolled_rebase {
            return Some(format!(
                "Rebase function lacks bounds checking, \
                extreme rebases can manipulate supply drastically"
            ));
        }

        // Pattern 10: Flash mint without fees or limits
        let is_flash_mint = func_source.contains("flashMint") ||
                           func_source.contains("flashLoan") ||
                           function.name.name.to_lowercase().contains("flash");

        let no_flash_controls = is_flash_mint &&
                               affects_supply &&
                               !func_source.contains("fee") &&
                               !func_source.contains("maxFlash");

        if no_flash_controls {
            return Some(format!(
                "Flash mint without fees or maximum limits, \
                enables free unlimited supply expansion attacks"
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
        let detector = TokenSupplyManipulationDetector::new();
        assert_eq!(detector.name(), "Token Supply Manipulation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
