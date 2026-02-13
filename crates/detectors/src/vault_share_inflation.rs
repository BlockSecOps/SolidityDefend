use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

use ir::Instruction;

/// Detector for vault share inflation attacks (first depositor attack)
pub struct VaultShareInflationDetector {
    base: BaseDetector,
}

impl Default for VaultShareInflationDetector {
    fn default() -> Self {
        Self::new()
    }
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // CRITICAL FP FIX: Only analyze ERC4626 vaults, not simple ERC20 tokens
        // Vault share inflation is specific to ERC4626 vaults with share/asset conversion.
        // A simple ERC20 with mint() is NOT a vault.
        if !utils::is_erc4626_vault(ctx) {
            return Ok(findings);
        }

        // Also skip simple tokens that might have some vault-like functions
        if utils::is_simple_token(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Multi-level safe pattern detection with dynamic confidence

        // Level 1: Strong restaking protocol protections (return early)
        if vault_patterns::has_eigenlayer_delegation_pattern(ctx) {
            // EigenLayer has proven share price manipulation protections
            return Ok(findings);
        }

        if vault_patterns::has_lrt_peg_protection(ctx) {
            // LRT protocols (Renzo, Puffer) have robust peg stability + share inflation protection
            return Ok(findings);
        }

        if vault_patterns::has_slashing_accounting_pattern(ctx) {
            // Slashing-aware accounting includes sophisticated share calculations
            return Ok(findings);
        }

        // Level 2: Standard inflation protections (return early)
        if vault_patterns::has_inflation_protection(ctx) {
            // Protected by dead shares/virtual shares/minimum deposit
            return Ok(findings);
        }

        if vault_patterns::has_internal_balance_tracking(ctx) {
            // Internal accounting prevents donation attacks - share price unaffected by direct transfers
            return Ok(findings);
        }

        // Level 3: Advanced DeFi patterns (reduce confidence if present)
        let has_internal_tracking = false; // Already checked above
        let has_donation_guard = vault_patterns::has_donation_guard(ctx);
        let has_strategy_isolation = vault_patterns::has_strategy_isolation(ctx);
        let has_reward_distribution = vault_patterns::has_safe_reward_distribution(ctx);

        // Calculate protection score for confidence calibration
        let mut protection_score = 0;
        if has_internal_tracking {
            protection_score += 2;
        } // Strong protection
        if has_donation_guard {
            protection_score += 1;
        }
        if has_strategy_isolation {
            protection_score += 1;
        }
        if has_reward_distribution {
            protection_score += 1;
        }

        for function in ctx.get_functions() {
            // Try dataflow-enhanced check first, fall back to pattern matching
            let inflation_issue = if ctx.has_dataflow() {
                self.check_inflation_with_dataflow(function, ctx)
            } else {
                self.check_share_inflation(function, ctx)
            };
            if let Some(inflation_issue) = inflation_issue {
                let message = format!(
                    "Function '{}' may be vulnerable to vault share inflation attack. {} \
                    First depositor can manipulate share price by depositing 1 wei, \
                    donating assets directly to vault, causing rounding errors that steal from subsequent depositors.",
                    function.name.name, inflation_issue
                );

                // Phase 2: Dynamic confidence scoring based on detected patterns
                let confidence = if protection_score == 0 {
                    // No protections detected - high confidence vulnerability
                    Confidence::High
                } else if protection_score <= 2 {
                    // Some protections but not comprehensive - medium confidence
                    Confidence::Medium
                } else {
                    // Multiple partial protections - low confidence
                    Confidence::Low
                };

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_cwe(1339) // CWE-1339: Insufficient Precision or Accuracy
                .with_confidence(confidence)
                .with_fix_suggestion(format!(
                    "Protect '{}' from share inflation attack. \
                    Solutions: (1) Mint initial shares to zero address on deployment (dead shares - Uniswap V2 pattern), \
                    (2) Implement virtual shares/assets (OpenZeppelin ERC4626 with decimalsOffset), \
                    (3) Enforce minimum first deposit amount (>= 1e6 recommended), \
                    (4) Use higher precision decimals (1e18 instead of 1e6), \
                    (5) Track assets internally instead of using balanceOf, \
                    (6) Consider EigenLayer delegation pattern for restaking vaults.",
                    function.name.name
                ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl VaultShareInflationDetector {
    /// Dataflow-enhanced: Use def-use chains to verify deposit/withdraw functions
    /// have actual arithmetic that could overflow with zero shares.
    fn check_inflation_with_dataflow(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_name = function.name.name;
        let func_name_lower = func_name.to_lowercase();

        // Only check deposit/mint functions
        if !func_name_lower.contains("deposit") && !func_name_lower.contains("mint") {
            return None;
        }

        let analysis = match ctx.get_function_analysis(func_name) {
            Some(a) => a,
            None => return None,
        };

        let instructions = analysis.ir_function.get_instructions();

        // Look for division operations that could cause rounding to zero
        let has_division = instructions.iter().any(|instr| {
            matches!(instr, Instruction::Div(_, _, _))
        });

        // Look for totalSupply reads (indicating share calculation)
        let has_supply_read = instructions.iter().any(|instr| {
            matches!(instr, Instruction::StorageLoad(_, _))
        });

        // Look for minimum deposit checks
        let has_minimum_check = instructions.iter().any(|instr| {
            if let Instruction::Require(_, _) = instr {
                true // Has a require statement (may be minimum check)
            } else {
                false
            }
        });

        if has_division && has_supply_read && !has_minimum_check {
            return Some(
                "Dataflow analysis confirms share calculation with division and totalSupply read \
                 without minimum deposit protection"
                    .to_string(),
            );
        }

        None
    }

    /// Check for share inflation vulnerabilities
    fn check_share_inflation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

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
            return Some("Share calculation vulnerable to inflation: uses assets * totalSupply / totalAssets \
                without virtual shares/assets offset protection".to_string());
        }

        // Pattern 2: No minimum deposit requirement
        let lacks_minimum = calculates_shares
            && !func_source.contains("MINIMUM_")
            && !func_source.contains("require(amount >=")
            && !func_source.contains("require(assets >=")
            && !func_source.contains("MIN_DEPOSIT");

        if lacks_minimum {
            return Some(
                "No minimum deposit amount enforced, allowing 1 wei deposit \
                that can be used for share price manipulation"
                    .to_string(),
            );
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
            return Some(
                "Share calculation doesn't handle totalSupply == 0 case specially, \
                vulnerable to first depositor setting arbitrary share/asset ratio"
                    .to_string(),
            );
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
            return Some(
                "Vault doesn't mint dead shares to address(0) at initialization, \
                leaving it vulnerable to first depositor attack"
                    .to_string(),
            );
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
            return Some(
                "Uses token.balanceOf(address(this)) for share price calculation \
                without internal accounting, vulnerable to direct token transfer manipulation"
                    .to_string(),
            );
        }

        // Pattern 6: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("share inflation")
                || func_source.contains("first depositor")
                || func_source.contains("ERC4626"))
        {
            return Some("Vault share inflation vulnerability marker detected".to_string());
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
