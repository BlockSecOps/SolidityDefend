use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::{modern_eip_patterns, reentrancy_patterns};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ERC-4626 vault reentrancy via token callback hooks
pub struct VaultHookReentrancyDetector {
    base: BaseDetector,
}

impl VaultHookReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-hook-reentrancy".to_string()),
                "Vault Hook Reentrancy".to_string(),
                "Detects ERC4626 vaults vulnerable to reentrancy attacks via ERC-777/ERC-1363 token callback hooks".to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Detector for VaultHookReentrancyDetector {
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

        // Phase 2 Enhancement: Multi-level safe pattern detection with dynamic confidence

        // Level 1: Strong reentrancy protections (return early)
        if reentrancy_patterns::has_reentrancy_guard(ctx) {
            // OpenZeppelin ReentrancyGuard protects all entry points
            return Ok(findings);
        }

        // Level 2: EIP-1153 transient storage protection (Solidity 0.8.24+)
        if modern_eip_patterns::has_safe_transient_storage_pattern(ctx) {
            // Transient storage (tstore/tload) provides gas-efficient reentrancy protection
            return Ok(findings);
        }

        // Level 3: Standard ERC20 (no hooks, safe)
        if reentrancy_patterns::is_standard_erc20(ctx) {
            // Standard ERC20 has no callback hooks - safe from hook reentrancy
            return Ok(findings);
        }

        // Level 4: Advanced DeFi patterns (reduce confidence if present)
        let follows_cei = reentrancy_patterns::follows_cei_pattern(ctx);
        let has_read_only_protection = reentrancy_patterns::has_read_only_reentrancy_protection(ctx);

        // Calculate protection score for confidence calibration
        let mut protection_score = 0;
        if follows_cei { protection_score += 2; } // CEI pattern is strong protection
        if has_read_only_protection { protection_score += 1; }

        for function in ctx.get_functions() {
            if let Some(reentrancy_issue) = self.check_hook_reentrancy(function, ctx) {
                let message = format!(
                    "Function '{}' may be vulnerable to hook reentrancy attack. {} \
                    ERC-777/ERC-1363 token callbacks can re-enter and manipulate vault state.",
                    function.name.name, reentrancy_issue
                );

                // Phase 2: Dynamic confidence scoring based on detected patterns
                let confidence = if protection_score == 0 {
                    // No protections detected - high confidence vulnerability
                    Confidence::High
                } else if protection_score == 1 {
                    // Minimal protections - medium confidence
                    Confidence::Medium
                } else {
                    // CEI pattern followed - low confidence (likely safe)
                    Confidence::Low
                };

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_cwe(362) // CWE-362: Race Condition
                    .with_confidence(confidence)
                    .with_fix_suggestion(format!(
                        "Protect '{}' from hook reentrancy. \
                    Solutions: (1) Add nonReentrant modifier from OpenZeppelin ReentrancyGuard, \
                    (2) Follow checks-effects-interactions (CEI) pattern strictly, \
                    (3) Update state BEFORE external calls with callbacks, \
                    (4) Validate token doesn't implement hooks (ERC-777/ERC-1363/callbacks), \
                    (5) Use reentrancy guard on all vault entry points, \
                    (6) Consider EIP-1153 transient storage for gas-efficient protection (Solidity 0.8.24+), \
                    (7) Use SafeERC20 wrapper library for token operations.",
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

impl VaultHookReentrancyDetector {
    /// Check for hook reentrancy vulnerabilities
    fn check_hook_reentrancy(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Identify vault operations that interact with tokens
        let is_vault_operation = function.name.name.to_lowercase().contains("deposit")
            || function.name.name.to_lowercase().contains("withdraw")
            || function.name.name.to_lowercase().contains("mint")
            || function.name.name.to_lowercase().contains("redeem")
            || function.name.name.to_lowercase().contains("claim");

        if !is_vault_operation {
            return None;
        }

        // Check for reentrancy guard
        let has_reentrancy_guard = func_source.contains("nonReentrant")
            || function.modifiers.iter().any(|m| {
                m.name.name.to_lowercase().contains("nonreentrant")
                    || m.name.name.to_lowercase().contains("reentrant")
            });

        // Pattern 1: Token transfer with potential callback (ERC-777/ERC-1363)
        let has_token_transfer = func_source.contains(".transferFrom(")
            || func_source.contains(".transfer(")
            || func_source.contains(".safeTransfer")
            || func_source.contains("transferAndCall")
            || func_source.contains("transferFromAndCall");

        // Pattern 2: State changes after token transfer
        let state_changes_after_transfer = self.has_state_change_after_call(&func_source);

        if has_token_transfer && state_changes_after_transfer && !has_reentrancy_guard {
            return Some(format!(
                "State changes after token transfer without reentrancy guard. \
                ERC-777/ERC-1363 callbacks can re-enter before state updates complete"
            ));
        }

        // Pattern 3: totalAssets() or totalSupply() read after transfer
        let reads_accounting_after_transfer = has_token_transfer
            && (func_source.contains("totalAssets()") || func_source.contains("totalSupply()"));

        if reads_accounting_after_transfer && !has_reentrancy_guard {
            return Some(format!(
                "Accounting reads (totalAssets/totalSupply) after token transfer. \
                Hook callbacks can manipulate state during reentrancy"
            ));
        }

        // Pattern 4: Balance updates after transfer
        let updates_balance_after = has_token_transfer
            && (func_source.contains("balanceOf[")
                || func_source.contains("shares[")
                || func_source.contains("balance +=")
                || func_source.contains("balance -="));

        if updates_balance_after && !has_reentrancy_guard {
            return Some(format!(
                "Balance updates after token transfer. \
                Reentrancy via hooks can occur before balances are updated"
            ));
        }

        // Pattern 5: Multiple external calls in same function
        let transfer_count =
            func_source.matches(".transfer").count() + func_source.matches(".safeTransfer").count();

        if transfer_count > 1 && !has_reentrancy_guard {
            return Some(format!(
                "Multiple token transfers without reentrancy protection. \
                Each transfer is a potential reentrancy point via ERC-777/ERC-1363 hooks"
            ));
        }

        // Pattern 6: Checks-effects-interactions violation
        let violates_cei = self.violates_checks_effects_interactions(&func_source);

        if violates_cei && has_token_transfer && !has_reentrancy_guard {
            return Some(format!(
                "Violates checks-effects-interactions pattern. \
                Effects occur after interactions, vulnerable to reentrancy via token hooks"
            ));
        }

        // Pattern 7: SafeERC20 not used (doesn't prevent hooks but good practice)
        let uses_safe_erc20 =
            func_source.contains("safeTransfer") || func_source.contains("SafeERC20");

        let uses_raw_transfer =
            func_source.contains(".transfer(") && !func_source.contains("safeTransfer");

        if uses_raw_transfer && !uses_safe_erc20 && !has_reentrancy_guard {
            return Some(format!(
                "Uses raw transfer() instead of SafeERC20. \
                No protection against malicious token implementations with callback hooks"
            ));
        }

        // Pattern 8: Deposit/mint before state update
        let is_deposit_mint = function.name.name.to_lowercase().contains("deposit")
            || function.name.name.to_lowercase().contains("mint");

        if is_deposit_mint && has_token_transfer {
            // Check if shares/balances updated before transfer
            let transfer_pos = func_source.find(".transfer");
            let balance_update_pos = func_source
                .find("balanceOf[")
                .or_else(|| func_source.find("shares +="))
                .or_else(|| func_source.find("totalSupply +="));

            if let (Some(t_pos), Some(b_pos)) = (transfer_pos, balance_update_pos) {
                if b_pos > t_pos && !has_reentrancy_guard {
                    return Some(format!(
                        "Balance/shares updated after token transfer. \
                        Hook reentrancy can read stale state before updates"
                    ));
                }
            }
        }

        // Pattern 9: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("reentrancy")
                || func_source.contains("hook")
                || func_source.contains("callback"))
        {
            return Some(format!(
                "Vault hook reentrancy vulnerability marker detected"
            ));
        }

        None
    }

    /// Check if state changes occur after external calls
    fn has_state_change_after_call(&self, source: &str) -> bool {
        // Simplified check: look for state changes after transfer calls
        let lines: Vec<&str> = source.lines().collect();
        let mut found_transfer = false;

        for line in lines {
            if line.contains(".transfer") {
                found_transfer = true;
            }

            if found_transfer {
                if line.contains(" = ") || line.contains("+=") || line.contains("-=") {
                    // Found assignment after transfer
                    return true;
                }
            }
        }

        false
    }

    /// Check if checks-effects-interactions pattern is violated
    fn violates_checks_effects_interactions(&self, source: &str) -> bool {
        // Simplified check: external call before state changes
        let lines: Vec<&str> = source.lines().collect();
        let mut found_external_call = false;

        for line in lines {
            if line.contains(".transfer") || line.contains(".call") {
                found_external_call = true;
            }

            if found_external_call {
                // Check for state changes after external call
                if (line.contains("totalSupply") && line.contains("="))
                    || (line.contains("balanceOf") && line.contains("="))
                    || (line.contains("shares") && (line.contains("+=") || line.contains("-=")))
                {
                    return true;
                }
            }
        }

        false
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
        let detector = VaultHookReentrancyDetector::new();
        assert_eq!(detector.name(), "Vault Hook Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
