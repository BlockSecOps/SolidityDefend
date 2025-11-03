//! Flash Loan Reentrancy Combo Detector
//!
//! Detects combined flash loan + reentrancy attacks (Penpie $27M pattern).
//! Identifies state inconsistency during flash loan callbacks.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct FlashLoanReentrancyComboDetector {
    base: BaseDetector,
}

impl FlashLoanReentrancyComboDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flash-loan-reentrancy-combo".to_string()),
                "Flash Loan Reentrancy Combo".to_string(),
                "Detects combined flash loan + reentrancy attacks (Penpie pattern)".to_string(),
                vec![DetectorCategory::FlashLoan, DetectorCategory::Reentrancy],
                Severity::Critical,
            ),
        }
    }
}

impl Default for FlashLoanReentrancyComboDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashLoanReentrancyComboDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lower = ctx.source_code.to_lowercase();

        // Check for flash loan callback
        let is_flash_loan = lower.contains("onflashloan")
            || lower.contains("flashloan")
            || lower.contains("receivetokens")
            || lower.contains("executeoperation");

        if !is_flash_loan {
            return Ok(findings);
        }

        // Skip flash loan PROVIDERS - they implement flash loan logic, not vulnerabilities
        // Flash loan providers (Aave, Compound, ERC-3156) MUST:
        // 1. Execute callback on borrower (onFlashLoan/executeOperation)
        // 2. Handle callback execution which involves external calls
        // 3. Verify repayment after callback completes
        // This is the standard flash loan pattern per ERC-3156, not a Penpie-style attack.
        // This detector should focus on flash loan CONSUMERS with unsafe state management.
        if utils::is_flash_loan_provider(ctx) {
            return Ok(findings);
        }

        // Pattern 1: Flash loan callback without reentrancy guard
        let has_flash_callback = lower.contains("onflashloan")
            || lower.contains("receivetokens")
            || lower.contains("executeoperation");

        if has_flash_callback {
            let has_reentrancy_guard = lower.contains("nonreentrant")
                || lower.contains("_reentrancyguard")
                || lower.contains("locked")
                || lower.contains("mutex");

            let has_external_call = lower.contains(".call(")
                || lower.contains(".call{")
                || lower.contains("delegatecall")
                || lower.contains("transfer(");

            if !has_reentrancy_guard && has_external_call {
                let finding = self.base.create_finding(
                    ctx,
                    "Flash loan callback lacks reentrancy guard - Penpie-style combo attack possible ($27M exploit)".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add nonReentrant modifier to flash loan callback and all functions it calls".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: State updated after flash loan repayment
        let lines: Vec<&str> = ctx.source_code.lines().collect();
        let mut in_flash_callback = false;
        let mut found_repay_line = None;

        for (i, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            if line_lower.contains("onflashloan") || line_lower.contains("flashloan") {
                in_flash_callback = true;
            } else if in_flash_callback && line_lower.contains("function ") {
                in_flash_callback = false;
            }

            if in_flash_callback {
                if line_lower.contains("transfer")
                    && (line_lower.contains("lender") || line_lower.contains("flashloan"))
                    || line_lower.contains("repay")
                {
                    found_repay_line = Some(i);
                }

                // Check for state changes after repayment
                if let Some(repay_line) = found_repay_line {
                    if i > repay_line
                        && i < repay_line + 15
                        && (line_lower.contains(" = ") || line_lower.contains("++") || line_lower.contains("--"))
                        && !line_lower.contains("//")
                    {
                        let finding = self.base.create_finding(
                            ctx,
                            "State updated after flash loan repayment - reentrancy can exploit inconsistent state".to_string(),
                            (i + 1) as u32,
                            1,
                            line.len() as u32,
                        )
                        .with_fix_suggestion(
                            "Update all state before repayment (checks-effects-interactions pattern)".to_string()
                        );

                        findings.push(finding);
                        break; // Exit after finding to avoid duplicates
                    }
                }
            }
        }

        // Pattern 3: Balance check during flash loan execution
        if is_flash_loan {
            let has_balance_check = lower.contains("balanceof(address(this))")
                || lower.contains("address(this).balance");

            let updates_based_on_balance = has_balance_check
                && (lower.contains("shares")
                    || lower.contains("deposit")
                    || lower.contains("mint")
                    || lower.contains("totalassets"));

            if updates_based_on_balance {
                let finding = self.base.create_finding(
                    ctx,
                    "Contract logic depends on balance during flash loan - state can be manipulated via temporary inflated balance".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Track internal accounting separately from balanceOf; use locked flag during flash loans".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Flash loan callback calls back into same contract
        if has_flash_callback {
            // Count references to contract functions
            let has_self_call = lower.contains("this.")
                || lower.contains("address(this)")
                || (lower.contains("call(") && lower.contains("address"));

            if has_self_call {
                let finding = self.base.create_finding(
                    ctx,
                    "Flash loan callback may call back into same contract - creates reentrancy opportunity".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Prevent callbacks from calling back into contract via reentrancy guard or locked state".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Multiple flash loans in single transaction
        if is_flash_loan {
            let flash_call_count = lower.matches("flashloan(").count()
                + lower.matches("flashborrow").count()
                + lower.matches("borrow").count();

            if flash_call_count > 1 {
                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Multiple flash loans ({}) in single flow - compound reentrancy attack surface",
                        flash_call_count
                    ),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Limit to single flash loan per transaction or add global reentrancy lock".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
