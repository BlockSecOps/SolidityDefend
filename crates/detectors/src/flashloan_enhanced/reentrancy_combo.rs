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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Scope check: verify THIS contract actually defines flash loan callback functions.
        // Multi-contract files can have flash loan keywords in OTHER contracts — don't
        // attribute those findings to an unrelated contract.
        let contract_fn_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();

        let contract_has_flash_fn = if contract_fn_names.is_empty() {
            // Fallback for test contexts with empty AST: extract contract source scope
            // and check within it
            let contract_name = ctx.contract.name.as_str();
            let lower_full = ctx.source_code.to_lowercase();
            // Find this contract's body in the source
            if let Some(contract_start) = lower_full.find(&format!("contract {}", contract_name.to_lowercase())) {
                let contract_src = &lower_full[contract_start..];
                contract_src.contains("onflashloan")
                    || contract_src.contains("flashloan(")
                    || contract_src.contains("receivetokens")
                    || contract_src.contains("executeoperation")
            } else {
                // Can't scope — fall through to full source check
                lower_full.contains("onflashloan")
                    || lower_full.contains("flashloan")
                    || lower_full.contains("receivetokens")
                    || lower_full.contains("executeoperation")
            }
        } else {
            contract_fn_names.iter().any(|name| {
                name.contains("onflashloan")
                    || name.contains("flashloan")
                    || name.contains("receivetokens")
                    || name.contains("executeoperation")
            })
        };

        if !contract_has_flash_fn {
            return Ok(findings);
        }

        // Extract contract-scoped source for accurate analysis.
        // In multi-contract files, ctx.source_code is the full file.
        // We scope to this contract's body to avoid cross-contract FPs.
        let contract_name = ctx.contract.name.as_str();
        let contract_source = extract_contract_source(&ctx.source_code, contract_name);
        let lower = contract_source.to_lowercase();

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

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        // Pre-compute line array for accurate location reporting across all patterns.
        // Uses contract-scoped source to avoid cross-contract FPs in multi-contract files.
        let contract_lines: Vec<&str> = contract_source.lines().collect();

        // Compute the line offset of this contract within the full file
        let contract_line_offset = if let Some(pos) = ctx.source_code.find(&format!("contract {}", contract_name)) {
            ctx.source_code[..pos].lines().count().saturating_sub(1)
        } else {
            0
        };

        // Check for flash loan callback in contract scope
        let is_flash_loan = lower.contains("onflashloan")
            || lower.contains("flashloan")
            || lower.contains("receivetokens")
            || lower.contains("executeoperation");

        if !is_flash_loan {
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
                // Find the actual callback line for accurate location reporting
                let (callback_line, callback_col, callback_len) = contract_lines
                    .iter()
                    .enumerate()
                    .find(|(_, line)| {
                        let ll = line.to_lowercase();
                        ll.contains("onflashloan")
                            || ll.contains("receivetokens")
                            || ll.contains("executeoperation")
                    })
                    .map(|(i, line)| ((i + 1 + contract_line_offset) as u32, 1u32, line.len() as u32))
                    .unwrap_or(((1 + contract_line_offset) as u32, 1, 10));

                let finding = self.base.create_finding(
                    ctx,
                    "Flash loan callback lacks reentrancy guard - Penpie-style combo attack possible ($27M exploit)".to_string(),
                    callback_line,
                    callback_col,
                    callback_len,
                )
                .with_fix_suggestion(
                    "Add nonReentrant modifier to flash loan callback and all functions it calls".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: State updated after flash loan repayment
        let mut in_flash_callback = false;
        let mut found_repay_line = None;

        for (i, line) in contract_lines.iter().enumerate() {
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
                        && (line_lower.contains(" = ")
                            || line_lower.contains("++")
                            || line_lower.contains("--"))
                        && !line_lower.contains("//")
                    {
                        let file_line = (i + 1 + contract_line_offset) as u32;
                        let finding = self.base.create_finding(
                            ctx,
                            "State updated after flash loan repayment - reentrancy can exploit inconsistent state".to_string(),
                            file_line,
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
                // Find the actual balance check line for accurate location reporting
                let (balance_line, balance_col, balance_len) = contract_lines
                    .iter()
                    .enumerate()
                    .find(|(_, line)| {
                        let ll = line.to_lowercase();
                        ll.contains("balanceof(address(this))")
                            || ll.contains("address(this).balance")
                    })
                    .map(|(i, line)| ((i + 1 + contract_line_offset) as u32, 1u32, line.len() as u32))
                    .unwrap_or(((1 + contract_line_offset) as u32, 1, 10));

                let finding = self.base.create_finding(
                    ctx,
                    "Contract logic depends on balance during flash loan - state can be manipulated via temporary inflated balance".to_string(),
                    balance_line,
                    balance_col,
                    balance_len,
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
                // Find the self-call line for accurate location reporting
                let (self_call_line, self_call_col, self_call_len) = contract_lines
                    .iter()
                    .enumerate()
                    .find(|(_, line)| {
                        let ll = line.to_lowercase();
                        ll.contains("this.") || (ll.contains("call(") && ll.contains("address"))
                    })
                    .map(|(i, line)| ((i + 1 + contract_line_offset) as u32, 1u32, line.len() as u32))
                    .unwrap_or(((1 + contract_line_offset) as u32, 1, 10));

                let finding = self.base.create_finding(
                    ctx,
                    "Flash loan callback may call back into same contract - creates reentrancy opportunity".to_string(),
                    self_call_line,
                    self_call_col,
                    self_call_len,
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
                // Find the first flash loan call line for accurate location reporting
                let (flash_line, flash_col, flash_len) = contract_lines
                    .iter()
                    .enumerate()
                    .find(|(_, line)| {
                        let ll = line.to_lowercase();
                        ll.contains("flashloan(")
                            || ll.contains("flashborrow")
                            || ll.contains("borrow")
                    })
                    .map(|(i, line)| ((i + 1 + contract_line_offset) as u32, 1u32, line.len() as u32))
                    .unwrap_or(((1 + contract_line_offset) as u32, 1, 10));

                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Multiple flash loans ({}) in single flow - compound reentrancy attack surface",
                        flash_call_count
                    ),
                    flash_line,
                    flash_col,
                    flash_len,
                )
                .with_fix_suggestion(
                    "Limit to single flash loan per transaction or add global reentrancy lock".to_string()
                );

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

/// Extract the source code for a specific contract from a multi-contract file.
/// Uses brace-counting to find the contract body boundaries.
/// Falls back to full source if the contract can't be found.
fn extract_contract_source<'a>(full_source: &'a str, contract_name: &str) -> &'a str {
    // Find "contract <Name>" (case-sensitive since Solidity identifiers are case-sensitive)
    let search = format!("contract {}", contract_name);
    if let Some(start) = full_source.find(&search) {
        // Find the opening brace
        if let Some(brace_offset) = full_source[start..].find('{') {
            let body_start = start + brace_offset;
            let mut depth = 0;
            let mut end = body_start;

            for (i, ch) in full_source[body_start..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = body_start + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if end > start {
                return &full_source[start..end];
            }
        }
    }

    // Fallback: return full source
    full_source
}
