//! AA Entry Point Reentrancy Detector
//!
//! Detects reentrancy vulnerabilities in EntryPoint's handleOps and validateUserOp
//! functions. AA-specific reentrancy can manipulate state during validation phase.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::{modern_eip_patterns, reentrancy_patterns};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AAEntryPointReentrancyDetector {
    base: BaseDetector,
}

impl AAEntryPointReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-entry-point-reentrancy".to_string()),
                "AA Entry Point Reentrancy".to_string(),
                "Detects reentrancy in handleOps and validateUserOp functions".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Reentrancy],
                Severity::Medium,
            ),
        }
    }
}

impl Default for AAEntryPointReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AAEntryPointReentrancyDetector {
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

        let lower = ctx.source_code.to_lowercase();

        // Check for EntryPoint or AA wallet
        let is_aa_contract = lower.contains("handleops")
            || lower.contains("validateuserop")
            || lower.contains("entrypoint");

        if !is_aa_contract {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong reentrancy protections (return early)
        if reentrancy_patterns::has_reentrancy_guard(ctx) {
            // OpenZeppelin ReentrancyGuard protects all entry points
            return Ok(findings);
        }

        // Level 2: EIP-1153 transient storage protection
        if modern_eip_patterns::has_safe_transient_storage_pattern(ctx) {
            // Transient storage provides gas-efficient reentrancy protection
            return Ok(findings);
        }

        // Level 3: CEI pattern compliance
        if reentrancy_patterns::follows_cei_pattern(ctx) {
            // Checks-effects-interactions pattern reduces reentrancy risk
            return Ok(findings);
        }

        // Pattern 1: External call in validateUserOp without reentrancy guard
        let has_validate =
            lower.contains("function validateuserop") || lower.contains("function _validateuserop");

        if has_validate {
            let has_external_call = lower.contains(".call{")
                || lower.contains(".call(")
                || lower.contains("delegatecall")
                || lower.contains("transfer(")
                || lower.contains(".send(");

            let has_reentrancy_guard = lower.contains("nonreentrant")
                || lower.contains("_reentrancyguard")
                || lower.contains("locked")
                || lower.contains("mutex");

            if has_external_call && !has_reentrancy_guard {
                let finding = self.base.create_finding(
                    ctx,
                    "validateUserOp makes external calls without reentrancy guard - state manipulation during validation possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add nonReentrant modifier to validateUserOp or use checks-effects-interactions pattern".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: handleOps processes multiple operations without reentrancy protection
        let has_handle_ops = lower.contains("function handleops");
        if has_handle_ops {
            let has_loop = lower.contains("for (") || lower.contains("for(");
            let has_reentrancy_guard = lower.contains("nonreentrant")
                || lower.contains("_reentrancyguard")
                || lower.contains("locked");

            if has_loop && !has_reentrancy_guard {
                let finding = self.base.create_finding(
                    ctx,
                    "handleOps processes multiple operations without reentrancy guard - cross-operation reentrancy risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add nonReentrant modifier to handleOps function to prevent reentrancy across batch".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: State changes after external call in validation
        let lines: Vec<&str> = ctx.source_code.lines().collect();
        let mut in_validate_function = false;
        let mut found_external_call_line = None;

        for (i, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            // Track if we're in validateUserOp
            if line_lower.contains("function validateuserop") {
                in_validate_function = true;
            } else if in_validate_function && line_lower.contains("function ") {
                in_validate_function = false;
            }

            // In validateUserOp, look for external calls followed by state changes
            if in_validate_function {
                if line_lower.contains(".call(") || line_lower.contains(".call{") {
                    found_external_call_line = Some(i);
                }

                // Check for state changes after external call
                if let Some(call_line) = found_external_call_line {
                    if i > call_line
                        && i < call_line + 10
                        && (line_lower.contains(" = ")
                            || line_lower.contains("++")
                            || line_lower.contains("--"))
                        && !line_lower.contains("//")
                    {
                        let finding = self.base.create_finding(
                            ctx,
                            "State modified after external call in validateUserOp - reentrancy can exploit this".to_string(),
                            (i + 1) as u32,
                            1,
                            line.len() as u32,
                        )
                        .with_fix_suggestion(
                            "Move state changes before external call (checks-effects-interactions pattern)".to_string()
                        );

                        findings.push(finding);
                        break; // Exit after finding to avoid duplicates
                    }
                }
            }
        }

        // Pattern 4: Callback to untrusted contract during validation
        if has_validate {
            let has_callback =
                lower.contains("callback") || lower.contains("hook") || lower.contains("notify");

            let validates_callback_target = lower.contains("trusted")
                || lower.contains("whitelist")
                || lower.contains("authorized");

            if has_callback && !validates_callback_target {
                let finding = self.base.create_finding(
                    ctx,
                    "Callback to untrusted contract during validation - reentrancy entry point".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate callback targets against whitelist or remove callbacks from validation phase".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: postOp function lacks reentrancy protection
        let has_post_op = lower.contains("function postop") || lower.contains("function _postop");
        if has_post_op {
            let has_reentrancy_guard =
                lower.contains("nonreentrant") || lower.contains("_reentrancyguard");

            if !has_reentrancy_guard {
                let finding = self.base.create_finding(
                    ctx,
                    "postOp function lacks reentrancy guard - can be exploited after UserOp execution".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add nonReentrant modifier to postOp or ensure it only makes read-only calls".to_string()
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
