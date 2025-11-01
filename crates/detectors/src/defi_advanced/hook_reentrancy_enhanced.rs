//! Hook-Based Reentrancy Enhanced Detector
//!
//! Detects reentrancy vulnerabilities specific to Uniswap V4 hooks and similar systems.
//! Uniswap V4 introduces hooks that execute at specific points during swaps:
//! - beforeSwap: Executes before the swap
//! - afterSwap: Executes after the swap
//!
//! These hooks create new attack surfaces if they make external calls without
//! proper reentrancy protection, as they can re-enter the pool during a swap.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct HookReentrancyEnhancedDetector {
    base: BaseDetector,
}

impl HookReentrancyEnhancedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("hook-reentrancy-enhanced".to_string()),
                "Hook-Based Reentrancy Enhanced".to_string(),
                "Detects reentrancy vulnerabilities in Uniswap V4 hooks and similar callback systems where external calls in hooks can re-enter the contract".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }
}

impl Default for HookReentrancyEnhancedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HookReentrancyEnhancedDetector {
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

        // Check for Uniswap V4 hook functions with external calls
        let is_before_hook = lower.contains("beforeswap")
            || lower.contains("beforeaddliquidity")
            || lower.contains("beforeremoveliquidity");

        let is_after_hook = lower.contains("afterswap")
            || lower.contains("afteraddliquidity")
            || lower.contains("afterremoveliquidity");

        if is_before_hook || is_after_hook {
            // Check for external calls in hooks
            let has_external_call = lower.contains(".call{")
                || lower.contains(".transfer(")
                || lower.contains(".send(")
                || lower.contains("delegatecall");

            if has_external_call {
                // Check for reentrancy guards
                let has_reentrancy_guard = lower.contains("nonreentrant")
                    || lower.contains("locked")
                    || lower.contains("reentrancyguard")
                    || lower.contains("require(!locked");

                if !has_reentrancy_guard {
                    let hook_type = if is_before_hook { "before" } else { "after" };
                    let finding = self.base.create_finding(
                        ctx,
                        format!("External call in {}-hook without reentrancy protection - attacker can re-enter during swap", hook_type),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Add reentrancy guard (nonReentrant modifier) or follow checks-effects-interactions pattern in hook functions".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Check for callback functions that can be re-entered
        let is_callback = lower.contains("callback")
            || lower.contains("onswap")
            || lower.contains("onerc")
            || lower.contains("tokensreceived");

        if is_callback {
            let has_external_call = lower.contains(".call{")
                || lower.contains("external")
                || lower.contains("this.")
                || lower.contains("address(");

            if has_external_call {
                // Check for callback validation
                let has_callback_validation = lower.contains("require(msg.sender")
                    || lower.contains("onlypool")
                    || lower.contains("onlyhook")
                    || lower.contains("authorized");

                if !has_callback_validation {
                    let finding = self.base.create_finding(
                        ctx,
                        "Callback function lacks sender validation - attacker can trigger malicious reentry".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Validate callback sender (e.g., require(msg.sender == pool)) to prevent unauthorized reentry".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
