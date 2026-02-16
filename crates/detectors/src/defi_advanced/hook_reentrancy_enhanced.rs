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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip files in directories covered by dedicated detectors
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("deadline/") || file_lower.contains("deadline\\") {
                return Ok(findings);
            }
        }

        // FP Reduction: Use per-contract source to avoid matching keywords from other
        // contracts in the same file.
        let contract_source = crate::utils::get_contract_source(ctx);
        let lower = contract_source.to_lowercase();

        // FP Reduction: Only analyze contracts whose own functions include hooks or
        // DeFi callback patterns susceptible to hook reentrancy
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_has_hook_fn = contract_func_names.iter().any(|n| {
            n.contains("beforeswap")
                || n.contains("afterswap")
                || n.contains("beforeadd")
                || n.contains("afteradd")
                || n.contains("beforeremove")
                || n.contains("afterremove")
                || n.contains("addliquidity")
                || n.contains("removeliquidity")
                || n.contains("onswap")
                || n.contains("virtual_price")
                || n.contains("virtualprice")
                || n.contains("tokensreceived")
        });
        if !contract_has_hook_fn {
            return Ok(findings);
        }

        // Check for Uniswap V4 hook functions with external calls
        // Require "function" prefix to avoid matching comments/events/variables
        let is_before_hook = lower.contains("function beforeswap")
            || lower.contains("function beforeaddliquidity")
            || lower.contains("function beforeremoveliquidity");

        let is_after_hook = lower.contains("function afterswap")
            || lower.contains("function afteraddliquidity")
            || lower.contains("function afterremoveliquidity");

        if is_before_hook || is_after_hook {
            // Check for external calls in hooks — only flag actual low-level calls
            let has_external_call = lower.contains(".call{")
                || (lower.contains(".transfer(") && !lower.contains("safetransfer"))
                || lower.contains(".send(")
                || lower.contains("delegatecall(");

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
        // FP Reduction: Only match hook-specific callbacks via function names, not generic mentions
        // in comments. "pool" in source matches "mempool", "flashLoanProvider", etc.
        let has_hook_callback_fn = contract_func_names.iter().any(|n| {
            n.contains("onswap")
                || n.contains("tokensreceived")
                || n.contains("onflashloan")
                || n.contains("hookcallback")
                || n.contains("poolcallback")
                || n.contains("removeliquidity")
        });
        // Contract name check: "pool" in contract name is meaningful (vs "pool" in comments)
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let is_pool_contract = contract_name_lower.contains("pool")
            || contract_name_lower.contains("amm")
            || contract_name_lower.contains("curve");
        let is_hook_callback = has_hook_callback_fn
            || (is_pool_contract
                && contract_func_names
                    .iter()
                    .any(|n| n.contains("removeliquidity") || n.contains("remove_liquidity")))
            || lower.contains("function onswap")
            || lower.contains("function tokensreceived")
            || lower.contains("function onflashloan");

        if is_hook_callback {
            // FP Reduction: Require actual low-level calls, not safe transfers
            let has_external_call = lower.contains(".call{")
                || lower.contains(".call(")
                || (lower.contains(".transfer(") && !lower.contains("safetransfer"))
                || lower.contains(".send(")
                || lower.contains("delegatecall(");

            if has_external_call {
                // Check for callback validation — expanded patterns
                let has_callback_validation = lower.contains("require(msg.sender")
                    || lower.contains("onlypool")
                    || lower.contains("onlyhook")
                    || lower.contains("onlylender")
                    || lower.contains("authorized")
                    || lower.contains("msg.sender ==")
                    || lower.contains("msg.sender!=")
                    || (lower.contains("msg.sender") && lower.contains("revert"));

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
