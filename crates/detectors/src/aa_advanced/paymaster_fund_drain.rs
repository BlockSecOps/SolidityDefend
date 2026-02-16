//! AA Paymaster Fund Drain Detector
//!
//! Detects paymaster sponsorship abuse patterns that can drain paymaster funds.
//! Paymasters in ERC-4337 sponsor gas for users, but improper validation can
//! lead to fund drainage attacks.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AAPaymasterFundDrainDetector {
    base: BaseDetector,
}

impl AAPaymasterFundDrainDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-paymaster-fund-drain".to_string()),
                "AA Paymaster Fund Drain".to_string(),
                "Detects paymaster sponsorship abuse that can drain paymaster funds".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }
}

impl Default for AAPaymasterFundDrainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AAPaymasterFundDrainDetector {
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

        let lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // FP Reduction: Only analyze contracts that implement paymaster functions
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let contract_is_paymaster = contract_func_names.iter().any(|n| {
            n.contains("validatepaymasteruserop")
                || n.contains("postop")
                || n.contains("sponsor")
                || n.contains("payfor")
        }) || contract_name_lower.contains("paymaster");

        if !contract_is_paymaster {
            return Ok(findings);
        }

        // Check for paymaster implementation
        let is_paymaster = lower.contains("ipaymaster")
            || lower.contains("validatepaymasteruserop")
            || lower.contains("paymaster");

        if !is_paymaster {
            return Ok(findings);
        }

        // FP Reduction: Consolidate all sub-pattern findings into 1 finding per contract
        let has_validate_paymaster = lower.contains("validatepaymasteruserop");
        let mut sub_issues: Vec<String> = Vec::new();

        // Pattern 1: No gas limit cap
        if has_validate_paymaster {
            let has_gas_limit_check = lower.contains("maxgaslimit")
                || lower.contains("gaslimit <=")
                || lower.contains("gaslimit <")
                || (lower.contains("require") && lower.contains("gaslimit"));
            if !has_gas_limit_check {
                sub_issues.push("lacks gas limit validation".to_string());
            }
        }

        // Pattern 2: No user whitelist or rate limiting
        if is_paymaster {
            let has_whitelist = lower.contains("whitelist")
                || lower.contains("allowedusers")
                || lower.contains("isallowed");
            let has_rate_limit = lower.contains("ratelimit")
                || lower.contains("lastused")
                || lower.contains("cooldown")
                || lower.contains("requestcount");
            if !has_whitelist && !has_rate_limit {
                sub_issues.push("lacks user whitelist and rate limiting".to_string());
            }
        }

        // Pattern 3: Balance not checked
        if has_validate_paymaster {
            let checks_balance = lower.contains("address(this).balance")
                || lower.contains("getdeposit()")
                || lower.contains("balanceof(address(this))");
            let has_balance_require = checks_balance
                && (lower.contains("require")
                    || lower.contains("if (")
                    || lower.contains("revert"));
            if !has_balance_require {
                sub_issues.push("doesn't verify balance before sponsoring".to_string());
            }
        }

        // Pattern 4: No per-user spending limit
        if is_paymaster {
            let has_per_user_limit = lower.contains("userspent")
                || lower.contains("spendinglimit")
                || lower.contains("allowance[")
                || lower.contains("userlimit");
            if !has_per_user_limit {
                sub_issues.push("lacks per-user spending limits".to_string());
            }
        }

        // Pattern 5: No signature validation
        if has_validate_paymaster {
            let has_signature_validation = lower.contains("ecrecover")
                || lower.contains("verifysignature")
                || lower.contains("signature");
            let has_nonce_check = lower.contains("nonce");
            if !has_signature_validation && !has_nonce_check {
                sub_issues
                    .push("accepts operations without signature or nonce validation".to_string());
            }
        }

        // Pattern 6: Unlimited postOp gas refund
        let has_post_op = lower.contains("postop") || lower.contains("_postop");
        if has_post_op {
            let has_refund_limit = lower.contains("maxrefund")
                || lower.contains("refundlimit")
                || (lower.contains("refund") && lower.contains("min("));
            if !has_refund_limit {
                sub_issues.push("postOp lacks refund limit".to_string());
            }
        }

        if !sub_issues.is_empty() {
            let consolidated_msg = format!(
                "Paymaster '{}' has {} fund drain risks: {}",
                ctx.contract.name.name,
                sub_issues.len(),
                sub_issues.join("; ")
            );
            let finding = self
                .base
                .create_finding(ctx, consolidated_msg, 1, 1, 20)
                .with_fix_suggestion(
                    "Implement gas limits, user whitelist/rate limiting, balance checks, \
                     per-user spending limits, signature validation, and postOp refund caps"
                        .to_string(),
                );
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
