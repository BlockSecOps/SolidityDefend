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

        let lower = ctx.source_code.to_lowercase();

        // Check for paymaster implementation
        let is_paymaster = lower.contains("ipaymaster")
            || lower.contains("validatepaymasteruserop")
            || lower.contains("paymaster");

        if !is_paymaster {
            return Ok(findings);
        }

        // Pattern 1: No gas limit cap on sponsored operations
        let has_validate_paymaster = lower.contains("validatepaymasteruserop");
        if has_validate_paymaster {
            let has_gas_limit_check = lower.contains("maxgaslimit")
                || lower.contains("gaslimit <=")
                || lower.contains("gaslimit <")
                || (lower.contains("require") && lower.contains("gaslimit"));

            if !has_gas_limit_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster lacks gas limit validation - attacker can sponsor unlimited gas consumption".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement max gas limit per operation (e.g., require(userOp.callGasLimit <= MAX_GAS_LIMIT))".to_string()
                );

                findings.push(finding);
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
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster lacks user whitelist and rate limiting - anyone can drain funds via repeated operations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement either user whitelist OR rate limiting (requests per user per time period)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Paymaster balance not checked before sponsorship
        if has_validate_paymaster {
            let checks_balance = lower.contains("address(this).balance")
                || lower.contains("getdeposit()")
                || lower.contains("balanceof(address(this))");

            let has_balance_require = checks_balance
                && (lower.contains("require")
                    || lower.contains("if (")
                    || lower.contains("revert"));

            if !has_balance_require {
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster doesn't verify sufficient balance before sponsoring - can lead to failed operations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Check paymaster balance before accepting sponsorship: require(getDeposit() >= estimatedCost)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: No per-user spending limit
        if is_paymaster {
            let has_per_user_limit = lower.contains("userspent")
                || lower.contains("spendinglimit")
                || lower.contains("allowance[")
                || lower.contains("userlimit");

            if !has_per_user_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster lacks per-user spending limits - single user can drain all funds".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement per-user spending limits: mapping(address => uint256) public userSpent; enforce daily/weekly caps".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Paymaster accepts any signature without validation
        if has_validate_paymaster {
            let has_signature_validation = lower.contains("ecrecover")
                || lower.contains("verifysignature")
                || lower.contains("signature");

            let has_nonce_check = lower.contains("nonce");

            // If no signature validation and no nonce check, it's very dangerous
            if !has_signature_validation && !has_nonce_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster accepts operations without signature or nonce validation - replay and unauthorized sponsorship possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate paymaster-specific data signature and implement nonce to prevent replay attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: Unlimited postOp gas refund
        let has_post_op = lower.contains("postop") || lower.contains("_postop");
        if has_post_op {
            let has_refund_limit = lower.contains("maxrefund")
                || lower.contains("refundlimit")
                || (lower.contains("refund") && lower.contains("min("));

            if !has_refund_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "postOp function lacks refund limit - can drain paymaster via inflated gas costs".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Cap refund amount: uint256 refund = Math.min(actualGasCost, maxRefund)".to_string()
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
