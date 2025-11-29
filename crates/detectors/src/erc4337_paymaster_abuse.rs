//! ERC-4337 Paymaster Abuse Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct PaymasterAbuseDetector {
    base: BaseDetector,
}

impl PaymasterAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc4337-paymaster-abuse".to_string()),
                "ERC-4337 Paymaster Abuse".to_string(),
                "Detects unlimited sponsorship, missing gas validation, and spending limit issues in paymasters".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    fn is_paymaster_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("ipaymaster") || source.contains("paymaster"))
            && (source.contains("validatepaymasteruserop") || source.contains("postop"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check validatePaymasterUserOp function
        if name.contains("validatepaymaster") {
            // Check for unlimited sponsorship (no spending limits)
            let has_balance_check = source_lower.contains("balance")
                && (source_lower.contains(">=") || source_lower.contains(">"));
            let has_allowance =
                source_lower.contains("allowance") || source_lower.contains("spendinglimit");
            let has_deposit_check = source_lower.contains("deposit")
                && (source_lower.contains("require") || source_lower.contains("revert"));

            if !has_balance_check && !has_allowance && !has_deposit_check {
                issues.push((
                    "Unlimited sponsorship without balance or spending limit checks".to_string(),
                    Severity::Critical,
                    "Add spending limits: require(sponsoredAmount[user] + actualGasCost <= maxSpendingLimit, \"Limit exceeded\");".to_string()
                ));
            }

            // Check for missing gas validation
            let has_gas_check = (source_lower.contains("gaslimit") || source_lower.contains("gas"))
                && (source_lower.contains("require") || source_lower.contains("revert"));
            let has_gas_cap = source_lower.contains("maxgas") || source_lower.contains("gaslimit");

            if !has_gas_check && !has_gas_cap {
                issues.push((
                    "Missing gas validation in paymaster".to_string(),
                    Severity::High,
                    "Add gas limits: require(userOp.callGasLimit <= maxGasLimit && userOp.verificationGasLimit <= maxVerificationGas);".to_string()
                ));
            }

            // Check for missing user validation
            let has_whitelist =
                source_lower.contains("whitelist") || source_lower.contains("allowed");
            let has_user_validation =
                source_lower.contains("verify") && source_lower.contains("user");

            if !has_whitelist && !has_user_validation {
                issues.push((
                    "No user validation in paymaster (anyone can drain funds)".to_string(),
                    Severity::Critical,
                    "Add user whitelist: require(allowedUsers[userOp.sender], \"User not authorized\");".to_string()
                ));
            }

            // Check for missing rate limiting
            let has_rate_limit = source_lower.contains("ratelimit")
                || (source_lower.contains("timestamp") && source_lower.contains("last"));

            if !has_rate_limit {
                issues.push((
                    "Missing rate limiting (paymaster drain via spam)".to_string(),
                    Severity::High,
                    "Add rate limiting: require(block.timestamp >= lastUsed[user] + cooldownPeriod, \"Rate limited\");".to_string()
                ));
            }
        }

        // Check postOp function for refund validation
        if name.contains("postop") {
            let has_refund_validation = source_lower.contains("actualgas")
                && (source_lower.contains("<=") || source_lower.contains("<"));

            if !has_refund_validation {
                issues.push((
                    "Missing refund validation in postOp (overpayment risk)".to_string(),
                    Severity::Medium,
                    "Validate refunds: require(refundAmount <= maxRefund, \"Invalid refund\");"
                        .to_string(),
                ));
            }
        }

        issues
    }
}

impl Default for PaymasterAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PaymasterAbuseDetector {
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

        if !self.is_paymaster_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
