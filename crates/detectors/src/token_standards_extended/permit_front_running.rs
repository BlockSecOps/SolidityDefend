//! Token Permit Front-Running Detector
//!
//! Detects ERC-2612 permit griefing and front-running vulnerabilities.
//! Attackers can front-run permit transactions causing DOS or theft.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TokenPermitFrontRunningDetector {
    base: BaseDetector,
}

impl TokenPermitFrontRunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-permit-front-running".to_string()),
                "Token Permit Front-Running".to_string(),
                "Detects ERC-2612 permit griefing and front-running vulnerabilities".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for TokenPermitFrontRunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TokenPermitFrontRunningDetector {
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

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts with permit-related functions
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_has_permit_fn = contract_func_names
            .iter()
            .any(|n| n.contains("permit") || n.contains("transferfrom") || n.contains("spend"));
        if !contract_has_permit_fn {
            return Ok(findings);
        }

        // Use per-contract source to avoid cross-contract false positives in multi-contract files.
        // ctx.source_code is the full file; contract_lower scopes to just this contract.
        let contract_lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // Check for actual ERC-2612 permit implementation or consumption IN THIS CONTRACT
        let has_permit_function = contract_lower.contains("function permit(")
            || contract_lower.contains("ierc20permit")
            || contract_lower.contains("erc2612")
            || contract_lower.contains("erc20permit");
        let has_permit_call = contract_lower.contains(".permit(")
            && (contract_lower.contains("token.permit(")
                || contract_lower.contains(").permit(")
                || contract_lower.contains("ierc20permit("));

        if !has_permit_function && !has_permit_call {
            return Ok(findings);
        }

        // FP Reduction: Exempt permit implementers that have proper EIP-712 domain WITH chainId
        // in DOMAIN_SEPARATOR construction AND proper deadline/replay protection.
        let is_secure_permit_impl = contract_lower.contains("function permit(")
            && contract_lower.contains("ecrecover")
            && contract_lower.contains("eip712domain(")
            && contract_lower.contains("block.chainid");
        let has_deadline_or_replay_protection = contract_lower.contains("require(deadline")
            || contract_lower.contains("deadline <=")
            || contract_lower.contains("deadline >=")
            || contract_lower.contains("<= deadline")
            || contract_lower.contains(">= deadline")
            || contract_lower.contains("usedsignatures")
            || contract_lower.contains("safepermit");
        if is_secure_permit_impl && has_deadline_or_replay_protection {
            return Ok(findings);
        }

        // Permit implementers: tokens with function permit() + ecrecover.
        // These are only vulnerable if they lack deadline enforcement.
        let is_permit_implementer =
            contract_lower.contains("function permit(") && contract_lower.contains("ecrecover");

        // FP Reduction: Exempt OZ ERC20Permit consumers — contracts that simply
        // call permit() on an external token. If they use try-catch or allowance checks they're safe.
        // Fixed: "ierc20permit" without requiring "()" catches `IERC20Permit public token` patterns
        let is_permit_consumer = contract_lower.contains("ierc20permit")
            || (contract_lower.contains("erc20permit") && !contract_lower.contains("ecrecover"))
            || (contract_lower.contains(".permit(")
                && !contract_lower.contains("function permit("));
        let has_try_catch_or_allowance = contract_lower.contains("try ")
            || (contract_lower.contains("allowance(") && contract_lower.contains("if "))
            || contract_lower.contains("safepermit");
        // FP Reduction: Permit consumers that call .permit() + .transferFrom() atomically
        // in the same contract are using the standard safe pattern. The permit sets the
        // allowance and transferFrom uses it in the same transaction.
        let has_atomic_permit_transfer = contract_lower.contains(".permit(")
            && contract_lower.contains("transferfrom")
            && !contract_lower.contains("function permit(");
        if is_permit_consumer && (has_try_catch_or_allowance || has_atomic_permit_transfer) {
            return Ok(findings);
        }

        // FP Reduction: Consolidate all sub-pattern findings into 1 finding per contract
        let mut sub_issues: Vec<String> = Vec::new();

        // Pattern 1: permit() followed by transferFrom without try-catch
        if contract_lower.contains("permit(") {
            let has_transferfrom = contract_lower.contains("transferfrom");
            let has_error_handling =
                contract_lower.contains("try") || contract_lower.contains("catch");
            if has_transferfrom && !has_error_handling {
                sub_issues.push("permit() without error handling (front-run griefing)".to_string());
            }
        }

        // Pattern 2: No allowance check before permit (consumer-only concern)
        if !is_permit_implementer && (has_permit_function || has_permit_call) {
            let checks_allowance = contract_lower.contains("allowance(")
                || contract_lower.contains("currentallowance");
            if !checks_allowance {
                sub_issues.push("no allowance check before permit (DOS risk)".to_string());
            }
        }

        // Pattern 3: Deadline too far in future
        if contract_lower.contains("permit(") {
            let has_deadline_check = contract_lower.contains("deadline")
                && (contract_lower.contains("block.timestamp")
                    || contract_lower.contains("require(deadline"));
            let has_max_deadline = contract_lower.contains("max_deadline")
                || contract_lower.contains("deadline_limit");
            if has_deadline_check && !has_max_deadline {
                sub_issues.push("permit deadline not bounded".to_string());
            }
        }

        // Pattern 4: Permit signature reuse protection missing (consumer-only concern)
        if !is_permit_implementer && (has_permit_function || has_permit_call) {
            let has_nonce_tracking =
                contract_lower.contains("nonce") || contract_lower.contains("nonces(");
            if !has_nonce_tracking {
                sub_issues.push("no nonce validation in permit usage".to_string());
            }
        }

        // Pattern 5: Permit used in critical path without backup (consumer-only concern)
        if !is_permit_implementer && contract_lower.contains("permit(") {
            let has_alternative = contract_lower.contains("approve")
                || contract_lower.contains("else")
                || contract_lower.contains("fallback");
            if !has_alternative {
                sub_issues.push("permit in critical path without fallback".to_string());
            }
        }

        // Pattern 6: Permit implementer missing deadline enforcement
        if is_permit_implementer {
            let enforces_deadline = contract_lower.contains("require(deadline")
                || contract_lower.contains("deadline <=")
                || contract_lower.contains("deadline >=")
                || contract_lower.contains("<= deadline")
                || contract_lower.contains(">= deadline")
                || contract_lower.contains("block.timestamp <= ")
                || contract_lower.contains("block.timestamp >= ");
            if !enforces_deadline {
                sub_issues.push("permit implementation missing deadline enforcement".to_string());
            }
        }

        if !sub_issues.is_empty() {
            let consolidated_msg = format!(
                "Permit front-running risks in '{}': {}",
                ctx.contract.name.name,
                sub_issues.join("; ")
            );
            let finding = self
                .base
                .create_finding(ctx, consolidated_msg, 1, 1, 20)
                .with_fix_suggestion(
                    "Use try-catch for permit calls, check allowance before permit, \
                     bound deadlines, verify nonce usage, and provide approve() fallback"
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
