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

        // FP Reduction: Only analyze contracts with permit-related functions
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_has_permit_fn = contract_func_names.iter().any(|n| {
            n.contains("permit")
                || n.contains("transferfrom")
                || n.contains("approve")
                || n.contains("deposit")
                || n.contains("swap")
                || n.contains("spend")
        });
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
            || contract_lower.contains("usedsignatures")
            || contract_lower.contains("safepermit");
        if is_secure_permit_impl && has_deadline_or_replay_protection {
            return Ok(findings);
        }

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

        // Pattern 1: permit() followed by transferFrom without try-catch
        if contract_lower.contains("permit(") {
            let has_transferfrom = contract_lower.contains("transferfrom");
            let has_error_handling =
                contract_lower.contains("try") || contract_lower.contains("catch");

            if has_transferfrom && !has_error_handling {
                let finding = self.base.create_finding(
                    ctx,
                    "permit() without error handling - front-runner can grief by using permit first, causing revert".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use try-catch: try token.permit(...) {} catch {} or check allowance before permit".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No allowance check before permit
        if has_permit_function || has_permit_call {
            let checks_allowance = contract_lower.contains("allowance(")
                || contract_lower.contains("currentallowance");

            if !checks_allowance {
                let finding = self.base.create_finding(
                    ctx,
                    "No allowance check before permit - can revert if allowance already set, causing DOS".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Check allowance first: if (token.allowance(owner, spender) < amount) token.permit(...)".to_string()
                );

                findings.push(finding);
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
                let finding = self.base.create_finding(
                    ctx,
                    "Permit deadline not bounded - signatures valid indefinitely create security risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Enforce maximum deadline: require(deadline <= block.timestamp + MAX_DEADLINE, \"Deadline too far\")".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Permit signature reuse protection missing
        if has_permit_function || has_permit_call {
            let has_nonce_tracking =
                contract_lower.contains("nonce") || contract_lower.contains("nonces(");

            if !has_nonce_tracking {
                let finding = self.base.create_finding(
                    ctx,
                    "No nonce validation in permit usage - signature replay possible".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "ERC-2612 includes nonces by default, but verify it's used: uint256 nonce = token.nonces(owner)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Permit used in critical path without backup
        if contract_lower.contains("permit(") {
            let has_alternative = contract_lower.contains("approve")
                || contract_lower.contains("else")
                || contract_lower.contains("fallback");

            if !has_alternative {
                let finding = self.base.create_finding(
                    ctx,
                    "Permit in critical path without fallback - DOS if permit fails (e.g., already used)".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Provide approve() fallback: try permit(...) catch { require(approve successful) }".to_string()
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
