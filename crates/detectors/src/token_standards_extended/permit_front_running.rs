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

        let lower = ctx.source_code.to_lowercase();

        // Check for ERC-2612 permit usage
        let uses_permit = lower.contains("permit(")
            || lower.contains("ierc20permit")
            || lower.contains("erc2612");

        if !uses_permit {
            return Ok(findings);
        }

        // Pattern 1: permit() followed by transferFrom without try-catch
        if lower.contains("permit(") {
            let has_transferfrom = lower.contains("transferfrom");
            let has_error_handling = lower.contains("try") || lower.contains("catch");

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
        if uses_permit {
            let checks_allowance =
                lower.contains("allowance(") || lower.contains("currentallowance");

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
        if lower.contains("permit(") {
            let has_deadline_check = lower.contains("deadline")
                && (lower.contains("block.timestamp") || lower.contains("require(deadline"));

            let has_max_deadline =
                lower.contains("max_deadline") || lower.contains("deadline_limit");

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
        if uses_permit {
            let has_nonce_tracking = lower.contains("nonce") || lower.contains("nonces(");

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
        if lower.contains("permit(") {
            let has_alternative =
                lower.contains("approve") || lower.contains("else") || lower.contains("fallback");

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
