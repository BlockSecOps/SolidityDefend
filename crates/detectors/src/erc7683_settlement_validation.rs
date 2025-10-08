//! ERC-7683 Settlement Validation Detector
//!
//! Detects missing validation in ERC-7683 settlement contracts.

use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct SettlementValidationDetector {
    base: BaseDetector,
}

impl SettlementValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-settlement-validation".to_string()),
                "ERC-7683 Settlement Validation".to_string(),
                "Detects missing nonce, deadline, and Permit2 validation in ERC-7683 settlements".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    fn is_erc7683_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        let has_settlement_func = source.contains("fillorder") || source.contains("fill(") || source.contains("settle");
        let has_order_struct = source.contains("crosschainorder") || source.contains("struct order");
        let has_keywords = source.contains("crosschain") || source.contains("bridge") || source.contains("intent");

        (has_settlement_func && has_order_struct) || (has_settlement_func && has_keywords)
    }

    fn is_settlement_function(&self, func_name: &str) -> bool {
        let name = func_name.to_lowercase();
        name.contains("fill") || name.contains("settle") || name.contains("resolve") || name.contains("open")
    }

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();

        if !self.is_settlement_function(&function.name.name) {
            return issues;
        }

        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check nonce validation
        let has_nonce = source_lower.contains("nonce") &&
            (source_lower.contains("used") || source_lower.contains("filled") || source_lower.contains("require"));

        if !has_nonce {
            issues.push((
                format!("Missing nonce validation in '{}'", function.name.name),
                Severity::High,
                "Add nonce validation: require(!usedNonces[order.nonce], \"Nonce used\"); usedNonces[order.nonce] = true;".to_string()
            ));
        }

        // Check deadline validation
        let has_deadline = (source_lower.contains("deadline") || source_lower.contains("expir")) &&
            source_lower.contains("timestamp");

        if !has_deadline {
            issues.push((
                format!("Missing deadline validation in '{}'", function.name.name),
                Severity::High,
                "Add deadline check: require(block.timestamp <= order.deadline, \"Expired\");".to_string()
            ));
        }

        // Check Permit2 vs approve
        let uses_permit2 = source_lower.contains("permit2") || source_lower.contains("permittransfer");
        let uses_approve = source_lower.contains(".approve(") && !uses_permit2;

        if uses_approve {
            issues.push((
                format!("Using approve() instead of Permit2 in '{}'", function.name.name),
                Severity::Medium,
                "Use Permit2: PERMIT2.permitTransferFrom(permit, details, user, signature);".to_string()
            ));
        }

        issues
    }
}

impl Default for SettlementValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SettlementValidationDetector {
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

        if !self.is_erc7683_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    title,
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    severity,
                )
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
