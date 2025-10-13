//! ERC-7683 Permit2 Integration Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct Permit2IntegrationDetector {
    base: BaseDetector,
}

impl Permit2IntegrationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-unsafe-permit2".to_string()),
                "ERC-7683 Unsafe Permit2".to_string(),
                "Detects unsafe token approval patterns in ERC-7683 settlements".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Medium,
            ),
        }
    }

    fn is_erc7683_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("fillorder") || source.contains("settle"))
            && (source.contains("crosschain") || source.contains("bridge"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("fill") && !name.contains("settle") {
            return issues;
        }

        let source = &ctx.source_code.to_lowercase();

        let uses_approve = source.contains(".approve(") && !source.contains("permit");
        let uses_permit2 = source.contains("permit2") || source.contains("permittransfer");

        if uses_approve && !uses_permit2 {
            issues.push((
                format!(
                    "Using approve() instead of Permit2 in '{}'",
                    function.name.name
                ),
                Severity::High,
                "Use Permit2: PERMIT2.permitTransferFrom(permit, details, user, sig);".to_string(),
            ));
        }

        if uses_permit2 {
            let validates_deadline = source.contains("deadline") && source.contains("timestamp");
            let validates_nonce =
                source.contains("nonce") && (source.contains("used") || source.contains("mapping"));

            if !validates_deadline {
                issues.push((
                    format!(
                        "Missing Permit2 deadline validation in '{}'",
                        function.name.name
                    ),
                    Severity::Medium,
                    "Add: require(permit.deadline >= block.timestamp);".to_string(),
                ));
            }

            if !validates_nonce {
                issues.push((
                    format!("Missing Permit2 nonce tracking in '{}'", function.name.name),
                    Severity::Medium,
                    "Add: require(!usedNonces[user][nonce]); usedNonces[user][nonce] = true;"
                        .to_string(),
                ));
            }
        }

        issues
    }
}

impl Default for Permit2IntegrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Permit2IntegrationDetector {
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
                let finding = self
                    .base
                    .create_finding_with_severity(
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
