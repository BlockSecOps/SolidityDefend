//! ERC-7683 Filler Front-Running Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct FillerFrontrunningDetector {
    base: BaseDetector,
}

impl FillerFrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-filler-frontrunning".to_string()),
                "ERC-7683 Filler Front-Running".to_string(),
                "Detects missing MEV protection in ERC-7683 settlements".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::MEV],
                Severity::High,
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

        let has_slippage = (source.contains("minoutput") || source.contains("minamount"))
            || (source.contains(">=") && source.contains("min"));

        let has_auth = source.contains("onlyauthorized")
            || source.contains("onlyfiller")
            || source.contains("onlyrole")
            || source.contains("authorized[msg.sender]");

        if !has_slippage && !has_auth {
            issues.push((
                format!(
                    "Function '{}' vulnerable to front-running and MEV",
                    function.name.name
                ),
                Severity::Critical,
                "Add slippage protection AND filler authorization".to_string(),
            ));
        } else if !has_slippage {
            issues.push((
                format!("Missing slippage protection in '{}'", function.name.name),
                Severity::High,
                "Add: require(outputAmount >= minOutputAmount);".to_string(),
            ));
        } else if !has_auth {
            issues.push((
                format!("Missing filler authorization in '{}'", function.name.name),
                Severity::High,
                "Add: modifier onlyAuthorizedFiller { require(authorizedFillers[msg.sender]); _; }"
                    .to_string(),
            ));
        }

        issues
    }
}

impl Default for FillerFrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FillerFrontrunningDetector {
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
                    .with_cwe(362) // CWE-362: Concurrent Execution (race condition)
                    .with_cwe(20) // CWE-20: Improper Input Validation
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
