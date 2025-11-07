//! ERC-7821 Batch Authorization Detector
//!
//! Detects missing authorization checks in ERC-7821 batch executor implementations.

use anyhow::Result;
use std::any::Any;

use super::is_erc7821_executor;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC7821BatchAuthorizationDetector {
    base: BaseDetector,
}

impl ERC7821BatchAuthorizationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7821-batch-authorization".to_string()),
                "ERC-7821 Batch Authorization".to_string(),
                "Detects missing authorization in ERC-7821 batch executor implementations"
                    .to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let func_name = &function.name.name.to_lowercase();

        // Check for batch execution functions
        if !func_name.contains("execute") && !func_name.contains("batch") {
            return issues;
        }

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // Check for authorization
        let has_auth = func_lower.contains("require")
            && (func_lower.contains("msg.sender")
                || func_lower.contains("owner")
                || func_lower.contains("authorized"));

        let has_modifier = !function.modifiers.is_empty();

        if !has_auth && !has_modifier {
            issues.push((
                format!("Missing authorization in batch executor '{}' - anyone can execute arbitrary calls", function.name.name),
                Severity::Critical,
                "Add authorization check:\n\
                 \n\
                 address public owner;\n\
                 \n\
                 function executeBatch(\n\
                     address[] calldata targets,\n\
                     bytes[] calldata datas\n\
                 ) external {\n\
                     require(msg.sender == owner, \"Not authorized\");\n\
                     \n\
                     for (uint i = 0; i < targets.length; i++) {\n\
                         (bool success,) = targets[i].call(datas[i]);\n\
                         require(success);\n\
                     }\n\
                 }".to_string()
            ));
        }

        issues
    }
}

impl Default for ERC7821BatchAuthorizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC7821BatchAuthorizationDetector {
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

        if !is_erc7821_executor(ctx) {
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
