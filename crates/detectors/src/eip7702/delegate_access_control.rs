//! EIP-7702 Delegate Access Control Detector
//!
//! Detects missing authorization in EIP-7702 delegate execute functions that allow
//! arbitrary execution and token drainage.
//!
//! Severity: CRITICAL
//! Real-World: Part of $12M+ 2025 phishing attacks

use anyhow::Result;
use std::any::Any;

use super::is_eip7702_delegate;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EIP7702DelegateAccessControlDetector {
    base: BaseDetector,
}

impl EIP7702DelegateAccessControlDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-delegate-access-control".to_string()),
                "EIP-7702 Delegate Access Control".to_string(),
                "Detects missing authorization in delegate execution functions allowing arbitrary calls".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
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

        // Check execute/call functions
        if !func_name.contains("execute")
            && !func_name.contains("call")
            && !func_name.contains("batch")
        {
            return issues;
        }

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let has_auth = func_text.to_lowercase().contains("require")
            && func_text.to_lowercase().contains("msg.sender");

        let has_call = func_text.to_lowercase().contains(".call")
            || func_text.to_lowercase().contains("delegatecall");

        if has_call && !has_auth {
            issues.push((
                format!(
                    "Missing access control in '{}' - allows arbitrary execution",
                    function.name.name
                ),
                Severity::Critical,
                "Fix: Add owner/authorization check:\n\
                 \n\
                 address public owner;\n\
                 \n\
                 function execute(address target, bytes calldata data) external payable {\n\
                     require(msg.sender == owner, \"Not authorized\");\n\
                     (bool success, ) = target.call{value: msg.value}(data);\n\
                     require(success, \"Call failed\");\n\
                 }"
                .to_string(),
            ));
        }

        issues
    }
}

impl Default for EIP7702DelegateAccessControlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702DelegateAccessControlDetector {
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

        if !is_eip7702_delegate(ctx) {
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
