//! EIP-7702 Batch Phishing Detector
//!
//! Detects batch execution patterns used in phishing attacks to drain multiple assets.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use super::is_eip7702_delegate;

pub struct EIP7702BatchPhishingDetector {
    base: BaseDetector,
}

impl EIP7702BatchPhishingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-batch-phishing".to_string()),
                "EIP-7702 Batch Phishing".to_string(),
                "Detects batch execution used for multi-asset drainage in phishing attacks".to_string(),
                vec![DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let func_name = &function.name.name.to_lowercase();

        if !func_name.contains("batch") && !func_name.contains("multi") {
            return issues;
        }

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()].to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // Check for batch operations without proper safeguards
        let has_loop = func_lower.contains("for") || func_lower.contains("while");
        let has_call = func_lower.contains(".call") || func_lower.contains("transfer");
        let has_auth = func_lower.contains("require") && func_lower.contains("msg.sender");

        if has_loop && has_call && !has_auth {
            issues.push((
                format!("Unprotected batch execution in '{}' - phishing risk", function.name.name),
                Severity::High,
                "Batch functions without authorization enable phishing:\n\
                 \n\
                 Attack pattern:\n\
                 1. Phishing site prompts EIP-7702 delegation\n\
                 2. Malicious batch function executes multiple calls\n\
                 3. Drains ETH, all ERC-20s, all NFTs in single transaction\n\
                 4. User sees only one transaction signature\n\
                 \n\
                 Fix: Add proper authorization:\n\
                 function batchExecute(Call[] calldata calls) external {\n\
                     require(msg.sender == owner, \"Not authorized\");\n\
                     \n\
                     for (uint i = 0; i < calls.length; i++) {\n\
                         (bool success,) = calls[i].target.call(calls[i].data);\n\
                         require(success, \"Call failed\");\n\
                     }\n\
                 }".to_string()
            ));
        }

        issues
    }
}

impl Default for EIP7702BatchPhishingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702BatchPhishingDetector {
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
                let finding = self.base.create_finding_with_severity(
                    ctx, title, function.name.location.start().line() as u32, 0, 20, severity
                ).with_fix_suggestion(remediation);
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
