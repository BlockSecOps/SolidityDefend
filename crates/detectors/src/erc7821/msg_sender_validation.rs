//! ERC-7821 msg.sender Validation Detector

use anyhow::Result;
use std::any::Any;

use super::is_erc7821_executor;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC7821MsgSenderValidationDetector {
    base: BaseDetector,
}

impl ERC7821MsgSenderValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7821-msg-sender-validation".to_string()),
                "ERC-7821 msg.sender Validation".to_string(),
                "Detects msg.sender authentication issues in batch execution context".to_string(),
                vec![DetectorCategory::Auth],
                Severity::Medium,
            ),
        }
    }
}

impl Default for ERC7821MsgSenderValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC7821MsgSenderValidationDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        if !is_erc7821_executor(ctx) {
            return Ok(findings);
        }

        let source_lower = ctx.source_code.to_lowercase();

        // Check for settler/executor context confusion
        if source_lower.contains("msg.sender")
            && (source_lower.contains("settler") || source_lower.contains("executor"))
        {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "ERC-7821 executor may confuse msg.sender context in settler/executor pattern"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Be explicit about msg.sender context:\n\
                 \n\
                 // In batch executor:\n\
                 // msg.sender = settler contract\n\
                 // tx.origin = original user\n\
                 \n\
                 function executeBatch(address user, ...) external {\n\
                     // ✅ Pass user explicitly, don't rely on msg.sender\n\
                     require(msg.sender == trustedSettler, \"Not settler\");\n\
                     \n\
                     // Use 'user' parameter for user-specific logic\n\
                     _processForUser(user);\n\
                 }"
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
