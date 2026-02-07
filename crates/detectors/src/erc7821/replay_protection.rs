//! ERC-7821 Replay Protection Detector

use anyhow::Result;
use std::any::Any;

use super::is_erc7821_executor;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC7821ReplayProtectionDetector {
    base: BaseDetector,
}

impl ERC7821ReplayProtectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7821-replay-protection".to_string()),
                "ERC-7821 Replay Protection".to_string(),
                "Detects missing nonce or replay protection in batch executors".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for ERC7821ReplayProtectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC7821ReplayProtectionDetector {
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

        // Check for nonce/replay protection
        let has_nonce = source_lower.contains("nonce");
        let has_used_tracking = source_lower.contains("used") || source_lower.contains("executed");

        if !has_nonce && !has_used_tracking {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "ERC-7821 executor missing replay protection - orders can be executed multiple times".to_string(),
                1,
                0,
                20,
                Severity::High,
            ).with_fix_suggestion(
                "Add nonce-based replay protection:\n\
                 \n\
                 mapping(address => uint256) public nonces;\n\
                 \n\
                 function executeBatch(\n\
                     uint256 nonce,\n\
                     bytes calldata signature\n\
                 ) external {\n\
                     require(nonce == nonces[msg.sender], \"Invalid nonce\");\n\
                     nonces[msg.sender]++;\n\
                     \n\
                     // Execute batch...\n\
                 }".to_string()
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
