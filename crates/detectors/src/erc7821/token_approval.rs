//! ERC-7821 Token Approval Detector
//!
//! Detects token approval vulnerabilities in ERC-7821 batch executors.

use anyhow::Result;
use std::any::Any;

use super::is_erc7821_executor;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC7821TokenApprovalDetector {
    base: BaseDetector,
}

impl ERC7821TokenApprovalDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7821-token-approval".to_string()),
                "ERC-7821 Token Approval Security".to_string(),
                "Detects unsafe token approval patterns in batch executors, recommends Permit2"
                    .to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }
}

impl Default for ERC7821TokenApprovalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC7821TokenApprovalDetector {
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

        // Check for unsafe approval patterns
        let uses_approve = source_lower.contains(".approve(");
        let uses_permit2 =
            source_lower.contains("permit2") || source_lower.contains("permittransfer");

        if uses_approve && !uses_permit2 {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "ERC-7821 executor uses unsafe token approvals instead of Permit2".to_string(),
                1,
                0,
                20,
                Severity::High,
            ).with_fix_suggestion(
                "ERC-7821 should integrate with Permit2 for secure token approvals:\n\
                 \n\
                 import {IPermit2} from \"permit2/interfaces/IPermit2.sol\";\n\
                 \n\
                 IPermit2 public constant PERMIT2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);\n\
                 \n\
                 function executeBatch(\n\
                     IPermit2.PermitTransferFrom memory permit,\n\
                     bytes calldata signature\n\
                 ) external {\n\
                     // ✅ Use Permit2 for safe approvals\n\
                     PERMIT2.permitTransferFrom(\n\
                         permit,\n\
                         IPermit2.SignatureTransferDetails({to: address(this), requestedAmount: amount}),\n\
                         msg.sender,\n\
                         signature\n\
                     );\n\
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
