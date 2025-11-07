//! EIP-7702 Storage Collision Detector
//!
//! Detects storage layout mismatches that can corrupt EOA state when using delegation.

use anyhow::Result;
use std::any::Any;

use super::is_eip7702_delegate;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EIP7702StorageCollisionDetector {
    base: BaseDetector,
}

impl EIP7702StorageCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-storage-collision".to_string()),
                "EIP-7702 Storage Collision".to_string(),
                "Detects storage layout mismatches between EOA and delegate contracts".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for EIP7702StorageCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702StorageCollisionDetector {
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

        // Check for storage variables
        let has_storage = ctx.source_code.contains("mapping(")
            || (ctx.source_code.contains("uint") && ctx.source_code.contains("public"));

        if has_storage {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "EIP-7702 delegate uses storage - verify no collision with EOA state"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Use EIP-7201 namespaced storage to avoid collisions:\n\
                 \n\
                 bytes32 private constant STORAGE_LOCATION = \n\
                     keccak256(\"myprotocol.delegate.storage\");\n\
                 \n\
                 struct DelegateStorage {\n\
                     address owner;\n\
                     mapping(address => uint256) balances;\n\
                 }\n\
                 \n\
                 function _getStorage() private pure returns (DelegateStorage storage $) {\n\
                     assembly { $.slot := STORAGE_LOCATION }\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
