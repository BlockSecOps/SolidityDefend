//! Storage Slot Predictability Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct StorageSlotPredictabilityDetector {
    base: BaseDetector,
}

impl StorageSlotPredictabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("storage-slot-predictability".to_string()),
                "Storage Slot Predictability".to_string(),
                "Detects predictable storage slots used for sensitive data".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }
}

impl Default for StorageSlotPredictabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for StorageSlotPredictabilityDetector {
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
        let source_lower = ctx.source_code.to_lowercase();

        // Check for sequential storage of sensitive data
        let has_seed = source_lower.contains("seed");
        let has_sequential = source_lower.contains("uint256") && source_lower.contains("[");

        if has_seed && has_sequential {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Sensitive data in predictable storage slots - use hashing or off-chain storage".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            ).with_fix_suggestion(
                "Storage slots are predictable and can be read:\n\
                 \n\
                 ❌ Predictable:\n\
                 uint256[10] private seeds;  // Slot 0-9 are known\n\
                 \n\
                 ✅ Better approaches:\n\
                 \n\
                 1. Hash before storing:\n\
                    mapping(address => bytes32) public seedHashes;\n\
                    seedHashes[user] = keccak256(abi.encode(seed, salt));\n\
                 \n\
                 2. Use commit-reveal:\n\
                    mapping(address => bytes32) public commitments;\n\
                    // Commit phase\n\
                    commitments[user] = keccak256(abi.encode(value, salt));\n\
                    // Reveal phase (after commitment period)\n\
                    require(keccak256(abi.encode(value, salt)) == commitments[user]);\n\
                 \n\
                 3. Store off-chain, only store hash on-chain".to_string()
            );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
