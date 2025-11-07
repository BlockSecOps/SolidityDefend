//! Private Variable Exposure Detector
//!
//! Educational detector for developers misunderstanding "private" visibility.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct PrivateVariableExposureDetector {
    base: BaseDetector,
}

impl PrivateVariableExposureDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("private-variable-exposure".to_string()),
                "Private Variable Exposure".to_string(),
                "Detects sensitive data stored in 'private' variables (all blockchain data is public)".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }
}

impl Default for PrivateVariableExposureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PrivateVariableExposureDetector {
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
        let source = &ctx.source_code;
        let lines: Vec<&str> = source.lines().collect();

        let sensitive_keywords = [
            "password",
            "secret",
            "key",
            "seed",
            "private",
            "credential",
            "token",
            "passphrase",
            "pin",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            // Check for private variables with sensitive names
            if line_lower.contains("private") {
                for keyword in &sensitive_keywords {
                    if line_lower.contains(keyword) {
                        let finding = self.base.create_finding_with_severity(
                            ctx,
                            format!("Sensitive data '{}' in 'private' variable - all blockchain storage is publicly readable", keyword),
                            (line_num + 1) as u32,
                            0,
                            20,
                            Severity::High,
                        ).with_fix_suggestion(
                            "CRITICAL: 'private' visibility does NOT encrypt data!\n\
                             \n\
                             All blockchain storage is publicly readable via:\n\
                             - eth_getStorageAt RPC call\n\
                             - Block explorers\n\
                             - Archive nodes\n\
                             \n\
                             ❌ This is INSECURE:\n\
                             string private password = \"mysecret123\";\n\
                             \n\
                             ✅ Correct approaches:\n\
                             \n\
                             1. NEVER store secrets on-chain\n\
                             2. Store hashes instead:\n\
                                bytes32 public passwordHash = keccak256(\"password\");\n\
                             \n\
                             3. Use commit-reveal for sensitive values:\n\
                                bytes32 public commitment = keccak256(abi.encode(value, salt));\n\
                             \n\
                             4. For truly private data, use off-chain storage or ZK proofs".to_string()
                        );
                        findings.push(finding);
                        break;
                    }
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
