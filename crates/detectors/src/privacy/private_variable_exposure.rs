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
                // Phase 6 FP Reduction: Reduced from High to Medium.
                // This is educational - developers may not understand private visibility.
                Severity::Medium,
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let lines: Vec<&str> = source.lines().collect();

        // Phase 6 FP Reduction: Removed overly broad keywords that match normal code:
        // - "private" - matches Solidity visibility modifier
        // - "key" - matches mapping keys, API keys variables, etc.
        // - "token" - matches all DeFi token contracts
        // - "seed" - removed, too broad
        // Only flag clearly sensitive naming patterns
        let sensitive_keywords = [
            "password",
            "secret",
            "credential",
            "passphrase",
            "pin",
            "apikey",     // More specific than "key"
            "privatekey", // More specific than "private" or "key"
            "secretkey",  // More specific than "secret" or "key"
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            // Check for private variables with sensitive names
            if line_lower.contains("private") {
                for keyword in &sensitive_keywords {
                    // Use word-boundary matching for short keywords to avoid
                    // substring false positives (e.g., "pin" in "mapping")
                    let is_match = if keyword.len() <= 4 {
                        // For short keywords, require word boundaries
                        line_lower
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|word| word == *keyword)
                    } else {
                        line_lower.contains(keyword)
                    };
                    if is_match {
                        let finding = self.base.create_finding_with_severity(
                            ctx,
                            format!("Sensitive data '{}' in 'private' variable - all blockchain storage is publicly readable", keyword),
                            (line_num + 1) as u32,
                            0,
                            20,
                            // Phase 6: Reduced from High to Medium
                            Severity::Medium,
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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
