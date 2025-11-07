//! Plaintext Secret Storage Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct PlaintextSecretStorageDetector {
    base: BaseDetector,
}

impl PlaintextSecretStorageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("plaintext-secret-storage".to_string()),
                "Plaintext Secret Storage".to_string(),
                "Detects unhashed secrets stored on-chain".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }
}

impl Default for PlaintextSecretStorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PlaintextSecretStorageDetector {
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

        // Check for string storage of sensitive data
        let has_string_secret = source_lower.contains("string")
            && (source_lower.contains("password")
                || source_lower.contains("secret")
                || source_lower.contains("key"));

        let has_hash = source_lower.contains("keccak256") || source_lower.contains("sha256");

        if has_string_secret && !has_hash {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Plaintext secrets stored on-chain - use hashing instead".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "NEVER store plaintext secrets on-chain:\n\
                 \n\
                 ❌ INSECURE:\n\
                 string private password = \"mysecret\";\n\
                 \n\
                 function authenticate(string memory input) public {\n\
                     require(keccak256(bytes(input)) == keccak256(bytes(password)));\n\
                 }\n\
                 \n\
                 ✅ SECURE:\n\
                 bytes32 public passwordHash = 0xabc...;  // Store hash only\n\
                 \n\
                 function authenticate(string memory input) public {\n\
                     require(keccak256(bytes(input)) == passwordHash);\n\
                 }\n\
                 \n\
                 ✅ BETTER: Use signatures\n\
                 function authenticate(bytes memory signature) public {\n\
                     address signer = ECDSA.recover(messageHash, signature);\n\
                     require(signer == authorizedSigner);\n\
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
