use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-4844 blob transaction validation vulnerabilities
///
/// EIP-4844 introduces blob-carrying transactions for L2 data availability.
/// Vulnerabilities include:
/// 1. Missing blob versioned hash validation
/// 2. Incorrect blob gas price handling
/// 3. Blob data commitment verification issues
/// 4. KZG proof validation bypasses
///
/// Vulnerable pattern:
/// ```solidity
/// function processBlobData(bytes32 versionedHash) external {
///     // VULNERABLE: No verification that versionedHash is valid
///     processData(versionedHash);
/// }
/// ```
pub struct Eip4844BlobValidationDetector {
    base: BaseDetector,
}

impl Default for Eip4844BlobValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip4844BlobValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip4844-blob-validation"),
                "EIP-4844 Blob Validation".to_string(),
                "Detects improper validation of EIP-4844 blob transactions. \
                 Blob versioned hashes, KZG proofs, and blob gas pricing must be \
                 properly validated to prevent data availability attacks."
                    .to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    /// Check for blob-related code without proper validation
    fn find_blob_validation_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract deals with EIP-4844 blobs specifically
        // Must be precise to avoid false positives on generic "blob" references
        let uses_4844_blobs = source.contains("blobhash")
            || source.contains("BLOBHASH")
            || source.contains("versionedHash")
            || source.contains("blobBaseFee")
            || source.contains("BLOBBASEFEE")
            || source.contains("blobGas")
            || source.contains("point_evaluation_precompile")
            || (source.contains("KZG") && source.contains("proof"))
            || (source.contains("kzg") && source.contains("proof"));

        if !uses_4844_blobs {
            return findings;
        }

        // Check for versioned hash validation
        let has_version_check = source.contains("0x01")
            || source.contains("VERSION_HASH_PREFIX")
            || source.contains("versionedHash >> 248");

        // Check for KZG proof validation
        let has_kzg_check = source.contains("verifyKZG")
            || source.contains("verify_kzg")
            || source.contains("point_evaluation_precompile")
            || source.contains("0x0a"); // KZG precompile address

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for blobhash opcode usage
            if trimmed.contains("blobhash(") || trimmed.contains("BLOBHASH") {
                if !has_version_check {
                    findings.push((
                        line_num as u32 + 1,
                        "BLOBHASH usage".to_string(),
                        "missing versioned hash prefix validation".to_string(),
                    ));
                }
            }

            // Check for versioned hash parameter without validation
            if trimmed.contains("bytes32") && trimmed.contains("versionedHash") {
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_function_end(&lines, func_start);
                let func_body: String = lines[func_start..func_end].join("\n");

                if !func_body.contains("require") && !func_body.contains("revert") {
                    findings.push((
                        line_num as u32 + 1,
                        "versionedHash parameter".to_string(),
                        "no validation of versioned hash".to_string(),
                    ));
                }
            }

            // Check for blob data processing without KZG verification
            if (trimmed.contains("blobData") || trimmed.contains("blob_data"))
                && !has_kzg_check {
                findings.push((
                    line_num as u32 + 1,
                    "blob data processing".to_string(),
                    "no KZG proof verification".to_string(),
                ));
            }

            // Check for blobBaseFee usage
            if trimmed.contains("blobBaseFee") || trimmed.contains("BLOBBASEFEE") {
                // Look for proper gas price handling
                if !source.contains("blobBaseFee *") && !source.contains("* blobBaseFee") {
                    findings.push((
                        line_num as u32 + 1,
                        "BLOBBASEFEE usage".to_string(),
                        "blob gas price may not be properly calculated".to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Check for L2 rollup blob-related issues
    fn find_rollup_blob_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if this is rollup-related code WITH blob handling
        // Must have both rollup indicators AND blob-specific code
        let has_rollup_indicators = source.contains("sequencer")
            || source.contains("Sequencer")
            || source.contains("rollup")
            || source.contains("Rollup")
            || source.contains("L1MessageQueue")
            || source.contains("L2OutputOracle")
            || source.contains("CrossDomainMessenger");

        let has_blob_handling = source.contains("blobhash")
            || source.contains("BLOBHASH")
            || source.contains("blob")
            || source.contains("batchData");

        if !has_rollup_indicators || !has_blob_handling {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for batch submission without blob hash verification
            if (trimmed.contains("submitBatch") || trimmed.contains("postBatch"))
                && source.contains("blob") {
                if !source.contains("blobhash") && !source.contains("BLOBHASH") {
                    findings.push((
                        line_num as u32 + 1,
                        "batch submission without blobhash verification".to_string(),
                    ));
                }
            }

            // Check for data availability checks
            if trimmed.contains("dataAvailability") || trimmed.contains("DA") {
                if !source.contains("point_evaluation") && !source.contains("KZG") {
                    findings.push((
                        line_num as u32 + 1,
                        "DA check without KZG verification".to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Find function start
    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            if lines[i].contains("function ") {
                return i;
            }
        }
        0
    }

    /// Find function end
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut brace_count = 0;
        let mut found_open = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        brace_count += 1;
                        found_open = true;
                    }
                    '}' => {
                        brace_count -= 1;
                        if found_open && brace_count == 0 {
                            return (i + 1).min(lines.len());
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip4844BlobValidationDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Check for blob validation issues
        let blob_issues = self.find_blob_validation_issues(source);
        for (line, context, issue) in blob_issues {
            let message = format!(
                "EIP-4844 blob validation issue in contract '{}': {} - {}. \
                 Improper blob validation can allow data availability attacks \
                 or incorrect L2 state transitions.",
                contract_name, context, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Properly validate EIP-4844 blob data:\n\n\
                     1. Verify versioned hash prefix (0x01):\n\
                        require(versionedHash >> 248 == 0x01, \"Invalid version\");\n\n\
                     2. Use point_evaluation_precompile (0x0a) for KZG proofs:\n\
                        (bool success, ) = address(0x0a).staticcall(\n\
                            abi.encode(versionedHash, z, y, commitment, proof)\n\
                        );\n\n\
                     3. Verify blobhash matches expected:\n\
                        require(blobhash(index) == expectedHash, \"Hash mismatch\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for rollup-specific issues
        let rollup_issues = self.find_rollup_blob_issues(source);
        for (line, issue) in rollup_issues {
            let message = format!(
                "L2 rollup blob issue in contract '{}': {}. \
                 This could allow invalid state transitions or data availability attacks.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Ensure batch submissions verify blob data via BLOBHASH opcode \
                     and KZG proofs before accepting state updates."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = Eip4844BlobValidationDetector::new();
        assert_eq!(detector.name(), "EIP-4844 Blob Validation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_blob_detection() {
        let detector = Eip4844BlobValidationDetector::new();

        let vulnerable = r#"
            contract BlobProcessor {
                function processBlobData(bytes32 versionedHash) external {
                    // No validation
                    emit BlobProcessed(versionedHash);
                }
            }
        "#;
        let issues = detector.find_blob_validation_issues(vulnerable);
        assert!(!issues.is_empty());
    }
}
