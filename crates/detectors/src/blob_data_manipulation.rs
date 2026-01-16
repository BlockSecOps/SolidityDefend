use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-4844 blob data manipulation vulnerabilities
///
/// Detects patterns where blob data handling could be manipulated,
/// including missing KZG verification and blob lifecycle issues.
pub struct BlobDataManipulationDetector {
    base: BaseDetector,
}

impl Default for BlobDataManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobDataManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("blob-data-manipulation"),
                "Blob Data Manipulation".to_string(),
                "Detects EIP-4844 blob data vulnerabilities including missing KZG \
                 verification, improper blob lifecycle handling, and data tampering risks."
                    .to_string(),
                vec![
                    DetectorCategory::L2,
                    DetectorCategory::DataAvailability,
                ],
                Severity::High,
            ),
        }
    }

    /// Find missing KZG verification
    fn find_kzg_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect blobhash usage
            if (trimmed.contains("blobhash(") || trimmed.contains("BLOBHASH"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 30)].join("\n");

                // Check for KZG proof verification
                if !func_body.contains("kzg")
                    && !func_body.contains("KZG")
                    && !func_body.contains("point_evaluation")
                    && !func_body.contains("verifyProof")
                {
                    let issue = "Blob hash used without KZG commitment verification".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect blob data handling functions
            if trimmed.contains("function ")
                && (trimmed.contains("submitBlob")
                    || trimmed.contains("processBlob")
                    || trimmed.contains("verifyBlob"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for commitment verification
                if !func_body.contains("commitment") && !func_body.contains("proof") {
                    let issue = "Blob processing without commitment verification".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find blob lifecycle issues
    fn find_lifecycle_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if this is a blob-related contract
        let uses_blobs = source.contains("blob")
            || source.contains("Blob")
            || source.contains("BLOBHASH")
            || source.contains("blobhash");

        if !uses_blobs {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect blob data storage without expiry consideration
            if trimmed.contains("function ")
                && (trimmed.contains("store") || trimmed.contains("save"))
                && trimmed.contains("blob")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Blobs expire after ~18 days, check for expiry handling
                if !func_body.contains("expiry")
                    && !func_body.contains("deadline")
                    && !func_body.contains("timestamp")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find data availability assumptions
    fn find_da_assumptions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect functions assuming blob data availability
            if trimmed.contains("function ")
                && (trimmed.contains("retrieveBlob") || trimmed.contains("getBlobData"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for fallback handling
                if !func_body.contains("revert") && !func_body.contains("fallback") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find precompile interaction issues
    fn find_precompile_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect point evaluation precompile calls (0x0A)
            if (trimmed.contains("0x0a") || trimmed.contains("0x0A"))
                && (trimmed.contains("call") || trimmed.contains("staticcall"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 20)].join("\n");

                // Check for return value validation
                if !func_body.contains("require") && !func_body.contains("revert") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect inline assembly blob operations
            if trimmed.contains("assembly") && source[line_num..].contains("blobhash") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find versioned hash issues
    fn find_versioned_hash_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect versioned hash handling
            if (trimmed.contains("versionedHash") || trimmed.contains("versioned_hash"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 15)].join("\n");

                // Check for version byte validation (should be 0x01 for KZG)
                if !func_body.contains("0x01") && !func_body.contains("version") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for BlobDataManipulationDetector {
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

        for (line, func_name, issue) in self.find_kzg_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has blob KZG issue: {}. \
                 Without proper KZG verification, blob data integrity cannot be guaranteed.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add KZG verification for blobs:\n\n\
                     1. Use the point evaluation precompile (0x0A) to verify KZG proofs\n\
                     2. Verify blob commitment matches expected value\n\
                     3. Validate versioned hash format (0x01 prefix)\n\
                     4. Check proof against claimed data\n\
                     5. Handle verification failures gracefully"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_lifecycle_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' stores blob references without expiry handling. \
                 Blob data expires after ~18 days and won't be available.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Handle blob expiry:\n\n\
                     1. Track blob submission timestamp\n\
                     2. Implement deadline for blob-dependent operations\n\
                     3. Archive blob data if needed beyond expiry\n\
                     4. Use data availability layers for long-term storage"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_da_assumptions(source) {
            let message = format!(
                "Function '{}' in contract '{}' assumes blob data availability without fallback. \
                 Blob data may not be retrievable after expiry period.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add data availability fallbacks:\n\n\
                     1. Implement graceful degradation when blob unavailable\n\
                     2. Use alternative DA layers as backup\n\
                     3. Cache critical blob data on-chain if needed\n\
                     4. Add clear error handling for missing blobs"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_precompile_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' calls KZG precompile without proper return validation. \
                 Failed verification could go undetected.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Validate precompile returns:\n\n\
                     1. Check call success status\n\
                     2. Verify return data length and format\n\
                     3. Revert on verification failure\n\
                     4. Handle edge cases (empty input, malformed data)"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_versioned_hash_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' handles versioned hashes without version validation. \
                 Future blob formats may have different version bytes.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Validate versioned hash format:\n\n\
                     1. Check first byte is 0x01 (KZG version)\n\
                     2. Validate total hash length (32 bytes)\n\
                     3. Consider forward compatibility for future versions\n\
                     4. Document version byte expectations"
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
        let detector = BlobDataManipulationDetector::new();
        assert_eq!(detector.name(), "Blob Data Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
