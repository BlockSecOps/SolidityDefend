use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for data availability sampling attacks
///
/// Detects vulnerabilities in data availability layer interactions where
/// under-sampling or insufficient validation could lead to data withholding attacks.
pub struct DaSamplingAttackDetector {
    base: BaseDetector,
}

impl Default for DaSamplingAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DaSamplingAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("da-sampling-attack"),
                "DA Sampling Attack".to_string(),
                "Detects data availability sampling vulnerabilities where insufficient \
                 sampling or validation could enable data withholding attacks."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::DataAvailability],
                Severity::High,
            ),
        }
    }

    /// Find data availability validation issues
    fn find_da_validation_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect DA commitment handling
            if trimmed.contains("function ")
                && (trimmed.contains("commitData")
                    || trimmed.contains("submitData")
                    || trimmed.contains("postData"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for proper DA validation
                if !func_body.contains("keccak256") && !func_body.contains("hash") {
                    let issue = "Data commitment without hash validation".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for erasure coding verification
                if !func_body.contains("erasure")
                    && !func_body.contains("reed")
                    && !func_body.contains("polynomial")
                {
                    let issue = "Missing erasure coding verification".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect blob data handling (EIP-4844)
            if (trimmed.contains("blobhash") || trimmed.contains("BLOBHASH"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 20)].join("\n");

                if !func_body.contains("verify") && !func_body.contains("kzg") {
                    let issue = "Blob hash used without KZG verification".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find insufficient sampling patterns
    fn find_sampling_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect sampling functions
            if trimmed.contains("function ")
                && (trimmed.contains("sample") || trimmed.contains("Sample"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for randomness in sampling
                if !func_body.contains("random")
                    && !func_body.contains("vrf")
                    && !func_body.contains("prevrandao")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find data availability committee issues
    fn find_dac_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if this is a DAC-related contract
        let has_dac = source.contains("DataAvailability")
            || source.contains("DAC")
            || source.contains("committee");

        if !has_dac {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect threshold validation
            if trimmed.contains("threshold") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if threshold is too low
                if trimmed.contains("= 1") || trimmed.contains("== 1") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect attestation verification
            if trimmed.contains("function ")
                && (trimmed.contains("verifyAttestation") || trimmed.contains("checkSignatures"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for quorum validation
                if !func_body.contains("quorum") && !func_body.contains("majority") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find data root validation issues
    fn find_data_root_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect data root handling
            if (trimmed.contains("dataRoot") || trimmed.contains("dataCommitment"))
                && trimmed.contains("=")
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 15)].join("\n");

                // Check for merkle proof verification
                if !func_body.contains("merkle")
                    && !func_body.contains("Merkle")
                    && !func_body.contains("proof")
                {
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

impl Detector for DaSamplingAttackDetector {
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

        for (line, func_name, issue) in self.find_da_validation_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has DA validation vulnerability: {}. \
                 Insufficient data availability validation enables withholding attacks.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Improve data availability validation:\n\n\
                     1. Verify data commitments with cryptographic hashes\n\
                     2. Implement erasure coding for data redundancy\n\
                     3. Use KZG commitments for blob verification\n\
                     4. Require sufficient sampling before accepting data\n\
                     5. Implement challenge mechanisms for data availability"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_sampling_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs data sampling without proper randomness. \
                 Predictable sampling enables targeted data withholding.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add randomness to sampling:\n\n\
                     1. Use VRF for sample selection\n\
                     2. Include block.prevrandao in sampling\n\
                     3. Implement commit-reveal for sample indices\n\
                     4. Ensure sufficient sample count for security"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dac_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has weak data availability committee validation. \
                 Low threshold or missing quorum checks enable collusion attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Strengthen DAC validation:\n\n\
                     1. Require supermajority threshold (2/3+)\n\
                     2. Implement proper quorum calculations\n\
                     3. Add economic penalties for misbehavior\n\
                     4. Use rotating committee membership"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_data_root_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts data roots without merkle proof verification. \
                 Invalid data roots could be accepted.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(20)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add data root verification:\n\n\
                     1. Require merkle proofs for data inclusion\n\
                     2. Verify data root against known commitments\n\
                     3. Implement data availability proofs\n\
                     4. Add dispute period for data roots"
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
        let detector = DaSamplingAttackDetector::new();
        assert_eq!(detector.name(), "DA Sampling Attack");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
