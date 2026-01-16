use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for weak randomness using multiple block variables
///
/// Detects patterns where multiple block variables are combined for randomness,
/// which provides a false sense of security as all are predictable.
pub struct MultiBlockRandomnessDetector {
    base: BaseDetector,
}

impl Default for MultiBlockRandomnessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiBlockRandomnessDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("multi-block-randomness"),
                "Multi-Block Randomness".to_string(),
                "Detects patterns combining multiple block variables for randomness, \
                 which falsely appears more secure but remains predictable."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find multi-variable randomness patterns
    fn find_multi_block_patterns(&self, source: &str) -> Vec<(u32, String, u32)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Count block variables in the same expression
            let mut block_var_count = 0;

            if trimmed.contains("block.timestamp") {
                block_var_count += 1;
            }
            if trimmed.contains("block.number") {
                block_var_count += 1;
            }
            if trimmed.contains("block.prevrandao") || trimmed.contains("block.difficulty") {
                block_var_count += 1;
            }
            if trimmed.contains("block.coinbase") {
                block_var_count += 1;
            }
            if trimmed.contains("block.gaslimit") {
                block_var_count += 1;
            }
            if trimmed.contains("blockhash") {
                block_var_count += 1;
            }

            // If multiple block variables combined
            if block_var_count >= 2 {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name, block_var_count));
            }
        }

        findings
    }

    /// Find abi.encodePacked with block variables
    fn find_encoded_block_vars(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect abi.encodePacked/encode with block variables
            if (trimmed.contains("abi.encodePacked") || trimmed.contains("abi.encode")) &&
               trimmed.contains("block.")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find XOR/addition of block variables
    fn find_combined_operations(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect XOR or addition of block variables
            if trimmed.contains("block.") &&
               (trimmed.contains(" ^ ") || trimmed.contains(" + ") || trimmed.contains(" | "))
            {
                // Check for multiple block references
                let block_count = trimmed.matches("block.").count();
                if block_count >= 2 ||
                   (block_count >= 1 && (trimmed.contains("msg.sender") || trimmed.contains("tx.")))
                {
                    let func_name = self.find_containing_function(&lines, line_num);
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for MultiBlockRandomnessDetector {
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

        for (line, func_name, var_count) in self.find_multi_block_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' combines {} block variables for randomness. \
                 Combining predictable values does not create unpredictability - all block \
                 variables are known to miners/validators before block finalization.",
                func_name, contract_name, var_count
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Combining block variables does NOT improve randomness:\n\n\
                     - All block variables are known before finalization\n\
                     - Miners can try different combinations\n\
                     - Hash of predictable values is still predictable\n\n\
                     Use proper randomness sources:\n\
                     1. Chainlink VRF for cryptographic randomness\n\
                     2. Commit-reveal with economic bonds\n\
                     3. External randomness beacons"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_encoded_block_vars(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses abi.encode with block variables \
                 for randomness. Encoding predictable values produces predictable output.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "abi.encodePacked(block.timestamp, block.number, ...) is NOT random:\n\n\
                     All inputs are predictable, so the output is predictable.\n\
                     Use Chainlink VRF or commit-reveal schemes instead."
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_combined_operations(source) {
            let message = format!(
                "Function '{}' in contract '{}' XORs/adds block variables together. \
                 Mathematical operations on predictable values remain predictable.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "XOR/addition of block variables is not secure:\n\n\
                     block.timestamp ^ block.number is still predictable.\n\
                     Use external randomness sources."
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
        let detector = MultiBlockRandomnessDetector::new();
        assert_eq!(detector.name(), "Multi-Block Randomness");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
