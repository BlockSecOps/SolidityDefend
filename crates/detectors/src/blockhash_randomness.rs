use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for weak randomness using blockhash/prevrandao
///
/// Detects patterns where block.prevrandao, blockhash, or similar block
/// variables are used as sources of randomness, which can be manipulated.
pub struct BlockhashRandomnessDetector {
    base: BaseDetector,
}

impl Default for BlockhashRandomnessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockhashRandomnessDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("blockhash-randomness"),
                "Blockhash Randomness".to_string(),
                "Detects weak randomness patterns using block.prevrandao, blockhash, \
                 or other block variables that can be manipulated by miners/validators."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find weak randomness patterns
    fn find_weak_randomness(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Detect block.prevrandao usage
            if trimmed.contains("block.prevrandao") || trimmed.contains("block.difficulty") {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "block.prevrandao/difficulty used as randomness source".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Detect blockhash usage for randomness
            if trimmed.contains("blockhash(") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if it's being used in a hash/random context
                if trimmed.contains("keccak256")
                    || trimmed.contains("random")
                    || trimmed.contains("seed")
                    || trimmed.contains("entropy")
                {
                    let issue = "blockhash used as randomness seed".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect keccak256 with block variables
            if trimmed.contains("keccak256")
                && (trimmed.contains("block.timestamp")
                    || trimmed.contains("block.number")
                    || trimmed.contains("block.coinbase")
                    || trimmed.contains("block.prevrandao"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "keccak256 hash of block variables for randomness".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Find randomness in critical functions
    fn find_critical_randomness_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect lottery/game/random functions
            if trimmed.contains("function ")
                && (trimmed.contains("random")
                    || trimmed.contains("Random")
                    || trimmed.contains("lottery")
                    || trimmed.contains("Lottery")
                    || trimmed.contains("draw")
                    || trimmed.contains("winner")
                    || trimmed.contains("roll")
                    || trimmed.contains("flip"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if using weak randomness
                if (func_body.contains("block.") || func_body.contains("blockhash"))
                    && !func_body.contains("chainlink")
                    && !func_body.contains("vrf")
                    && !func_body.contains("VRF")
                    && !func_body.contains("oracle")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find predictable seed patterns
    fn find_predictable_seeds(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect seed assignments with block variables
            if (trimmed.contains("seed")
                || trimmed.contains("Seed")
                || trimmed.contains("entropy")
                || trimmed.contains("nonce"))
                && trimmed.contains("=")
                && (trimmed.contains("block.")
                    || trimmed.contains("tx.")
                    || trimmed.contains("msg.sender"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
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

impl Detector for BlockhashRandomnessDetector {
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

        for (line, func_name, issue) in self.find_weak_randomness(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses weak randomness: {}. \
                 Miners/validators can manipulate block variables to influence outcomes.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use secure randomness sources:\n\n\
                     1. Chainlink VRF for verifiable randomness\n\
                     2. Commit-reveal schemes with economic incentives\n\
                     3. External oracle services\n\
                     4. RANDAO with proper delay (post-merge)\n\n\
                     Example with Chainlink VRF:\n\
                     uint256 requestId = COORDINATOR.requestRandomWords(...);\n\
                     // Handle in fulfillRandomWords callback"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_critical_randomness_usage(source) {
            let message = format!(
                "Function '{}' in contract '{}' appears to be a lottery/game function \
                 using on-chain randomness. This is exploitable by miners/validators.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Critical randomness functions require secure sources:\n\n\
                     1. Integrate Chainlink VRF v2/v2.5\n\
                     2. Use commit-reveal with bonded participants\n\
                     3. Consider hybrid approaches (VRF + commit-reveal)\n\
                     4. Add delays between action and resolution"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_predictable_seeds(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses predictable values for seed/entropy. \
                 Attackers can predict or influence the random outcome.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use unpredictable entropy sources:\n\n\
                     1. Chainlink VRF provides cryptographic randomness\n\
                     2. Commit-reveal prevents prediction\n\
                     3. Multiple independent entropy sources\n\
                     4. Time-delayed revelation"
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
        let detector = BlockhashRandomnessDetector::new();
        assert_eq!(detector.name(), "Blockhash Randomness");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
