use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for weak randomness using modulo on block variables
///
/// Detects patterns like block.timestamp % N or block.number % N which are
/// commonly used for "random" selection but are easily predictable.
pub struct ModuloBlockVariableDetector {
    base: BaseDetector,
}

impl Default for ModuloBlockVariableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuloBlockVariableDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("modulo-block-variable"),
                "Modulo Block Variable".to_string(),
                "Detects block.timestamp % N or block.number % N patterns used for \
                 random selection, which are predictable and exploitable."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find modulo patterns on block variables
    fn find_modulo_patterns(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Skip power-of-2 modulo patterns - these are for overflow/type casting, not randomness
            // Common pattern: block.timestamp % 2**32 (used in Uniswap for uint32 timestamp)
            if self.is_power_of_two_modulo(trimmed) {
                continue;
            }

            // Skip if assigning to smaller uint type (indicates overflow protection)
            if self.is_type_casting_pattern(trimmed) {
                continue;
            }

            // Detect block.timestamp % N
            if trimmed.contains("block.timestamp") && trimmed.contains("%") {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "block.timestamp % N pattern".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Detect block.number % N
            if trimmed.contains("block.number") && trimmed.contains("%") {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "block.number % N pattern".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Detect block.prevrandao % N
            if (trimmed.contains("block.prevrandao") || trimmed.contains("block.difficulty"))
                && trimmed.contains("%")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "block.prevrandao % N pattern".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Detect blockhash % N
            if trimmed.contains("blockhash") && trimmed.contains("%") {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "blockhash % N pattern".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Check if this is a power-of-2 modulo for type casting/overflow
    fn is_power_of_two_modulo(&self, line: &str) -> bool {
        // Patterns like: % 2**32, % 2**64, % 2**128, % 2**256
        let power_of_two_patterns = [
            "% 2**32",
            "% 2**64",
            "% 2**128",
            "% 2**256",
            "% (2**32)",
            "% (2**64)",
            "% (2**128)",
            "% (2**256)",
            "% type(uint32).max",
            "% type(uint64).max",
            "% type(uint128).max",
            "% type(uint256).max",
        ];

        for pattern in power_of_two_patterns {
            if line.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if this is a type casting pattern (assigning to smaller uint)
    fn is_type_casting_pattern(&self, line: &str) -> bool {
        // Pattern: uint32 x = uint32(block.timestamp % ...)
        // These are for converting to smaller types, not randomness
        if (line.contains("uint32") || line.contains("uint64") || line.contains("uint128"))
            && line.contains("=")
            && line.contains("%")
            && (line.contains("block.timestamp") || line.contains("block.number"))
        {
            // Check if this is a timestamp storage pattern (like Uniswap)
            if line.contains("Timestamp") || line.contains("timestamp") || line.contains("Time") {
                return true;
            }
        }
        false
    }

    /// Find index selection using block variables
    fn find_index_selection(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect array index using block variable modulo
            if trimmed.contains("[")
                && trimmed.contains("]")
                && trimmed.contains("%")
                && (trimmed.contains("block.") || trimmed.contains("blockhash"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find winner/selection logic using modulo
    fn find_selection_logic(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect selection patterns
            let has_selection_keyword = trimmed.contains("winner")
                || trimmed.contains("selected")
                || trimmed.contains("index")
                || trimmed.contains("choice")
                || trimmed.contains("pick");

            if has_selection_keyword
                && trimmed.contains("%")
                && (trimmed.contains("block.")
                    || trimmed.contains("blockhash")
                    || trimmed.contains("uint256(keccak256"))
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ModuloBlockVariableDetector {
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

        for (line, func_name, issue) in self.find_modulo_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses weak randomness: {}. \
                 Miners can manipulate block variables to control modulo outcomes.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "block.timestamp % N is predictable:\n\n\
                     - Miners control timestamp within ~15 second range\n\
                     - For small N, they can easily hit desired values\n\
                     - block.number increments predictably\n\n\
                     Use Chainlink VRF:\n\
                     uint256 randomIndex = randomWord % arrayLength;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_index_selection(source) {
            let message = format!(
                "Function '{}' in contract '{}' selects array index using block variable modulo. \
                 Attackers can predict which element will be selected.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Array index selection should use secure randomness:\n\n\
                     // Insecure:\n\
                     uint index = block.timestamp % participants.length;\n\n\
                     // Secure (with Chainlink VRF):\n\
                     uint index = randomWord % participants.length;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_selection_logic(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses modulo for winner/selection logic \
                 with predictable inputs. The selection outcome can be manipulated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Winner selection requires unpredictable randomness:\n\n\
                     1. Request randomness before selection deadline\n\
                     2. Use Chainlink VRF callback to determine winner\n\
                     3. Add commit-reveal for participant actions"
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
        let detector = ModuloBlockVariableDetector::new();
        assert_eq!(detector.name(), "Modulo Block Variable");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
