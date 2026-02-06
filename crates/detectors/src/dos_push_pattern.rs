use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via push pattern on dynamic arrays
///
/// Detects patterns where users can push to arrays without bounds,
/// making iteration over those arrays potentially exceed gas limits.
pub struct DosPushPatternDetector {
    base: BaseDetector,
}

impl Default for DosPushPatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosPushPatternDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-push-pattern"),
                "DoS Push Pattern".to_string(),
                "Detects unbounded array growth via push operations that could lead to \
                 denial of service when iterating over the array."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find unbounded push patterns
    fn find_push_patterns(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect .push( patterns
            if trimmed.contains(".push(") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Extract array name
                if let Some(array_name) = self.extract_array_name(trimmed) {
                    // Check if there's a bounds check in the function
                    let func_start = self.find_function_start(&lines, line_num);
                    let func_end = self.find_function_end(&lines, func_start);
                    let func_body: String = lines[func_start..func_end].join("\n");

                    // Check for length limit
                    if !func_body.contains(&format!("{}.length", array_name))
                        || !func_body.contains("require")
                    {
                        let issue = format!("Unbounded push to array '{}'", array_name);
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }
        }

        findings
    }

    /// Find iteration over unbounded arrays
    fn find_unbounded_iteration(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for loops iterating over arrays
            if trimmed.contains("for") && trimmed.contains(".length") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if the array can be user-controlled
                if let Some(array_name) = self.extract_loop_array(trimmed) {
                    // Look for push to this array in external/public functions
                    if self.is_array_pushable_externally(source, &array_name) {
                        let issue = format!("Iteration over unbounded array '{}'", array_name);
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }
        }

        findings
    }

    /// Find gas-intensive operations in loops
    fn find_gas_intensive_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_loop_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for gas-intensive operations
                if loop_body.contains("transfer(")
                    || loop_body.contains(".call{")
                    || loop_body.contains("SSTORE")
                    || (loop_body.contains("delete ") && loop_body.contains("["))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_array_name(&self, line: &str) -> Option<String> {
        if let Some(push_pos) = line.find(".push(") {
            let before_push = &line[..push_pos];
            // Find the array name (last identifier before .push)
            let parts: Vec<&str> = before_push
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .collect();
            if let Some(name) = parts.last() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    fn extract_loop_array(&self, line: &str) -> Option<String> {
        if let Some(length_pos) = line.find(".length") {
            let before_length = &line[..length_pos];
            let parts: Vec<&str> = before_length
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .collect();
            if let Some(name) = parts.last() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    fn is_array_pushable_externally(&self, source: &str, array_name: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains(&format!("{}.push(", array_name)) {
                    return true;
                }
            }
        }
        false
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

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
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

    fn find_loop_end(&self, lines: &[&str], start: usize) -> usize {
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

impl Detector for DosPushPatternDetector {
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

        for (line, func_name, issue) in self.find_push_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' has DoS vulnerability: {}. \
                 Users can grow array indefinitely, making iteration exceed gas limits.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent unbounded array growth:\n\n\
                     1. Add maximum length check:\n\
                     require(array.length < MAX_SIZE, \"Array full\");\n\n\
                     2. Use mapping instead of array for iteration\n\
                     3. Implement pagination for large datasets\n\
                     4. Use pull pattern instead of push"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name, issue) in self.find_unbounded_iteration(source) {
            let message = format!(
                "Function '{}' in contract '{}' iterates over unbounded array: {}. \
                 Attackers can grow array to cause out-of-gas failures.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid unbounded iteration:\n\n\
                     1. Limit array size on push operations\n\
                     2. Use pagination for processing:\n\
                     function process(uint start, uint count) external {\n\
                         for (uint i = start; i < start + count && i < arr.length; i++) {\n\
                             // process arr[i]\n\
                         }\n\
                     }\n\
                     3. Consider pull-over-push pattern"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_gas_intensive_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs gas-intensive operations in a loop. \
                 This can exceed block gas limit with large arrays.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Move gas-intensive operations outside loops:\n\n\
                     1. Use pull pattern for transfers\n\
                     2. Batch operations with limits\n\
                     3. Use events for off-chain processing\n\
                     4. Consider withdrawal patterns"
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
        let detector = DosPushPatternDetector::new();
        assert_eq!(detector.name(), "DoS Push Pattern");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
