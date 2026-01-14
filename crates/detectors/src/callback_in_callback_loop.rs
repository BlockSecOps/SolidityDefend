use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for callback-in-callback loop vulnerabilities
///
/// Detects patterns where recursive callback exploitation can occur
/// through looped callback invocations.
pub struct CallbackInCallbackLoopDetector {
    base: BaseDetector,
}

impl Default for CallbackInCallbackLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CallbackInCallbackLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("callback-in-callback-loop"),
                "Callback In Callback Loop".to_string(),
                "Detects recursive callback patterns that can be exploited through \
                 looped callback invocations leading to stack exhaustion or reentrancy."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find loop-based callback patterns
    fn find_loop_callbacks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for callback-triggering operations in loop
                if loop_body.contains("safeTransfer")
                    || loop_body.contains("safeMint")
                    || loop_body.contains("_safeMint")
                    || loop_body.contains("safeTransferFrom")
                    || loop_body.contains("onERC")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find recursive callback patterns
    fn find_recursive_callbacks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for callback functions
            if (trimmed.contains("function on") && trimmed.contains("Received"))
                || trimmed.contains("function tokensReceived")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if callback can trigger itself
                if func_body.contains(&func_name) || func_body.contains("this.") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find unbounded iteration with callbacks
    fn find_unbounded_callback_iteration(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for array iteration with callbacks
                if (func_body.contains(".length") || func_body.contains("for ("))
                    && (func_body.contains("safeTransfer") || func_body.contains("safeMint"))
                {
                    // Check if there's no bound
                    if !func_body.contains("require(") || !func_body.contains("< MAX") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
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

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    fn find_block_end(&self, lines: &[&str], start: usize) -> usize {
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

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        self.find_block_end(lines, start)
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for CallbackInCallbackLoopDetector {
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

        for (line, func_name) in self.find_loop_callbacks(source) {
            let message = format!(
                "Function '{}' in contract '{}' triggers callbacks in a loop. \
                 Each callback can reenter, causing exponential complexity.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(674)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid callbacks in loops:\n\n\
                     1. Use non-safe transfer variants (transfer instead of safeTransfer)\n\
                     2. Batch operations outside of callbacks\n\
                     3. Apply reentrancy guards\n\
                     4. Limit loop iterations"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_recursive_callbacks(source) {
            let message = format!(
                "Function '{}' in contract '{}' may trigger recursive callbacks. \
                 Recursive callbacks can cause stack overflow or gas exhaustion.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(674)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent recursive callbacks:\n\n\
                     1. Add recursion depth tracking\n\
                     2. Use reentrancy guards\n\
                     3. Avoid self-calls in callbacks\n\
                     4. Use pull pattern instead"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unbounded_callback_iteration(source) {
            let message = format!(
                "Function '{}' in contract '{}' has unbounded iteration with callbacks. \
                 Large arrays can cause gas exhaustion or DoS.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(674)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Bound callback iterations:\n\n\
                     1. Limit array sizes\n\
                     2. Use pagination\n\
                     3. Apply gas limits\n\
                     4. Use pull pattern for large sets"
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
        let detector = CallbackInCallbackLoopDetector::new();
        assert_eq!(detector.name(), "Callback In Callback Loop");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
