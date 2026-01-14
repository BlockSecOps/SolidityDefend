use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for constructor reentrancy vulnerabilities
///
/// Detects patterns where reentrancy can occur during contract
/// construction, before security mechanisms are fully initialized.
pub struct ConstructorReentrancyDetector {
    base: BaseDetector,
}

impl Default for ConstructorReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstructorReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("constructor-reentrancy"),
                "Constructor Reentrancy".to_string(),
                "Detects external calls in constructors that can enable reentrancy \
                 before security mechanisms are fully initialized."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Deployment],
                Severity::High,
            ),
        }
    }

    /// Find external calls in constructors
    fn find_constructor_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for external calls
                if constructor_body.contains(".call")
                    || constructor_body.contains(".delegatecall")
                    || constructor_body.contains(".transfer")
                    || constructor_body.contains(".send")
                {
                    findings.push((line_num as u32 + 1, "constructor".to_string()));
                }
            }
        }

        findings
    }

    /// Find callback triggers in constructors
    fn find_constructor_callbacks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for operations that trigger callbacks
                if constructor_body.contains("safeTransfer")
                    || constructor_body.contains("safeMint")
                    || constructor_body.contains("onERC")
                    || constructor_body.contains("_mint")
                {
                    findings.push((line_num as u32 + 1, "constructor".to_string()));
                }
            }
        }

        findings
    }

    /// Find state modifications after external calls in constructor
    fn find_state_after_call(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_lines = &lines[line_num..func_end];

                let mut found_call = false;
                let mut call_line = 0;

                for (i, cline) in constructor_lines.iter().enumerate() {
                    if cline.contains(".call")
                        || cline.contains("transfer")
                        || cline.contains("safeTransfer")
                    {
                        found_call = true;
                        call_line = i;
                    }

                    // Check for state modifications after external call
                    if found_call && i > call_line {
                        if cline.contains(" = ") && !cline.contains("==") {
                            findings.push((
                                (line_num + i) as u32 + 1,
                                "constructor".to_string(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find inherited constructor issues
    fn find_inherited_constructor_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for parent constructor calls with external addresses
            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for inherited constructor with external interaction
                if (constructor_body.contains("ERC721") || constructor_body.contains("ERC1155"))
                    && constructor_body.contains("_mint")
                {
                    findings.push((line_num as u32 + 1, "constructor".to_string()));
                }
            }
        }

        findings
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

impl Detector for ConstructorReentrancyDetector {
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

        for (line, _) in self.find_constructor_external_calls(source) {
            let message = format!(
                "Constructor in contract '{}' makes external calls. \
                 Reentrancy can occur before security mechanisms are initialized.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid external calls in constructor:\n\n\
                     1. Move external calls to an initialize() function\n\
                     2. Use two-step initialization pattern\n\
                     3. Ensure all state is set before external calls\n\
                     4. Use reentrancy guards even in constructor"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_constructor_callbacks(source) {
            let message = format!(
                "Constructor in contract '{}' triggers callbacks (safeTransfer/safeMint). \
                 Callbacks can reenter before initialization completes.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid callback-triggering operations in constructor:\n\n\
                     1. Use non-safe variants (_mint instead of _safeMint)\n\
                     2. Move minting to post-construction initialize()\n\
                     3. Complete all state initialization first"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_state_after_call(source) {
            let message = format!(
                "Constructor in contract '{}' modifies state after external call. \
                 Classic checks-effects-interactions violation in constructor.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Follow checks-effects-interactions in constructor:\n\n\
                     constructor() {\n\
                         // 1. Set all state first\n\
                         owner = msg.sender;\n\
                         initialized = true;\n\n\
                         // 2. External calls last\n\
                         token.transfer(...);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_inherited_constructor_calls(source) {
            let message = format!(
                "Constructor in contract '{}' inherits from contracts with callback mechanisms. \
                 Ensure parent constructors don't enable reentrancy.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Review inherited constructor behavior:\n\n\
                     1. Check if parent constructors make external calls\n\
                     2. Audit ERC721/ERC1155 _safeMint in constructors\n\
                     3. Consider delaying minting to after construction"
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
        let detector = ConstructorReentrancyDetector::new();
        assert_eq!(detector.name(), "Constructor Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
