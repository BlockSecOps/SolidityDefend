use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for user-controlled selfdestruct recipient vulnerabilities
///
/// Detects patterns where the selfdestruct beneficiary address can be
/// controlled by users, enabling fund theft.
pub struct SelfdestructRecipientControlDetector {
    base: BaseDetector,
}

impl Default for SelfdestructRecipientControlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfdestructRecipientControlDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("selfdestruct-recipient-control"),
                "Selfdestruct Recipient Control".to_string(),
                "Detects selfdestruct operations where the recipient address can be \
                 controlled by users, allowing attackers to steal contract funds."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find selfdestruct with parameter recipient
    fn find_parameterized_recipient(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("selfdestruct(") || trimmed.contains("suicide(") {
                // Check if recipient is a parameter or variable that could be user-controlled
                let func_name = self.find_containing_function(&lines, line_num);

                // Look for function parameters
                let func_start = self.find_function_start(&lines, line_num);
                if func_start < lines.len() {
                    let func_sig = lines[func_start];
                    if func_sig.contains("address") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find selfdestruct without access control
    fn find_unprotected_selfdestruct(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("public") || trimmed.contains("external"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                if func_body.contains("selfdestruct") || func_body.contains("suicide") {
                    // Check for access control
                    let has_access_control = func_body.contains("onlyOwner")
                        || func_body.contains("require(msg.sender")
                        || func_body.contains("onlyAdmin")
                        || trimmed.contains("onlyOwner");

                    if !has_access_control {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find selfdestruct with msg.sender as recipient (potential abuse)
    fn find_msg_sender_recipient(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if (trimmed.contains("selfdestruct(") || trimmed.contains("suicide("))
                && trimmed.contains("msg.sender")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
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

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        lines.len()
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

impl Detector for SelfdestructRecipientControlDetector {
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

        for (line, func_name) in self.find_parameterized_recipient(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses selfdestruct with a parameterized recipient. \
                 Attackers may be able to control the recipient address.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use fixed recipient for selfdestruct:\n\n\
                     address constant TREASURY = 0x...;\n\n\
                     function destroy() external onlyOwner {\n\
                         selfdestruct(payable(TREASURY));\n\
                     }\n\n\
                     Or use withdrawal pattern instead of selfdestruct."
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unprotected_selfdestruct(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes selfdestruct without access control. \
                 Anyone can destroy the contract and redirect funds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add access control to selfdestruct:\n\n\
                     function destroy() external onlyOwner {\n\
                         selfdestruct(payable(owner));\n\
                     }\n\n\
                     Note: selfdestruct behavior changed after Dencun upgrade."
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_msg_sender_recipient(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses msg.sender as selfdestruct recipient. \
                 Without access control, any caller can receive contract funds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Restrict who can trigger selfdestruct:\n\n\
                     function destroy() external onlyOwner {\n\
                         // msg.sender is now guaranteed to be owner\n\
                         selfdestruct(payable(msg.sender));\n\
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = SelfdestructRecipientControlDetector::new();
        assert_eq!(detector.name(), "Selfdestruct Recipient Control");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
