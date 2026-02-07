use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for operator whitelist inheritance vulnerabilities
///
/// Detects patterns where operator approvals are not properly reset
/// after contract upgrades, leading to stale permissions.
pub struct OperatorWhitelistInheritanceDetector {
    base: BaseDetector,
}

impl Default for OperatorWhitelistInheritanceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorWhitelistInheritanceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("operator-whitelist-inheritance"),
                "Operator Whitelist Inheritance".to_string(),
                "Detects upgradeable contracts where operator approvals may persist \
                 after upgrades, granting unintended access to previous operators."
                    .to_string(),
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::Upgradeable,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Find operator approval persistence issues
    fn find_approval_persistence(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let is_upgradeable = source.contains("Upgradeable")
            || source.contains("initialize")
            || source.contains("UUPSUpgradeable");

        if !is_upgradeable {
            return findings;
        }

        // Check for operator approval mappings
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for operator approval storage
            if trimmed.contains("mapping")
                && (trimmed.contains("operator")
                    || trimmed.contains("approved")
                    || trimmed.contains("whitelist"))
            {
                // Check if there's a reset mechanism
                let has_reset = source.contains("clearOperators")
                    || source.contains("resetApprovals")
                    || source.contains("revokeAll");

                if !has_reset {
                    let var_name = self.extract_mapping_name(trimmed);
                    let issue = format!("Operator mapping '{}' lacks reset mechanism", var_name);
                    findings.push((line_num as u32 + 1, var_name, issue));
                }
            }
        }

        findings
    }

    /// Find setApprovalForAll without versioning
    fn find_approval_versioning_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for approval functions
            if trimmed.contains("function ")
                && (trimmed.contains("setApprovalForAll")
                    || trimmed.contains("approve")
                    || trimmed.contains("setOperator"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for version/epoch in approval logic
                let has_versioning = func_body.contains("version")
                    || func_body.contains("epoch")
                    || func_body.contains("nonce");

                if !has_versioning && source.contains("Upgradeable") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find inherited storage issues
    fn find_inherited_storage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for initializer without approval reset
            if trimmed.contains("function initialize") || trimmed.contains("reinitializer") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if approvals might need resetting
                if source.contains("operatorApprovals") || source.contains("isApprovedForAll") {
                    let clears_approvals = func_body.contains("delete")
                        || func_body.contains("= false")
                        || func_body.contains("clear");

                    if !clears_approvals {
                        let func_name = self.extract_function_name(trimmed);
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

    fn extract_mapping_name(&self, line: &str) -> String {
        // Extract variable name from mapping declaration
        if let Some(close_paren) = line.rfind(')') {
            let after_close = &line[close_paren + 1..];
            let trimmed = after_close.trim();
            if let Some(space_pos) = trimmed.find(|c: char| c == ';' || c.is_whitespace()) {
                return trimmed[..space_pos].trim().to_string();
            }
            return trimmed.trim_end_matches(';').to_string();
        }
        "operatorMapping".to_string()
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

impl Detector for OperatorWhitelistInheritanceDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, var_name, issue) in self.find_approval_persistence(source) {
            let message = format!(
                "Operator mapping '{}' in contract '{}' may persist after upgrade. {}. \
                 Previous operators retain access in new implementation.",
                var_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(732)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Handle operator persistence on upgrade:\n\n\
                     1. Add version/epoch to operator approvals\n\
                     2. Implement revokeAll function for upgrades\n\
                     3. Reset critical approvals in reinitializer\n\n\
                     Example:\n\
                     uint256 public approvalEpoch;\n\
                     mapping(uint256 => mapping(address => mapping(address => bool))) \
                     operatorApprovals;\n\n\
                     function setApprovalForAll(address op, bool approved) external {\n\
                         operatorApprovals[approvalEpoch][msg.sender][op] = approved;\n\
                     }\n\n\
                     function _resetApprovals() internal {\n\
                         approvalEpoch++; // Invalidates all previous approvals\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_approval_versioning_issues(source) {
            let message = format!(
                "Approval function '{}' in contract '{}' lacks versioning. \
                 Approvals may persist unexpectedly across upgrades.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(732)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Add approval versioning:\n\n\
                     1. Include epoch/version in approval mapping key\n\
                     2. Increment version on upgrade to invalidate old approvals"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_inherited_storage(source) {
            let message = format!(
                "Initializer '{}' in contract '{}' doesn't reset operator approvals. \
                 Previous approval state may persist after upgrade.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(732)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Consider approval state in reinitializer:\n\n\
                     function reinitialize() reinitializer(2) external {\n\
                         // Increment epoch to invalidate old approvals if needed\n\
                         approvalEpoch++;\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        let detector = OperatorWhitelistInheritanceDetector::new();
        assert_eq!(detector.name(), "Operator Whitelist Inheritance");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }
}
