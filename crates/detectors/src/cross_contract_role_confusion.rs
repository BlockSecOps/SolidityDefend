use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for cross-contract role confusion vulnerabilities
///
/// Detects patterns where roles from one contract are incorrectly
/// used for authorization in another contract.
pub struct CrossContractRoleConfusionDetector {
    base: BaseDetector,
}

impl Default for CrossContractRoleConfusionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossContractRoleConfusionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("cross-contract-role-confusion"),
                "Cross-Contract Role Confusion".to_string(),
                "Detects access control patterns where roles defined in one contract \
                 are mistakenly used for authorization in another contract."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find external role checks
    fn find_external_role_checks(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for hasRole calls on external contracts
            if trimmed.contains(".hasRole(") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if it's checking role on external contract
                if !trimmed.contains("this.hasRole") && !trimmed.contains("super.hasRole") {
                    let issue = "Checking roles on external contract".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Look for external accessControl references
            if (trimmed.contains("accessControl.") || trimmed.contains("roleManager."))
                && trimmed.contains("hasRole")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "Using external access control contract for authorization".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Find shared role constant issues
    fn find_shared_role_constants(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Track imported role constants
        let imports_roles = source.contains("import") && source.contains("Roles");

        if imports_roles {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Look for usage of imported role constants
                if trimmed.contains("onlyRole") && trimmed.contains("Roles.") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find role hash collision risks
    fn find_role_collision_risks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for keccak256 role definitions
            if trimmed.contains("keccak256") && trimmed.contains("_ROLE") {
                // Check for generic role names that might collide
                let is_generic = trimmed.contains("\"ADMIN\"")
                    || trimmed.contains("\"MINTER\"")
                    || trimmed.contains("\"OPERATOR\"")
                    || trimmed.contains("\"MANAGER\"");

                if is_generic {
                    let role_name = self.extract_role_name(trimmed);
                    findings.push((line_num as u32 + 1, role_name));
                }
            }
        }

        findings
    }

    /// Find msg.sender confusion in delegated calls
    fn find_sender_role_confusion(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for role checks in functions that make external calls
            if trimmed.contains("onlyRole") || trimmed.contains("hasRole(") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if function makes delegatecall (msg.sender preserved)
                if func_body.contains("delegatecall") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_role_name(&self, line: &str) -> String {
        // Extract role constant name from line
        if let Some(eq_pos) = line.find('=') {
            let before_eq = line[..eq_pos].trim();
            let parts: Vec<&str> = before_eq.split_whitespace().collect();
            if let Some(name) = parts.last() {
                return name.to_string();
            }
        }
        "ROLE".to_string()
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

impl Detector for CrossContractRoleConfusionDetector {
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

        for (line, func_name, issue) in self.find_external_role_checks(source) {
            let message = format!(
                "Function '{}' in contract '{}' checks roles on external contract. {}. \
                 Role semantics may differ between contracts, causing confusion.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Avoid cross-contract role checks:\n\n\
                     1. Define roles locally in each contract\n\
                     2. Use interface methods for authorization callbacks\n\
                     3. Trust external contracts based on address, not role\n\n\
                     Example:\n\
                     // Instead of: externalContract.hasRole(ADMIN, msg.sender)\n\
                     // Use: require(trustedContracts[msg.sender], \"Not trusted\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_shared_role_constants(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses imported role constants. \
                 Shared role definitions can cause authorization confusion across contracts.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Define roles locally:\n\n\
                     // Define contract-specific roles\n\
                     bytes32 public constant VAULT_ADMIN = keccak256(\"VaultContract.ADMIN\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, role_name) in self.find_role_collision_risks(source) {
            let message = format!(
                "Role '{}' in contract '{}' uses generic name that may collide with other contracts. \
                 Different contracts may interpret the same role hash differently.",
                role_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Use contract-specific role names:\n\n\
                     // Instead of: keccak256(\"ADMIN\")\n\
                     // Use: keccak256(\"MyContract.ADMIN\")\n\n\
                     bytes32 public constant ADMIN_ROLE = keccak256(\"MyVault.ADMIN_ROLE\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_sender_role_confusion(source) {
            let message = format!(
                "Function '{}' in contract '{}' has role check with delegatecall. \
                 msg.sender is preserved in delegatecall, which may bypass intended authorization.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect role checks in delegatecall context:\n\n\
                     1. Verify address(this) matches expected contract\n\
                     2. Use tx.origin carefully for additional checks\n\
                     3. Consider disabling delegatecall for sensitive functions"
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
        let detector = CrossContractRoleConfusionDetector::new();
        assert_eq!(detector.name(), "Cross-Contract Role Confusion");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
