use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for CREATE2 address collision attacks
///
/// Detects patterns where CREATE2 can be used to intentionally
/// reuse addresses after contract destruction.
pub struct Create2AddressCollisionDetector {
    base: BaseDetector,
}

impl Default for Create2AddressCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Create2AddressCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("create2-address-collision"),
                "CREATE2 Address Collision".to_string(),
                "Detects intentional address reuse patterns using CREATE2 after contract \
                 destruction that can be used for address collision attacks."
                    .to_string(),
                vec![DetectorCategory::Metamorphic, DetectorCategory::Deployment],
                Severity::Critical,
            ),
        }
    }

    /// Find address reuse patterns
    fn find_address_reuse(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for patterns that track and reuse addresses
        let has_address_tracking = source.contains("deployedAddresses")
            || source.contains("addressRegistry")
            || source.contains("usedAddresses");

        let has_create2 = source.contains("create2") || source.contains("CREATE2");
        let has_destroy = source.contains("selfdestruct") || source.contains("destroy");

        if has_create2 && has_destroy && has_address_tracking {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("create2") || trimmed.contains("CREATE2") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find fixed salt patterns that enable address prediction
    fn find_fixed_salt_reuse(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for salt that doesn't change between deployments
            if trimmed.contains("salt")
                && (trimmed.contains("constant")
                    || trimmed.contains("immutable")
                    || trimmed.contains("bytes32(0)"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find computeAddress patterns that could enable precomputation attacks
    fn find_address_precomputation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("computeAddress")
                || (trimmed.contains("keccak256")
                    && (trimmed.contains("0xff") || trimmed.contains("create2")))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find approval/trust patterns on CREATE2 addresses
    fn find_preapproval_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for approvals or trust before deployment
            if (trimmed.contains("approve") || trimmed.contains("trust"))
                && (trimmed.contains("computeAddress") || trimmed.contains("predictedAddress"))
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
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Create2AddressCollisionDetector {
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

        for (line, func_name) in self.find_address_reuse(source) {
            let message = format!(
                "Function '{}' in contract '{}' tracks addresses for potential reuse with CREATE2. \
                 This pattern can enable address collision attacks after destruction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(706)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent address collision attacks:\n\n\
                     1. Never reuse CREATE2 salts after destruction\n\
                     2. Include unique nonce in salt that increments\n\
                     3. Verify bytecode hash on every interaction\n\
                     4. Consider using CREATE instead of CREATE2"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_fixed_salt_reuse(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses fixed or constant salt for CREATE2. \
                 After destruction, the same address can receive different code.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(706)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use dynamic salt:\n\n\
                     bytes32 salt = keccak256(abi.encode(\n\
                         msg.sender,\n\
                         nonce++,  // Incrementing nonce\n\
                         block.timestamp\n\
                     ));"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_address_precomputation(source) {
            let message = format!(
                "Function '{}' in contract '{}' precomputes CREATE2 addresses. \
                 Ensure the computed address is not trusted before actual deployment.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(706)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Verify contract existence after precomputation:\n\n\
                     address predicted = computeAddress(salt, bytecodeHash);\n\
                     // Don't trust 'predicted' until:\n\
                     require(predicted.code.length > 0, \"Not deployed\");\n\
                     require(keccak256(predicted.code) == expectedHash);"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_preapproval_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' approves or trusts a predicted CREATE2 address \
                 before deployment. This can be exploited if different code is deployed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(706)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Never pre-approve CREATE2 addresses:\n\n\
                     1. Only approve after deployment is confirmed\n\
                     2. Verify bytecode matches expectations\n\
                     3. Use deployment callbacks for approval"
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
        let detector = Create2AddressCollisionDetector::new();
        assert_eq!(detector.name(), "CREATE2 Address Collision");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
