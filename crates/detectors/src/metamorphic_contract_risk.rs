use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for metamorphic contract risks
///
/// Detects patterns where CREATE2 combined with SELFDESTRUCT enables
/// bytecode mutation attacks (metamorphic contracts).
pub struct MetamorphicContractRiskDetector {
    base: BaseDetector,
}

impl Default for MetamorphicContractRiskDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetamorphicContractRiskDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("metamorphic-contract-risk"),
                "Metamorphic Contract Risk".to_string(),
                "Detects CREATE2 + SELFDESTRUCT patterns that enable metamorphic contracts \
                 where bytecode can be changed after deployment at the same address."
                    .to_string(),
                vec![DetectorCategory::Metamorphic, DetectorCategory::Deployment],
                Severity::Critical,
            ),
        }
    }

    /// Find CREATE2 with SELFDESTRUCT combination
    fn find_metamorphic_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_create2 = source.contains("create2") || source.contains("CREATE2");
        let has_selfdestruct = source.contains("selfdestruct") || source.contains("SELFDESTRUCT");

        if has_create2 && has_selfdestruct {
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

    /// Find factory patterns that could enable metamorphic contracts
    fn find_factory_metamorphic(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for factory with deploy and destroy capabilities
            if trimmed.contains("function ")
                && (trimmed.contains("deploy") || trimmed.contains("create"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if same contract can destroy and redeploy
                if func_body.contains("create2") {
                    // Look for destroy function in the contract
                    let has_destroy = source.contains("destroy")
                        || source.contains("kill")
                        || source.contains("selfdestruct");

                    if has_destroy {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find contracts that can be redeployed with different initcode
    fn find_initcode_variation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for create2 with variable bytecode
            if (trimmed.contains("create2") || trimmed.contains("CREATE2"))
                && (trimmed.contains("bytecode") || trimmed.contains("code"))
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

impl Detector for MetamorphicContractRiskDetector {
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

        for (line, func_name) in self.find_metamorphic_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses CREATE2 in a contract with SELFDESTRUCT. \
                 This enables metamorphic contracts where bytecode can be changed at the same address.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent metamorphic contract attacks:\n\n\
                     1. Remove SELFDESTRUCT from CREATE2-deployed contracts\n\
                     2. Use immutable deployment patterns\n\
                     3. Verify bytecode hash before trusting contract\n\
                     4. Use CREATE instead of CREATE2 for mutable contracts"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_factory_metamorphic(source) {
            let message = format!(
                "Function '{}' in contract '{}' is a factory that can deploy and potentially \
                 redeploy contracts at the same address with different code.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Secure factory patterns:\n\n\
                     1. Prevent redeployment after destruction\n\
                     2. Track deployed addresses permanently\n\
                     3. Use bytecode verification on interaction\n\
                     4. Document metamorphic capabilities"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_initcode_variation(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses CREATE2 with variable bytecode. \
                 Different contracts can be deployed at predictable addresses.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use fixed bytecode with CREATE2:\n\n\
                     1. Hash bytecode and verify before deployment\n\
                     2. Use constant initcode for predictable deployments\n\
                     3. Include bytecode hash in address calculation"
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
        let detector = MetamorphicContractRiskDetector::new();
        assert_eq!(detector.name(), "Metamorphic Contract Risk");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
