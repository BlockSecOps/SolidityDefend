use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for contract recreation attack vulnerabilities
///
/// Detects patterns where contracts can be destroyed and recreated
/// with different code at the same address.
pub struct ContractRecreationAttackDetector {
    base: BaseDetector,
}

impl Default for ContractRecreationAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractRecreationAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("contract-recreation-attack"),
                "Contract Recreation Attack".to_string(),
                "Detects patterns where contracts can be recreated at the same address \
                 with different code after destruction, enabling code substitution attacks."
                    .to_string(),
                vec![DetectorCategory::Metamorphic, DetectorCategory::Deployment],
                Severity::Critical,
            ),
        }
    }

    /// Find destroy and redeploy patterns
    fn find_destroy_redeploy_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_destroy = source.contains("selfdestruct")
            || source.contains("destroy")
            || source.contains("kill");
        let has_deploy = source.contains("deploy")
            || source.contains("create2")
            || source.contains("CREATE2");

        if has_destroy && has_deploy {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ")
                    && (trimmed.contains("redeploy")
                        || trimmed.contains("recreate")
                        || trimmed.contains("upgrade"))
                {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find patterns that allow bytecode changes
    fn find_bytecode_change_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for mutable bytecode storage
            if (trimmed.contains("bytes") && trimmed.contains("bytecode"))
                || (trimmed.contains("bytes") && trimmed.contains("code"))
            {
                // Check if it's not immutable
                if !trimmed.contains("constant") && !trimmed.contains("immutable") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find factory patterns that can recreate contracts
    fn find_factory_recreation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("deploy") || trimmed.contains("create"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for same-salt reuse capability
                if func_body.contains("create2") {
                    // Look for salt reuse patterns
                    let allows_salt_reuse = !func_body.contains("usedSalts")
                        && !func_body.contains("deployed[")
                        && !func_body.contains("saltUsed");

                    if allows_salt_reuse {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find contracts that trust addresses without bytecode verification
    fn find_unverified_trust(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for trusted address storage
            if (trimmed.contains("trusted") || trimmed.contains("whitelist"))
                && trimmed.contains("address")
            {
                // Check if there's bytecode verification
                let context_end = std::cmp::min(line_num + 20, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                let has_verification = context.contains("codehash")
                    || context.contains("extcodehash")
                    || context.contains("keccak256(code)");

                if !has_verification {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
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

impl Detector for ContractRecreationAttackDetector {
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

        for (line, func_name) in self.find_destroy_redeploy_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' implements destroy-redeploy pattern. \
                 This enables contract recreation with different code at the same address.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent contract recreation attacks:\n\n\
                     1. Track used salts and prevent reuse:\n\
                     mapping(bytes32 => bool) public usedSalts;\n\
                     require(!usedSalts[salt], \"Salt already used\");\n\
                     usedSalts[salt] = true;\n\n\
                     2. Use immutable deployment patterns\n\
                     3. Verify bytecode on every interaction"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_bytecode_change_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' stores mutable bytecode. \
                 Different code can be deployed at predictable addresses.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use immutable bytecode:\n\n\
                     bytes public constant BYTECODE = hex\"...\";\n\n\
                     Or track bytecode hashes:\n\
                     bytes32 public immutable EXPECTED_CODEHASH;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_factory_recreation(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows CREATE2 deployment without \
                 salt reuse prevention. Contracts can be recreated at same address.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Track deployed salts:\n\n\
                     mapping(bytes32 => bool) public deployed;\n\n\
                     function deploy(bytes32 salt) external {\n\
                         require(!deployed[salt], \"Already deployed\");\n\
                         deployed[salt] = true;\n\
                         // CREATE2 deployment\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unverified_trust(source) {
            let message = format!(
                "Function '{}' in contract '{}' trusts addresses without bytecode verification. \
                 Trusted contracts could be replaced with malicious code.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(913)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Verify bytecode of trusted addresses:\n\n\
                     bytes32 public immutable TRUSTED_CODEHASH;\n\n\
                     function call(address target) external {\n\
                         require(\n\
                             target.codehash == TRUSTED_CODEHASH,\n\
                             \"Invalid contract\"\n\
                         );\n\
                         // Safe to call\n\
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
        let detector = ContractRecreationAttackDetector::new();
        assert_eq!(detector.name(), "Contract Recreation Attack");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
