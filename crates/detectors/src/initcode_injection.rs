use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for initcode injection vulnerabilities
///
/// Detects patterns where malicious initcode can be injected into
/// CREATE2 deployments.
pub struct InitcodeInjectionDetector {
    base: BaseDetector,
}

impl Default for InitcodeInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InitcodeInjectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("initcode-injection"),
                "Initcode Injection".to_string(),
                "Detects CREATE2 deployments where initcode can be controlled or \
                 manipulated by attackers to deploy malicious contracts."
                    .to_string(),
                vec![DetectorCategory::Deployment, DetectorCategory::Validation],
                Severity::Critical,
            ),
        }
    }

    /// Find user-controlled initcode
    fn find_user_controlled_initcode(&self, source: &str) -> Vec<(u32, String)> {
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

                // Check if function accepts bytecode as parameter
                if (trimmed.contains("bytes") && trimmed.contains("code"))
                    || (trimmed.contains("bytes") && trimmed.contains("bytecode"))
                {
                    // And uses it in create/create2
                    if func_body.contains("create") || func_body.contains("CREATE") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find dynamic bytecode construction
    fn find_dynamic_bytecode(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Skip if using trusted bytecode sources
        let has_trusted_source = source.contains("type(") && source.contains(").creationCode")
            || source.contains("clone")
            || source.contains("Clone");

        if has_trusted_source {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for bytecode concatenation or construction
            // Must specifically be about "bytecode" or "creationCode", not just "code"
            // "code" alone matches too many false positives (e.g., hashCode, errorCode, opcode)
            let is_bytecode_construction = (trimmed.contains("abi.encodePacked")
                || trimmed.contains("bytes.concat"))
                && (trimmed.contains("bytecode")
                    || trimmed.contains("creationCode")
                    || trimmed.contains("initcode")
                    || trimmed.contains("runtimeCode"));

            if is_bytecode_construction {
                // Verify this is in a function that actually deploys
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_function_end(&lines, func_start);
                let func_body: String = lines[func_start..func_end].join("\n").to_lowercase();

                // Only flag if the function actually uses create/create2
                let is_deployment_context = func_body.contains("create(")
                    || func_body.contains("create2(")
                    || func_body.contains("new ")
                    || func_body.contains(".deploy");

                if is_deployment_context {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
    }

    /// Find unvalidated bytecode deployment
    fn find_unvalidated_deployment(&self, source: &str) -> Vec<(u32, String)> {
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

                // Check for CREATE2 with bytecode parameter
                if func_body.contains("create2") {
                    // Look for bytecode validation
                    let has_validation = func_body.contains("keccak256")
                        && func_body.contains("require")
                        && (func_body.contains("bytecode") || func_body.contains("code"));

                    if !has_validation {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find inline assembly create with untrusted data
    fn find_assembly_create(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Skip if using trusted bytecode sources
        let has_trusted_source = source.contains("type(") && source.contains(").creationCode")
            || source.contains("clone")
            || source.contains("Clone");

        if has_trusted_source {
            return findings;
        }

        let mut in_assembly = false;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("assembly") {
                in_assembly = true;
            }

            if in_assembly {
                if trimmed.contains("create(") || trimmed.contains("create2(") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }

                if trimmed.contains("}") && !trimmed.contains("{") {
                    in_assembly = false;
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

impl Detector for InitcodeInjectionDetector {
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

        // Skip deployment tooling contracts (factories, upgrade libraries, deployers)
        // These contracts are DESIGNED to deploy other contracts and are not vulnerable
        // to initcode injection - they ARE the deployment infrastructure
        if utils::is_deployment_tooling(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_user_controlled_initcode(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts user-controlled bytecode for deployment. \
                 Attackers can deploy arbitrary malicious contracts.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(94)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Validate initcode before deployment:\n\n\
                     bytes32 public immutable ALLOWED_CODEHASH;\n\n\
                     function deploy(bytes memory code) external {\n\
                         require(\n\
                             keccak256(code) == ALLOWED_CODEHASH,\n\
                             \"Invalid bytecode\"\n\
                         );\n\
                         // Safe to deploy\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dynamic_bytecode(source) {
            let message = format!(
                "Function '{}' in contract '{}' constructs bytecode dynamically. \
                 Ensure all components are trusted and validated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line, 1, 50, Severity::High)
                .with_cwe(94)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Validate dynamic bytecode components:\n\n\
                     1. Use constant/immutable bytecode templates\n\
                     2. Validate constructor arguments separately\n\
                     3. Verify final bytecode hash before deployment"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unvalidated_deployment(source) {
            let message = format!(
                "Function '{}' in contract '{}' deploys contracts via CREATE2 without \
                 bytecode validation. Arbitrary code can be deployed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(94)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add bytecode validation:\n\n\
                     mapping(bytes32 => bool) public allowedBytecodes;\n\n\
                     function deploy(bytes memory code, bytes32 salt) external {\n\
                         require(\n\
                             allowedBytecodes[keccak256(code)],\n\
                             \"Bytecode not whitelisted\"\n\
                         );\n\
                         // CREATE2 deployment\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_assembly_create(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses assembly create/create2. \
                 Ensure bytecode source is trusted and validated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line, 1, 50, Severity::High)
                .with_cwe(94)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Validate assembly deployment:\n\n\
                     1. Verify bytecode hash before create/create2\n\
                     2. Use high-level new ContractName() when possible\n\
                     3. Audit all sources of deployment bytecode"
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
        let detector = InitcodeInjectionDetector::new();
        assert_eq!(detector.name(), "Initcode Injection");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
