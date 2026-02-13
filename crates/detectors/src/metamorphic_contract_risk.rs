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

    /// Check if source has protective patterns that mitigate metamorphic risk
    fn has_protective_patterns(source: &str) -> bool {
        let lower = source.to_lowercase();
        // Timelock/delay patterns prevent immediate redeployment
        let has_delay = lower.contains("timelock")
            || lower.contains("delay")
            || lower.contains("cooldown")
            || (lower.contains("block.timestamp") && lower.contains(">="));
        // Commitment patterns prevent frontrunning of deploy
        let has_commitment = lower.contains("commit") && lower.contains("reveal");
        // Access control on both deploy and destroy
        let has_access_control = lower.contains("onlyowner")
            || lower.contains("onlyadmin")
            || lower.contains("accesscontrol")
            || lower.contains("onlyauthorized")
            || lower.contains("require(msg.sender == owner");

        // Need at least TWO protective patterns to suppress
        // (access control alone is not enough — owner can still bait-and-switch)
        (has_delay && has_access_control)
            || (has_commitment && has_access_control)
            || (has_delay && has_commitment)
    }

    /// Find CREATE2 with SELFDESTRUCT combination
    fn find_metamorphic_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_create2 = source.contains("create2") || source.contains("CREATE2");
        let has_selfdestruct = source.contains("selfdestruct") || source.contains("SELFDESTRUCT");

        if has_create2 && has_selfdestruct {
            // FP Reduction: Skip if contract has protective patterns
            // (timelock + access control, commit-reveal + access control, etc.)
            if Self::has_protective_patterns(source) {
                return findings;
            }

            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Skip comments
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }

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

        // FP Reduction: Skip if contract has protective patterns
        if Self::has_protective_patterns(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Look for factory with deploy and destroy capabilities
            if trimmed.contains("function ")
                && (trimmed.contains("deploy") || trimmed.contains("create"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if same contract can destroy and redeploy
                if func_body.contains("create2") {
                    // Look for destroy function in the contract (not in comments)
                    let has_destroy = source.contains("selfdestruct")
                        || source.contains("function destroy")
                        || source.contains("function kill");

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

        // FP Reduction: Skip if contract has protective patterns
        if Self::has_protective_patterns(source) {
            return findings;
        }

        // FP Reduction: CREATE2 + variable bytecode is only a metamorphic risk
        // if the contract also has selfdestruct (enabling the destroy-redeploy cycle)
        let has_selfdestruct = source.contains("selfdestruct") || source.contains("SELFDESTRUCT");
        if !has_selfdestruct {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts that have deployment or destruction functions.
        // Multi-contract files cause FPs when CREATE2 is in one contract and SELFDESTRUCT
        // in another unrelated contract. Require this contract to be involved.
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();

        let contract_has_relevant_fn = contract_func_names.iter().any(|n| {
            n.contains("deploy")
                || n.contains("create")
                || n.contains("clone")
                || n.contains("destroy")
                || n.contains("kill")
                || n.contains("selfdestruct")
        });
        let contract_name_relevant = contract_name_lower.contains("factory")
            || contract_name_lower.contains("deployer")
            || contract_name_lower.contains("metamorphic")
            || contract_name_lower.contains("proxy")
            || contract_name_lower.contains("create2");

        if !contract_has_relevant_fn && !contract_name_relevant {
            return Ok(findings);
        }

        // Use file source for prerequisite checks (cross-contract patterns),
        // but contract source for finding actual lines (prevents per-contract inflation)
        let file_source = &ctx.source_code;
        let contract_source = crate::utils::get_contract_source(ctx);
        let contract_name = self.get_contract_name(ctx);

        // find_metamorphic_pattern needs file-wide check for both create2+selfdestruct,
        // but should only report create2 lines in THIS contract
        let file_has_create2 = file_source.contains("create2") || file_source.contains("CREATE2");
        let file_has_selfdestruct =
            file_source.contains("selfdestruct") || file_source.contains("SELFDESTRUCT");

        if file_has_create2 && file_has_selfdestruct {
            // Only iterate contract source for actual create2 lines
            if !Self::has_protective_patterns(file_source) {
                let lines: Vec<&str> = contract_source.lines().collect();
                for (line_num, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") || trimmed.starts_with("*") {
                        continue;
                    }
                    if trimmed.contains("create2") || trimmed.contains("CREATE2") {
                        let func_name = self.find_containing_function(&lines, line_num);
                        let message = format!(
                            "Function '{}' in contract '{}' uses CREATE2 in a contract with SELFDESTRUCT. \
                             This enables metamorphic contracts where bytecode can be changed at the same address.",
                            func_name, contract_name
                        );
                        let finding = self
                            .base
                            .create_finding(ctx, message, line_num as u32 + 1, 1, 50)
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
                }
            }
        }

        for (line, func_name) in self.find_factory_metamorphic(&contract_source) {
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

        for (line, func_name) in self.find_initcode_variation(&contract_source) {
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
        let detector = MetamorphicContractRiskDetector::new();
        assert_eq!(detector.name(), "Metamorphic Contract Risk");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
