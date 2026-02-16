use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for CREATE2 salt front-running vulnerabilities
///
/// Detects patterns where CREATE2 salts are predictable, enabling
/// front-running attacks on contract deployment.
pub struct Create2SaltFrontrunningDetector {
    base: BaseDetector,
}

impl Default for Create2SaltFrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Create2SaltFrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("create2-salt-frontrunning"),
                "CREATE2 Salt Front-running".to_string(),
                "Detects CREATE2 deployments with predictable salts that can be \
                 front-run to deploy malicious contracts at expected addresses."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Deployment],
                Severity::High,
            ),
        }
    }

    /// Find predictable salt patterns
    fn find_predictable_salt(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // FP Reduction: Skip comment lines
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            // Look for salt assignments or CREATE2 calls
            // FP Reduction: Require "salt" in an assignment/declaration context, not just any mention
            let has_salt_context = (trimmed.contains("salt =")
                || trimmed.contains("salt,")
                || trimmed.contains("salt)")
                || trimmed.contains("bytes32 salt"))
                || trimmed.contains("create2");

            if has_salt_context
                && (trimmed.contains("msg.sender")
                    || trimmed.contains("block.number")
                    || trimmed.contains("block.timestamp")
                    || trimmed.contains("counter")
                    || trimmed.contains("nonce")
                    || trimmed.contains("++"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find CREATE2 without salt randomization
    fn find_deterministic_salt(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("create2") || trimmed.contains("CREATE2") {
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = (line_num + 3).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Check if salt is derived from public data only
                let has_secret = context.contains("secret")
                    || context.contains("random")
                    || context.contains("private")
                    || context.contains("commit")
                    || context.contains("keccak256(abi.encode")
                    || context.contains("keccak256(abi.encodePacked")
                    || context.contains("onlyOwner")
                    || context.contains("onlyAdmin")
                    || context.contains("onlyAuthorized")
                    || context.contains("onlyRole")
                    || context.contains("require(msg.sender")
                    || context.contains("immutable")
                    || context.contains("timelock")
                    || context.contains("delay");

                if !has_secret {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find public CREATE2 deployment functions
    fn find_public_create2(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("public") || trimmed.contains("external"))
                && (trimmed.contains("deploy") || trimmed.contains("create"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                if func_body.contains("create2") || func_body.contains("CREATE2") {
                    // Check for access control (modifiers or inline checks)
                    let has_access_control = func_body.contains("onlyOwner")
                        || func_body.contains("onlyAdmin")
                        || func_body.contains("onlyAuthorized")
                        || func_body.contains("onlyRole")
                        || func_body.contains("require(msg.sender")
                        || func_body.contains("msg.sender == owner")
                        || func_body.contains("msg.sender == admin");

                    if !has_access_control {
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

impl Detector for Create2SaltFrontrunningDetector {
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

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts — they ARE the attacker
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip selfdestruct/metamorphic test contracts
        // These have different primary vulnerabilities (selfdestruct-abuse, metamorphic-contract-risk)
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("selfdestruct") || file_lower.contains("eip6780") {
                return Ok(findings);
            }
        }

        // FP Reduction: Only analyze contracts with deploy/create functions
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let contract_has_deploy_fn = contract_func_names.iter().any(|n| {
            n.contains("deploy")
                || n.contains("create")
                || n.contains("clone")
                || n.contains("factory")
                || n.contains("salt")
        }) || contract_name_lower.contains("factory")
            || contract_name_lower.contains("deploy")
            || contract_name_lower.contains("create");
        if !contract_has_deploy_fn {
            return Ok(findings);
        }

        // Use per-contract source to avoid cross-contract false positives in multi-contract files.
        let contract_source = crate::utils::get_contract_source(ctx);
        let contract_source_lower = contract_source.to_lowercase();
        let contract_name = self.get_contract_name(ctx);

        // Early exit: contract must actually reference CREATE2 to be relevant
        if !contract_source_lower.contains("create2") && !contract_source_lower.contains("salt") {
            return Ok(findings);
        }

        // FP Reduction: Exempt if THIS contract implements commit-reveal for salt.
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let has_own_commit_reveal = contract_name_lower.contains("commitreveal")
            || (contract_source_lower.contains("function commit")
                && (contract_source_lower.contains("function reveal")
                    || contract_source_lower.contains("function deploy"))
                && (contract_source_lower.contains("commitment")
                    || contract_source_lower.contains("commitsalt")
                    || contract_source_lower.contains("committedsalt")));
        if has_own_commit_reveal {
            return Ok(findings);
        }

        // FP Reduction: Exempt contracts with timelock + access control.
        // Timelock prevents instant frontrunning even if salt is deterministic.
        let has_timelock = contract_source_lower.contains("timelock")
            || contract_source_lower.contains("timelocked")
            || (contract_source_lower.contains("delay")
                && contract_source_lower.contains("block.timestamp"));
        let has_access_control = contract_source_lower.contains("onlyowner")
            || contract_source_lower.contains("onlyadmin")
            || contract_source_lower.contains("msg.sender == owner")
            || contract_source_lower.contains("immutable")
                && contract_source_lower.contains("owner");
        if has_timelock && has_access_control {
            return Ok(findings);
        }

        for (line, func_name) in self.find_predictable_salt(&contract_source) {
            let message = format!(
                "Function '{}' in contract '{}' uses predictable values for CREATE2 salt. \
                 Attackers can front-run to deploy at the expected address first.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use unpredictable salt for CREATE2:\n\n\
                     1. Include a secret/commitment in salt:\n\
                     bytes32 salt = keccak256(abi.encode(msg.sender, secret, nonce));\n\n\
                     2. Use commit-reveal for deployment\n\
                     3. Add access control to deployment function"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_deterministic_salt(&contract_source) {
            let message = format!(
                "Function '{}' in contract '{}' uses CREATE2 without secret/random salt component. \
                 The deployment address is fully predictable.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add unpredictability to CREATE2 salt:\n\n\
                     1. Include user-provided secret in salt\n\
                     2. Use commit-reveal scheme\n\
                     3. Restrict deployment to authorized addresses"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_public_create2(&contract_source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes public CREATE2 deployment without \
                 access control. Anyone can deploy at predictable addresses.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add access control to CREATE2 deployment:\n\n\
                     function deploy(bytes32 salt) external onlyOwner {\n\
                         // CREATE2 deployment\n\
                     }\n\n\
                     Or use commit-reveal to prevent front-running."
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
        let detector = Create2SaltFrontrunningDetector::new();
        assert_eq!(detector.name(), "CREATE2 Salt Front-running");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
