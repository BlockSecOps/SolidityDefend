use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-6780 selfdestruct behavior change vulnerabilities
///
/// Post-Cancun (Dencun upgrade), SELFDESTRUCT behavior changed:
/// 1. Contract code is only deleted if called in same TX as creation
/// 2. ETH is still transferred to beneficiary
/// 3. Existing contracts relying on code deletion will break
///
/// Vulnerable patterns:
/// ```solidity
/// // Pattern relying on code deletion (broken post-Cancun)
/// function reset() external {
///     selfdestruct(payable(owner));
///     // Caller expects contract code to be deleted
/// }
///
/// // CREATE2 + selfdestruct for metamorphic contracts (broken)
/// function redeploy() external {
///     selfdestruct(payable(owner));
///     // Later: same CREATE2 salt deploys new code
/// }
/// ```
pub struct Eip6780SelfdestructChangeDetector {
    base: BaseDetector,
}

impl Default for Eip6780SelfdestructChangeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip6780SelfdestructChangeDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip6780-selfdestruct-change"),
                "EIP-6780 Selfdestruct Change".to_string(),
                "Detects code relying on pre-Cancun SELFDESTRUCT behavior. \
                 Post-Cancun, SELFDESTRUCT only deletes code if called in the \
                 same transaction as contract creation. Code relying on code \
                 deletion for security or upgrades will break."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Upgradeable],
                Severity::Medium,
            ),
        }
    }

    /// Check if the source contains an actual selfdestruct call (not just in comments/strings).
    fn has_actual_selfdestruct_call(source: &str) -> bool {
        for line in source.lines() {
            let trimmed = line.trim();
            // Skip comment lines
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }
            // Check for actual selfdestruct call or SELFDESTRUCT opcode
            if trimmed.contains("selfdestruct(") || trimmed.contains("SELFDESTRUCT") {
                return true;
            }
        }
        false
    }

    /// Find selfdestruct usage patterns
    fn find_selfdestruct_patterns(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for metamorphic patterns
        let uses_create2 = source.contains("create2") || source.contains("CREATE2");
        let has_redeploy_pattern = source.contains("redeploy") || source.contains("recreate");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Find selfdestruct usage
            if trimmed.contains("selfdestruct(") || trimmed.contains("SELFDESTRUCT") {
                // Check context to understand intent
                let func_start = self.find_function_start(&lines, line_num);
                let func_name = if func_start < lines.len() {
                    self.extract_function_name(lines[func_start])
                } else {
                    "unknown".to_string()
                };

                let func_end = self.find_function_end(&lines, func_start);
                // Guard against invalid slice range
                let func_body: String = if func_start < func_end {
                    lines[func_start..func_end].join("\n")
                } else {
                    String::new()
                };

                // Check for metamorphic pattern (CREATE2 + selfdestruct)
                if uses_create2 {
                    findings.push((
                        line_num as u32 + 1,
                        func_name.clone(),
                        "metamorphic contract pattern with CREATE2".to_string(),
                    ));
                }

                // Check for reset/upgrade patterns
                if func_name.contains("reset")
                    || func_name.contains("destroy")
                    || func_name.contains("kill")
                    || func_name.contains("upgrade")
                    || has_redeploy_pattern
                {
                    findings.push((
                        line_num as u32 + 1,
                        func_name.clone(),
                        "contract reset/upgrade relying on code deletion".to_string(),
                    ));
                }

                // Check if there's code after selfdestruct that assumes deletion
                // Guard against invalid slice range (line_num must be < func_end)
                let lines_after: String = if line_num < func_end {
                    lines[line_num..func_end].join("\n")
                } else {
                    String::new()
                };
                if lines_after.contains("// code will be deleted")
                    || lines_after.contains("// contract destroyed")
                    || source.contains("extcodesize")
                // Checking if code exists
                {
                    findings.push((
                        line_num as u32 + 1,
                        func_name.clone(),
                        "code assumes selfdestruct deletes bytecode".to_string(),
                    ));
                }

                // Check for emergency/security selfdestruct
                if func_body.contains("emergency")
                    || func_body.contains("Emergency")
                    || func_body.contains("onlyOwner")
                    || func_name.contains("emergency")
                {
                    findings.push((
                        line_num as u32 + 1,
                        func_name.clone(),
                        "emergency selfdestruct may not delete code post-Cancun".to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Check for extcodesize checks that assume selfdestruct deleted code
    fn find_extcodesize_assumptions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_selfdestruct = source.contains("selfdestruct");

        if !has_selfdestruct {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for extcodesize checks
            if trimmed.contains("extcodesize") || trimmed.contains("code.length") {
                // Look for patterns that check if contract was destroyed
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = (line_num + 5).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if context.contains("== 0") || context.contains("!= 0") || context.contains("> 0") {
                    findings.push((
                        line_num as u32 + 1,
                        "extcodesize check after selfdestruct pattern".to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Find function start
    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            if lines[i].contains("function ") {
                return i;
            }
        }
        0
    }

    /// Find function end
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut brace_count = 0;
        let mut found_open = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        brace_count += 1;
                        found_open = true;
                    }
                    '}' => {
                        brace_count -= 1;
                        if found_open && brace_count == 0 {
                            return (i + 1).min(lines.len());
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after = &line[start + 9..];
            if let Some(end) = after.find('(') {
                return after[..end].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip6780SelfdestructChangeDetector {
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

        // FP Reduction v10: Early exit if source has no selfdestruct keyword at all
        // (outside of comments). Many contracts mention selfdestruct in NatSpec or
        // string literals but don't actually call it.
        if !Self::has_actual_selfdestruct_call(source) {
            return Ok(findings);
        }

        // FP Reduction v10: Skip simple/standard tokens — they don't use selfdestruct
        if crate::utils::is_simple_token(ctx) || crate::utils::is_standard_token(ctx) {
            return Ok(findings);
        }

        // FP Reduction v10: Skip non-relevant contract types
        if crate::utils::is_bridge_contract(ctx)
            || crate::utils::is_oracle_implementation(ctx)
            || crate::utils::is_lending_protocol(ctx)
            || crate::utils::is_governance_protocol(ctx)
            || crate::utils::is_zk_contract(ctx)
            || crate::utils::is_view_only_lens_contract(ctx)
            || crate::utils::is_flash_loan_provider(ctx)
            || crate::utils::is_flash_loan_context(ctx)
            || crate::utils::is_test_contract(ctx)
        {
            return Ok(findings);
        }

        // Check for selfdestruct patterns
        let selfdestruct_patterns = self.find_selfdestruct_patterns(source);
        for (line, func_name, issue) in selfdestruct_patterns {
            let message = format!(
                "EIP-6780 behavior change in contract '{}', function '{}': {}. \
                 Post-Cancun (Dencun upgrade), SELFDESTRUCT only deletes code if \
                 called in the same transaction as contract creation. ETH transfer \
                 still works, but code deletion may not.",
                contract_name, func_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Post-Cancun SELFDESTRUCT changes:\n\n\
                     1. Code is only deleted if selfdestruct is in same TX as creation\n\
                     2. For ETH recovery: selfdestruct still works\n\
                     3. For metamorphic contracts: CREATE2 + selfdestruct NO LONGER works\n\n\
                     Alternatives:\n\
                     - Use upgradeable proxy patterns instead of metamorphic\n\
                     - For code removal: plan deployment to call selfdestruct in constructor\n\
                     - For ETH recovery: selfdestruct still transfers ETH\n\
                     - Consider using pausable pattern instead of destroy"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for extcodesize assumptions
        let extcodesize_issues = self.find_extcodesize_assumptions(source);
        for (line, issue) in extcodesize_issues {
            let message = format!(
                "Potential EIP-6780 issue in contract '{}': {}. \
                 extcodesize checks to verify contract destruction may return \
                 non-zero post-Cancun even after selfdestruct.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Do not rely on extcodesize == 0 to verify selfdestruct. \
                     Use explicit state flags or events instead."
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
        let detector = Eip6780SelfdestructChangeDetector::new();
        assert_eq!(detector.name(), "EIP-6780 Selfdestruct Change");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_selfdestruct_detection() {
        let detector = Eip6780SelfdestructChangeDetector::new();

        let vulnerable = r#"
            contract Metamorphic {
                function destroy() external {
                    selfdestruct(payable(owner));
                }
                function redeploy() external {
                    // Will use CREATE2 with same salt
                }
            }
        "#;
        let issues = detector.find_selfdestruct_patterns(vulnerable);
        assert!(!issues.is_empty());
    }
}
