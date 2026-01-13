use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for delegatecall inside loops
///
/// Detects delegatecall operations inside for/while loops which can lead to:
/// - Gas griefing attacks
/// - Reentrancy vulnerabilities
/// - Unbounded gas consumption
///
/// Vulnerable pattern:
/// ```solidity
/// function batchExecute(address[] calldata targets, bytes[] calldata data) external {
///     for (uint i = 0; i < targets.length; i++) {
///         targets[i].delegatecall(data[i]); // Dangerous
///     }
/// }
/// ```
pub struct DelegatecallInLoopDetector {
    base: BaseDetector,
}

impl Default for DelegatecallInLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallInLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("delegatecall-in-loop"),
                "Delegatecall in Loop".to_string(),
                "Detects delegatecall operations inside loops. This pattern is dangerous as it \
                 can lead to gas griefing, reentrancy, and unbounded gas consumption. Each \
                 delegatecall can modify contract state, making loop behavior unpredictable."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find delegatecall inside loops
    fn find_delegatecall_in_loop(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_loop = false;
        let mut loop_depth = 0;
        let mut loop_start_line = 0u32;
        let mut brace_depth = 0;
        let mut loop_brace_depth = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track brace depth
            for c in trimmed.chars() {
                match c {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }

            // Check for loop start
            if trimmed.starts_with("for ")
                || trimmed.starts_with("for(")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("while(")
                || trimmed.contains(" for ")
                || trimmed.contains(" for(")
                || trimmed.contains(" while ")
                || trimmed.contains(" while(")
            {
                if !in_loop {
                    in_loop = true;
                    loop_start_line = line_num as u32 + 1;
                    loop_brace_depth = brace_depth;
                }
                loop_depth += 1;
            }

            // Check for delegatecall inside loop
            if in_loop && trimmed.contains("delegatecall") {
                let loop_type = if source[..source.lines().take(line_num + 1).collect::<Vec<_>>().join("\n").len()]
                    .rfind("for")
                    > source[..source.lines().take(line_num + 1).collect::<Vec<_>>().join("\n").len()]
                        .rfind("while")
                {
                    "for"
                } else {
                    "while"
                };
                findings.push((line_num as u32 + 1, loop_type.to_string()));
            }

            // Check for loop end
            if in_loop && brace_depth < loop_brace_depth {
                loop_depth -= 1;
                if loop_depth == 0 {
                    in_loop = false;
                }
            }
        }

        findings
    }

    /// Check for unbounded loop with delegatecall
    fn has_unbounded_delegatecall_loop(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for array.length in loop condition with delegatecall
            if (trimmed.contains(".length") || trimmed.contains("length()"))
                && (trimmed.starts_with("for") || trimmed.contains(" for"))
            {
                // Check if loop body contains delegatecall
                let loop_end = self.find_loop_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                if loop_body.contains("delegatecall") {
                    // Check for any bounds check
                    if !loop_body.contains("require(")
                        && !loop_body.contains("< MAX")
                        && !loop_body.contains("<= MAX")
                        && !loop_body.contains("maxLength")
                    {
                        return Some(line_num as u32 + 1);
                    }
                }
            }
        }

        None
    }

    /// Find the end of a loop
    fn find_loop_end(&self, lines: &[&str], start: usize) -> usize {
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

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DelegatecallInLoopDetector {
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

        // Check for delegatecall in loops
        let delegatecalls = self.find_delegatecall_in_loop(source);
        for (line, loop_type) in delegatecalls {
            let message = format!(
                "Contract '{}' performs delegatecall inside a {} loop. This is dangerous: \
                 each delegatecall can modify state, potentially causing reentrancy or \
                 unexpected behavior. Gas consumption is also unpredictable.",
                contract_name, loop_type
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(834) // CWE-834: Excessive Iteration
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid delegatecall in loops. Consider:\n\n\
                     1. Batch operations in a single delegatecall:\n\
                     bytes memory batchData = abi.encode(targets, data);\n\
                     implementation.delegatecall(batchData);\n\n\
                     2. Use a trusted multicall contract:\n\
                     multicall.aggregate(calls);\n\n\
                     3. Implement loop in the target contract instead"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for unbounded delegatecall loops
        if let Some(line) = self.has_unbounded_delegatecall_loop(source) {
            let message = format!(
                "Contract '{}' has unbounded delegatecall loop iterating over array length. \
                 An attacker can provide a large array causing out-of-gas or gas griefing.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(834) // CWE-834: Excessive Iteration
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add bounds checking:\n\n\
                     uint256 constant MAX_BATCH_SIZE = 100;\n\
                     require(targets.length <= MAX_BATCH_SIZE, \"Batch too large\");\n\n\
                     for (uint i = 0; i < targets.length; i++) {\n\
                         // ...\n\
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
        let detector = DelegatecallInLoopDetector::new();
        assert_eq!(detector.name(), "Delegatecall in Loop");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_delegatecall_in_for_loop() {
        let detector = DelegatecallInLoopDetector::new();

        let vulnerable = r#"
            contract Batch {
                function execute(address[] calldata targets, bytes[] calldata data) external {
                    for (uint i = 0; i < targets.length; i++) {
                        targets[i].delegatecall(data[i]);
                    }
                }
            }
        "#;
        let findings = detector.find_delegatecall_in_loop(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_delegatecall_in_while_loop() {
        let detector = DelegatecallInLoopDetector::new();

        let vulnerable = r#"
            contract Batch {
                function execute() external {
                    uint i = 0;
                    while (i < 10) {
                        target.delegatecall(data);
                        i++;
                    }
                }
            }
        "#;
        let findings = detector.find_delegatecall_in_loop(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_no_loop() {
        let detector = DelegatecallInLoopDetector::new();

        let safe = r#"
            contract Single {
                function execute() external {
                    target.delegatecall(data);
                }
            }
        "#;
        let findings = detector.find_delegatecall_in_loop(safe);
        assert!(findings.is_empty());
    }
}
