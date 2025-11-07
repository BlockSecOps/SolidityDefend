use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for patterns causing excessive gas consumption
pub struct ExcessiveGasUsageDetector {
    base: BaseDetector,
}

impl Default for ExcessiveGasUsageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExcessiveGasUsageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("excessive-gas-usage".to_string()),
                "Excessive Gas Usage".to_string(),
                "Detects patterns causing excessive gas consumption such as storage operations in loops, redundant storage reads, and inefficient data structures".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Low,
            ),
        }
    }
}

impl Detector for ExcessiveGasUsageDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for function in ctx.get_functions() {
            if let Some(gas_issues) = self.check_excessive_gas(function, ctx) {
                for issue_desc in gas_issues {
                    let message = format!(
                        "Function '{}' contains excessive gas usage pattern. {} \
                        Excessive gas usage increases transaction costs and may cause out-of-gas errors.",
                        function.name.name, issue_desc
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                        .with_fix_suggestion(format!(
                            "Optimize gas usage in '{}'. \
                        Consider: (1) Move storage operations outside loops, \
                        (2) Cache storage reads in memory, \
                        (3) Use events instead of storage for historical data, \
                        (4) Pack struct variables efficiently, \
                        (5) Use memory arrays for temporary data.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExcessiveGasUsageDetector {
    fn check_excessive_gas(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<Vec<String>> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let mut issues = Vec::new();

        // Pattern 1: Storage operations in loops
        if self.has_loop(&func_source) {
            if func_source.contains(".push(") {
                issues.push(
                    "Storage array push operation inside loop. Extremely gas-intensive".to_string(),
                );
            }

            if self.has_storage_write_in_loop(&func_source) {
                issues.push(
                    "Storage write operation inside loop. Consider using memory array".to_string(),
                );
            }

            if func_source.contains("delete ") {
                issues.push(
                    "Storage deletion inside loop. Each delete costs significant gas".to_string(),
                );
            }
        }

        // Pattern 2: Redundant storage reads
        let storage_reads = self.count_storage_reads(&func_source);
        if storage_reads > 3 {
            issues.push(format!(
                "Multiple storage reads detected ({}). Cache in memory variable to save gas",
                storage_reads
            ));
        }

        // Pattern 3: String concatenation in loop or multiple times
        if self.has_loop(&func_source) && func_source.contains("string.concat") {
            issues.push(
                "String concatenation in loop. Use bytes for efficient concatenation".to_string(),
            );
        }

        // Pattern 4: Dynamic array length in loop condition
        if func_source.contains("for")
            && func_source.contains(".length")
            && !func_source.contains("uint len =")
            && !func_source.contains("uint256 len =")
        {
            issues.push(
                "Array length read in every loop iteration. Cache length in local variable"
                    .to_string(),
            );
        }

        // Pattern 5: Emitting events in loops
        if self.has_loop(&func_source) && func_source.contains("emit ") {
            issues.push(
                "Event emission inside loop. Can cause excessive gas costs for large arrays"
                    .to_string(),
            );
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn has_loop(&self, source: &str) -> bool {
        source.contains("for (")
            || source.contains("for(")
            || source.contains("while (")
            || source.contains("while(")
    }

    fn has_storage_write_in_loop(&self, source: &str) -> bool {
        // Look for storage variable assignments in loops
        // This is a simplified check - looks for assignment patterns after loop keywords
        let lines: Vec<&str> = source.lines().collect();
        let mut in_loop = false;
        let mut brace_count = 0;

        for line in lines {
            let trimmed = line.trim();

            if trimmed.starts_with("for ") || trimmed.starts_with("while ") {
                in_loop = true;
                brace_count = 0;
            }

            if in_loop {
                brace_count += trimmed.matches('{').count() as i32;
                brace_count -= trimmed.matches('}').count() as i32;

                // Look for storage writes (simplified)
                if trimmed.contains(" = ")
                    && !trimmed.contains("memory")
                    && !trimmed.contains("uint")
                    && !trimmed.contains("address")
                    && !trimmed.starts_with("//")
                {
                    return true;
                }

                if brace_count <= 0 {
                    in_loop = false;
                }
            }
        }

        false
    }

    fn count_storage_reads(&self, source: &str) -> usize {
        let mut count = 0;
        let state_var_patterns = ["balance", "owner", "totalSupply", "paused", "initialized"];

        for pattern in &state_var_patterns {
            count += source.matches(pattern).count();
        }

        // Also check for mapping reads
        count += source.matches("balances[").count();
        count += source.matches("allowances[").count();
        count += source.matches("stakes[").count();

        count
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ExcessiveGasUsageDetector::new();
        assert_eq!(detector.name(), "Excessive Gas Usage");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }
}
