use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
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
                // Phase 6 FP Reduction: Reclassified from Low to Info.
                // This is a gas optimization suggestion, not a security vulnerability.
                "Detects patterns causing excessive gas consumption such as storage operations in loops, redundant storage reads, and inefficient data structures".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Info,
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

        // Skip test contracts - gas optimization is less critical for tests
        if contract_classification::is_test_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip view/pure functions - no state changes = no gas concern for users
            // (they only consume gas when called internally, which is acceptable)
            if matches!(
                function.mutability,
                ast::StateMutability::View | ast::StateMutability::Pure
            ) {
                continue;
            }

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

        // Pattern 2: Redundant storage reads (raised threshold from 3 to 5)
        let storage_reads = self.count_storage_reads(&func_source);
        if storage_reads >= 5 {
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
        // Only flag if it's a storage array (indicated by lack of memory/calldata keywords nearby)
        if func_source.contains("for")
            && func_source.contains(".length")
            && !func_source.contains("uint len =")
            && !func_source.contains("uint256 len =")
            && !func_source.contains("length =")
            && self.is_storage_array_loop(&func_source)
        {
            issues.push(
                "Array length read in every loop iteration. Cache length in local variable"
                    .to_string(),
            );
        }

        // Pattern 5: Emitting events in loops - only flag if potentially unbounded
        // Small bounded loops (e.g., <= 10 iterations) are acceptable
        if self.has_loop(&func_source)
            && func_source.contains("emit ")
            && self.is_potentially_unbounded_loop(&func_source)
        {
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
        let lines: Vec<&str> = source.lines().collect();

        // Track locally declared variables to avoid FPs
        let mut local_vars: Vec<&str> = Vec::new();
        for line in &lines {
            let trimmed = line.trim();
            // Local variable declarations include memory/calldata or are type declarations
            if trimmed.contains("memory") || trimmed.contains("calldata") {
                // Extract variable name patterns
                if let Some(eq_idx) = trimmed.find(" = ") {
                    let before_eq = trimmed[..eq_idx].trim();
                    if let Some(name) = before_eq.split_whitespace().last() {
                        local_vars.push(name);
                    }
                }
            }
        }

        // Only count storage reads that aren't locally cached
        // Look for mapping access patterns with state variable indicators
        for line in &lines {
            let trimmed = line.trim();

            // Skip comments and local variable declarations
            if trimmed.starts_with("//")
                || trimmed.contains("memory")
                || trimmed.contains("calldata")
            {
                continue;
            }

            // Count mapping reads (these are definitely storage)
            count += trimmed.matches("balances[").count();
            count += trimmed.matches("allowances[").count();
            count += trimmed.matches("_balances[").count();
            count += trimmed.matches("_allowances[").count();
            count += trimmed.matches("stakes[").count();
            count += trimmed.matches("rewards[").count();
        }

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

    /// Check if loop iterates over storage array (not memory/calldata)
    fn is_storage_array_loop(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            let trimmed = line.trim();
            // Check for loop with .length
            if (trimmed.contains("for") || trimmed.contains("while")) && trimmed.contains(".length")
            {
                // Skip if it's clearly a memory or calldata array
                if trimmed.contains("memory") || trimmed.contains("calldata") {
                    continue;
                }
                // Check if array is a function parameter (likely memory/calldata)
                // Simple heuristic: storage arrays usually have state variable names
                return true;
            }
        }
        false
    }

    /// Check if loop is potentially unbounded (could iterate many times)
    fn is_potentially_unbounded_loop(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.contains("for") || trimmed.contains("while") {
                // Check for small bounded loops (explicit small limit)
                // e.g., for (uint i = 0; i < 10; i++) is bounded
                for bound in ["< 10", "< 5", "< 3", "<= 10", "<= 5", "<= 3", "< 2", "<= 2"] {
                    if trimmed.contains(bound) {
                        return false; // Small bounded loop is OK
                    }
                }
                // If it's bounded by .length, it could be large
                if trimmed.contains(".length") {
                    return true;
                }
            }
        }
        // Default: not clearly unbounded
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ExcessiveGasUsageDetector::new();
        assert_eq!(detector.name(), "Excessive Gas Usage");
        // Phase 6: Reclassified from Low to Info (gas optimization, not security)
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_enabled());
    }
}
