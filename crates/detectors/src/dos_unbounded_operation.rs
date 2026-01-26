use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::is_deployment_tooling;

/// Detector for DOS via unbounded operations
pub struct DosUnboundedOperationDetector {
    base: BaseDetector,
}

impl Default for DosUnboundedOperationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosUnboundedOperationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dos-unbounded-operation".to_string()),
                "DOS via Unbounded Operation".to_string(),
                "Detects unbounded loops and operations that can cause denial of service"
                    .to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for DosUnboundedOperationDetector {
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

        // Phase 16 FP Reduction: Skip deployment tooling files
        if is_deployment_tooling(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(dos_issue) = self.check_unbounded_operation(function, ctx) {
                let message = format!(
                    "Function '{}' has DOS vulnerability via unbounded operation. {} \
                    Can cause out-of-gas errors blocking contract functionality.",
                    function.name.name, dos_issue
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
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(format!(
                        "Fix unbounded operation in '{}'. \
                    Add pagination for large loops, implement maximum iteration limits, \
                    use pull pattern instead of push, add circuit breakers, batch operations.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DosUnboundedOperationDetector {
    fn check_unbounded_operation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Phase 16 FP Reduction: Skip safe enumeration patterns
        if self.is_safe_enumeration(ctx, &func_name_lower) {
            return None;
        }

        // Pattern 1: Loop over unbounded array
        let has_loop = func_source.contains("for") || func_source.contains("while");
        let loops_over_storage =
            has_loop && (func_source.contains(".length") || func_source.contains("[]"));

        // Phase 16 FP Reduction: Improved bounds detection
        let has_iteration_bound = loops_over_storage && self.has_iteration_bound(&func_source);

        let no_iteration_limit = loops_over_storage
            && !has_iteration_bound
            && !func_source.contains("MAX_")
            && !func_source.contains("require(")
            && !func_source.contains("<=");

        if no_iteration_limit {
            return Some(
                "Loop over unbounded array without iteration limit, \
                large arrays cause out-of-gas"
                    .to_string(),
            );
        }

        // Pattern 2: Deleting large structures
        // Phase 16 FP Reduction: Only flag if no bound check
        if func_source.contains("delete") && func_source.contains("[") {
            // Check if there's a bound on what's being deleted
            if !self.has_delete_bound(&func_source) {
                return Some(
                    "Deleting array or mapping without size limit, \
                    can exceed gas limit"
                        .to_string(),
                );
            }
        }

        None
    }

    /// Phase 16 FP Reduction: Check if loop has iteration bounds
    fn has_iteration_bound(&self, loop_source: &str) -> bool {
        // Detect MAX constant bounds
        let has_max_constant = loop_source.contains("MAX_")
            || loop_source.contains("_MAX")
            || loop_source.contains("LIMIT")
            || loop_source.contains("_LIMIT");

        if has_max_constant {
            return true;
        }

        // Detect min() bounds - common in OpenZeppelin
        if loop_source.contains("min(") || loop_source.contains("Math.min(") {
            return true;
        }

        // Detect hardcoded numeric limits (e.g., i < 100)
        // Look for comparison with a number >= 10
        let numeric_patterns = [
            "< 10", "< 20", "< 50", "< 100", "< 256", "< 1000",
            "<= 10", "<= 20", "<= 50", "<= 100", "<= 256", "<= 1000",
            "> 0 &&", ">= 1 &&", // combined with other checks
        ];

        for pattern in &numeric_patterns {
            if loop_source.contains(pattern) {
                return true;
            }
        }

        // Detect batch size patterns
        if loop_source.contains("batchSize")
            || loop_source.contains("batch_size")
            || loop_source.contains("chunkSize")
            || loop_source.contains("pageSize")
        {
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if delete operation has bounds
    fn has_delete_bound(&self, func_source: &str) -> bool {
        // Single element delete is safe
        if func_source.contains("delete ") && !func_source.contains("delete []") {
            // Check if it's a loop delete with bounds
            if func_source.contains("for") && self.has_iteration_bound(func_source) {
                return true;
            }
            // Single element delete
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if this is a safe enumeration pattern
    fn is_safe_enumeration(&self, ctx: &AnalysisContext, func_name: &str) -> bool {
        let source = &ctx.source_code;

        // AccessControl role enumeration is by design (bounded by role count)
        if source.contains("AccessControl") || source.contains("IAccessControl") {
            if func_name.contains("getrolemember")
                || func_name.contains("enumerate")
                || func_name.contains("getrolemembercount")
            {
                return true;
            }
        }

        // EnumerableSet/Map iterations are bounded by set size
        if source.contains("EnumerableSet") || source.contains("EnumerableMap") {
            if func_name.contains("values") || func_name.contains("keys") || func_name.contains("at(") {
                return true;
            }
        }

        // View functions that enumerate are often getter patterns
        if func_name.contains("getall") || func_name.contains("list") {
            // Check if it's a view function
            if source.contains(&format!("function {}(", func_name))
                && source.contains("view")
            {
                return true;
            }
        }

        false
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
        let detector = DosUnboundedOperationDetector::new();
        assert_eq!(detector.name(), "DOS via Unbounded Operation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
