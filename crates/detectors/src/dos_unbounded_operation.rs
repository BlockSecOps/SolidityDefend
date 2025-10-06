use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for DOS via unbounded operations
pub struct DosUnboundedOperationDetector {
    base: BaseDetector,
}

impl DosUnboundedOperationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dos-unbounded-operation".to_string()),
                "DOS via Unbounded Operation".to_string(),
                "Detects unbounded loops and operations that can cause denial of service".to_string(),
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

        for function in ctx.get_functions() {
            if let Some(dos_issue) = self.check_unbounded_operation(function, ctx) {
                let message = format!(
                    "Function '{}' has DOS vulnerability via unbounded operation. {} \
                    Can cause out-of-gas errors blocking contract functionality.",
                    function.name.name,
                    dos_issue
                );

                let finding = self.base.create_finding(
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
    fn check_unbounded_operation(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Loop over unbounded array
        let has_loop = func_source.contains("for") || func_source.contains("while");
        let loops_over_storage = has_loop &&
                                (func_source.contains(".length") ||
                                 func_source.contains("[]"));

        let no_iteration_limit = loops_over_storage &&
                                !func_source.contains("MAX_") &&
                                !func_source.contains("require(") &&
                                !func_source.contains("<=");

        if no_iteration_limit {
            return Some(format!(
                "Loop over unbounded array without iteration limit, \
                large arrays cause out-of-gas"
            ));
        }

        // Pattern 2: Deleting large structures
        if func_source.contains("delete") && func_source.contains("[") {
            return Some(format!(
                "Deleting array or mapping without size limit, \
                can exceed gas limit"
            ));
        }

        None
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
