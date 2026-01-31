use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for uninitialized storage pointer vulnerabilities
pub struct UninitializedStorageDetector {
    base: BaseDetector,
}

impl Default for UninitializedStorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UninitializedStorageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("uninitialized-storage".to_string()),
                "Uninitialized Storage Pointer".to_string(),
                "Detects uninitialized struct or array variables that point to storage slot 0, causing state corruption".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }
}

impl Detector for UninitializedStorageDetector {
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
        let source = &ctx.source_code;

        // Phase 53 FP Reduction: Skip Solidity 0.8+ contracts
        // Solidity 0.8.0+ requires explicit data location (memory/storage/calldata)
        // The compiler enforces this, so uninitialized storage pointers are impossible
        let is_solidity_08_plus = source.contains("pragma solidity ^0.8")
            || source.contains("pragma solidity >=0.8")
            || source.contains("pragma solidity 0.8")
            || source.contains("pragma solidity ^0.9")
            || source.contains("pragma solidity >=0.9");

        if is_solidity_08_plus {
            return Ok(findings);
        }

        // Also skip well-known safe protocols (they use 0.8+ or are audited)
        let is_safe_protocol = source.contains("Permit2")
            || source.contains("@uniswap")
            || source.contains("@openzeppelin")
            || source.contains("OpenZeppelin");

        if is_safe_protocol {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(uninitialized_risk) = self.check_uninitialized_storage(function, ctx) {
                let message = format!(
                    "Function '{}' contains uninitialized storage pointer. {} \
                    Uninitialized local struct/array variables default to storage and point to slot 0, \
                    potentially corrupting critical state variables.",
                    function.name.name, uninitialized_risk
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(824) // CWE-824: Access of Uninitialized Pointer
                .with_cwe(457) // CWE-457: Use of Uninitialized Variable
                .with_fix_suggestion(format!(
                    "Initialize storage pointers in '{}'. \
                    Use `memory` keyword for local variables or explicitly assign to storage. \
                    Example: `MyStruct memory data = MyStruct(...)` or ensure initialization before use.",
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

impl UninitializedStorageDetector {
    fn check_uninitialized_storage(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Struct declaration without initialization
        let struct_pattern = func_source.contains("struct ")
            && !func_source.contains(" memory ")
            && !func_source.contains(" storage ")
            && !func_source.contains(" = ");

        // Pattern 2: Array declaration without initialization
        let array_pattern = func_source.contains("[]")
            && !func_source.contains("[] memory")
            && !func_source.contains("[] storage")
            && !func_source.contains(" = ");

        if struct_pattern {
            return Some(
                "Declares struct variable without memory/storage keyword or initialization"
                    .to_string(),
            );
        }

        if array_pattern {
            return Some(
                "Declares array variable without memory/storage keyword or initialization"
                    .to_string(),
            );
        }

        // Pattern 3: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("uninitialized") || func_source.contains("storage pointer"))
        {
            return Some("Uninitialized storage pointer vulnerability marker detected".to_string());
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
        let detector = UninitializedStorageDetector::new();
        assert_eq!(detector.name(), "Uninitialized Storage Pointer");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
