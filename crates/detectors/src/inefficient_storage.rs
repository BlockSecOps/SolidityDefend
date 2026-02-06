use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for inefficient storage patterns and layout issues
pub struct InefficientStorageDetector {
    base: BaseDetector,
}

impl Default for InefficientStorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InefficientStorageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("inefficient-storage".to_string()),
                "Inefficient Storage Usage".to_string(),
                // Phase 6 FP Reduction: Reclassified from Low to Info.
                // This is a gas optimization suggestion, not a security vulnerability.
                "Detects inefficient storage patterns including unpacked structs, redundant storage variables, and suboptimal storage layout that waste gas".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Info,
            ),
        }
    }
}

impl Detector for InefficientStorageDetector {
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
        let contract_source = ctx.source_code.as_str();

        // Check for inefficient storage patterns at contract level
        if let Some(storage_issues) = self.check_storage_layout(contract_source) {
            for (line_num, issue_desc) in storage_issues {
                let message = format!(
                    "Inefficient storage pattern detected. {} \
                    Inefficient storage layout increases gas costs for all state-modifying operations.",
                    issue_desc
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line_num, 0, 30)
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(
                        "Optimize storage layout. \
                    Consider: (1) Pack variables <32 bytes together in structs, \
                    (2) Order struct fields by size (largest to smallest), \
                    (3) Use uint256 instead of smaller types for standalone variables, \
                    (4) Combine boolean flags into a single uint256 bitmap, \
                    (5) Use constants/immutables for unchanging values."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl InefficientStorageDetector {
    fn check_storage_layout(&self, contract_source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = contract_source.lines().collect();
        let mut issues = Vec::new();

        // Track boolean storage variables for Pattern 2
        let mut bool_storage_vars: Vec<(u32, &str)> = Vec::new();

        // Pattern 1: Unpacked structs (mixed sizes without optimization)
        let mut in_struct = false;
        let mut struct_start_line = 0;
        let mut struct_has_uint256 = false;
        let mut struct_has_small_types = false;
        let mut struct_small_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("struct ") {
                in_struct = true;
                struct_start_line = line_idx;
                struct_has_uint256 = false;
                struct_has_small_types = false;
                struct_small_count = 0;
            }

            if in_struct {
                if trimmed.contains("uint256") || trimmed.contains("address") {
                    struct_has_uint256 = true;
                }
                if trimmed.contains("uint8")
                    || trimmed.contains("uint16")
                    || trimmed.contains("uint32")
                    || trimmed.contains("uint64")
                    || trimmed.contains("uint128")
                    || trimmed.contains("bool")
                {
                    struct_has_small_types = true;
                    struct_small_count += 1;
                }

                if trimmed == "}" {
                    in_struct = false;
                    // Only flag if there are enough small types to make packing worthwhile (3+)
                    if struct_has_uint256 && struct_has_small_types && struct_small_count >= 3 {
                        issues.push((
                            (struct_start_line + 1) as u32,
                            "Struct contains mixed uint256 and smaller types. Pack smaller types together for gas savings".to_string()
                        ));
                    }
                }
            }

            // Track boolean storage variables (only at contract level)
            if !in_struct
                && trimmed.contains("bool ")
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal"))
                && !trimmed.contains("mapping")
                && !trimmed.contains("constant")
            {
                bool_storage_vars.push(((line_idx + 1) as u32, trimmed));
            }

            // Pattern 3: Small uint types as standalone storage variables
            // Only flag if it's clearly inefficient (not semantically meaningful)
            if !in_struct
                && (trimmed.contains("uint8 ")
                    || trimmed.contains("uint16 "))
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal"))
                && !trimmed.contains("decimals") // uint8 for decimals is standard
                && !trimmed.contains("version")  // uint8 for version is acceptable
                && !trimmed.contains("nonce")    // small nonces are intentional
                && !trimmed.contains("status")   // status codes are often uint8
                && !trimmed.contains("state")    // state enums are often uint8
                && !trimmed.contains("index")    // indices can be intentionally small
                && !trimmed.contains("count")    // counts can be intentionally bounded
                && !trimmed.contains("id")       // IDs can be intentionally small
                && !trimmed.contains("type")
            // type codes are often uint8
            {
                issues.push((
                    (line_idx + 1) as u32,
                    "Small uint type as standalone storage variable. Use uint256 or pack with other variables".to_string()
                ));
            }

            // Pattern 4: Constant-like variables stored in storage
            // Only flag if it looks like a hardcoded constant that never changes
            if trimmed.contains(" = ")
                && (trimmed.contains("public") || trimmed.contains("private"))
                && !trimmed.contains("constant")
                && !trimmed.contains("immutable")
                && !trimmed.contains("mapping")
                && !trimmed.contains("address")  // addresses aren't constants
                && !trimmed.contains("bool")
            // bools set to false/true are state
            {
                // Check for common constant patterns (large round numbers)
                let is_constant_like = (trimmed.contains("= 1000")
                    || trimmed.contains("= 10000")
                    || trimmed.contains("= 100000")
                    || trimmed.contains("= 1e"))
                    && !trimmed.contains("block.");

                if is_constant_like {
                    issues.push((
                        (line_idx + 1) as u32,
                        "Variable initialized with constant value but not marked as constant/immutable. Use constant or immutable".to_string()
                    ));
                }
            }
        }

        // Pattern 2: Only flag booleans if there are 3+ that could be packed
        if bool_storage_vars.len() >= 3 {
            issues.push((
                bool_storage_vars[0].0,
                format!(
                    "{} boolean storage variables found. Consider packing into uint256 bitmap for gas savings",
                    bool_storage_vars.len()
                )
            ));
        }

        // Pattern 5: Redundant storage reads
        for function in self.extract_functions(contract_source) {
            if self.has_redundant_storage_reads(&function.source) {
                issues.push((
                    function.line as u32,
                    format!(
                        "Function '{}' reads same storage variable multiple times. Cache in memory",
                        function.name
                    ),
                ));
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn extract_functions(&self, source: &str) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut current_function: Option<(String, usize, Vec<String>)> = None;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                if let Some(name) = self.extract_function_name(trimmed) {
                    current_function = Some((name, idx + 1, Vec::new()));
                }
            }

            if let Some((_, _, ref mut func_lines)) = current_function {
                func_lines.push(line.to_string());

                if trimmed == "}"
                    && func_lines.iter().filter(|l| l.contains('{')).count()
                        == func_lines.iter().filter(|l| l.contains('}')).count()
                {
                    let (name, line, source_lines) = current_function.take().unwrap();
                    functions.push(FunctionInfo {
                        name,
                        line,
                        source: source_lines.join("\n"),
                    });
                }
            }
        }

        functions
    }

    fn extract_function_name(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find("function ") {
            let after_keyword = &line[start + 9..];
            if let Some(end) = after_keyword.find('(') {
                return Some(after_keyword[..end].trim().to_string());
            }
        }
        None
    }

    fn has_redundant_storage_reads(&self, source: &str) -> bool {
        let state_vars = ["owner", "totalSupply", "paused", "balance"];

        // Remove comments to avoid false positives
        let source_no_comments: String = source
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("//")
                    && !trimmed.starts_with("*")
                    && !trimmed.starts_with("/*")
            })
            .collect::<Vec<_>>()
            .join("\n");

        for var in &state_vars {
            // Require 4+ usages to flag (increased from 2)
            if source_no_comments.matches(var).count() > 3
                && !source_no_comments.contains(&format!("uint256 {} =", var))
                && !source_no_comments.contains(&format!("{} memory", var))
            {
                return true;
            }
        }

        false
    }
}

struct FunctionInfo {
    name: String,
    line: usize,
    source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = InefficientStorageDetector::new();
        assert_eq!(detector.name(), "Inefficient Storage Usage");
        // Phase 6: Reclassified from Low to Info (gas optimization, not security)
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_enabled());
    }
}
