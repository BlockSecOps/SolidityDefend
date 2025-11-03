use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for variable shadowing that can cause confusion
pub struct ShadowingVariablesDetector {
    base: BaseDetector,
}

impl ShadowingVariablesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("shadowing-variables".to_string()),
                "Variable Shadowing".to_string(),
                "Detects variable shadowing where local variables hide state variables or inherited variables causing confusion".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for ShadowingVariablesDetector {
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

        // Collect state variable names
        let state_vars = self.collect_state_variables(ctx);

        // Check each function for shadowing
        for function in ctx.get_functions() {
            if let Some(shadowing_issues) = self.check_shadowing(function, &state_vars, ctx) {
                for issue_desc in shadowing_issues {
                    let message = format!(
                        "Function '{}' contains variable shadowing. {} \
                        Shadowing can cause confusion and lead to bugs where the wrong variable is accessed.",
                        function.name.name, issue_desc
                    );

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
                    .with_fix_suggestion(format!(
                        "Rename shadowing variables in '{}'. \
                        Use different names for local variables to avoid shadowing state variables. \
                        Consider prefixes like '_' for function parameters or descriptive names.",
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

impl ShadowingVariablesDetector {
    fn collect_state_variables(&self, ctx: &AnalysisContext) -> Vec<String> {
        let mut state_vars = Vec::new();
        let contract_source = ctx.source_code.as_str();

        // Simple pattern matching for state variable declarations
        for line in contract_source.lines() {
            let trimmed = line.trim();

            // Skip comments and functions
            if trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.contains("function")
                || trimmed.contains("modifier")
            {
                continue;
            }

            // Look for state variable patterns
            if (trimmed.contains("uint")
                || trimmed.contains("address")
                || trimmed.contains("bool")
                || trimmed.contains("string")
                || trimmed.contains("bytes")
                || trimmed.contains("mapping"))
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal")
                    || trimmed.ends_with(";"))
            {
                // Extract variable name (simplified)
                if let Some(var_name) = self.extract_variable_name(trimmed) {
                    state_vars.push(var_name);
                }
            }
        }

        state_vars
    }

    fn extract_variable_name(&self, line: &str) -> Option<String> {
        let trimmed = line.trim().trim_end_matches(';');

        // Exclude function calls and statements with parentheses
        if trimmed.contains('(') || trimmed.contains("require") || trimmed.contains("assert") {
            return None;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        if parts.len() < 2 {
            return None;
        }

        let mut found_type = false;

        for (_i, part) in parts.iter().enumerate() {
            // Track if we've seen a type
            if part.starts_with("uint") || part.starts_with("int")
                || *part == "address" || *part == "bool"
                || part.starts_with("bytes") || part.starts_with("string")
                || part.starts_with("mapping") {
                found_type = true;
                continue;
            }

            // Skip visibility keywords
            if *part == "public" || *part == "private" || *part == "internal"
                || *part == "constant" || *part == "immutable" {
                continue;
            }

            // After we've found the type, extract the variable name
            if found_type {
                let name = part.trim_end_matches(';').trim_end_matches('=').trim_end_matches(',');

                // Validate it's a proper identifier
                if self.is_valid_identifier(name) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    fn is_valid_identifier(&self, s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        // Must start with letter or underscore
        let first_char = s.chars().next().unwrap();
        if !first_char.is_alphabetic() && first_char != '_' {
            return false;
        }

        // Rest must be alphanumeric or underscore (no special characters)
        s.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    fn check_shadowing(
        &self,
        function: &ast::Function<'_>,
        state_vars: &[String],
        ctx: &AnalysisContext,
    ) -> Option<Vec<String>> {
        if function.body.is_none() {
            return None;
        }

        let mut issues = Vec::new();

        // Check function signature for parameter shadowing (simplified)
        let func_signature = ctx
            .source_code
            .lines()
            .skip(function.location.start().line())
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");

        for state_var in state_vars {
            if func_signature.contains(&format!("({})", state_var))
                || func_signature.contains(&format!("({} ", state_var))
                || func_signature.contains(&format!(" {},", state_var))
            {
                issues.push(format!("Parameter '{}' shadows state variable", state_var));
            }
        }

        // Check function body for local variable declarations that shadow state vars
        let func_source = self.get_function_source(function, ctx);

        for line in func_source.lines() {
            let trimmed = line.trim();

            // Look for local variable declarations
            if (trimmed.contains("uint")
                || trimmed.contains("address")
                || trimmed.contains("bool")
                || trimmed.contains("string"))
                && !trimmed.contains("public")
                && !trimmed.contains("private")
            {
                if let Some(local_var) = self.extract_variable_name(trimmed) {
                    if state_vars.iter().any(|sv| sv == &local_var) {
                        issues.push(format!(
                            "Local variable '{}' shadows state variable",
                            local_var
                        ));
                    }
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
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
        let detector = ShadowingVariablesDetector::new();
        assert_eq!(detector.name(), "Variable Shadowing");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
