use anyhow::Result;
use std::any::Any;
use std::collections::{HashMap, HashSet};

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for unused state variables that waste storage and deployment gas
pub struct UnusedStateVariablesDetector {
    base: BaseDetector,
}

impl UnusedStateVariablesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("unused-state-variables".to_string()),
                "Unused State Variables".to_string(),
                "Detects state variables that are declared but never used, wasting storage slots and deployment gas".to_string(),
                vec![DetectorCategory::BestPractices, DetectorCategory::Logic],
                Severity::Low,
            ),
        }
    }
}

impl Detector for UnusedStateVariablesDetector {
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
        let source = ctx.source_code.as_str();

        // Extract state variables and their locations
        let state_variables = self.extract_state_variables(source);

        // Build usage map
        let usage_map = self.build_usage_map(source, &state_variables);

        // Check each state variable for usage
        for (var_name, (line_num, var_type)) in state_variables {
            let usage_count = usage_map.get(&var_name).copied().unwrap_or(0);

            // If variable is only declared but never used (count == 1 means only declaration)
            if usage_count <= 1 {
                // Skip if it's a constant or immutable (these don't waste storage)
                if self.is_constant_or_immutable(&var_type) {
                    continue;
                }

                // Skip if it's a public variable (generates getter, so technically used)
                if var_type.contains("public") {
                    continue;
                }

                let message = format!(
                    "State variable '{}' is declared but never used. \
                    Unused state variables waste storage slots and increase deployment gas costs. \
                    Each unused storage slot costs gas during deployment.",
                    var_name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        line_num,
                        0,
                        var_name.len() as u32,
                    )
                    .with_cwe(563) // CWE-563: Assignment to Variable without Use
                    .with_fix_suggestion(format!(
                        "Remove unused state variable '{}'. \
                        If this variable is intended for future use, consider adding a TODO comment. \
                        If it needs to maintain storage layout for upgradeable contracts, \
                        add a comment explaining this.",
                        var_name
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

impl UnusedStateVariablesDetector {
    fn extract_state_variables(&self, source: &str) -> HashMap<String, (u32, String)> {
        let mut state_vars = HashMap::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut in_contract = false;
        let mut in_function = false;
        let mut brace_depth = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track contract and function boundaries
            if trimmed.starts_with("contract ")
                || trimmed.starts_with("abstract contract ")
                || trimmed.starts_with("library ")
            {
                in_contract = true;
                brace_depth = 0;
                continue;
            }

            if !in_contract {
                continue;
            }

            // Track braces to know when we're inside a function
            let open_braces = trimmed.matches('{').count();
            let close_braces = trimmed.matches('}').count();

            if trimmed.starts_with("function ") || trimmed.starts_with("constructor ") {
                in_function = true;
                brace_depth = 0;
            }

            if in_function {
                brace_depth += open_braces as i32;
                brace_depth -= close_braces as i32;

                if brace_depth <= 0 {
                    in_function = false;
                }
                continue;
            }

            // Skip if inside a function, modifier, or constructor
            if in_function || trimmed.starts_with("modifier ") {
                continue;
            }

            // Look for state variable declarations
            if self.looks_like_state_variable(trimmed) {
                if let Some((var_name, var_type)) = self.parse_state_variable(trimmed) {
                    state_vars.insert(var_name, ((line_idx + 1) as u32, var_type));
                }
            }
        }

        state_vars
    }

    fn looks_like_state_variable(&self, line: &str) -> bool {
        let trimmed = line.trim();

        // Must end with semicolon for a state variable declaration
        if !trimmed.ends_with(';') {
            return false;
        }

        // Exclude function calls, require statements, and other non-declarations
        if trimmed.contains('(') || trimmed.contains("require") || trimmed.contains("assert")
            || trimmed.contains("revert") || trimmed.starts_with("emit ")
            || trimmed.contains(".call") || trimmed.contains(".transfer")
            || trimmed.contains(".send") || trimmed.contains(".delegatecall") {
            return false;
        }

        // Exclude control flow and other statements
        if trimmed.starts_with("if ") || trimmed.starts_with("for ")
            || trimmed.starts_with("while ") || trimmed.starts_with("return ")
            || trimmed.starts_with("delete ") {
            return false;
        }

        // Exclude keywords that aren't state variables
        if trimmed.starts_with("function ") || trimmed.starts_with("modifier ")
            || trimmed.starts_with("constructor") || trimmed.starts_with("event ")
            || trimmed.starts_with("error ") || trimmed.starts_with("struct ")
            || trimmed.starts_with("enum ") || trimmed.starts_with("using ")
            || trimmed.starts_with("import ") || trimmed.starts_with("pragma ") {
            return false;
        }

        // State variables should start with a type or visibility modifier
        let has_type_or_visibility =
            trimmed.starts_with("uint") || trimmed.starts_with("int")
            || trimmed.starts_with("address") || trimmed.starts_with("bool")
            || trimmed.starts_with("bytes") || trimmed.starts_with("string")
            || trimmed.starts_with("mapping") || trimmed.starts_with("public ")
            || trimmed.starts_with("private ") || trimmed.starts_with("internal ")
            || trimmed.starts_with("constant ") || trimmed.starts_with("immutable ");

        has_type_or_visibility
    }

    fn parse_state_variable(&self, line: &str) -> Option<(String, String)> {
        let trimmed = line.trim().trim_end_matches(';');

        // Split by whitespace and find the variable name
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        if parts.len() < 2 {
            return None;
        }

        // Track position in the declaration
        let mut found_type = false;
        let mut found_visibility = false;

        // The variable name is typically after the type and optional visibility
        // Format: type [visibility] [constant|immutable] name [= value]
        for i in 0..parts.len() {
            let part = parts[i];

            // Skip type keywords
            if self.is_type_keyword(part) {
                found_type = true;
                continue;
            }

            // Skip visibility modifiers
            if self.is_visibility_modifier(part) {
                found_visibility = true;
                continue;
            }

            // Skip storage keywords
            if part == "constant" || part == "immutable" {
                continue;
            }

            // After we've seen the type, the next valid identifier is the variable name
            if found_type || found_visibility {
                // Handle case where name has '=' (e.g., "myVar = 10")
                if part.contains('=') {
                    let name = part.split('=').next().unwrap().trim();
                    if !name.is_empty() && self.is_valid_identifier(name) {
                        return Some((name.to_string(), trimmed.to_string()));
                    }
                } else if self.is_valid_identifier(part) && !self.is_keyword(part) {
                    return Some((part.to_string(), trimmed.to_string()));
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

        // Rest must be alphanumeric or underscore
        s.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    fn is_type_keyword(&self, word: &str) -> bool {
        word.starts_with("uint")
            || word.starts_with("int")
            || word == "address"
            || word == "bool"
            || word.starts_with("bytes")
            || word == "string"
            || word == "mapping"
    }

    fn is_visibility_modifier(&self, word: &str) -> bool {
        word == "public" || word == "private" || word == "internal" || word == "external"
    }

    fn is_keyword(&self, word: &str) -> bool {
        matches!(
            word,
            "function"
                | "modifier"
                | "constructor"
                | "event"
                | "error"
                | "struct"
                | "enum"
                | "constant"
                | "immutable"
                | "payable"
                | "view"
                | "pure"
        )
    }

    fn is_constant_or_immutable(&self, var_type: &str) -> bool {
        var_type.contains("constant") || var_type.contains("immutable")
    }

    fn build_usage_map(&self, source: &str, state_variables: &HashMap<String, (u32, String)>) -> HashMap<String, usize> {
        let mut usage_map = HashMap::new();

        // Initialize all variables with count 1 (declaration)
        for var_name in state_variables.keys() {
            usage_map.insert(var_name.clone(), 1);
        }

        // Count usage throughout the contract
        for var_name in state_variables.keys() {
            let count = self.count_variable_usage(source, var_name);
            usage_map.insert(var_name.clone(), count);
        }

        usage_map
    }

    fn count_variable_usage(&self, source: &str, var_name: &str) -> usize {
        let mut count = 0;
        let lines: Vec<&str> = source.lines().collect();

        for line in lines {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Count occurrences with word boundaries
            let words: HashSet<&str> = trimmed
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .collect();

            if words.contains(var_name) {
                count += 1;
            }
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = UnusedStateVariablesDetector::new();
        assert_eq!(detector.name(), "Unused State Variables");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_type_keyword() {
        let detector = UnusedStateVariablesDetector::new();
        assert!(detector.is_type_keyword("uint256"));
        assert!(detector.is_type_keyword("uint8"));
        assert!(detector.is_type_keyword("address"));
        assert!(detector.is_type_keyword("bool"));
        assert!(!detector.is_type_keyword("myVariable"));
    }

    #[test]
    fn test_is_constant_or_immutable() {
        let detector = UnusedStateVariablesDetector::new();
        assert!(detector.is_constant_or_immutable("uint256 constant MAX_SUPPLY"));
        assert!(detector.is_constant_or_immutable("address immutable owner"));
        assert!(!detector.is_constant_or_immutable("uint256 public balance"));
    }
}
