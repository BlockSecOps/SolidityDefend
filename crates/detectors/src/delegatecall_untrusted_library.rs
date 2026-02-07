use anyhow::Result;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detects delegatecall to mutable library addresses that can be changed
///
/// # Vulnerability
/// When library addresses used in delegatecall are stored in mutable storage variables,
/// the contract owner or an attacker with sufficient privileges can replace the library
/// with malicious code, leading to:
/// - Code substitution attacks
/// - Fund theft through malicious library logic
/// - Storage corruption
/// - Unauthorized access
///
/// # Secure Pattern
/// Library addresses should be:
/// 1. Declared as `immutable` (set once in constructor)
/// 2. Declared as `constant` (known at compile time)
/// 3. Verified with code hash checks
/// 4. Never changeable after deployment
///
/// # Example Vulnerable Code
/// ```solidity
/// contract VulnerableLibrary {
///     address public mathLibrary;  // VULNERABLE: Mutable!
///
///     function setLibrary(address newLibrary) external {
///         mathLibrary = newLibrary;  // Can be changed!
///     }
///
///     function calculate(bytes calldata data) external {
///         mathLibrary.delegatecall(data);  // Calls mutable target
///     }
/// }
/// ```
///
/// # Example Secure Code
/// ```solidity
/// contract SecureLibrary {
///     address public immutable mathLibrary;  // SECURE: Immutable!
///
///     constructor(address _library) {
///         mathLibrary = _library;  // Set once, never changes
///     }
///
///     function calculate(bytes calldata data) external {
///         mathLibrary.delegatecall(data);  // Safe: immutable target
///     }
/// }
/// ```
///
/// # CWE-494: Download of Code Without Integrity Check
/// This detector identifies code substitution vulnerabilities where library code
/// can be changed without integrity verification.
pub struct DelegatecallUntrustedLibraryDetector {
    base: BaseDetector,
}

impl DelegatecallUntrustedLibraryDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegatecall-untrusted-library".to_string()),
                "Delegatecall to Untrusted Library".to_string(),
                "Detects delegatecall to mutable library addresses that can be changed after deployment".to_string(),
                vec![DetectorCategory::ExternalCalls, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Gets the source code of a function
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let lines: Vec<&str> = ctx.source_code.lines().collect();
        if start > 0 && end <= lines.len() {
            let start_idx = start.saturating_sub(1);
            lines[start_idx..end].join("\n")
        } else {
            String::new()
        }
    }

    /// Gets all state variable declarations from the contract
    fn get_state_variables(&self, ctx: &AnalysisContext) -> String {
        // Get the first ~100 lines which typically contain state variables
        let lines: Vec<&str> = ctx.source_code.lines().take(100).collect();
        lines.join("\n")
    }

    /// Checks if a variable is declared as immutable or constant
    fn is_variable_immutable_or_constant(&self, var_name: &str, contract_source: &str) -> bool {
        let patterns = [
            format!("address public immutable {}", var_name),
            format!("address private immutable {}", var_name),
            format!("address internal immutable {}", var_name),
            format!("address immutable public {}", var_name),
            format!("address immutable private {}", var_name),
            format!("address immutable {}", var_name),
            format!("address public constant {}", var_name),
            format!("address private constant {}", var_name),
            format!("address constant public {}", var_name),
            format!("address constant {}", var_name),
        ];

        patterns
            .iter()
            .any(|pattern| contract_source.contains(pattern))
    }

    /// Checks if a delegatecall uses a mutable library address
    fn check_delegatecall_target(
        &self,
        function_source: &str,
        contract_source: &str,
    ) -> Option<String> {
        if !function_source.contains("delegatecall") {
            return None;
        }

        // Pattern 1: Direct variable delegatecall: library.delegatecall(...)
        let var_delegatecall_patterns = [r"(\w+)\.delegatecall\("];

        for pattern in &var_delegatecall_patterns {
            if let Some(var_name) = self.extract_variable_name(function_source, pattern) {
                // Check if this variable is immutable/constant
                if !self.is_variable_immutable_or_constant(&var_name, contract_source) {
                    // Check if it's a state variable (appears in contract body outside functions)
                    if self.is_state_variable(&var_name, contract_source) {
                        return Some(format!(
                            "Delegatecall to mutable library '{}' - library address can be changed after deployment",
                            var_name
                        ));
                    }
                }
            }
        }

        // Pattern 2: Mapping access: libraries[name].delegatecall(...)
        if function_source.contains("libraries[") && function_source.contains("].delegatecall") {
            return Some(
                "Delegatecall to library from mutable mapping - library addresses can be changed"
                    .to_string(),
            );
        }

        // Pattern 3: Array access: libraries[index].delegatecall(...)
        if function_source.contains("libraries[") && function_source.contains("].delegatecall") {
            return Some(
                "Delegatecall to library from mutable array - library addresses can be changed"
                    .to_string(),
            );
        }

        // Pattern 4: External registry: IRegistry(registry).getLibrary(...).delegatecall
        if function_source.contains("getLibrary(") && function_source.contains(".delegatecall") {
            return Some(
                "Delegatecall to library from external registry - library address can be changed externally".to_string()
            );
        }

        // Pattern 5: Conditional library selection from storage
        if function_source.contains("? ")
            && function_source.contains(": ")
            && function_source.contains(".delegatecall")
        {
            // Check for patterns like: useTestLibrary ? testLib : prodLib
            if self.has_storage_conditional(function_source, contract_source) {
                return Some(
                    "Delegatecall to conditionally selected library from mutable storage"
                        .to_string(),
                );
            }
        }

        // Pattern 6: Assignment to local variable from storage
        if self.has_storage_to_local_delegatecall(function_source, contract_source) {
            return Some(
                "Delegatecall uses library address loaded from mutable storage".to_string(),
            );
        }

        None
    }

    /// Extracts variable name from delegatecall pattern
    fn extract_variable_name(&self, source: &str, _pattern: &str) -> Option<String> {
        // Simple extraction: find "varname.delegatecall("
        if let Some(idx) = source.find(".delegatecall(") {
            let before = &source[..idx];
            // Find the last word before .delegatecall
            let words: Vec<&str> = before.split_whitespace().collect();
            if let Some(last_word) = words.last() {
                // Extract just the variable name (remove any operators)
                let var_name = last_word
                    .trim_end_matches(')')
                    .trim_end_matches(']')
                    .trim_start_matches('(')
                    .split('.')
                    .last()
                    .unwrap_or(last_word);
                return Some(var_name.to_string());
            }
        }
        None
    }

    /// Checks if a variable is a state variable
    fn is_state_variable(&self, var_name: &str, contract_source: &str) -> bool {
        let patterns = [
            format!("address public {}", var_name),
            format!("address private {}", var_name),
            format!("address internal {}", var_name),
            format!("address {}", var_name),
        ];

        // Check if variable is declared at contract level (not in a function)
        for line in contract_source.lines() {
            let trimmed = line.trim();
            // Skip function bodies
            if trimmed.contains("function ") {
                break;
            }
            for pattern in &patterns {
                if trimmed.contains(pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Checks if there's a conditional using storage variables
    fn has_storage_conditional(&self, function_source: &str, contract_source: &str) -> bool {
        // Look for patterns like: bool useTestLibrary
        let storage_bools = ["useTestLibrary", "useTest", "testMode", "isTest"];

        for var in &storage_bools {
            if function_source.contains(var) && self.is_state_variable(var, contract_source) {
                return true;
            }
        }

        false
    }

    /// Checks if delegatecall uses address loaded from storage into local variable
    fn has_storage_to_local_delegatecall(
        &self,
        function_source: &str,
        contract_source: &str,
    ) -> bool {
        // Look for pattern: address lib = storageVar; ... lib.delegatecall(...)
        let lines: Vec<&str> = function_source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Find local variable assignment: address lib = ...
            if line.contains("address") && line.contains("=") && !line.contains("immutable") {
                if let Some(var_name) = self.extract_local_var_name(line) {
                    // Check if this local var is used in delegatecall later
                    for later_line in lines.iter().skip(i + 1) {
                        if later_line.contains(&format!("{}.delegatecall", var_name)) {
                            // Check if it was loaded from storage
                            if self.is_loaded_from_storage(line, contract_source) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Extracts local variable name from assignment
    fn extract_local_var_name(&self, line: &str) -> Option<String> {
        // Pattern: address varName = ...
        if let Some(eq_pos) = line.find('=') {
            let before_eq = &line[..eq_pos];
            let words: Vec<&str> = before_eq.split_whitespace().collect();
            if words.len() >= 2 {
                return Some(words[words.len() - 1].to_string());
            }
        }
        None
    }

    /// Checks if a line loads from storage
    fn is_loaded_from_storage(&self, line: &str, contract_source: &str) -> bool {
        // Look for patterns like: = libraryRegistry; = libraries[...]; = getLibrary(...)
        if let Some(eq_pos) = line.find('=') {
            let after_eq = &line[eq_pos + 1..].trim();

            // Check if RHS is a state variable
            let words: Vec<&str> = after_eq
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty())
                .collect();

            if let Some(first_word) = words.first() {
                if self.is_state_variable(first_word, contract_source) {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for DelegatecallUntrustedLibraryDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DelegatecallUntrustedLibraryDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        // Get contract source for state variable analysis
        let contract_source = self.get_state_variables(ctx);

        // Check all functions for delegatecall to mutable libraries
        for function in ctx.get_functions() {
            let function_source = self.get_function_source(function, ctx);

            if let Some(reason) = self.check_delegatecall_target(&function_source, &contract_source)
            {
                let message = format!(
                    "Function '{}' uses delegatecall to mutable library address. {}",
                    function.name.name, reason
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
                    .with_cwe(494)
                    .with_swc("SWC-112"); // SWC-112: Delegatecall to Untrusted Callee

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DelegatecallUntrustedLibraryDetector::new();
        assert_eq!(detector.id().0, "delegatecall-untrusted-library");
        assert_eq!(detector.name(), "Delegatecall to Untrusted Library");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_default() {
        let detector = DelegatecallUntrustedLibraryDetector::default();
        assert_eq!(detector.id().0, "delegatecall-untrusted-library");
    }
}
