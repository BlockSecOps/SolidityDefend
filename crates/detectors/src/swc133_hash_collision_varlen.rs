use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for SWC-133: Hash Collisions With Multiple Variable Length Arguments
///
/// Detects usage of `abi.encodePacked()` with multiple variable-length arguments
/// (strings, bytes, arrays) which can lead to hash collisions.
///
/// Example vulnerability:
/// ```solidity
/// // These produce the same hash!
/// keccak256(abi.encodePacked("a", "bc"))
/// keccak256(abi.encodePacked("ab", "c"))
/// ```
///
/// Safe alternatives:
/// - Use `abi.encode()` instead (adds length prefixes)
/// - Use fixed-length types
/// - Add separator between variable-length arguments
pub struct HashCollisionVarlenDetector {
    base: BaseDetector,
}

impl Default for HashCollisionVarlenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HashCollisionVarlenDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("swc133-hash-collision-varlen"),
                "Hash Collision with Variable Length Args (SWC-133)".to_string(),
                "Detects abi.encodePacked() with multiple variable-length arguments \
                 which can produce hash collisions"
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }

    /// Check if source contains vulnerable encodePacked patterns
    fn find_vulnerable_encode_packed(&self, source: &str) -> Vec<(usize, String)> {
        let mut vulnerabilities = Vec::new();

        // Find all abi.encodePacked calls
        for (line_idx, line) in source.lines().enumerate() {
            if line.contains("abi.encodePacked(") {
                // Check if it has multiple arguments that could be variable length
                if let Some(issue) = self.analyze_encode_packed_call(line) {
                    vulnerabilities.push((line_idx + 1, issue));
                }
            }
        }

        vulnerabilities
    }

    /// Analyze a single encodePacked call for vulnerability
    fn analyze_encode_packed_call(&self, line: &str) -> Option<String> {
        // Extract the arguments from abi.encodePacked(...)
        let start = line.find("abi.encodePacked(")?;
        let args_start = start + "abi.encodePacked(".len();

        // Find matching closing paren (simplified - doesn't handle nested parens perfectly)
        let remaining = &line[args_start..];
        let end = remaining.find(')')?;
        let args_str = &remaining[..end];

        // Count arguments and check for variable-length types
        let args: Vec<&str> = args_str.split(',').map(|s| s.trim()).collect();

        if args.len() < 2 {
            return None; // Single argument is safe
        }

        // Count variable-length arguments
        let mut var_len_count = 0;
        let mut var_len_types = Vec::new();

        for arg in &args {
            if self.is_variable_length_type(arg) {
                var_len_count += 1;
                var_len_types.push(self.get_type_hint(arg));
            }
        }

        if var_len_count >= 2 {
            Some(format!(
                "Multiple variable-length arguments detected: {}. \
                 This can lead to hash collisions where different inputs produce the same hash.",
                var_len_types.join(", ")
            ))
        } else {
            None
        }
    }

    /// Check if an argument is likely a variable-length type
    fn is_variable_length_type(&self, arg: &str) -> bool {
        let arg_lower = arg.to_lowercase();

        // Fixed-size bytes types are NOT variable length
        // bytes1, bytes2, ..., bytes32 are fixed-size
        if self.is_fixed_size_bytes(&arg_lower) {
            return false;
        }

        // Direct type indicators for variable-length types
        if arg_lower.contains("string")
            || arg_lower == "bytes"
            || arg_lower.contains("bytes ")
            || arg_lower.contains("bytes,")
            || arg_lower.contains("bytes)")
            || arg_lower.starts_with("bytes ")
            || arg.contains("[]") // arrays are variable length
        {
            return true;
        }

        // String literals (quoted strings)
        if (arg.starts_with('"') && arg.ends_with('"'))
            || (arg.starts_with('\'') && arg.ends_with('\''))
        {
            return true;
        }

        // Common variable names for strings/bytes (but not if they look like fixed types)
        let var_length_patterns = [
            "str", "string", "name", "symbol", "message", "data", "payload",
            "text", "content", "description", "uri", "url", "path", "input",
            "sig", "signature", "encoded", "packed",
        ];

        // Only match if it contains the pattern but isn't a fixed bytes type
        var_length_patterns
            .iter()
            .any(|p| arg_lower.contains(p))
    }

    /// Check if the type is a fixed-size bytes type (bytes1 through bytes32)
    fn is_fixed_size_bytes(&self, arg: &str) -> bool {
        // Match bytes1 through bytes32
        for i in 1..=32 {
            if arg.contains(&format!("bytes{}", i)) {
                return true;
            }
        }
        false
    }

    /// Get a type hint for the argument
    fn get_type_hint(&self, arg: &str) -> String {
        if arg.starts_with('"') || arg.starts_with('\'') {
            "string literal".to_string()
        } else if arg.contains("[]") {
            "array".to_string()
        } else if arg.to_lowercase().contains("bytes") {
            "bytes".to_string()
        } else if arg.to_lowercase().contains("string")
            || arg.to_lowercase().contains("str")
            || arg.to_lowercase().contains("name")
        {
            "string variable".to_string()
        } else {
            format!("'{}'", arg.trim())
        }
    }

    /// Check if the pattern is used in a security-critical context
    fn is_security_critical_context(&self, source: &str) -> bool {
        source.contains("keccak256(")
            || source.contains("sha256(")
            || source.contains("sha3(")
            || source.contains("ecrecover(")
            || source.contains("verify")
            || source.contains("signature")
            || source.contains("hash")
    }
}

impl Detector for HashCollisionVarlenDetector {
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

        // Scan entire source for vulnerable patterns
        let vulnerabilities = self.find_vulnerable_encode_packed(&ctx.source_code);

        for (line_num, issue) in vulnerabilities {
            // Check if it's in a security-critical context
            let line = ctx.source_code.lines().nth(line_num - 1).unwrap_or("");
            let is_critical = self.is_security_critical_context(line);

            let confidence = if is_critical {
                Confidence::High
            } else {
                Confidence::Medium
            };

            let severity = if is_critical {
                Severity::High
            } else {
                Severity::Medium
            };

            let message = format!(
                "abi.encodePacked() with multiple variable-length arguments at line {}. {}",
                line_num, issue
            );

            let mut finding = self
                .base
                .create_finding(
                    ctx,
                    message,
                    line_num as u32,
                    1,
                    line.len() as u32,
                )
                .with_swc("SWC-133")
                .with_cwe(328) // CWE-328: Reversible One-Way Hash
                .with_cwe(697) // CWE-697: Incorrect Comparison
                .with_confidence(confidence)
                .with_fix_suggestion(
                    "Replace abi.encodePacked() with one of these safe alternatives:\n\
                     1. Use abi.encode() - adds length prefixes, preventing collisions\n\
                     2. Add a fixed separator between arguments:\n\
                        keccak256(abi.encodePacked(a, \"|\", b))\n\
                     3. Use fixed-length types (bytes32, uint256) instead of dynamic types\n\
                     4. Hash each argument separately and combine:\n\
                        keccak256(abi.encode(keccak256(a), keccak256(b)))"
                        .to_string(),
                );

            finding.severity = severity;
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
        let detector = HashCollisionVarlenDetector::new();
        assert_eq!(
            detector.name(),
            "Hash Collision with Variable Length Args (SWC-133)"
        );
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_variable_length_type() {
        let detector = HashCollisionVarlenDetector::new();
        assert!(detector.is_variable_length_type("string memory name"));
        assert!(detector.is_variable_length_type("bytes memory data"));
        assert!(detector.is_variable_length_type("uint256[] arr"));
        assert!(detector.is_variable_length_type("\"hello\""));
        assert!(!detector.is_variable_length_type("uint256"));
        assert!(!detector.is_variable_length_type("address"));
        assert!(!detector.is_variable_length_type("bytes32"));
    }

    #[test]
    fn test_find_vulnerable_patterns() {
        let detector = HashCollisionVarlenDetector::new();

        // Vulnerable: two string arguments
        let vulnerable = r#"
            keccak256(abi.encodePacked(name, symbol))
        "#;
        let results = detector.find_vulnerable_encode_packed(vulnerable);
        assert!(!results.is_empty());

        // Safe: single argument
        let safe = r#"
            keccak256(abi.encodePacked(name))
        "#;
        let results = detector.find_vulnerable_encode_packed(safe);
        assert!(results.is_empty());

        // Safe: using abi.encode instead
        let safe_encode = r#"
            keccak256(abi.encode(name, symbol))
        "#;
        let results = detector.find_vulnerable_encode_packed(safe_encode);
        assert!(results.is_empty());
    }
}
