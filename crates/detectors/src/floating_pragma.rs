use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for floating pragma directives that can cause inconsistent compiler behavior
pub struct FloatingPragmaDetector {
    base: BaseDetector,
}

impl Default for FloatingPragmaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FloatingPragmaDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("floating-pragma".to_string()),
                "Floating Pragma".to_string(),
                "Detects floating pragma directives (e.g., ^0.8.0) that allow compilation with multiple compiler versions, potentially causing inconsistent behavior and security issues".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Low,
            ),
        }
    }
}

impl Detector for FloatingPragmaDetector {
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
        let lines: Vec<&str> = source.lines().collect();

        // Phase 9 FP Reduction: Skip library/interface files (lower risk)
        let is_lib_or_interface = self.is_library_or_interface(source);

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for pragma solidity declarations
            if trimmed.starts_with("pragma solidity") {
                let pragma_statement = trimmed;
                let version = self.extract_version(pragma_statement);
                let is_080_plus = self.is_080_or_higher(&version);

                // Phase 9 FP Reduction: Skip library/interface files for non-critical versions
                if is_lib_or_interface && is_080_plus {
                    continue;
                }

                // Pattern 1: Caret operator (^) - floating pragma
                if pragma_statement.contains('^') {
                    // Phase 16 FP Reduction: Skip caret pragmas for 0.8+ entirely
                    // Caret on 0.8+ is very low risk (built-in overflow, bounded range)
                    if is_080_plus {
                        continue;
                    }

                    // Phase 9 FP Reduction: Lower severity for 0.8.x (has overflow checks)
                    let severity = if is_080_plus {
                        Severity::Info
                    } else {
                        Severity::Low
                    };

                    let message = if is_080_plus {
                        format!(
                            "Floating pragma detected: {}. \
                            While 0.8+ has built-in overflow checks, locking the version ensures \
                            consistent compilation across environments.",
                            pragma_statement
                        )
                    } else {
                        format!(
                            "Floating pragma detected: {}. \
                            Using '^' with pre-0.8 Solidity is higher risk as these versions \
                            lack built-in overflow protection. Lock to a specific version.",
                            pragma_statement
                        )
                    };

                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            message,
                            (line_idx + 1) as u32,
                            0,
                            pragma_statement.len() as u32,
                            severity,
                        )
                        .with_cwe(710)
                        .with_fix_suggestion(format!(
                            "Lock pragma to specific version: 'pragma solidity {};'",
                            version.trim_start_matches('^')
                        ));

                    findings.push(finding);
                }
                // Pattern 2: Range operator (>=) - floating pragma
                else if pragma_statement.contains(">=") || pragma_statement.contains('>') {
                    let is_bounded = pragma_statement.contains(">=")
                        && pragma_statement.contains('<')
                        && !pragma_statement.contains("||");

                    if is_bounded {
                        // Phase 9 FP Reduction: Skip bounded ranges for 0.8+ (very low risk)
                        if is_080_plus {
                            continue;
                        }

                        let message = format!(
                            "Bounded pragma range detected: {}. \
                            Consider locking to a specific version for maximum reproducibility.",
                            pragma_statement
                        );

                        let finding = self
                            .base
                            .create_finding_with_severity(
                                ctx,
                                message,
                                (line_idx + 1) as u32,
                                0,
                                pragma_statement.len() as u32,
                                Severity::Info,
                            )
                            .with_cwe(710)
                            .with_confidence(Confidence::Low)
                            .with_fix_suggestion(
                                "Consider locking to specific version for deployment: \
                                'pragma solidity 0.8.19;'"
                                    .to_string(),
                            );

                        findings.push(finding);
                    } else {
                        // Unbounded range - severity depends on version
                        let severity = if is_080_plus {
                            Severity::Low
                        } else {
                            Severity::Medium
                        };

                        let message = format!(
                            "Floating pragma detected: {}. \
                            Using '>=' or '>' allows compilation with any future compiler version.",
                            pragma_statement
                        );

                        let finding = self
                            .base
                            .create_finding_with_severity(
                                ctx,
                                message,
                                (line_idx + 1) as u32,
                                0,
                                pragma_statement.len() as u32,
                                severity,
                            )
                            .with_cwe(710)
                            .with_fix_suggestion(
                                "Lock pragma to specific version: 'pragma solidity 0.8.19;'"
                                    .to_string(),
                            );

                        findings.push(finding);
                    }
                }
                // Pattern 3: Multiple versions or complex ranges
                else if pragma_statement.matches("||").count() > 0 {
                    let message = format!(
                        "Complex pragma range detected: {}. \
                        Multiple version ranges make it difficult to ensure consistent behavior.",
                        pragma_statement
                    );

                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            message,
                            (line_idx + 1) as u32,
                            0,
                            pragma_statement.len() as u32,
                            Severity::Low,
                        )
                        .with_cwe(710)
                        .with_fix_suggestion(
                            "Use a single, specific compiler version: 'pragma solidity 0.8.19;'"
                                .to_string(),
                        );

                    findings.push(finding);
                }
                // Pattern 4: Wildcard versions
                else if pragma_statement.contains('*') {
                    let message = format!(
                        "Wildcard pragma detected: {}. \
                        Wildcard versions allow any compiler version to be used.",
                        pragma_statement
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            (line_idx + 1) as u32,
                            0,
                            pragma_statement.len() as u32,
                        )
                        .with_cwe(710)
                        .with_fix_suggestion(
                            "Use a specific compiler version: 'pragma solidity 0.8.19;'"
                                .to_string(),
                        );

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

impl FloatingPragmaDetector {
    fn extract_version(&self, pragma_statement: &str) -> String {
        // Extract version from pragma statement
        if let Some(start) = pragma_statement.find("solidity") {
            let after_solidity = &pragma_statement[start + 8..];
            let version = after_solidity.trim().trim_end_matches(';').trim();
            version.to_string()
        } else {
            String::new()
        }
    }

    /// Check if the version is 0.8.x or higher (has built-in overflow checks)
    /// These are safer and lower priority for floating pragma warnings
    fn is_080_or_higher(&self, version: &str) -> bool {
        // Extract the minor version number
        // Version formats: ^0.8.0, >=0.8.0 <0.9.0, 0.8.19, etc.
        let version_clean = version
            .trim_start_matches('^')
            .trim_start_matches('>')
            .trim_start_matches('=')
            .trim();

        // Check for 0.8+ or 0.9+ or 1.x (future major version)
        if version_clean.starts_with("0.8")
            || version_clean.starts_with("0.9")
            || version_clean.starts_with("1.")
        {
            return true;
        }

        // Check for ranges like >=0.8.0
        if version.contains("0.8") || version.contains("0.9") {
            return true;
        }

        false
    }

    /// Check if this is a library or interface file (lower risk for floating pragma)
    fn is_library_or_interface(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            let trimmed = line.trim();
            // Check for library or interface declarations
            if trimmed.starts_with("library ") || trimmed.starts_with("interface ") {
                return true;
            }
            // Check for abstract contracts (also lower risk)
            if trimmed.starts_with("abstract contract ") {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = FloatingPragmaDetector::new();
        assert_eq!(detector.name(), "Floating Pragma");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_extract_version() {
        let detector = FloatingPragmaDetector::new();

        let version1 = detector.extract_version("pragma solidity ^0.8.0;");
        assert_eq!(version1, "^0.8.0");

        let version2 = detector.extract_version("pragma solidity >=0.8.0 <0.9.0;");
        assert_eq!(version2, ">=0.8.0 <0.9.0");

        let version3 = detector.extract_version("pragma solidity 0.8.19;");
        assert_eq!(version3, "0.8.19");
    }
}
