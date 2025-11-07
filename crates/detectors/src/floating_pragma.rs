use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

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

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for pragma solidity declarations
            if trimmed.starts_with("pragma solidity") {
                let pragma_statement = trimmed;

                // Pattern 1: Caret operator (^) - floating pragma
                if pragma_statement.contains('^') {
                    let version = self.extract_version(pragma_statement);
                    let message = format!(
                        "Floating pragma detected: {}. \
                        Using '^' allows compilation with multiple compiler versions, \
                        which may introduce unexpected behavior or security vulnerabilities. \
                        Different compiler versions may have different bugs, optimizations, \
                        or security fixes.",
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
                        .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
                        .with_fix_suggestion(format!(
                            "Lock pragma to specific version: 'pragma solidity {};'. \
                            This ensures consistent compilation across environments and prevents \
                            unexpected behavior from compiler version differences.",
                            version.trim_start_matches('^')
                        ));

                    findings.push(finding);
                }
                // Pattern 2: Range operator (>=) - floating pragma
                else if pragma_statement.contains(">=") || pragma_statement.contains('>') {
                    let message = format!(
                        "Floating pragma detected: {}. \
                        Using '>=' or '>' allows compilation with any future compiler version, \
                        including versions with breaking changes or unknown security issues.",
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
                        .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
                        .with_fix_suggestion(
                            "Lock pragma to specific version range with both lower and upper bounds: \
                            'pragma solidity =0.8.19;' or use exact version 'pragma solidity 0.8.19;'"
                                .to_string(),
                        );

                    findings.push(finding);
                }
                // Pattern 3: Multiple versions or complex ranges
                else if pragma_statement.matches("||").count() > 0 {
                    let message = format!(
                        "Complex pragma range detected: {}. \
                        Multiple version ranges make it difficult to ensure consistent behavior \
                        and security properties across deployments.",
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
                        .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
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
                        Wildcard versions allow any compiler version to be used, \
                        which is extremely dangerous and unpredictable.",
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
                        .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
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
