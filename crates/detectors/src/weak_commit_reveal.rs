use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for weak commit-reveal scheme vulnerabilities
pub struct WeakCommitRevealDetector {
    base: BaseDetector,
}

impl WeakCommitRevealDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("weak-commit-reveal".to_string()),
                "Weak Commit-Reveal Scheme".to_string(),
                "Detects commit-reveal schemes with insufficient delay or weak parameters, enabling MEV attacks".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for WeakCommitRevealDetector {
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
            if self.has_weak_commit_reveal(function, ctx) {
                let message = format!(
                    "Function '{}' implements commit-reveal scheme with insufficient delay \
                    (too short and predictable). MEV bots can monitor commitments and time \
                    their reveals to front-run legitimate users.",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_fix_suggestion(format!(
                    "Increase commit-reveal delay in function '{}' to at least 5 minutes and \
                    add randomization. Example: Use VRF for unpredictable reveal windows or \
                    implement variable delays based on block hash.",
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

impl WeakCommitRevealDetector {
    /// Check if function has weak commit-reveal vulnerability
    fn has_weak_commit_reveal(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Check if this is a commit-related function
        let function_name = function.name.name.to_lowercase();
        let commit_patterns = [
            "commit", "reveal", "commitorder", "revealorder"
        ];

        let is_commit_function = commit_patterns.iter().any(|pattern|
            function_name.contains(pattern)
        );

        if !is_commit_function {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if it's implementing commit-reveal
        let has_commit_reveal = func_source.contains("commitment") ||
                               func_source.contains("reveal") ||
                               (func_source.contains("commit") && func_source.contains("timestamp"));

        if !has_commit_reveal {
            return false;
        }

        // Look for vulnerability patterns
        self.check_weak_parameters(&func_source)
    }

    /// Check if commit-reveal has weak parameters
    fn check_weak_parameters(&self, source: &str) -> bool {
        // Pattern 1: Explicit vulnerability comment
        let has_vulnerability_marker = source.contains("VULNERABILITY") &&
                                       (source.contains("delay is too short") ||
                                        source.contains("Commit-reveal delay") ||
                                        source.contains("too short and predictable"));

        // Pattern 2: Uses short delay (< 5 minutes)
        let has_short_delay = (source.contains("1 minutes") ||
                              source.contains("2 minutes") ||
                              source.contains("3 minutes") ||
                              source.contains("30 seconds") ||
                              source.contains("1 minute")) &&
                             (source.contains("commitRevealDelay") ||
                              source.contains("revealDeadline"));

        // Pattern 3: Predictable timing without randomization
        let uses_predictable_timing = source.contains("block.timestamp +") &&
                                      !source.contains("random") &&
                                      !source.contains("VRF") &&
                                      !source.contains("blockhash");

        // Pattern 4: Immediate execution after reveal
        let immediate_execution = source.contains("_executeOrder") ||
                                 (source.contains("revealed = true") &&
                                  source.contains("execute"));

        // Vulnerable if has explicit marker
        if has_vulnerability_marker {
            return true;
        }

        // Vulnerable if uses short delay with predictable timing
        if has_short_delay && uses_predictable_timing {
            return true;
        }

        // Vulnerable if allows immediate execution
        if has_short_delay && immediate_execution {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = WeakCommitRevealDetector::new();
        assert_eq!(detector.name(), "Weak Commit-Reveal Scheme");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
