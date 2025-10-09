use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

/// Detector for ERC-721/ERC-1155 callback reentrancy vulnerabilities
pub struct Erc721CallbackReentrancyDetector {
    base: BaseDetector,
}

impl Erc721CallbackReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc721-callback-reentrancy".to_string()),
                "ERC-721/1155 Callback Reentrancy".to_string(),
                "Detects contracts vulnerable to reentrancy via ERC-721/1155 receiver callbacks".to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for Erc721CallbackReentrancyDetector {
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
            if let Some(issue) = self.check_nft_callback_reentrancy(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to NFT callback reentrancy. {} \
                    Real-world example: HypeBears security incident.",
                    function.name.name,
                    issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Behavioral Workflow
                .with_cwe(691) // CWE-691: Insufficient Control Flow
                .with_fix_suggestion(format!(
                    "Protect '{}' from NFT callback reentrancy. Solutions: (1) Add nonReentrant modifier, \
                    (2) Follow checks-effects-interactions pattern, (3) Complete state updates before safe operations, \
                    (4) Use _mint() instead of _safeMint() with explicit checks",
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

impl Erc721CallbackReentrancyDetector {
    fn check_nft_callback_reentrancy(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check for reentrancy guard
        let has_reentrancy_guard = func_source.contains("nonReentrant") ||
                                  function.modifiers.iter().any(|m| {
                                      m.name.name.to_lowercase().contains("nonreentrant")
                                  });

        // Check for safe NFT operations
        let has_safe_ops = func_source.contains("_safeMint(") ||
                          func_source.contains(".safeMint(") ||
                          func_source.contains("_safeTransfer(") ||
                          func_source.contains(".safeTransferFrom(") ||
                          func_source.contains("_safeBatchMint(") ||
                          func_source.contains(".safeBatchTransferFrom(");

        if has_safe_ops && !has_reentrancy_guard {
            // Check if state changes after safe operation
            let state_after_safe_op = self.has_state_change_after_safe_op(&func_source);

            if state_after_safe_op {
                return Some("State changes after safe NFT operation without reentrancy guard".to_string());
            }

            // Check for mint operations specifically
            if func_source.contains("Mint") || func_source.contains("mint") {
                return Some("Uses safe mint without reentrancy guard, can bypass mint limits".to_string());
            }

            return Some("Uses safe NFT operations without reentrancy guard".to_string());
        }

        // Check if implementing receiver callbacks
        if function.name.name == "onERC721Received" ||
           function.name.name == "onERC1155Received" ||
           function.name.name == "onERC1155BatchReceived" {

            let has_external_calls = func_source.contains(".call") ||
                                    func_source.contains(".transfer(");

            let has_state_changes = func_source.contains(" = ") &&
                                   !func_source.contains("==");

            if (has_external_calls || has_state_changes) && !has_reentrancy_guard {
                return Some(format!("Callback '{}' makes external calls or modifies state without reentrancy guard", function.name.name));
            }
        }

        None
    }

    fn has_state_change_after_safe_op(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let mut found_safe_op = false;

        for line in lines {
            if line.contains("safeMint") || line.contains("safeTransfer") {
                found_safe_op = true;
            }

            if found_safe_op {
                // Look for storage writes
                if (line.contains(" = ") || line.contains("+=") || line.contains("-=")) &&
                   !line.contains("==") &&
                   !line.starts_with("//") {
                    return true;
                }

                // Array/mapping operations
                if line.contains("[") && line.contains("]") && line.contains("=") {
                    return true;
                }
            }
        }

        false
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
        let detector = Erc721CallbackReentrancyDetector::new();
        assert_eq!(detector.name(), "ERC-721/1155 Callback Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
