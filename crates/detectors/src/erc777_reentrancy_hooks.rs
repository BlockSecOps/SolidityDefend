use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ERC-777 tokensReceived/tokensToSend hook reentrancy vulnerabilities
pub struct Erc777ReentrancyHooksDetector {
    base: BaseDetector,
}

impl Erc777ReentrancyHooksDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc777-reentrancy-hooks".to_string()),
                "ERC-777 Reentrancy Hooks".to_string(),
                "Detects contracts vulnerable to reentrancy via ERC-777 tokensReceived/tokensToSend callbacks".to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Detector for Erc777ReentrancyHooksDetector {
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
            if let Some(issue) = self.check_erc777_reentrancy(function, ctx) {
                let message = format!(
                    "Function '{}' is vulnerable to ERC-777 hook reentrancy. {} \
                    Historical losses: $18.8M+ (Cream Finance), $25M (LendfMe), $300k (Uniswap V1).",
                    function.name.name, issue
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
                    "Protect '{}' from ERC-777 reentrancy. Solutions: (1) Add nonReentrant modifier, \
                    (2) Follow checks-effects-interactions pattern, (3) Update state before token transfers, \
                    (4) Use pull-over-push pattern",
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

impl Erc777ReentrancyHooksDetector {
    fn check_erc777_reentrancy(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check for reentrancy guard
        let has_reentrancy_guard = func_source.contains("nonReentrant")
            || function
                .modifiers
                .iter()
                .any(|m| m.name.name.to_lowercase().contains("nonreentrant"));

        // Check for ERC-777 token operations
        let has_erc777_ops = func_source.contains(".send(")
            || func_source.contains(".operatorSend(")
            || func_source.contains(".burn(")
            || func_source.contains(".operatorBurn(");

        // Check for generic token transfers that could be ERC-777
        let has_token_transfer =
            func_source.contains(".transfer(") || func_source.contains(".transferFrom(");

        // Check for ERC-1820 registry (used by ERC-777)
        let has_erc1820 =
            func_source.contains("ERC1820") || func_source.contains("IERC1820Registry");

        if (has_erc777_ops || (has_token_transfer && has_erc1820)) && !has_reentrancy_guard {
            // Check if state changes after transfer
            let state_after_transfer = self.has_state_change_after_transfer(&func_source);

            if state_after_transfer {
                return Some(
                    "State changes after ERC-777 transfer without reentrancy guard".to_string(),
                );
            }

            return Some("Interacts with ERC-777 tokens without reentrancy guard".to_string());
        }

        // Check if implementing tokensReceived callback
        if function.name.name == "tokensReceived" || function.name.name == "tokensToSend" {
            let has_external_calls =
                func_source.contains(".call") || func_source.contains(".transfer(");

            if has_external_calls && !has_reentrancy_guard {
                return Some(format!(
                    "Callback '{}' makes external calls without reentrancy guard",
                    function.name.name
                ));
            }
        }

        None
    }

    fn has_state_change_after_transfer(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let mut found_transfer = false;

        for line in lines {
            if line.contains(".transfer") || line.contains(".send(") {
                found_transfer = true;
            }

            if found_transfer
                && (line.contains(" = ") || line.contains("+=") || line.contains("-="))
            {
                return true;
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
        let detector = Erc777ReentrancyHooksDetector::new();
        assert_eq!(detector.name(), "ERC-777 Reentrancy Hooks");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
