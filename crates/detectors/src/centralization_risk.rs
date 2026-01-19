use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for dangerous centralization of control
pub struct CentralizationRiskDetector {
    base: BaseDetector,
}

impl Default for CentralizationRiskDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CentralizationRiskDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("centralization-risk".to_string()),
                "Centralization Risk".to_string(),
                "Detects dangerous concentration of control in single address or entity creating single points of failure".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for CentralizationRiskDetector {
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

        // Check contract-level centralization
        if let Some(contract_issue) = self.check_contract_centralization(ctx) {
            let message = format!(
                "Contract has centralization risk. {} \
                Single point of failure can lead to fund loss, governance attacks, or complete system compromise.",
                contract_issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, 1, 0, 20)
                .with_cwe(269) // CWE-269: Improper Privilege Management
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_fix_suggestion(
                    "Implement decentralized governance. \
                Use: (1) Multi-signature wallet (Gnosis Safe), \
                (2) Timelock delays for critical operations, \
                (3) DAO governance with voting mechanisms, \
                (4) Role-based access control (OpenZeppelin AccessControl), \
                (5) Emergency pause with multiple approvers."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check function-level centralization
        for function in ctx.get_functions() {
            if let Some(function_issue) = self.check_function_centralization(function, ctx) {
                let message = format!(
                    "Function '{}' has centralization risk. {} \
                    Critical function controlled by single address creates attack vector.",
                    function.name.name, function_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(269)
                .with_cwe(284)
                .with_fix_suggestion(format!(
                    "Add decentralization to '{}'. \
                    Implement multi-signature requirements, timelock delays, or DAO governance for this critical function.",
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

impl CentralizationRiskDetector {
    fn check_contract_centralization(&self, ctx: &AnalysisContext) -> Option<String> {
        // Clean source to avoid FPs from comments/strings
        let contract_source = utils::clean_source_for_search(ctx.source_code.as_str());

        // Pattern 1: Single owner with no multi-sig
        let has_owner = contract_source.contains("address public owner")
            || contract_source.contains("address private owner");

        let has_multisig = contract_source.contains("multisig")
            || contract_source.contains("MultiSig")
            || contract_source.contains("Gnosis")
            || contract_source.contains("threshold");

        if has_owner && !has_multisig {
            return Some(
                "Contract uses single owner without multi-signature protection. \
                Single private key compromise leads to total contract control"
                    .to_string(),
            );
        }

        // Pattern 2: Critical functions without timelock
        // Be more specific to avoid FPs: look for actual function definitions
        let has_critical_ops = contract_source.contains("function withdraw")
            || contract_source.contains("function pause")
            || contract_source.contains("function upgrade");

        let has_timelock = contract_source.contains("timelock")
            || contract_source.contains("delay")
            || contract_source.contains("TimeLock");

        if has_critical_ops && !has_timelock && !has_multisig {
            return Some(
                "Critical operations (withdraw/pause/upgrade) lack timelock delays. \
                Malicious owner can drain funds or brick contract instantly"
                    .to_string(),
            );
        }

        None
    }

    fn check_function_centralization(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // Pattern 1: Owner-only critical functions
        let is_owner_check =
            func_source.contains("msg.sender == owner") || func_source.contains("onlyOwner");

        let is_critical_function = func_name.contains("withdraw")
            || func_name.contains("pause")
            || func_name.contains("unpause")
            || func_name.contains("upgrade")
            || func_name.contains("setOwner")
            || func_name.contains("destroy")
            || func_name.contains("kill");

        if is_owner_check && is_critical_function {
            let has_decentralization = func_source.contains("require(multisig")
                || func_source.contains("timelock")
                || func_source.contains("governance");

            if !has_decentralization {
                return Some(format!(
                    "Critical '{}' function restricted to single owner without multi-sig or timelock. \
                    Single point of failure for critical operation",
                    func_name
                ));
            }
        }

        // Pattern 2: Emergency functions without safeguards
        if func_name.contains("emergency") || func_name.contains("Emergency") {
            let has_safeguards = func_source.contains("multisig")
                || func_source.contains("timelock")
                || func_source.contains("governance")
                || func_source.contains("threshold");

            if !has_safeguards {
                return Some(format!(
                    "Emergency function '{}' lacks multi-party approval. \
                    Can be abused by single compromised key",
                    func_name
                ));
            }
        }

        None
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            utils::clean_source_for_search(&raw_source)
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
        let detector = CentralizationRiskDetector::new();
        assert_eq!(detector.name(), "Centralization Risk");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
