use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for dangerous tx.origin usage in authentication
///
/// Detects when tx.origin is used for access control, which is vulnerable
/// to phishing attacks where a malicious contract can call the victim's
/// contract while tx.origin remains the victim's address.
pub struct TxOriginDetector {
    base: BaseDetector,
}

impl Default for TxOriginDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TxOriginDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("tx-origin-authentication".to_string()),
                "tx.origin Authentication".to_string(),
                "Detects use of tx.origin for authentication/authorization which is vulnerable to phishing attacks".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::BestPractices],
                Severity::Critical,
            ),
        }
    }

    /// Check if function contains tx.origin usage for authentication
    fn check_function_for_tx_origin(&self, function_source: &str, _function_name: &str) -> bool {
        let lower = function_source.to_lowercase();

        // Check if tx.origin is used
        if !lower.contains("tx.origin") {
            return false;
        }

        // Pattern 1: tx.origin in comparison (likely authentication)
        let auth_patterns = [
            "tx.origin ==",
            "tx.origin!=",
            "tx.origin !=",
            "== tx.origin",
            "!= tx.origin",
            "msg.sender == tx.origin",
            "tx.origin == msg.sender",
        ];

        let has_auth_pattern = auth_patterns.iter().any(|p| lower.contains(p));

        // Pattern 2: tx.origin in require/if/revert (control flow)
        let control_flow_patterns = [
            "require(tx.origin",
            "require (tx.origin",
            "if(tx.origin",
            "if (tx.origin",
        ];

        let in_control_flow = control_flow_patterns.iter().any(|p| lower.contains(p));

        has_auth_pattern || in_control_flow
    }

    /// Extract function source code from context
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

impl Detector for TxOriginDetector {
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

        // FP Reduction: Skip EIP-7702 delegation files where tx.origin has different semantics
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("eip7702") || file_lower.contains("delegation") {
                return Ok(findings);
            }
        }

        // FP Reduction: Consolidate per-function issues into 1 finding per contract
        let mut sub_issues: Vec<(String, u32)> = Vec::new();

        for function in ctx.get_functions() {
            if function.body.is_none() {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            if self.check_function_for_tx_origin(&func_source, function.name.name) {
                sub_issues.push((
                    function.name.name.to_string(),
                    function.name.location.start().line() as u32,
                ));
            }
        }

        if !sub_issues.is_empty() {
            let first_line = sub_issues[0].1;
            let func_names: Vec<&str> = sub_issues.iter().map(|(n, _)| n.as_str()).collect();
            let consolidated_msg = format!(
                "Contract '{}' uses tx.origin for authentication in {} functions: {}. \
                Vulnerable to phishing attacks. Use msg.sender instead.",
                ctx.contract.name.name,
                sub_issues.len(),
                func_names.join(", ")
            );

            let finding = self
                .base
                .create_finding(ctx, consolidated_msg, first_line, 0, 40)
                .with_cwe(477)
                .with_cwe(284)
                .with_swc("SWC-115")
                .with_fix_suggestion(
                    "Replace tx.origin with msg.sender for access control.".to_string(),
                );
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
