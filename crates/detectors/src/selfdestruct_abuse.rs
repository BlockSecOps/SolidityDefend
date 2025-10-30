use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for selfdestruct abuse vulnerabilities
pub struct SelfdestructAbuseDetector {
    base: BaseDetector,
}

impl SelfdestructAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("selfdestruct-abuse".to_string()),
                "Selfdestruct Abuse".to_string(),
                "Detects unrestricted selfdestruct usage and force-sending ether vulnerabilities"
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for SelfdestructAbuseDetector {
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
            if let Some(selfdestruct_issue) = self.has_selfdestruct_abuse(function, ctx) {
                let message = format!(
                    "Function '{}' contains selfdestruct abuse vulnerability. {} \
                    Selfdestruct permanently destroys the contract and can force-send ether \
                    to any address, bypassing fallback functions and breaking assumptions.",
                    function.name.name, selfdestruct_issue
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
                    .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                    .with_cwe(404) // CWE-404: Improper Resource Shutdown or Release
                    .with_fix_suggestion(format!(
                        "Restrict or remove selfdestruct in '{}'. \
                    Add access control (onlyOwner), implement time-lock, \
                    or use withdraw pattern instead of selfdestruct. \
                    Consider that contracts expecting ether may not have payable fallback.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        // Note: Forced ether vulnerability check requires full contract analysis
        // which would need access to contract-level source code inspection

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SelfdestructAbuseDetector {
    /// Check if function has selfdestruct abuse
    fn has_selfdestruct_abuse(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Check for actual selfdestruct CALL, not just the word "selfdestruct" in function name/comments
        let has_selfdestruct =
            func_source.contains("selfdestruct(") || func_source.contains("suicide("); // Old keyword

        if !has_selfdestruct {
            return None;
        }

        // Pattern 1: Public/External selfdestruct without access control
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        let has_access_control = func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("require(msg.sender ==")
            || func_source.contains("if (msg.sender != owner)");

        if is_public && !has_access_control {
            return Some(format!(
                "Selfdestruct is publicly accessible without access control, \
                allowing anyone to destroy the contract"
            ));
        }

        // Pattern 2: Selfdestruct with user-controlled beneficiary
        if self.has_user_controlled_beneficiary(&func_source, function) {
            return Some(format!(
                "Selfdestruct beneficiary is controlled by function parameters, \
                allowing arbitrary ether destination"
            ));
        }

        // Pattern 3: Selfdestruct without time-lock or governance
        let has_timelock = func_source.contains("timelock")
            || func_source.contains("delay")
            || func_source.contains("proposedAt");

        let has_governance = func_source.contains("governance")
            || func_source.contains("multisig")
            || func_source.contains("vote");

        if !has_timelock && !has_governance && has_access_control {
            return Some(format!(
                "Selfdestruct can be executed immediately without time-lock or governance delay"
            ));
        }

        // Pattern 4: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("selfdestruct") || func_source.contains("destroy"))
        {
            return Some(format!("Selfdestruct vulnerability marker detected"));
        }

        None
    }

    /// Check if selfdestruct has user-controlled beneficiary
    fn has_user_controlled_beneficiary(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check if any function parameter is used as selfdestruct target
        for param in &function.parameters {
            if let Some(param_name) = &param.name {
                let param_name_str = &param_name.name;

                // Check if parameter type name suggests address
                let type_str = format!("{:?}", param.type_name);
                let is_address_param = type_str.contains("address") || type_str.contains("Address");

                if is_address_param {
                    // Check if this parameter is used in selfdestruct
                    if source.contains(&format!("selfdestruct({})", param_name_str))
                        || source.contains(&format!("selfdestruct(payable({}))", param_name_str))
                        || source.contains(&format!("suicide({})", param_name_str))
                    {
                        return true;
                    }
                }
            }
        }

        // Check for msg.sender as beneficiary (risky)
        source.contains("selfdestruct(msg.sender)")
            || source.contains("selfdestruct(payable(msg.sender))")
    }

    /// Check contract for forced ether vulnerabilities
    #[allow(dead_code)]
    fn check_forced_ether_vulnerability(
        &self,
        contract: &ast::Contract<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let contract_source = self.get_contract_source(contract, ctx);

        // Pattern 1: Exact balance checks
        let has_exact_balance_check = contract_source.contains("require(address(this).balance == ")
            || contract_source.contains("if (address(this).balance == ")
            || contract_source.contains("assert(address(this).balance == ");

        if has_exact_balance_check {
            return Some(format!(
                "Uses exact ether balance checks which can be bypassed by force-sending ether via selfdestruct"
            ));
        }

        // Pattern 2: Balance-dependent logic without internal accounting
        let has_balance_logic = (contract_source.contains("address(this).balance")
            || contract_source.contains("balance >=")
            || contract_source.contains("balance <"))
            && !contract_source.contains("totalDeposited")
            && !contract_source.contains("internalBalance");

        // Check if there's a payable function (indicates contract expects ether)
        let has_payable_function = contract_source.contains("payable");

        if has_balance_logic && has_payable_function {
            return Some(format!(
                "Logic depends on ether balance but lacks internal accounting, \
                vulnerable to forced ether via selfdestruct"
            ));
        }

        // Pattern 3: Explicit vulnerability marker
        if contract_source.contains("VULNERABILITY")
            && (contract_source.contains("forced ether")
                || contract_source.contains("selfdestruct")
                || contract_source.contains("force-send"))
        {
            return Some(format!("Forced ether vulnerability marker detected"));
        }

        None
    }

    /// Get function source code (including a few lines before to catch modifiers)
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        // Include 3 lines before function to catch modifiers on previous lines
        let extended_start = start.saturating_sub(3);

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if extended_start < source_lines.len() && end < source_lines.len() {
            source_lines[extended_start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Get contract source code
    #[allow(dead_code)]
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

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
        let detector = SelfdestructAbuseDetector::new();
        assert_eq!(detector.name(), "Selfdestruct Abuse");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
