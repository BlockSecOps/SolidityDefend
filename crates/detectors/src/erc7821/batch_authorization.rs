//! ERC-7821 Batch Authorization Detector
//!
//! Detects missing authorization checks in ERC-7821 batch executor implementations.

use anyhow::Result;
use std::any::Any;

use super::is_erc7821_executor;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC7821BatchAuthorizationDetector {
    base: BaseDetector,
}

impl ERC7821BatchAuthorizationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7821-batch-authorization".to_string()),
                "ERC-7821 Batch Authorization".to_string(),
                "Detects missing authorization in ERC-7821 batch executor implementations"
                    .to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let func_name = &function.name.name.to_lowercase();

        // Check for batch execution functions
        if !func_name.contains("execute") && !func_name.contains("batch") {
            return issues;
        }

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // FP Reduction: Skip generic delegatecall wrappers.
        // ERC-7821 batch executors use call (not delegatecall) to execute batched operations.
        // Functions that only do delegatecall to a single user-controlled target are plain
        // delegatecall patterns, not batch executors. These are already caught by the
        // delegatecall-user-controlled detector.
        if func_lower.contains("delegatecall") && !func_lower.contains(".call(") {
            return issues;
        }

        // FP Reduction: Skip functions that are clearly single-target delegatecall/call
        // wrappers without batch semantics (no loop, no array iteration).
        let has_batch_semantics = func_lower.contains("for (")
            || func_lower.contains("for(")
            || func_lower.contains("while (")
            || func_lower.contains("while(")
            || func_lower.contains(".length");
        let is_batch_name = func_name.contains("batch") || func_name == "executebatch";

        if !has_batch_semantics && !is_batch_name {
            // Single execution function without batch semantics - not an ERC-7821 pattern
            return issues;
        }

        // Check for authorization
        let has_auth = func_lower.contains("require")
            && (func_lower.contains("msg.sender")
                || func_lower.contains("owner")
                || func_lower.contains("authorized"));

        let has_modifier = !function.modifiers.is_empty();

        if !has_auth && !has_modifier {
            issues.push((
                format!("Missing authorization in batch executor '{}' - anyone can execute arbitrary calls", function.name.name),
                Severity::Critical,
                "Add authorization check:\n\
                 \n\
                 address public owner;\n\
                 \n\
                 function executeBatch(\n\
                     address[] calldata targets,\n\
                     bytes[] calldata datas\n\
                 ) external {\n\
                     require(msg.sender == owner, \"Not authorized\");\n\
                     \n\
                     for (uint i = 0; i < targets.length; i++) {\n\
                         (bool success,) = targets[i].call(datas[i]);\n\
                         require(success);\n\
                     }\n\
                 }".to_string()
            ));
        }

        issues
    }

    /// Phase 54 FP Reduction: Check if contract inherits access control patterns
    fn has_inherited_access_control(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // OpenZeppelin Ownable
        if source.contains("is Ownable")
            || source.contains("Ownable,")
            || source.contains("OwnableUpgradeable")
        {
            return true;
        }

        // OpenZeppelin AccessControl
        if source.contains("is AccessControl")
            || source.contains("AccessControl,")
            || source.contains("AccessControlUpgradeable")
        {
            return true;
        }

        // Check for role-based patterns
        if source.contains("onlyRole(") || source.contains("hasRole(") {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Check for Diamond proxy patterns
    fn is_diamond_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Diamond standard patterns
        source.contains("IDiamondCut")
            || source.contains("IDiamondLoupe")
            || source.contains("DiamondCutFacet")
            || source_lower.contains("diamond")
            || source_lower.contains("facet")
    }

    /// Phase 54 FP Reduction: Check for smart contract wallet patterns
    fn is_smart_contract_wallet(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Safe (Gnosis Safe) patterns
        if source.contains("GnosisSafe")
            || source.contains("Safe")
            || source.contains("execTransaction")
        {
            return true;
        }

        // Account abstraction patterns
        if source.contains("IAccount")
            || source.contains("UserOperation")
            || source.contains("validateUserOp")
            || source.contains("ERC4337")
        {
            return true;
        }

        // General smart wallet patterns
        if source_lower.contains("smartwallet")
            || source_lower.contains("smart_wallet")
            || source_lower.contains("smartaccount")
            || source_lower.contains("smart_account")
        {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Check for trusted automation executors
    fn is_trusted_automation_executor(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Gelato automation
        if source.contains("Gelato") || source.contains("IOps") || source_lower.contains("gelato") {
            return true;
        }

        // Chainlink automation (Keepers)
        if source.contains("AutomationCompatible")
            || source.contains("KeeperCompatible")
            || source.contains("checkUpkeep")
            || source.contains("performUpkeep")
        {
            return true;
        }

        // Keep3r network
        if source.contains("Keep3r") || source.contains("IKeep3r") {
            return true;
        }

        // OpenZeppelin Defender
        if source.contains("Defender") || source_lower.contains("relayer") {
            return true;
        }

        false
    }
}

impl Default for ERC7821BatchAuthorizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC7821BatchAuthorizationDetector {
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

        if !is_erc7821_executor(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip if contract inherits access control
        if self.has_inherited_access_control(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip Diamond proxy patterns
        if self.is_diamond_proxy(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip smart contract wallet patterns
        if self.is_smart_contract_wallet(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip trusted automation executors
        if self.is_trusted_automation_executor(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
