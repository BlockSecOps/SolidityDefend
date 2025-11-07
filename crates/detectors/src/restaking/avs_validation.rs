//! AVS Validation Bypass Detector
//!
//! Detects Actively Validated Service (AVS) registration without proper security validation,
//! allowing malicious services to slash operator stakes without adequate oversight.
//!
//! Severity: HIGH
//! Category: DeFi, Restaking
//!
//! Vulnerabilities Detected:
//! 1. No AVS security requirements (audit, validator count)
//! 2. No AVS collateral requirement
//! 3. No slashing policy limits (AVS can set 100% slashing)
//! 4. Operators cannot opt-out of AVS
//!
//! Real-World Context:
//! - AVSs can slash operator stakes if they misbehave
//! - Malicious/poorly-designed AVSs pose systemic risk
//! - Small validator pools vulnerable to 51% attacks before joining EigenLayer

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::restaking::classification::*;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct AVSValidationBypassDetector {
    base: BaseDetector,
}

impl AVSValidationBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("avs-validation-bypass".to_string()),
                "AVS Validation Bypass".to_string(),
                "Detects AVS registration without proper security validation, allowing malicious services to slash stakes".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Checks AVS registration for collateral requirement
    fn check_collateral_requirement(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check AVS registration functions
        if !func_name_lower.contains("registeravs")
            && !func_name_lower.contains("register")
            && !(func_name_lower.contains("avs") && func_name_lower.contains("create"))
        {
            return findings;
        }

        // Skip if not AVS-related
        if !func_name_lower.contains("avs") {
            return findings;
        }

        // Check for collateral requirement
        if !has_collateral_requirement(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No collateral requirement for AVS registration in '{}' - malicious AVS can slash without skin in the game",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Require AVS collateral as deterrent:\n\
                 \n\
                 uint256 public constant MIN_AVS_COLLATERAL = 100 ether;\n\
                 \n\
                 struct AVSMetadata {\n\
                     string name;\n\
                     address owner;\n\
                     uint256 collateral;\n\
                     bool approved;\n\
                 }\n\
                 \n\
                 mapping(address => AVSMetadata) public avsMetadata;\n\
                 \n\
                 function registerAVS(\n\
                     string calldata name\n\
                 ) external payable {\n\
                     require(\n\
                         msg.value >= MIN_AVS_COLLATERAL,\n\
                         \"Insufficient collateral (100 ETH minimum)\"\n\
                     );\n\
                     \n\
                     avsMetadata[msg.sender] = AVSMetadata({\n\
                         name: name,\n\
                         owner: msg.sender,\n\
                         collateral: msg.value,\n\
                         approved: false  // Requires governance approval\n\
                     });\n\
                     \n\
                     emit AVSRegistrationRequested(msg.sender, name, msg.value);\n\
                 }\n\
                 \n\
                 // Collateral can be slashed if AVS misbehaves\n\
                 function slashAVSCollateral(address avs, uint256 amount) external onlyGovernance {\n\
                     avsMetadata[avs].collateral -= amount;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks AVS registration for security validation
    fn check_security_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check AVS registration functions
        if !func_name_lower.contains("registeravs") && !func_name_lower.contains("register") {
            return findings;
        }

        if !func_name_lower.contains("avs") {
            return findings;
        }

        // Check for security validation
        if !has_security_validation(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No security validation for AVS in '{}' - unaudited AVS can be registered",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Require security validation for AVS:\n\
                 \n\
                 struct AVSMetadata {\n\
                     string name;\n\
                     uint256 collateral;\n\
                     bytes auditReport;  // Security audit required\n\
                     bool audited;\n\
                     bool approved;\n\
                 }\n\
                 \n\
                 function registerAVS(\n\
                     string calldata name,\n\
                     bytes calldata auditReport  // Require audit\n\
                 ) external payable {\n\
                     require(auditReport.length > 0, \"Security audit report required\");\n\
                     require(msg.value >= MIN_AVS_COLLATERAL, \"Insufficient collateral\");\n\
                     \n\
                     avsMetadata[msg.sender] = AVSMetadata({\n\
                         name: name,\n\
                         collateral: msg.value,\n\
                         auditReport: auditReport,\n\
                         audited: true,\n\
                         approved: false  // Still needs governance approval\n\
                     });\n\
                 }\n\
                 \n\
                 function approveAVS(address avs) external onlyGovernance {\n\
                     AVSMetadata storage metadata = avsMetadata[avs];\n\
                     require(metadata.audited, \"Not audited\");\n\
                     require(metadata.collateral >= MIN_AVS_COLLATERAL, \"Insufficient collateral\");\n\
                     metadata.approved = true;\n\
                     emit AVSApproved(avs);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks slashing policy for maximum limits
    fn check_slashing_policy_limits(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check slashing policy functions
        if !func_name_lower.contains("setslashing")
            && !func_name_lower.contains("slashingpolicy")
            && !func_name_lower.contains("registeravs")
        {
            return findings;
        }

        // Check if function sets slashing percentage
        if !has_slashing_percentage_param(function) {
            return findings;
        }

        // Check for max slashing cap
        if !has_max_slashing_cap(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No maximum slashing percentage cap in '{}' - AVS can set 100% slashing policy",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Enforce maximum slashing percentage:\n\
                 \n\
                 uint256 public constant MAX_AVS_SLASH_PERCENTAGE = 10;  // 10% max\n\
                 \n\
                 function registerAVS(\n\
                     string calldata name,\n\
                     uint256 slashPercentage\n\
                 ) external payable {\n\
                     require(\n\
                         slashPercentage <= MAX_AVS_SLASH_PERCENTAGE,\n\
                         \"Slashing percentage too high (10% maximum)\"\n\
                     );\n\
                     \n\
                     avsSlashingPolicies[msg.sender] = slashPercentage;\n\
                     // ... rest of registration\n\
                 }\n\
                 \n\
                 function setSlashingPolicy(uint256 percentage) external onlyAVS {\n\
                     require(\n\
                         percentage <= MAX_AVS_SLASH_PERCENTAGE,\n\
                         \"Percentage exceeds maximum\"\n\
                     );\n\
                     require(avsMetadata[msg.sender].approved, \"AVS not approved\");\n\
                     avsSlashingPolicies[msg.sender] = percentage;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for operator opt-in mechanism
    fn check_operator_opt_in(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check AVS delegation/assignment functions
        if !func_name_lower.contains("delegate")
            && !func_name_lower.contains("assign")
            && !func_name_lower.contains("join")
        {
            return findings;
        }

        if !func_name_lower.contains("avs") {
            return findings;
        }

        // Check for operator approval
        if !requires_operator_approval(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No operator approval required in '{}' - operators forced to validate unvetted AVS",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Implement operator opt-in mechanism:\n\
                 \n\
                 mapping(address => mapping(address => bool)) public operatorOptIn;\n\
                 \n\
                 function operatorJoinAVS(address avs) external {\n\
                     require(avsMetadata[avs].approved, \"AVS not approved\");\n\
                     require(!operatorOptIn[msg.sender][avs], \"Already opted in\");\n\
                     \n\
                     // Operator explicitly opts in\n\
                     operatorOptIn[msg.sender][avs] = true;\n\
                     avsMetadata[avs].validatorCount++;\n\
                     \n\
                     emit OperatorJoinedAVS(msg.sender, avs);\n\
                 }\n\
                 \n\
                 function operatorLeaveAVS(address avs) external {\n\
                     require(operatorOptIn[msg.sender][avs], \"Not opted in\");\n\
                     \n\
                     // Operator can leave at any time\n\
                     operatorOptIn[msg.sender][avs] = false;\n\
                     avsMetadata[avs].validatorCount--;\n\
                     \n\
                     emit OperatorLeftAVS(msg.sender, avs);\n\
                 }\n\
                 \n\
                 This prevents operators from being forced to validate risky AVSs.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for governance approval process
    fn check_governance_approval(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if contract has AVS registration
        let has_avs_registration = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            (name.contains("register") && name.contains("avs")) || name == "registeravs"
        });

        if !has_avs_registration {
            return findings;
        }

        // Check for governance approval mechanism
        if !has_governance_approval(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No governance approval process for AVS registration - AVS can be registered without oversight".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Implement governance approval for AVS:\n\
                 \n\
                 struct AVSMetadata {\n\
                     string name;\n\
                     uint256 collateral;\n\
                     bool audited;\n\
                     bool approved;  // Requires governance approval\n\
                 }\n\
                 \n\
                 function registerAVS(string calldata name) external payable {\n\
                     // ... validation checks\n\
                     \n\
                     avsMetadata[msg.sender] = AVSMetadata({\n\
                         name: name,\n\
                         collateral: msg.value,\n\
                         audited: true,\n\
                         approved: false  // Not approved yet\n\
                     });\n\
                     \n\
                     emit AVSRegistrationRequested(msg.sender, name);\n\
                 }\n\
                 \n\
                 function approveAVS(address avs) external onlyGovernance {\n\
                     AVSMetadata storage metadata = avsMetadata[avs];\n\
                     require(metadata.collateral >= MIN_AVS_COLLATERAL, \"Insufficient collateral\");\n\
                     require(metadata.audited, \"Not audited\");\n\
                     \n\
                     metadata.approved = true;\n\
                     emit AVSApproved(avs);\n\
                 }\n\
                 \n\
                 function rejectAVS(address avs, string calldata reason) external onlyGovernance {\n\
                     // Refund collateral\n\
                     uint256 collateral = avsMetadata[avs].collateral;\n\
                     delete avsMetadata[avs];\n\
                     payable(avs).transfer(collateral);\n\
                     \n\
                     emit AVSRejected(avs, reason);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for AVSValidationBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AVSValidationBypassDetector {
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

        // Only run on restaking contracts
        if !is_restaking_contract(ctx) {
            return Ok(findings);
        }

        // Check each function for AVS validation vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_collateral_requirement(function, ctx));
            findings.extend(self.check_security_validation(function, ctx));
            findings.extend(self.check_slashing_policy_limits(function, ctx));
            findings.extend(self.check_operator_opt_in(function, ctx));
        }

        // Contract-level checks
        findings.extend(self.check_governance_approval(ctx));

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {

    // Test cases would go here
    // Should cover:
    // 1. No AVS collateral
    // 2. No security validation
    // 3. No slashing policy limits
    // 4. No operator opt-in
    // 5. No governance approval
    // 6. No false positives on secure implementations
}
