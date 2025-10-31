//! Restaking Delegation Manipulation Detector
//!
//! Detects improper delegation validation in restaking protocols where operators can
//! manipulate staker allocations without consent or where malicious operators can be selected.
//!
//! Severity: CRITICAL
//! Category: DeFi, Restaking
//!
//! Vulnerabilities Detected:
//! 1. No operator whitelist/validation
//! 2. Unconstrained allocation changes (no 14-day delay)
//! 3. Missing delegation caps (centralization risk)
//! 4. No undelegation mechanism
//!
//! Real-World Context:
//! - EigenLayer: Operators can change allocations with 14-day delay
//! - Centralization: Few operators controlling majority of stake creates systemic risk

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::restaking::classification::*;
use ast;

pub struct RestakingDelegationManipulationDetector {
    base: BaseDetector,
}

impl RestakingDelegationManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("restaking-delegation-manipulation".to_string()),
                "Restaking Delegation Manipulation".to_string(),
                "Detects improper delegation validation in restaking protocols allowing unauthorized operator changes".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Checks delegation functions for operator validation
    fn check_operator_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check delegation functions
        if !func_name_lower.contains("delegate") &&
           !func_name_lower.contains("setoperator") {
            return findings;
        }

        // Skip undelegation functions
        if func_name_lower.contains("undelegate") {
            return findings;
        }

        // Check if function has operator parameter
        if !has_operator_parameter(function) {
            return findings;
        }

        // Check 1: Operator validation
        if !has_operator_validation(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No operator validation in '{}' - stakers can delegate to unapproved operators",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Implement operator whitelist:\n\
                 \n\
                 mapping(address => bool) public approvedOperators;\n\
                 mapping(address => uint256) public operatorMaxDelegation;\n\
                 \n\
                 function approveOperator(address operator, uint256 maxDelegation) external onlyOwner {\n\
                     approvedOperators[operator] = true;\n\
                     operatorMaxDelegation[operator] = maxDelegation;\n\
                 }\n\
                 \n\
                 function delegateTo(address operator, uint256 amount) external {\n\
                     require(approvedOperators[operator], \"Operator not approved\");\n\
                     require(\n\
                         currentDelegation[operator] + amount <= operatorMaxDelegation[operator],\n\
                         \"Exceeds operator delegation cap\"\n\
                     );\n\
                     _delegate(msg.sender, operator, amount);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        // Check 2: Delegation cap enforcement
        if increases_delegation_amount(function, ctx) {
            if !has_delegation_cap(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!(
                        "No delegation cap check in '{}' - centralization risk",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Enforce delegation caps to prevent centralization:\n\
                     \n\
                     mapping(address => uint256) public operatorMaxDelegation;\n\
                     mapping(address => uint256) public currentDelegation;\n\
                     \n\
                     function delegateTo(address operator, uint256 amount) external {\n\
                         require(\n\
                             currentDelegation[operator] + amount <= operatorMaxDelegation[operator],\n\
                             \"Exceeds max delegation per operator\"\n\
                         );\n\
                         currentDelegation[operator] += amount;\n\
                         // ... rest of delegation logic\n\
                     }".to_string()
                );

                findings.push(finding);
            }
        }

        findings
    }

    /// Checks allocation change functions for time delays
    fn check_allocation_delays(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check allocation update functions
        if !func_name_lower.contains("allocation") &&
           !func_name_lower.contains("setallocation") &&
           !func_name_lower.contains("updateallocation") {
            return findings;
        }

        // Check for time delay enforcement
        if !has_allocation_delay(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No time delay for allocation changes in '{}' - operators can instantly redirect stake",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Implement 14-day delay for allocation changes (EigenLayer standard):\n\
                 \n\
                 uint256 public constant ALLOCATION_DELAY = 14 days;\n\
                 \n\
                 struct PendingAllocation {\n\
                     uint256 percentage;\n\
                     uint256 timestamp;\n\
                 }\n\
                 \n\
                 mapping(address => mapping(address => PendingAllocation)) public pendingAllocations;\n\
                 \n\
                 function requestAllocationChange(address avs, uint256 percentage) external onlyOperator {\n\
                     pendingAllocations[msg.sender][avs] = PendingAllocation({\n\
                         percentage: percentage,\n\
                         timestamp: block.timestamp\n\
                     });\n\
                     emit AllocationChangeRequested(msg.sender, avs, percentage);\n\
                 }\n\
                 \n\
                 function executeAllocationChange(address avs) external onlyOperator {\n\
                     PendingAllocation memory pending = pendingAllocations[msg.sender][avs];\n\
                     require(\n\
                         block.timestamp >= pending.timestamp + ALLOCATION_DELAY,\n\
                         \"Delay not elapsed\"\n\
                     );\n\
                     allocations[msg.sender][avs] = pending.percentage;\n\
                     emit AllocationChanged(msg.sender, avs, pending.percentage);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for undelegation mechanism
    fn check_undelegation_mechanism(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find delegation functions
        let has_delegation = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            (name.contains("delegate") && !name.contains("undelegate")) ||
            name == "delegateto" ||
            name == "delegate_to"
        });

        // Find undelegation functions
        let has_undelegation = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("undelegate") ||
            name == "undelegatefrom" ||
            name == "undelegate_from" ||
            name == "revokedelegation"
        });

        if has_delegation && !has_undelegation {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No undelegation mechanism - funds can be permanently locked with operator".to_string(),
                1,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Implement undelegation mechanism:\n\
                 \n\
                 mapping(address => address) public delegations;\n\
                 mapping(address => uint256) public pendingWithdrawals;\n\
                 uint256 public constant UNDELEGATION_DELAY = 7 days;\n\
                 \n\
                 function undelegateFrom(address operator) external {\n\
                     require(delegations[msg.sender] == operator, \"Not delegated to operator\");\n\
                     \n\
                     // Start withdrawal delay\n\
                     pendingWithdrawals[msg.sender] = block.timestamp;\n\
                     delegations[msg.sender] = address(0);\n\
                     \n\
                     emit UndelegationRequested(msg.sender, operator);\n\
                 }\n\
                 \n\
                 function completeUndelegation() external {\n\
                     require(pendingWithdrawals[msg.sender] != 0, \"No pending withdrawal\");\n\
                     require(\n\
                         block.timestamp >= pendingWithdrawals[msg.sender] + UNDELEGATION_DELAY,\n\
                         \"Delay not elapsed\"\n\
                     );\n\
                     \n\
                     uint256 amount = delegatedAmounts[msg.sender];\n\
                     delegatedAmounts[msg.sender] = 0;\n\
                     pendingWithdrawals[msg.sender] = 0;\n\
                     \n\
                     asset.transfer(msg.sender, amount);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for centralization risk (no max delegation cap)
    fn check_centralization_risk(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if contract tracks delegation
        if !has_delegation_tracking(ctx) {
            return findings;
        }

        // Check if there's a max delegation cap
        if !has_max_operator_delegation(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No maximum delegation per operator - centralization risk (few operators could control majority)".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Implement maximum delegation caps:\n\
                 \n\
                 mapping(address => uint256) public operatorMaxDelegation;\n\
                 mapping(address => uint256) public currentDelegation;\n\
                 \n\
                 function setOperatorMaxDelegation(address operator, uint256 maxAmount) external onlyGovernance {\n\
                     operatorMaxDelegation[operator] = maxAmount;\n\
                 }\n\
                 \n\
                 function delegateTo(address operator, uint256 amount) external {\n\
                     require(\n\
                         currentDelegation[operator] + amount <= operatorMaxDelegation[operator],\n\
                         \"Exceeds operator delegation cap\"\n\
                     );\n\
                     currentDelegation[operator] += amount;\n\
                     // ... delegation logic\n\
                 }\n\
                 \n\
                 This prevents concentration of stake in few operators.".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for RestakingDelegationManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RestakingDelegationManipulationDetector {
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

        // Check each function for delegation vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_operator_validation(function, ctx));
            findings.extend(self.check_allocation_delays(function, ctx));
        }

        // Contract-level checks
        findings.extend(self.check_undelegation_mechanism(ctx));
        findings.extend(self.check_centralization_risk(ctx));

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test cases would go here
    // Should cover:
    // 1. No operator validation
    // 2. No allocation delay
    // 3. No delegation cap
    // 4. No undelegation mechanism
    // 5. No false positives on secure implementations
}
