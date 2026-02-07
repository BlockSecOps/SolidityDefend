// ERC-7683 Intent Solver/Filler Manipulation Detector
//
// Detects vulnerabilities where malicious solvers/fillers can manipulate the state
// or execution of intent fulfillment to profit at the user's expense. This includes
// front-running, state manipulation, and missing solver authentication.
//
// Severity: High
// Category: Security, MEV
//
// Vulnerabilities Detected:
// 1. No solver authentication (anyone can fill orders)
// 2. Missing reentrancy protection
// 3. No state validation before/after execution
// 4. No MEV protection (orders visible in mempool)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::erc7683::classification::*;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct IntentSolverManipulationDetector {
    base: BaseDetector,
}

impl IntentSolverManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("intent-solver-manipulation".to_string()),
                "Intent Solver Manipulation".to_string(),
                "Detects vulnerabilities where malicious solvers can manipulate intent execution for profit".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    /// Checks for solver authentication in fill functions
    fn check_solver_authentication(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check fill/execution functions
        if !is_fill_function(function) {
            return findings;
        }

        // Check for solver authentication
        if !has_solver_authentication(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "No solver authentication in '{}' - any address can fill orders",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Implement solver whitelist:\n\
                 \n\
                 mapping(address => bool) public approvedSolvers;\n\
                 \n\
                 function approveSolver(address solver) external onlyOwner {\n\
                     approvedSolvers[solver] = true;\n\
                 }\n\
                 \n\
                 function fill(...) external {\n\
                     require(approvedSolvers[msg.sender], \"Unauthorized solver\");\n\
                     // ... rest of fill logic\n\
                 }\n\
                 \n\
                 This prevents unauthorized actors from filling orders maliciously."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for reentrancy protection
    fn check_reentrancy_protection(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check settlement functions
        if !is_settlement_function(function) {
            return findings;
        }

        // Check for reentrancy protection
        if !has_reentrancy_protection(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Missing reentrancy protection in '{}' - vulnerable to reentrancy attacks",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Add reentrancy protection:\n\
                 \n\
                 import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n\
                 \n\
                 contract YourContract is ReentrancyGuard {\n\
                     function fill(...) external nonReentrant {\n\
                         // ... fill logic\n\
                     }\n\
                 }\n\
                 \n\
                 Or implement manual reentrancy guard:\n\
                 \n\
                 uint256 private _locked = 1;\n\
                 \n\
                 modifier nonReentrant() {\n\
                     require(_locked == 1, \"Reentrant call\");\n\
                     _locked = 2;\n\
                     _;\n\
                     _locked = 1;\n\
                 }"
                    .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for state validation before/after execution
    fn check_state_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check fill functions
        if !is_fill_function(function) {
            return findings;
        }

        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return findings;
        }

        let func_source = &source[func_start..func_end.min(source.len())];
        let func_lower = func_source.to_lowercase();

        // Check for state validation patterns
        let has_balance_check = func_lower.contains("balanceof")
            && (func_lower.contains("before") || func_lower.contains("after"));

        let has_state_snapshot = func_lower.contains("snapshot")
            || (func_lower.contains("before") && func_lower.contains("after"));

        if !has_balance_check && !has_state_snapshot {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "No state validation in '{}' - vulnerable to state manipulation",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Add state validation before and after execution:\n\
                 \n\
                 function fill(...) external {\n\
                     // State snapshot before\n\
                     uint256 balanceBefore = IERC20(token).balanceOf(user);\n\
                     \n\
                     // Execute fill\n\
                     _transferOutputs(order.minReceived, user);\n\
                     \n\
                     // Validate state after\n\
                     uint256 balanceAfter = IERC20(token).balanceOf(user);\n\
                     require(\n\
                         balanceAfter >= balanceBefore + order.minReceived[0].amount,\n\
                         \"State manipulation detected\"\n\
                     );\n\
                 }\n\
                 \n\
                 This prevents attackers from manipulating state between validation and execution."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for MEV protection mechanisms
    fn check_mev_protection(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only provide recommendation if contract has fill functions
        let has_fill_funcs = ctx.get_functions().iter().any(|f| is_fill_function(f));

        if !has_fill_funcs {
            return findings;
        }

        // Check for MEV protection
        if !has_mev_protection(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "No MEV protection detected - orders visible in mempool can be front-run"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Consider implementing MEV protection:\n\
                 \n\
                 Option 1: Commit-Reveal Scheme\n\
                 \n\
                 mapping(bytes32 => uint256) public commitments;\n\
                 \n\
                 function commitFill(bytes32 commitment) external {\n\
                     commitments[commitment] = block.timestamp;\n\
                 }\n\
                 \n\
                 function revealAndFill(\n\
                     bytes32 orderId,\n\
                     bytes calldata data,\n\
                     bytes32 salt\n\
                 ) external {\n\
                     bytes32 commitment = keccak256(abi.encode(orderId, data, salt));\n\
                     require(commitments[commitment] != 0, \"Not committed\");\n\
                     require(\n\
                         block.timestamp >= commitments[commitment] + 2,\n\
                         \"Commit period not elapsed\"\n\
                     );\n\
                     // Execute fill...\n\
                 }\n\
                 \n\
                 Option 2: Private Mempool (Flashbots)\n\
                 - Integrate with Flashbots Protect or similar service\n\
                 - Orders submitted through private mempool\n\
                 \n\
                 This prevents front-runners from seeing order details before execution."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for TOCTOU (Time-of-Check Time-of-Use) vulnerabilities
    fn check_toctou_vulnerabilities(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check fill functions
        if !is_fill_function(function) {
            return findings;
        }

        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return findings;
        }

        let func_source = &source[func_start..func_end.min(source.len())];
        let func_lower = func_source.to_lowercase();

        // Look for validation followed by execution with potential state changes between
        // This is a simplified heuristic - may need refinement
        let has_early_validation = func_lower.contains("require") || func_lower.contains("if");
        let has_later_transfer = func_lower.contains("transfer") || func_lower.contains("call");

        // Check if validation and execution are far apart (potential TOCTOU)
        if has_early_validation && has_later_transfer {
            // Calculate rough distance between validation and transfer
            if let Some(require_pos) = func_lower.find("require") {
                if let Some(transfer_pos) = func_lower.find("transfer") {
                    let distance = transfer_pos.saturating_sub(require_pos);

                    // If more than 200 chars between validation and transfer, flag it
                    if distance > 200 {
                        let finding = self.base.create_finding_with_severity(
                            ctx,
                            format!(
                                "Potential TOCTOU vulnerability in '{}' - state can change between validation and execution",
                                function.name.name
                            ),
                            function.name.location.start().line() as u32,
                            0,
                            20,
                            Severity::Low,
                        )
                        .with_fix_suggestion(
                            "Minimize gap between validation and execution:\n\
                             1. Validate state immediately before critical operations\n\
                             2. Use reentrancy guards to prevent state changes mid-execution\n\
                             3. Perform validation and execution atomically\n\
                             \n\
                             Example:\n\
                             function fill(...) external nonReentrant {\n\
                                 // Validate immediately before execution\n\
                                 require(block.timestamp <= order.fillDeadline, \"Expired\");\n\
                                 require(!filledOrders[orderId], \"Already filled\");\n\
                                 \n\
                                 // Update state BEFORE external calls\n\
                                 filledOrders[orderId] = true;\n\
                                 \n\
                                 // Execute transfer\n\
                                 _transferOutputs(order.minReceived, order.user);\n\
                             }".to_string()
                        );

                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }
}

impl Default for IntentSolverManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IntentSolverManipulationDetector {
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


        // Only run on intent contracts
        if !is_intent_contract(ctx) {
            return Ok(findings);
        }

        // Only check destination settlers (where solvers fill orders)
        if !is_destination_settler(ctx) {
            return Ok(findings);
        }

        // Check each function for solver manipulation vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_solver_authentication(function, ctx));
            findings.extend(self.check_reentrancy_protection(function, ctx));
            findings.extend(self.check_state_validation(function, ctx));
            findings.extend(self.check_toctou_vulnerabilities(function, ctx));
        }

        // Check contract-level MEV protection
        findings.extend(self.check_mev_protection(ctx));

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
    // 1. Missing solver authentication
    // 2. Missing reentrancy protection
    // 3. No state validation
    // 4. No MEV protection
    // 5. No false positives on secure contracts with proper protections
}
