//! Restaking Slashing Conditions Detector
//!
//! Detects missing slashing protection, improper penalty calculation, and compound slashing
//! risks in restaking protocols. EigenLayer's slashing mechanism launched April 2025 creates
//! new attack surface where validators can lose 100% of stake for ANY AVS violation.
//!
//! Severity: CRITICAL
//! Category: DeFi, Restaking
//!
//! Vulnerabilities Detected:
//! 1. No slashing policy validation (AVS can set 100% slashing)
//! 2. Missing evidence validation
//! 3. Compound slashing not prevented (multiple AVSs slash same stake)
//! 4. No slashing appeal period
//!
//! Real-World Context:
//! - EigenLayer slashing launched April 2025 - very new, high bug probability
//! - Validators can lose 100% of staked ETH if they breach any AVS rules
//! - Each AVS defines custom slashing policies

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::restaking::classification::*;
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct RestakingSlashingConditionsDetector {
    base: BaseDetector,
}

impl RestakingSlashingConditionsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("restaking-slashing-conditions".to_string()),
                "Restaking Slashing Conditions Bypass".to_string(),
                "Detects missing slashing protection, improper penalty calculation, and compound slashing risks".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Checks slashing functions for evidence validation
    fn check_evidence_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check slashing functions
        if !func_name_lower.contains("slash") && !func_name_lower.contains("penalize") {
            return findings;
        }

        // Check 1: Evidence parameter exists
        if !has_evidence_parameter(function) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No evidence parameter in slashing function '{}' - slashing can occur without proof",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Add evidence parameter to slashing function:\n\
                 \n\
                 function requestSlashing(\n\
                     address operator,\n\
                     uint256 amount,\n\
                     bytes calldata evidence  // Add evidence\n\
                 ) external onlyAVS returns (bytes32 requestId) {\n\
                     require(evidence.length > 0, \"Evidence required\");\n\
                     \n\
                     // Validate evidence format\n\
                     // Store for governance review\n\
                     \n\
                     requestId = keccak256(abi.encode(msg.sender, operator, amount, block.timestamp));\n\
                     slashingRequests[requestId] = SlashingRequest({\n\
                         operator: operator,\n\
                         amount: amount,\n\
                         evidence: evidence,\n\
                         timestamp: block.timestamp\n\
                     });\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        // Check 2: Evidence is validated
        if has_evidence_parameter(function) && !validates_evidence(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Evidence parameter present but not validated in '{}'",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Critical,
                )
                .with_fix_suggestion(
                    "Validate evidence before accepting slashing request:\n\
                 \n\
                 function requestSlashing(\n\
                     address operator,\n\
                     uint256 amount,\n\
                     bytes calldata evidence\n\
                 ) external onlyAVS {\n\
                     // Validate evidence exists\n\
                     require(evidence.length > 0, \"Evidence required\");\n\
                     \n\
                     // Validate evidence format (example)\n\
                     require(evidence.length >= 32, \"Evidence too short\");\n\
                     \n\
                     // Store evidence for dispute/governance review\n\
                     slashingEvidence[operator] = evidence;\n\
                     \n\
                     emit SlashingRequested(operator, amount, evidence);\n\
                 }"
                    .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for slashing delay/appeal period
    fn check_slashing_delay(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check slashing execution functions
        if !func_name_lower.contains("slash") && !func_name_lower.contains("penalize") {
            return findings;
        }

        // Skip request functions, check execution functions
        if func_name_lower.contains("request") {
            return findings;
        }

        // Check for delay enforcement
        if !has_slashing_delay(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No appeal period for slashing in '{}' - instant slashing without recourse",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Implement two-step slashing with delay:\n\
                 \n\
                 uint256 public constant SLASHING_DELAY = 7 days;\n\
                 \n\
                 struct SlashingRequest {\n\
                     address operator;\n\
                     uint256 amount;\n\
                     bytes evidence;\n\
                     uint256 timestamp;\n\
                     bool executed;\n\
                 }\n\
                 \n\
                 mapping(bytes32 => SlashingRequest) public slashingRequests;\n\
                 \n\
                 function requestSlashing(\n\
                     address operator,\n\
                     uint256 amount,\n\
                     bytes calldata evidence\n\
                 ) external onlyAVS returns (bytes32 requestId) {\n\
                     requestId = keccak256(abi.encode(msg.sender, operator, amount, block.timestamp));\n\
                     slashingRequests[requestId] = SlashingRequest({\n\
                         operator: operator,\n\
                         amount: amount,\n\
                         evidence: evidence,\n\
                         timestamp: block.timestamp,\n\
                         executed: false\n\
                     });\n\
                 }\n\
                 \n\
                 function executeSlashing(bytes32 requestId) external {\n\
                     SlashingRequest storage request = slashingRequests[requestId];\n\
                     require(!request.executed, \"Already executed\");\n\
                     require(\n\
                         block.timestamp >= request.timestamp + SLASHING_DELAY,\n\
                         \"Delay period not elapsed - operator can still appeal\"\n\
                     );\n\
                     \n\
                     stakes[request.operator] -= request.amount;\n\
                     request.executed = true;\n\
                 }\n\
                 \n\
                 function appealSlashing(bytes32 requestId, bytes calldata defense) external {\n\
                     SlashingRequest storage request = slashingRequests[requestId];\n\
                     require(msg.sender == request.operator, \"Not operator\");\n\
                     require(!request.executed, \"Already executed\");\n\
                     require(\n\
                         block.timestamp < request.timestamp + SLASHING_DELAY,\n\
                         \"Appeal period expired\"\n\
                     );\n\
                     \n\
                     emit SlashingAppealed(requestId, defense);\n\
                     // Governance reviews appeal\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for compound slashing prevention
    fn check_compound_slashing(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check slashing functions
        if !func_name_lower.contains("slash") {
            return findings;
        }

        // Check if compound slashing is prevented
        if !checks_already_slashed(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Compound slashing possible in '{}' - multiple AVSs can slash same stake (operator can lose >100%)",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Prevent compound slashing:\n\
                 \n\
                 mapping(address => uint256) public totalSlashed;\n\
                 \n\
                 function executeSlashing(bytes32 requestId) external {\n\
                     SlashingRequest storage request = slashingRequests[requestId];\n\
                     \n\
                     uint256 operatorStake = stakes[request.operator];\n\
                     \n\
                     // Prevent compound slashing\n\
                     require(\n\
                         totalSlashed[request.operator] + request.amount <= operatorStake,\n\
                         \"Compound slashing prevented - would exceed total stake\"\n\
                     );\n\
                     \n\
                     stakes[request.operator] -= request.amount;\n\
                     totalSlashed[request.operator] += request.amount;\n\
                     request.executed = true;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks AVS registration for maximum slashing policy
    fn check_max_slashing_policy(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check AVS registration and slashing policy functions
        if !func_name_lower.contains("registeravs")
            && !func_name_lower.contains("register")
            && !func_name_lower.contains("setslashing")
            && !func_name_lower.contains("slashingpolicy")
        {
            return findings;
        }

        // Check if function has slashing percentage parameter
        if !has_slashing_percentage_param(function) {
            return findings;
        }

        // Check for max percentage validation
        if !validates_max_slashing(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No maximum slashing percentage validation in '{}' - AVS can set 100% slashing",
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
                 uint256 public constant MAX_SLASH_PERCENTAGE = 10; // 10% max per incident\n\
                 \n\
                 function registerAVS(\n\
                     string calldata name,\n\
                     uint256 slashPercentage\n\
                 ) external payable {\n\
                     require(\n\
                         slashPercentage <= MAX_SLASH_PERCENTAGE,\n\
                         \"Slashing percentage exceeds maximum (10%)\"\n\
                     );\n\
                     \n\
                     avsSlashingPolicies[msg.sender] = slashPercentage;\n\
                     isAVS[msg.sender] = true;\n\
                 }\n\
                 \n\
                 function setSlashingPolicy(uint256 percentage) external onlyAVS {\n\
                     require(\n\
                         percentage <= MAX_SLASH_PERCENTAGE,\n\
                         \"Percentage too high\"\n\
                     );\n\
                     avsSlashingPolicies[msg.sender] = percentage;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for MAX_SLASH_PERCENTAGE constant
    fn check_max_slash_constant(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract has slashing functions
        let has_slashing = ctx
            .get_functions()
            .iter()
            .any(|f| f.name.name.to_lowercase().contains("slash"));

        if !has_slashing {
            return findings;
        }

        // Check for MAX_SLASH_PERCENTAGE constant
        if !has_max_slash_percentage_constant(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No MAX_SLASH_PERCENTAGE constant defined - should limit maximum slashing per incident".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Define maximum slashing percentage:\n\
                 \n\
                 // Limit slashing to 10% per incident (industry standard)\n\
                 uint256 public constant MAX_SLASH_PERCENTAGE = 10;\n\
                 \n\
                 // Or make it governance-controlled\n\
                 uint256 public maxSlashPercentage = 10;\n\
                 \n\
                 function setMaxSlashPercentage(uint256 newMax) external onlyGovernance {\n\
                     require(newMax <= 20, \"Cannot exceed 20%\");\n\
                     maxSlashPercentage = newMax;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for RestakingSlashingConditionsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RestakingSlashingConditionsDetector {
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

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong restaking protocol protections (return early)
        if vault_patterns::has_slashing_accounting_pattern(ctx) {
            // Comprehensive slashing accounting - prevents double slashing, validates evidence
            return Ok(findings);
        }

        if vault_patterns::has_eigenlayer_delegation_pattern(ctx) {
            // EigenLayer has battle-tested slashing mechanisms with appeals
            return Ok(findings);
        }

        // Check each function for slashing vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_evidence_validation(function, ctx));
            findings.extend(self.check_slashing_delay(function, ctx));
            findings.extend(self.check_compound_slashing(function, ctx));
            findings.extend(self.check_max_slashing_policy(function, ctx));
        }

        // Contract-level checks
        findings.extend(self.check_max_slash_constant(ctx));

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
    // 1. Missing evidence parameter
    // 2. Evidence not validated
    // 3. No slashing delay
    // 4. Compound slashing possible
    // 5. No max slashing percentage
    // 6. No false positives on secure implementations
}
