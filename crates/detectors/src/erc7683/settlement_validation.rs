// ERC-7683 Intent Settlement Validation Detector
//
// Detects missing or improper validation in ERC-7683 settlement contracts.
// Since the standard explicitly delegates settlement security to implementers,
// this detector ensures critical validations are present: deadline enforcement,
// output amount verification, and fill instruction validation.
//
// Severity: High
// Category: Security, CrossChain
//
// Vulnerabilities Detected:
// 1. Missing fillDeadline validation (expired orders can be filled)
// 2. Missing openDeadline validation (stale orders can be opened)
// 3. minReceived not validated (user receives less than specified)
// 4. maxSpent not validated (user pays more than specified)
// 5. Fill instructions not validated or processed
// 6. Double-fill not prevented (order filled multiple times)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::erc7683::classification::*;
use ast;

pub struct IntentSettlementValidationDetector {
    base: BaseDetector,
}

impl IntentSettlementValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("intent-settlement-validation".to_string()),
                "Intent Settlement Validation".to_string(),
                "Detects missing validation in ERC-7683 settlement contracts (deadlines, outputs, fill instructions)".to_string()
                    .to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    /// Checks deadline validation in settlement functions
    fn check_deadline_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Check fill functions for fillDeadline
        if is_fill_function(function) {
            if !has_deadline_validation(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!(
                        "Missing fillDeadline validation in '{}' - expired orders can be filled",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Critical,
                )
                .with_fix_suggestion(
                    "Add fillDeadline validation:\n\
                     \n\
                     function fill(\n\
                         bytes32 orderId,\n\
                         bytes calldata originData,\n\
                         bytes calldata fillerData\n\
                     ) external {\n\
                         ResolvedCrossChainOrder memory order = abi.decode(\n\
                             originData,\n\
                             (ResolvedCrossChainOrder)\n\
                         );\n\
                         \n\
                         // Validate fillDeadline\n\
                         require(\n\
                             block.timestamp <= order.fillDeadline,\n\
                             \"Order expired\"\n\
                         );\n\
                         \n\
                         // ... rest of fill logic\n\
                     }\n\
                     \n\
                     This prevents solvers from filling orders after they've expired.".to_string()
                );

                findings.push(finding);
            }
        }

        // Check open/openFor functions for openDeadline
        if func_name_lower.contains("open") && !func_name_lower.contains("opened") {
            if !has_deadline_validation(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!(
                        "Missing openDeadline validation in '{}' - stale orders can be opened",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Add openDeadline validation:\n\
                     \n\
                     function openFor(\n\
                         GaslessCrossChainOrder calldata order,\n\
                         bytes calldata signature,\n\
                         bytes calldata originFillerData\n\
                     ) external {\n\
                         // Validate openDeadline\n\
                         require(\n\
                             block.timestamp <= order.openDeadline,\n\
                             \"Open deadline passed\"\n\
                         );\n\
                         \n\
                         // ... rest of open logic\n\
                     }\n\
                     \n\
                     This prevents opening orders after the user's intended deadline.".to_string()
                );

                findings.push(finding);
            }
        }

        findings
    }

    /// Checks output amount validation (minReceived)
    fn check_output_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check fill functions (destination settlers)
        if !is_fill_function(function) {
            return findings;
        }

        if !has_output_validation(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Missing minReceived validation in '{}' - user may receive less than specified",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Validate output amounts match minReceived:\n\
                 \n\
                 function fill(...) external {\n\
                     ResolvedCrossChainOrder memory order = abi.decode(...);\n\
                     \n\
                     // Process fill instructions\n\
                     for (uint256 i = 0; i < order.fillInstructions.length; i++) {\n\
                         FillInstruction memory instruction = order.fillInstructions[i];\n\
                         \n\
                         if (instruction.destinationChainId == block.chainid) {\n\
                             // Validate each output\n\
                             for (uint256 j = 0; j < instruction.outputs.length; j++) {\n\
                                 Output memory output = instruction.outputs[j];\n\
                                 Output memory minOutput = order.minReceived[j];\n\
                                 \n\
                                 // CRITICAL: Validate amount meets minimum\n\
                                 require(\n\
                                     output.amount >= minOutput.amount,\n\
                                     \"Output below minimum\"\n\
                                 );\n\
                                 \n\
                                 // Transfer tokens\n\
                                 _transfer(output.token, output.recipient, output.amount);\n\
                             }\n\
                         }\n\
                     }\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks input amount validation (maxSpent)
    fn check_input_validation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check open functions (origin settlers)
        let func_name_lower = function.name.name.to_lowercase();
        if !func_name_lower.contains("open") || func_name_lower.contains("opened") {
            return findings;
        }

        if !has_max_spent_validation(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Missing maxSpent validation in '{}' - user may pay more than specified",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Validate input amounts don't exceed maxSpent:\n\
                 \n\
                 function openFor(...) external {\n\
                     ResolvedCrossChainOrder memory resolved = resolveFor(order, originFillerData);\n\
                     \n\
                     // Validate and transfer maxSpent from user\n\
                     for (uint256 i = 0; i < resolved.maxSpent.length; i++) {\n\
                         Output memory spent = resolved.maxSpent[i];\n\
                         \n\
                         // Validate chain\n\
                         require(\n\
                             spent.chainId == block.chainid,\n\
                             \"Invalid spent chain\"\n\
                         );\n\
                         \n\
                         // Transfer from user (will fail if amount > maxSpent)\n\
                         IERC20(spent.token).safeTransferFrom(\n\
                             order.user,\n\
                             address(this),\n\
                             spent.amount  // Must be <= maxSpent\n\
                         );\n\
                     }\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for double-fill prevention
    fn check_double_fill_prevention(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check fill and open functions
        if !is_fill_function(function) && !function.name.name.to_lowercase().contains("open") {
            return findings;
        }

        if !has_double_fill_prevention(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Missing double-fill prevention in '{}' - order can be executed multiple times",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Implement double-fill prevention:\n\
                 \n\
                 mapping(bytes32 => bool) public filledOrders;\n\
                 \n\
                 function fill(bytes32 orderId, ...) external {\n\
                     // Check not already filled\n\
                     require(!filledOrders[orderId], \"Order already filled\");\n\
                     \n\
                     // Mark as filled BEFORE external calls\n\
                     filledOrders[orderId] = true;\n\
                     \n\
                     // Execute fill\n\
                     _transferOutputs(...);\n\
                 }\n\
                 \n\
                 IMPORTANT: Mark as filled BEFORE external calls to prevent reentrancy.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for fill instruction validation
    fn check_fill_instruction_validation(
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

        // Check if fill instructions are processed
        let processes_instructions = func_lower.contains("fillinstruction")
            || func_lower.contains("fill_instruction");

        // Check if destination chain is validated
        let validates_chain = func_lower.contains("destinationchainid")
            || func_lower.contains("destination_chain_id")
            || func_lower.contains("chainid") && func_lower.contains("block.chainid");

        if !processes_instructions {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Fill instructions not processed in '{}' - may execute on wrong chain",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Process fill instructions and validate destination chain:\n\
                 \n\
                 function fill(...) external {\n\
                     ResolvedCrossChainOrder memory order = abi.decode(...);\n\
                     \n\
                     bool foundInstruction = false;\n\
                     \n\
                     // Find and process instruction for this chain\n\
                     for (uint256 i = 0; i < order.fillInstructions.length; i++) {\n\
                         FillInstruction memory instruction = order.fillInstructions[i];\n\
                         \n\
                         // Validate this instruction is for current chain\n\
                         if (instruction.destinationChainId == uint64(block.chainid)) {\n\
                             foundInstruction = true;\n\
                             \n\
                             // Process outputs for this chain\n\
                             for (uint256 j = 0; j < instruction.outputs.length; j++) {\n\
                                 // ... process output\n\
                             }\n\
                         }\n\
                     }\n\
                     \n\
                     require(foundInstruction, \"No instruction for this chain\");\n\
                 }".to_string()
            );

            findings.push(finding);
        } else if !validates_chain {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Fill instruction destination chain not validated in '{}'",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Validate fill instruction is for current chain:\n\
                 \n\
                 if (instruction.destinationChainId == uint64(block.chainid)) {\n\
                     // Only process instructions for this chain\n\
                     _processFill(instruction);\n\
                 }".to_string());

            findings.push(finding);
        }

        findings
    }

    /// Checks for proper order ID generation and usage
    fn check_order_id_handling(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let source_lower = ctx.source_code.to_lowercase();

        // Check if contract uses order IDs
        let uses_order_ids = source_lower.contains("orderid")
            || source_lower.contains("order_id");

        if !uses_order_ids && is_destination_settler(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No order ID tracking - cannot prevent double-fills or track order status".to_string(),
                1,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Use order IDs for tracking:\n\
                 \n\
                 // Generate consistent order ID\n\
                 bytes32 orderId = keccak256(abi.encode(\n\
                     order.user,\n\
                     order.originChainId,\n\
                     order.nonce,\n\
                     order.maxSpent,\n\
                     order.minReceived\n\
                 ));\n\
                 \n\
                 // Track filled orders\n\
                 mapping(bytes32 => bool) public filledOrders;\n\
                 \n\
                 function fill(bytes32 orderId, ...) external {\n\
                     require(!filledOrders[orderId], \"Already filled\");\n\
                     filledOrders[orderId] = true;\n\
                     // ...\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for IntentSettlementValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IntentSettlementValidationDetector {
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

        // Only run on intent contracts
        if !is_intent_contract(ctx) {
            return Ok(findings);
        }

        // Check each settlement function for proper validation
        for function in ctx.get_functions() {
            findings.extend(self.check_deadline_validation(function, ctx));
            findings.extend(self.check_output_validation(function, ctx));
            findings.extend(self.check_input_validation(function, ctx));
            findings.extend(self.check_double_fill_prevention(function, ctx));
            findings.extend(self.check_fill_instruction_validation(function, ctx));
        }

        // Check contract-level order ID handling
        findings.extend(self.check_order_id_handling(ctx));

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
    // 1. Missing fillDeadline validation
    // 2. Missing openDeadline validation
    // 3. Missing minReceived validation
    // 4. Missing maxSpent validation
    // 5. No double-fill prevention
    // 6. Fill instructions not validated
    // 7. No false positives on secure contracts
}
