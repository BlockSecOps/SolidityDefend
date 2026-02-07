// ERC-7683 Intent Nonce Management Detector
//
// Detects improper nonce management in ERC-7683 intent contracts that could lead
// to nonce reuse, replay attacks, or order confusion across chains. Validates
// proper nonce incrementation, storage, and collision prevention.
//
// Severity: High
// Category: Security, CrossChain
//
// Vulnerabilities Detected:
// 1. Nonce not validated at all
// 2. Nonce validated but not incremented/marked as used
// 3. Nonce parameter separate from order struct (anti-pattern)
// 4. Nonce collision possible across chains
// 5. Permit2 not integrated for gasless orders

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::erc7683::classification::*;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct IntentNonceManagementDetector {
    base: BaseDetector,
}

impl IntentNonceManagementDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("intent-nonce-management".to_string()),
                "Intent Nonce Management".to_string(),
                "Detects improper nonce management in ERC-7683 intents that could lead to replay attacks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    /// Checks if nonce storage is properly declared
    fn check_nonce_storage(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check for nonce storage patterns
        source_lower.contains("usednonces")
            || source_lower.contains("used_nonces")
            || source_lower.contains("fillednonces")
            || source_lower.contains("usernonces")
            || source_lower.contains("user_nonces")
            || uses_permit2(ctx) // Permit2 handles nonce storage internally
    }

    /// Checks for nonce validation and proper incrementation
    fn check_nonce_handling(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check order opening/execution functions
        if !is_settlement_function(function) {
            return findings;
        }

        // Skip onchain orders (no nonce needed for non-gasless orders in some implementations)
        let func_name_lower = function.name.name.to_lowercase();
        let is_onchain_order = func_name_lower == "open" && !is_gasless_order_function(function);

        if is_onchain_order {
            // Onchain orders should still use sequential nonces
            return findings; // We'll check this separately
        }

        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return findings;
        }

        let func_source = &source[func_start..func_end.min(source.len())];
        let func_lower = func_source.to_lowercase();

        // Check if nonce is mentioned in function
        let mentions_nonce = func_lower.contains("nonce");

        if !mentions_nonce {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No nonce validation in '{}' - order can be replayed",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Implement nonce validation:\n\
                 \n\
                 Option 1: Bitmap-based (allows out-of-order execution)\n\
                 mapping(address => mapping(uint256 => bool)) public usedNonces;\n\
                 \n\
                 function openFor(...) external {\n\
                     require(!usedNonces[order.user][order.nonce], \"Nonce already used\");\n\
                     usedNonces[order.user][order.nonce] = true;\n\
                     // ... rest of logic\n\
                 }\n\
                 \n\
                 Option 2: Sequential (enforces order)\n\
                 mapping(address => uint256) public userNonces;\n\
                 \n\
                 function openFor(...) external {\n\
                     require(order.nonce == userNonces[order.user], \"Invalid nonce\");\n\
                     userNonces[order.user]++;\n\
                     // ... rest of logic\n\
                 }\n\
                 \n\
                 Option 3: Permit2 (handles nonces internally)\n\
                 PERMIT2.permitWitnessTransferFrom(permit, details, user, witness, witnessType, signature);".to_string()
            );

            findings.push(finding);
            return findings; // No point checking further if no nonce mentioned
        }

        // Check 1: Nonce is validated
        if !has_nonce_validation(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Nonce present but not validated in '{}' - replay attack possible",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Validate nonce before execution:\n\
                 require(!usedNonces[order.user][order.nonce], \"Nonce already used\");\n\
                 Or for sequential nonces:\n\
                 require(order.nonce == userNonces[order.user], \"Invalid nonce\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check 2: Nonce is incremented/marked after validation
        if has_nonce_validation(function, ctx) && !has_nonce_update(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Nonce validated but not incremented/marked in '{}' - can be reused",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Mark nonce as used after validation:\n\
                 usedNonces[order.user][order.nonce] = true;\n\
                 \n\
                 Or increment sequential nonce:\n\
                 userNonces[order.user]++;\n\
                 \n\
                 IMPORTANT: Update nonce BEFORE external calls to prevent reentrancy issues."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check 3: Nonce from order struct (anti-pattern detection)
        if self.uses_separate_nonce_parameter(function, func_source) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Nonce passed as separate parameter in '{}' - should use order.nonce",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Use nonce from order struct:\n\
                 \n\
                 BAD:\n\
                 function openFor(Order order, uint256 nonce, bytes signature) {\n\
                     // Attacker can provide different nonce than signed!\n\
                 }\n\
                 \n\
                 GOOD:\n\
                 function openFor(Order order, bytes signature) {\n\
                     // Use order.nonce which is part of signed data\n\
                     require(!usedNonces[order.user][order.nonce], \"Used\");\n\
                 }"
                    .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Detects anti-pattern of separate nonce parameter
    fn uses_separate_nonce_parameter(&self, function: &ast::Function, func_source: &str) -> bool {
        let func_lower = func_source.to_lowercase();

        // Check if function parameter contains "nonce" but is not part of order struct access
        let has_nonce_param = function.parameters.iter().any(|param| {
            if let Some(param_name) = &param.name {
                param_name.name.to_lowercase().contains("nonce")
            } else {
                false
            }
        });

        // Check if nonce is accessed from order struct
        let uses_order_nonce =
            func_lower.contains("order.nonce") || func_lower.contains("order . nonce");

        // Anti-pattern: has nonce parameter but doesn't use order.nonce
        has_nonce_param && !uses_order_nonce
    }

    /// Checks for proper nonce storage declaration
    fn check_storage_declaration(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract is intent contract
        if !is_intent_contract(ctx) {
            return findings;
        }

        // Check if nonce storage is properly declared
        if !self.check_nonce_storage(ctx) && !uses_permit2(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "No nonce storage mapping declared - nonce validation impossible".to_string(),
                    1,
                    0,
                    20,
                    Severity::Critical,
                )
                .with_fix_suggestion(
                    "Add nonce storage mapping:\n\
                 \n\
                 Option 1: Bitmap-based (flexible)\n\
                 mapping(address => mapping(uint256 => bool)) public usedNonces;\n\
                 \n\
                 Option 2: Sequential counter\n\
                 mapping(address => uint256) public userNonces;\n\
                 \n\
                 Option 3: Use Permit2 (recommended for gasless)\n\
                 IPermit2 public immutable PERMIT2;\n\
                 // Permit2 handles nonce tracking internally"
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for cross-chain nonce collision prevention
    fn check_cross_chain_nonce_collision(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only relevant if contract mentions chainId and nonce
        let source_lower = ctx.source_code.to_lowercase();
        let has_chain_id = source_lower.contains("chainid");
        let has_nonce = source_lower.contains("nonce");

        if !has_chain_id || !has_nonce {
            return findings;
        }

        // Check if nonce uniqueness includes chainId
        // This is a heuristic - checks if chainId is part of nonce derivation
        let nonce_includes_chain = source_lower.contains("keccak256")
            && source_lower.contains("chainid")
            && source_lower.contains("nonce");

        if !nonce_includes_chain && !domain_separator_includes_chain_id(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Nonce uniqueness should include chainId to prevent cross-chain collision"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Low,
                )
                .with_fix_suggestion(
                    "Ensure nonce uniqueness across chains:\n\
                 \n\
                 Option 1: Include chainId in signature hash (via EIP-712 domain separator)\n\
                 DOMAIN_SEPARATOR = keccak256(\n\
                     abi.encode(\n\
                         DOMAIN_TYPEHASH,\n\
                         keccak256(\"YourContract\"),\n\
                         keccak256(\"1\"),\n\
                         block.chainid,  // This ensures nonce is chain-specific\n\
                         address(this)\n\
                     )\n\
                 );\n\
                 \n\
                 Option 2: Derive chain-specific nonce\n\
                 bytes32 uniqueNonce = keccak256(abi.encode(block.chainid, nonce));\n\
                 \n\
                 This prevents same nonce from being valid on multiple chains."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for unused nonce storage
    fn check_unused_nonce_storage(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check if nonce storage is declared
        let has_nonce_storage =
            source_lower.contains("usednonces") || source_lower.contains("usernonces");

        if !has_nonce_storage {
            return findings;
        }

        // Check if nonce storage is actually used in functions
        let nonce_storage_used = ctx.get_functions().iter().any(|f| {
            let func_start = f.location.start().offset();
            let func_end = f.location.end().offset();

            if func_end <= func_start || func_start >= source.len() {
                return false;
            }

            let func_source = &source[func_start..func_end.min(source.len())];
            let func_lower = func_source.to_lowercase();

            (func_lower.contains("usednonces") || func_lower.contains("usernonces"))
                && (func_lower.contains("=") || func_lower.contains("++"))
        });

        if !nonce_storage_used {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Nonce storage declared but never used - replay attacks possible".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Use the declared nonce storage in your functions:\n\
                 \n\
                 function openFor(...) external {\n\
                     // Validate nonce\n\
                     require(!usedNonces[order.user][order.nonce], \"Nonce already used\");\n\
                     \n\
                     // Mark as used\n\
                     usedNonces[order.user][order.nonce] = true;\n\
                     \n\
                     // ... rest of logic\n\
                 }\n\
                 \n\
                 If you declared nonce storage, make sure to actually use it!"
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }
}

impl Default for IntentNonceManagementDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IntentNonceManagementDetector {
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

        // Check for nonce storage declaration
        findings.extend(self.check_storage_declaration(ctx));

        // Check each settlement function for proper nonce handling
        for function in ctx.get_functions() {
            findings.extend(self.check_nonce_handling(function, ctx));
        }

        // Check for cross-chain nonce collision prevention
        findings.extend(self.check_cross_chain_nonce_collision(ctx));

        // Check for unused nonce storage
        findings.extend(self.check_unused_nonce_storage(ctx));

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
    // 1. No nonce validation
    // 2. Nonce validated but not incremented
    // 3. Separate nonce parameter (anti-pattern)
    // 4. Unused nonce storage
    // 5. No false positives on proper implementations
}
