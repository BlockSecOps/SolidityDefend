// ERC-7683 Intent Signature Replay Detector
//
// Detects missing or improper validation of cross-chain signature replay protection
// in ERC-7683 intent contracts. Even though ERC-7683 includes a nonce field,
// contracts must validate both the chainId and nonce to prevent replay attacks
// across different chains.
//
// Severity: Critical
// Category: CrossChain, Security
//
// Vulnerabilities Detected:
// 1. Missing chainId validation (allows cross-chain replay)
// 2. Nonce not validated or tracked (allows same-chain replay)
// 3. EIP-712 domain separator missing chainId
// 4. Permit2 not integrated for gasless orders

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::erc7683::classification::*;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct IntentSignatureReplayDetector {
    base: BaseDetector,
}

impl IntentSignatureReplayDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("intent-signature-replay".to_string()),
                "Intent Signature Replay".to_string(),
                "Detects missing chainId and nonce validation enabling cross-chain replay attacks in ERC-7683 intents".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Analyzes signature verification for replay protection
    fn check_signature_verification(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check settlement functions that handle signed orders
        if !is_settlement_function(function) {
            return findings;
        }

        // Skip if it's an onchain order (no signature needed)
        let func_name_lower = function.name.name.to_lowercase();
        if func_name_lower == "open" && !is_gasless_order_function(function) {
            return findings;
        }

        // Check 1: ChainId validation
        if !has_chain_id_validation(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Missing chainId validation in '{}' - cross-chain replay attack possible",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Add chainId validation: require(order.originChainId == block.chainid, \"Invalid chain\");\n\
                 This prevents attackers from replaying the signature on different chains.".to_string()
            );

            findings.push(finding);
        }

        // Check 2: Nonce validation
        if !has_nonce_validation(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Missing nonce validation in '{}' - replay attack possible",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Add nonce validation and tracking:\n\
                 require(!usedNonces[order.user][order.nonce], \"Nonce already used\");\n\
                 usedNonces[order.user][order.nonce] = true;\n\
                 Or use Permit2 which handles nonces internally."
                        .to_string(),
                );

            findings.push(finding);
        } else {
            // Check 2b: Nonce validated but not updated
            if !has_nonce_update(function, ctx) {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!(
                        "Nonce validated but not incremented/marked in '{}' - replay still possible",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "After validating nonce, mark it as used:\n\
                     usedNonces[order.user][order.nonce] = true;\n\
                     Or increment sequential nonce:\n\
                     userNonces[order.user]++;".to_string());

                findings.push(finding);
            }
        }

        findings
    }

    /// Checks EIP-712 domain separator for chainId inclusion
    fn check_domain_separator(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract uses EIP-712
        if !has_eip712_domain_separator(ctx) {
            return findings;
        }

        // Check if domain separator includes chainId
        if !domain_separator_includes_chain_id(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "EIP-712 domain separator should include chainId for replay protection".to_string(),
                1, // Domain separator usually defined early
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Include chainId in EIP-712 domain separator:\n\
                 DOMAIN_SEPARATOR = keccak256(\n\
                     abi.encode(\n\
                         keccak256(\"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)\"),\n\
                         keccak256(\"YourContract\"),\n\
                         keccak256(\"1\"),\n\
                         block.chainid,  // Include this!\n\
                         address(this)\n\
                     )\n\
                 );".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for Permit2 integration in gasless order functions
    fn check_permit2_integration(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if contract has gasless functions but doesn't use Permit2
        let has_gasless_funcs = ctx
            .get_functions()
            .iter()
            .any(|f| is_gasless_order_function(f));

        if has_gasless_funcs && !uses_permit2(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Consider using Permit2 for gasless orders - provides transparent nonce management".to_string(),
                1,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Integrate Permit2 for nonce management:\n\
                 IPermit2 public immutable PERMIT2;\n\
                 \n\
                 PERMIT2.permitWitnessTransferFrom(\n\
                     permit,\n\
                     transferDetails,\n\
                     order.user,\n\
                     orderHash,\n\
                     WITNESS_TYPE_STRING,\n\
                     signature\n\
                 );\n\
                 \n\
                 Permit2 handles signature validation and nonce tracking automatically.".to_string());

            findings.push(finding);
        }

        findings
    }
}

impl Default for IntentSignatureReplayDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IntentSignatureReplayDetector {
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

        // Check each settlement function for signature replay vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_signature_verification(function, ctx));
        }

        // Check EIP-712 domain separator
        findings.extend(self.check_domain_separator(ctx));

        // Check Permit2 integration
        findings.extend(self.check_permit2_integration(ctx));

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
    // 1. Missing chainId validation
    // 2. Missing nonce validation
    // 3. Nonce validated but not incremented
    // 4. EIP-712 domain separator without chainId
    // 5. No false positives on secure contracts
}
