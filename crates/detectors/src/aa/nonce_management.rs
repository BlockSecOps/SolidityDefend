//! AA Nonce Management Detector
//!
//! Detects improper nonce management in ERC-4337 accounts:
//! 1. Always uses nonce key 0 (no parallel operation support)
//! 2. Manual nonce tracking (not using EntryPoint)
//! 3. Non-sequential nonce validation
//! 4. Session keys share nonce space (collision risk)
//!
//! Severity: HIGH
//! Category: Account Abstraction

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AANonceManagementDetector {
    base: BaseDetector,
}

impl AANonceManagementDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-nonce-management".to_string()),
                "AA Nonce Management Vulnerabilities".to_string(),
                "Detects improper nonce management causing parallel operation failures and transaction collisions".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }
}

impl Default for AANonceManagementDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AANonceManagementDetector {
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

        // Only run on AA accounts
        if !is_aa_account(ctx) {
            return Ok(findings);
        }

        // Find validateUserOp function
        for function in ctx.get_functions() {
            if function.name.name == "validateUserOp" {
                let line = function.name.location.start().line() as u32;

                // Check 1: Fixed nonce key (no parallel support)
                if uses_fixed_nonce_key(function, ctx) {
                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            "Always uses nonce key 0 - no parallel operation support".to_string(),
                            line,
                            0,
                            20,
                            Severity::Medium,
                        )
                        .with_fix_suggestion(
                            "Support dynamic nonce keys for parallel operations:\n\
                         \n\
                         function validateUserOp(...) external {\n\
                             // Extract nonce key from userOp.nonce\n\
                             uint192 key = uint192(userOp.nonce >> 64);\n\
                             \n\
                             // Use key-specific nonce validation\n\
                             uint256 expectedNonce = entryPoint.getNonce(address(this), key);\n\
                             require(userOp.nonce == expectedNonce, \"Invalid nonce\");\n\
                         }\n\
                         \n\
                         This allows parallel UserOps with different nonce keys."
                                .to_string(),
                        );

                    findings.push(finding);
                }

                // Check 2: Manual nonce tracking
                if !uses_entrypoint_nonce(function, ctx) {
                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            "Manual nonce tracking - not using EntryPoint enforcement".to_string(),
                            line,
                            0,
                            20,
                            Severity::High,
                        )
                        .with_fix_suggestion(
                            "Use EntryPoint's nonce validation (ERC-4337 spec):\n\
                         \n\
                         IEntryPoint public immutable entryPoint;\n\
                         \n\
                         function validateUserOp(...) external {\n\
                             uint192 key = uint192(userOp.nonce >> 64);\n\
                             \n\
                             // ✅ Use EntryPoint's getNonce (enforces sequential nonces)\n\
                             uint256 expectedNonce = entryPoint.getNonce(address(this), key);\n\
                             require(userOp.nonce == expectedNonce, \"Invalid nonce\");\n\
                             \n\
                             // EntryPoint automatically increments nonce\n\
                         }\n\
                         \n\
                         Benefits:\n\
                         - Sequential nonce enforcement\n\
                         - Unique userOpHash guarantee\n\
                         - Standard compliant"
                                .to_string(),
                        );

                    findings.push(finding);
                }
            }
        }

        // Check 3: Session key nonce isolation
        if has_session_keys(ctx) && !has_session_key_nonce_isolation(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Session keys share nonce space - parallel operations will collide".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "Assign unique nonce key per session key:\n\
                 \n\
                 mapping(address => uint192) public sessionNonceKeys;\n\
                 uint192 private _nextNonceKey;\n\
                 \n\
                 function createSessionKey(address key) external onlyOwner {\n\
                     _nextNonceKey++;\n\
                     sessionNonceKeys[key] = _nextNonceKey;\n\
                     \n\
                     emit SessionKeyCreated(key, _nextNonceKey);\n\
                 }\n\
                 \n\
                 function validateUserOp(...) external {\n\
                     uint192 key = uint192(userOp.nonce >> 64);\n\
                     address signer = validateSignature(userOp);\n\
                     \n\
                     // Verify signer authorized for this nonce key\n\
                     require(\n\
                         key == 0 || sessionNonceKeys[signer] == key,\n\
                         \"Unauthorized nonce key\"\n\
                     );\n\
                 }\n\
                 \n\
                 This prevents nonce collisions between owner and session keys."
                        .to_string(),
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
