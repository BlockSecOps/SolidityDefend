//! ERC-4337 Paymaster Abuse Detector
//!
//! Detects vulnerabilities in ERC-4337 paymaster implementations that allow:
//! 1. Replay attacks via nonce bypass (Biconomy exploit)
//! 2. Gas estimation manipulation (~0.05 ETH per exploit)
//! 3. Arbitrary transaction sponsorship
//! 4. Missing spending limits (sponsor fund draining)
//! 5. No chain ID binding (cross-chain replay)
//!
//! Severity: CRITICAL
//! Category: DeFi, Account Abstraction
//!
//! Real-World Exploit:
//! - Biconomy Nonce Bypass (2024): Attacker upgraded accounts to bypass nonce verification,
//!   drained paymaster funds via signature replay
//! - Alchemy Audit (2025): Compromised signer API can withdraw full approval

use anyhow::Result;
use std::any::Any;

use crate::aa::classification::*;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC4337PaymasterAbuseDetector {
    base: BaseDetector,
}

impl ERC4337PaymasterAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc4337-paymaster-abuse".to_string()),
                "ERC-4337 Paymaster Abuse".to_string(),
                "Detects vulnerabilities in paymaster implementations allowing replay attacks, gas griefing, and sponsor fund draining".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }
}

impl Default for ERC4337PaymasterAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC4337PaymasterAbuseDetector {
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

        // Only run on paymaster contracts
        if !is_paymaster_contract(ctx) {
            return Ok(findings);
        }

        // Find validatePaymasterUserOp function
        for function in ctx.get_functions() {
            if function.name.name == "validatePaymasterUserOp" {
                let line = function.name.location.start().line() as u32;

                // Check 1: Replay protection
                if !has_replay_protection(function, ctx) {
                    let finding = self.base.create_finding_with_severity(
                        ctx,
                        "No replay protection in paymaster - vulnerable to nonce bypass (Biconomy exploit)".to_string(),
                        line,
                        0,
                        20,
                        Severity::Critical,
                    )
                    .with_fix_suggestion(
                        "Add hash tracking to prevent replay attacks:\n\
                         \n\
                         mapping(bytes32 => bool) public usedHashes;\n\
                         \n\
                         function validatePaymasterUserOp(...) external {\n\
                             require(!usedHashes[userOpHash], \"Already executed\");\n\
                             usedHashes[userOpHash] = true;\n\
                             \n\
                             // ... signature validation\n\
                         }\n\
                         \n\
                         This prevents attacker from reusing same signature repeatedly.\n\
                         \n\
                         Reference: Biconomy nonce bypass (2024) - attacker drained paymaster via replay".to_string()
                    );

                    findings.push(finding);
                }

                // Check 2: Spending limits
                if !has_spending_limits(function, ctx) {
                    let finding = self.base.create_finding_with_severity(
                        ctx,
                        "No spending limits - sponsor funds can be drained".to_string(),
                        line,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion(
                        "Implement per-account spending limits:\n\
                         \n\
                         mapping(address => uint256) public accountSpent;\n\
                         uint256 public constant MAX_PER_ACCOUNT = 0.1 ether;\n\
                         \n\
                         function validatePaymasterUserOp(..., uint256 maxCost) external {\n\
                             require(\n\
                                 accountSpent[userOp.sender] + maxCost <= MAX_PER_ACCOUNT,\n\
                                 \"Account limit exceeded\"\n\
                             );\n\
                             \n\
                             accountSpent[userOp.sender] += maxCost;\n\
                             // ... validation logic\n\
                         }\n\
                         \n\
                         function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external {\n\
                             // Refund unused gas\n\
                             (address sender, uint256 maxCost) = abi.decode(context, (address, uint256));\n\
                             accountSpent[sender] -= (maxCost - actualGasCost);\n\
                         }".to_string()
                    );

                    findings.push(finding);
                }

                // Check 3: Target validation
                if !has_target_validation(function, ctx) {
                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            "No target whitelist - arbitrary transactions can be sponsored"
                                .to_string(),
                            line,
                            0,
                            20,
                            Severity::High,
                        )
                        .with_fix_suggestion(
                            "Add target contract whitelist:\n\
                         \n\
                         mapping(address => bool) public allowedTargets;\n\
                         \n\
                         function validatePaymasterUserOp(...) external {\n\
                             // Extract target from callData\n\
                             address target = address(bytes20(userOp.callData[16:36]));\n\
                             \n\
                             require(allowedTargets[target], \"Target not allowed\");\n\
                             \n\
                             // ... rest of validation\n\
                         }\n\
                         \n\
                         function addAllowedTarget(address target) external onlyOwner {\n\
                             allowedTargets[target] = true;\n\
                         }"
                            .to_string(),
                        );

                    findings.push(finding);
                }

                // Check 4: Gas limits
                if !has_gas_limits(function, ctx) {
                    let finding = self.base.create_finding_with_severity(
                        ctx,
                        "No gas limits - vulnerable to gas griefing (~0.05 ETH per exploit)".to_string(),
                        line,
                        0,
                        20,
                        Severity::Medium,
                    )
                    .with_fix_suggestion(
                        "Enforce maximum gas per operation:\n\
                         \n\
                         uint256 public constant MAX_GAS_PER_OP = 500_000;\n\
                         \n\
                         function validatePaymasterUserOp(...) external {\n\
                             require(\n\
                                 userOp.callGasLimit + userOp.verificationGasLimit <= MAX_GAS_PER_OP,\n\
                                 \"Gas limit too high\"\n\
                             );\n\
                             \n\
                             // ... validation logic\n\
                         }\n\
                         \n\
                         This prevents attacker from specifying excessive gas to grief bundler.".to_string()
                    );

                    findings.push(finding);
                }

                // Check 5: Chain ID validation
                if !validates_chain_id(function, ctx) {
                    let finding = self.base.create_finding_with_severity(
                        ctx,
                        "Signature not bound to chain ID - cross-chain replay possible".to_string(),
                        line,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion(
                        "Include block.chainid in signature hash:\n\
                         \n\
                         function validatePaymasterUserOp(...) external {\n\
                             bytes32 hash = keccak256(abi.encode(\n\
                                 userOp.sender,\n\
                                 userOp.nonce,\n\
                                 userOp.callData,\n\
                                 block.chainid,        // ✅ Chain ID\n\
                                 address(this)         // ✅ Paymaster address\n\
                             ));\n\
                             \n\
                             address signer = hash.toEthSignedMessageHash().recover(userOp.signature);\n\
                             require(signer == owner, \"Invalid signature\");\n\
                         }\n\
                         \n\
                         This prevents signature replay across chains.".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

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
    // 1. No replay protection (CRITICAL)
    // 2. No spending limits (HIGH)
    // 3. No target validation (HIGH)
    // 4. No gas limits (MEDIUM)
    // 5. No chain ID (HIGH)
    // 6. No false positives on secure paymaster
}
