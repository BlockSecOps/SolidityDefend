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
        // FP Reduction: Consolidate all sub-check failures into single finding per function
        for function in ctx.get_functions() {
            if function.name.name == "validatePaymasterUserOp" {
                let line = function.name.location.start().line() as u32;
                let mut sub_issues: Vec<String> = Vec::new();

                if !has_replay_protection(function, ctx) {
                    sub_issues
                        .push("no replay protection (Biconomy nonce bypass risk)".to_string());
                }
                if !has_spending_limits(function, ctx) {
                    sub_issues.push("no spending limits (sponsor fund draining)".to_string());
                }
                if !has_target_validation(function, ctx) {
                    sub_issues.push("no target whitelist (arbitrary sponsorship)".to_string());
                }
                if !has_gas_limits(function, ctx) {
                    sub_issues.push("no gas limits (gas griefing risk)".to_string());
                }
                if !validates_chain_id(function, ctx) {
                    sub_issues
                        .push("signature not bound to chain ID (cross-chain replay)".to_string());
                }

                if !sub_issues.is_empty() {
                    let consolidated_msg = format!(
                        "validatePaymasterUserOp has {} issues: {}",
                        sub_issues.len(),
                        sub_issues.join("; ")
                    );

                    let finding = self
                        .base
                        .create_finding_with_severity(
                            ctx,
                            consolidated_msg,
                            line,
                            0,
                            20,
                            Severity::Critical,
                        )
                        .with_fix_suggestion(
                            "Add replay protection (usedHashes mapping), per-account spending limits, \
                             target whitelist, gas limits (MAX_GAS_PER_OP), and include block.chainid \
                             in signature hash to prevent cross-chain replay."
                                .to_string(),
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
