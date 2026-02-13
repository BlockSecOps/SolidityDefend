//! Transient Storage Reentrancy Detector
//!
//! Detects low-gas reentrancy vulnerabilities via EIP-1153 transient storage (TSTORE/TLOAD).
//!
//! **CRITICAL Vulnerability**: EIP-1153 breaks the decade-old assumption that transfer() and
//! send() are safe against reentrancy. With only 100 gas cost per TSTORE, attackers can now
//! modify state within the 2300 gas stipend.
//!
//! ## Attack Scenario
//!
//! ```solidity
//! contract Vulnerable {
//!     mapping(address => uint256) public balances;
//!
//!     function withdraw() public {
//!         uint256 amount = balances[msg.sender];
//!         require(amount > 0);
//!
//!         // ❌ UNSAFE: transfer() no longer prevents reentrancy
//!         payable(msg.sender).transfer(amount);
//!
//!         balances[msg.sender] = 0;
//!     }
//! }
//!
//! contract Attacker {
//!     uint256 transient counter;  // Only 100 gas per TSTORE!
//!
//!     receive() external payable {
//!         if (counter < 10) {
//!             counter++;  // Reentrancy with 2300 gas!
//!             Vulnerable(msg.sender).withdraw();
//!         }
//!     }
//! }
//! ```
//!
//! ## Detection Strategy
//!
//! 1. Find contracts using transient storage (Solidity 0.8.24+)
//! 2. Identify external calls with gas limits (transfer, send, call{gas: X})
//! 3. Check if state changes occur after external calls
//! 4. Flag patterns vulnerable to transient storage reentrancy
//!
//! Severity: CRITICAL
//! Category: Reentrancy
//!
//! References:
//! - ChainSecurity: TSTORE Low Gas Reentrancy research (2024)
//! - EIP-1153: https://eips.ethereum.org/EIPS/eip-1153

use anyhow::Result;
use std::any::Any;

use super::uses_transient_storage;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TransientStorageReentrancyDetector {
    base: BaseDetector,
}

impl TransientStorageReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("transient-storage-reentrancy".to_string()),
                "Transient Storage Reentrancy".to_string(),
                "Detects low-gas reentrancy via EIP-1153 transient storage breaking transfer()/send() safety assumptions".to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::ReentrancyAttacks],
                Severity::Critical,
            ),
        }
    }

    /// Check if the pragma indicates Solidity 0.8.24+ (which supports transient storage)
    fn has_transient_storage_pragma(&self, source_lower: &str) -> bool {
        // Find pragma statement
        if let Some(pragma_start) = source_lower.find("pragma solidity") {
            let pragma_end = source_lower[pragma_start..]
                .find(';')
                .map(|i| pragma_start + i)
                .unwrap_or(source_lower.len());
            let pragma = &source_lower[pragma_start..pragma_end];

            // Transient storage is only available in 0.8.24+
            // Check for explicit version matches
            let transient_versions = [
                "0.8.24", "0.8.25", "0.8.26", "0.8.27", "0.8.28", "0.8.29", "0.9",
            ];

            for version in transient_versions {
                if pragma.contains(version) {
                    return true;
                }
            }

            // Check for range specifications that include 0.8.24+
            // e.g., ">=0.8.24" or ">=0.8.24 <0.9.0"
            if pragma.contains(">=0.8.24")
                || pragma.contains(">0.8.23")
                || pragma.contains(">=0.8.25")
                || pragma.contains(">=0.8.26")
            {
                return true;
            }

            // ^0.8.24 or higher
            for i in 24..=29 {
                if pragma.contains(&format!("^0.8.{}", i)) {
                    return true;
                }
            }
        }
        false
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();

        // Get function body text
        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // FP Reduction: Skip functions with reentrancy guards
        if func_lower.contains("nonreentrant") || func_lower.contains("reentrancyguard") {
            return issues;
        }

        // Check for vulnerable patterns: transfer/send after transient storage modifications
        let has_transfer_or_send =
            func_lower.contains(".transfer(") || func_lower.contains(".send(");
        let has_low_gas_call =
            func_lower.contains(".call{gas:") || func_lower.contains(".call{value:");

        if !has_transfer_or_send && !has_low_gas_call {
            return issues;
        }

        // FP Reduction: Use position-based check — only flag when state changes occur
        // AFTER the external call (checks-effects-interactions violation), not just
        // co-existence of both patterns anywhere in the function.
        let transfer_idx = func_lower
            .find(".transfer(")
            .or_else(|| func_lower.find(".send("))
            .or_else(|| func_lower.find(".call{gas:"))
            .or_else(|| func_lower.find(".call{value:"));

        if let Some(call_pos) = transfer_idx {
            let after_call = &func_lower[call_pos..];
            let has_state_change_after = after_call.contains("= 0")
                || after_call.contains("= 0;")
                || after_call.contains("delete ")
                || after_call.contains("-= ")
                || after_call.contains("+= ");

            if has_state_change_after {
                issues.push((
                    format!("Vulnerable to transient storage reentrancy in '{}' - transfer()/send() no longer safe with EIP-1153", function.name.name),
                    Severity::Critical,
                    "EIP-1153 breaks transfer()/send() safety assumption:\n\
                     \n\
                     CRITICAL: Transient storage (100 gas per TSTORE) allows reentrancy within\n\
                     the 2300 gas stipend of transfer() and send().\n\
                     \n\
                     Fix 1: Use checks-effects-interactions pattern\n\
                     function withdraw() public {\n\
                         uint256 amount = balances[msg.sender];\n\
                         require(amount > 0);\n\
                         \n\
                         // Update state BEFORE external call\n\
                         balances[msg.sender] = 0;\n\
                         \n\
                         payable(msg.sender).transfer(amount);\n\
                     }\n\
                     \n\
                     Fix 2: Use ReentrancyGuard\n\
                     import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n\
                     \n\
                     function withdraw() public nonReentrant {\n\
                         uint256 amount = balances[msg.sender];\n\
                         require(amount > 0);\n\
                         \n\
                         balances[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
                     }\n\
                     \n\
                     Reference: ChainSecurity TSTORE Low Gas Reentrancy research (2024)".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for TransientStorageReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TransientStorageReentrancyDetector {
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

        // Check if contract uses transient storage or has a pragma that enables it.
        // EIP-1153 (0.8.24+) breaks the 2300-gas reentrancy assumption: even
        // transfer()/send() can now execute TSTORE (100 gas), so any contract
        // compiled with 0.8.24+ that does external-call-before-state-update is at risk.
        let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();
        let uses_transient = uses_transient_storage(ctx);

        if !uses_transient && !self.has_transient_storage_pragma(&source_lower) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
