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

        // Check for vulnerable patterns: transfer/send after transient storage modifications
        let has_transfer_or_send =
            func_lower.contains(".transfer(") || func_lower.contains(".send(");
        let has_low_gas_call =
            func_lower.contains(".call{gas:") || func_lower.contains(".call{value:");

        if !has_transfer_or_send && !has_low_gas_call {
            return issues;
        }

        // Check if state changes occur after external calls (checks-effects-interactions violation)
        let has_state_change_after = func_lower.contains("= 0") || func_lower.contains("delete");

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
                     // ✅ Update state BEFORE external call\n\
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

        // Check for explicit reentrancy vulnerability patterns
        if func_lower.contains("transfer(") && func_lower.contains("balance") {
            let transfer_idx = func_lower.find(".transfer(").unwrap_or(0);
            let balance_idx = func_lower.rfind("= 0").unwrap_or(usize::MAX);

            if balance_idx > transfer_idx {
                issues.push((
                    format!(
                        "Classic reentrancy pattern with transient storage risk in '{}'",
                        function.name.name
                    ),
                    Severity::Critical,
                    "State update after external call is vulnerable to reentrancy:\n\
                     \n\
                     Current pattern (VULNERABLE):\n\
                     1. Read balance\n\
                     2. Call transfer() ← attacker can reenter here with transient storage!\n\
                     3. Update balance to 0\n\
                     \n\
                     Secure pattern:\n\
                     1. Read balance\n\
                     2. Update balance to 0 ← do this FIRST\n\
                     3. Call transfer()\n\
                     \n\
                     With EIP-1153, even 2300 gas is enough to modify transient state and re-enter."
                        .to_string(),
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

        // Check if contract might be affected by transient storage
        // (either using it directly or callable by contracts that do)
        let uses_transient = uses_transient_storage(ctx);
        let source_lower = ctx.source_code.to_lowercase();
        let pragma_version = source_lower.contains("pragma solidity")
            && (source_lower.contains("0.8.24")
                || source_lower.contains("0.8.25")
                || source_lower.contains("0.8.26")
                || source_lower.contains("^0.8")
                || source_lower.contains(">=0.8"));

        // Only check contracts compiled with Solidity 0.8.24+ or explicitly using transient storage
        if !uses_transient && !pragma_version {
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

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
