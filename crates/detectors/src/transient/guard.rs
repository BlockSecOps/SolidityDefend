//! Transient Reentrancy Guard Detector
//!
//! Detects improper usage of transient storage for reentrancy guards with low-gas external calls.
//!
//! ## Problem
//!
//! While transient storage is ideal for reentrancy guards (gas-efficient, auto-clears), it
//! creates a new attack vector when combined with low-gas external calls that can now modify state.
//!
//! ## Vulnerability Example
//!
//! ```solidity
//! contract VulnerableGuard {
//!     uint256 transient private locked;
//!
//!     modifier nonReentrant() {
//!         require(locked == 0, "Reentrant");
//!         locked = 1;
//!         _;
//!         locked = 0;
//!     }
//!
//!     function withdraw() public nonReentrant {
//!         uint256 amount = balances[msg.sender];
//!
//!         // ❌ transfer() can now set transient state with 100 gas
//!         payable(msg.sender).transfer(amount);
//!
//!         // Traditional guard still works, but attacker can use TSTORE
//!         // to manipulate read-only reentrancy or side channels
//!         balances[msg.sender] = 0;
//!     }
//! }
//! ```
//!
//! ## New Attack Surface
//!
//! With EIP-1153, even low-gas calls (transfer, send) can:
//! 1. Set transient storage flags to coordinate multi-step attacks
//! 2. Signal state to other contracts in same transaction
//! 3. Pollute transient state for subsequent calls
//!
//! Severity: MEDIUM
//! Category: Reentrancy

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use super::has_transient_storage_declarations;

pub struct TransientReentrancyGuardDetector {
    base: BaseDetector,
}

impl TransientReentrancyGuardDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("transient-reentrancy-guard".to_string()),
                "Transient Reentrancy Guard Issues".to_string(),
                "Detects transient reentrancy guards that may not protect against new EIP-1153 attack vectors".to_string(),
                vec![DetectorCategory::Reentrancy],
                Severity::Medium,
            ),
        }
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()].to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // Check for transient reentrancy guard usage
        let has_transient_guard = ctx.source_code.to_lowercase().contains("transient") &&
            (ctx.source_code.to_lowercase().contains("locked") ||
             ctx.source_code.to_lowercase().contains("guard") ||
             ctx.source_code.to_lowercase().contains("reentrant"));

        if !has_transient_guard {
            return issues;
        }

        // Check for low-gas external calls that could set transient state
        let has_low_gas_call = func_lower.contains(".transfer(") ||
            func_lower.contains(".send(") ||
            func_lower.contains(".call{gas:");

        if has_low_gas_call {
            issues.push((
                format!("Transient reentrancy guard with low-gas call in '{}' - attacker can set transient state", function.name.name),
                Severity::Medium,
                "EIP-1153 allows attackers to set transient state even in low-gas contexts:\n\
                 \n\
                 ❌ Problem:\n\
                 1. Traditional guard blocks classic reentrancy\n\
                 2. But attacker can use TSTORE (100 gas) in receive() fallback\n\
                 3. Can coordinate multi-step attacks or signal to other contracts\n\
                 \n\
                 Fix 1: Use checks-effects-interactions pattern ALWAYS\n\
                 function withdraw() public nonReentrant {\n\
                     uint256 amount = balances[msg.sender];\n\
                     \n\
                     // ✅ Update state BEFORE external call\n\
                     balances[msg.sender] = 0;\n\
                     \n\
                     payable(msg.sender).transfer(amount);\n\
                 }\n\
                 \n\
                 Fix 2: Add read-only reentrancy protection for view functions\n\
                 uint256 transient private locked;\n\
                 \n\
                 modifier nonReentrant() {\n\
                     require(locked == 0, \"Reentrant\");\n\
                     locked = 1;\n\
                     _;\n\
                     locked = 0;\n\
                 }\n\
                 \n\
                 // ✅ Also protect view functions\n\
                 function getBalance(address user) public view returns (uint256) {\n\
                     require(locked == 0, \"No read during state change\");\n\
                     return balances[user];\n\
                 }\n\
                 \n\
                 Fix 3: Use OpenZeppelin ReentrancyGuard v5.0+\n\
                 // Uses transient storage automatically in Solidity 0.8.24+\n\
                 import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n\
                 \n\
                 contract Secure is ReentrancyGuard {\n\
                     function withdraw() public nonReentrant {\n\
                         // Protected against both classic and transient reentrancy\n\
                     }\n\
                 }".to_string()
            ));
        }

        // Check for read-only reentrancy protection
        let has_view_protection = ctx.source_code.contains("view") &&
            ctx.source_code.to_lowercase().contains("require") &&
            ctx.source_code.to_lowercase().contains("locked");

        if has_transient_guard && !has_view_protection {
            issues.push((
                format!("Missing read-only reentrancy protection in contract with transient guard"),
                Severity::Low,
                "Add read-only reentrancy protection for view functions:\n\
                 \n\
                 Without EIP-1153, view functions couldn't be exploited during external calls.\n\
                 With EIP-1153, attackers can set transient state to manipulate view function results.\n\
                 \n\
                 Add protection:\n\
                 uint256 transient private locked;\n\
                 \n\
                 modifier nonReentrant() {\n\
                     require(locked == 0);\n\
                     locked = 1;\n\
                     _;\n\
                     locked = 0;\n\
                 }\n\
                 \n\
                 // ✅ Protect view functions too\n\
                 function getAccountData(address user) public view returns (uint256, uint256) {\n\
                     require(locked == 0, \"Cannot read during external call\");\n\
                     return (balances[user], debt[user]);\n\
                 }\n\
                 \n\
                 This prevents attackers from calling view functions during external calls\n\
                 to get inconsistent state readings.".to_string()
            ));
        }

        issues
    }
}

impl Default for TransientReentrancyGuardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TransientReentrancyGuardDetector {
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

        if !has_transient_storage_declarations(ctx) {
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
