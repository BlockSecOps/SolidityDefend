//! Transient Storage State Leak Detector
//!
//! Detects intentional lack of transient storage cleanup that blocks other contract interactions.
//!
//! ## Attack Scenario
//!
//! Malicious contracts can intentionally leave transient storage "dirty" to interfere with
//! subsequent contract calls in the same transaction (e.g., multicall, router patterns).
//!
//! ```solidity
//! contract MaliciousContract {
//!     uint256 transient private poisonState;
//!
//!     function poisonTransaction() public {
//!         poisonState = type(uint256).max;
//!         // Intentionally NO cleanup - pollutes transaction state
//!     }
//! }
//!
//! contract VictimContract {
//!     uint256 transient private expectedCleanState;
//!
//!     function operate() public {
//!         require(expectedCleanState == 0, "Dirty state detected");
//!         // ❌ This fails if poisonTransaction() was called earlier!
//!     }
//! }
//!
//! // Attack:
//! multicall([
//!     malicious.poisonTransaction(),  // Poisons transient storage
//!     victim.operate()                // Fails due to polluted state
//! ]);
//! ```
//!
//! Severity: MEDIUM
//! Category: Logic, BestPractices

use anyhow::Result;
use std::any::Any;

use super::has_transient_storage_declarations;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TransientStorageStateLeakDetector {
    base: BaseDetector,
}

impl TransientStorageStateLeakDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("transient-storage-state-leak".to_string()),
                "Transient Storage State Leak".to_string(),
                "Detects missing cleanup of transient storage that could poison transaction state for subsequent calls".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
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
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // Check if function modifies transient storage
        let modifies_transient = func_lower.contains("transient")
            && (func_lower.contains("=") || func_lower.contains("++") || func_lower.contains("--"));

        if !modifies_transient {
            return issues;
        }

        // Check for cleanup (delete statement)
        let has_cleanup = func_lower.contains("delete") && func_lower.contains("transient");

        // Check for early returns (which skip cleanup)
        let has_early_return = func_text.matches("return").count() > 1
            || (func_text.contains("return") && !func_text.ends_with("return"));

        if !has_cleanup {
            issues.push((
                format!(
                    "No transient storage cleanup in '{}' - can poison multicall transactions",
                    function.name.name
                ),
                Severity::Medium,
                "Add explicit cleanup to prevent state pollution:\n\
                 \n\
                 Bad pattern (state leak):\n\
                 function process() public {\n\
                     transientState = msg.value;\n\
                     // ... logic\n\
                     // ❌ NO cleanup - pollutes transaction\n\
                 }\n\
                 \n\
                 Good pattern (explicit cleanup):\n\
                 function process() public {\n\
                     transientState = msg.value;\n\
                     // ... logic\n\
                     \n\
                     // ✅ Explicit cleanup\n\
                     delete transientState;\n\
                 }\n\
                 \n\
                 Or use try-finally pattern:\n\
                 function process() public {\n\
                     transientState = msg.value;\n\
                     try this._internalLogic() {\n\
                         // success\n\
                     } catch {\n\
                         // handle error\n\
                     }\n\
                     // ✅ Always cleanup\n\
                     delete transientState;\n\
                 }"
                .to_string(),
            ));
        }

        if has_early_return && has_cleanup {
            issues.push((
                format!(
                    "Early returns in '{}' may skip transient storage cleanup",
                    function.name.name
                ),
                Severity::Medium,
                "Early returns can skip cleanup, leaving dirty state:\n\
                 \n\
                 Bad pattern:\n\
                 function process(uint256 amount) public {\n\
                     transientState = amount;\n\
                     \n\
                     if (amount == 0) {\n\
                         return;  // ❌ Skips cleanup!\n\
                     }\n\
                     \n\
                     // ... logic\n\
                     delete transientState;\n\
                 }\n\
                 \n\
                 Fix 1: Cleanup on all paths\n\
                 function process(uint256 amount) public {\n\
                     transientState = amount;\n\
                     \n\
                     if (amount == 0) {\n\
                         delete transientState;  // ✅ Cleanup\n\
                         return;\n\
                     }\n\
                     \n\
                     // ... logic\n\
                     delete transientState;  // ✅ Cleanup\n\
                 }\n\
                 \n\
                 Fix 2: Use modifier\n\
                 modifier cleanupTransient() {\n\
                     _;\n\
                     delete transientState;  // Always runs\n\
                 }\n\
                 \n\
                 function process(uint256 amount) public cleanupTransient {\n\
                     transientState = amount;\n\
                     if (amount == 0) return;  // Cleanup still happens\n\
                     // ... logic\n\
                 }"
                .to_string(),
            ));
        }

        issues
    }
}

impl Default for TransientStorageStateLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TransientStorageStateLeakDetector {
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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
