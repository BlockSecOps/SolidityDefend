//! Transient Storage Composability Detector
//!
//! Detects composability issues in contracts using EIP-1153 transient storage.
//!
//! ## Problem
//!
//! Transient storage is cleared at the end of each transaction, which creates unexpected
//! behavior in multi-call scenarios and atomic transaction groups.
//!
//! ## Vulnerability Example
//!
//! ```solidity
//! contract TokenSwap {
//!     uint256 transient private swapState;
//!
//!     function startSwap(uint256 amount) public {
//!         swapState = amount;  // TSTORE
//!     }
//!
//!     function completeSwap() public {
//!         require(swapState > 0, "No active swap");  // May fail!
//!         // ... swap logic
//!     }
//! }
//!
//! // ❌ This multicall will FAIL:
//! multicall.aggregate([
//!     tokenSwap.startSwap(100),  // Sets transient state
//!     tokenSwap.completeSwap()   // State is GONE if separate call
//! ]);
//! ```
//!
//! ## Detection Strategy
//!
//! 1. Identify functions that write to transient storage
//! 2. Identify functions that read from transient storage
//! 3. Flag if reader/writer are in separate functions (composability risk)
//! 4. Warn about multicall compatibility issues
//!
//! Severity: HIGH
//! Category: Logic

use anyhow::Result;
use std::any::Any;

use super::{has_transient_storage_declarations, uses_transient_storage};
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TransientStorageComposabilityDetector {
    base: BaseDetector,
}

impl TransientStorageComposabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("transient-storage-composability".to_string()),
                "Transient Storage Composability Issues".to_string(),
                "Detects multi-call and composability issues with transient storage that may break atomic operations".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    fn check_contract(&self, ctx: &AnalysisContext) -> Vec<(String, u32, Severity, String)> {
        let mut issues = Vec::new();

        if !has_transient_storage_declarations(ctx) {
            return issues;
        }

        let source = &ctx.source_code;

        // Find all function pairs where one writes and another reads transient storage
        let functions = ctx.get_functions();
        let mut writers = Vec::new();
        let mut readers = Vec::new();

        for function in functions {
            let func_text = if let Some(body) = &function.body {
                source[body.location.start().offset()..body.location.end().offset()].to_string()
            } else {
                continue;
            };

            let has_write = func_text.contains("transient")
                && (func_text.contains("=")
                    || func_text.contains("++")
                    || func_text.contains("--"));

            let has_read = func_text.contains("transient")
                && (func_text.contains("require(") || func_text.contains("if ("));

            if has_write {
                writers.push((
                    function.name.name,
                    function.name.location.start().line() as u32,
                ));
            }

            if has_read {
                readers.push((
                    function.name.name,
                    function.name.location.start().line() as u32,
                ));
            }
        }

        // If we have separate readers and writers, flag composability issue
        if !writers.is_empty() && !readers.is_empty() {
            let writer_names: Vec<String> = writers.iter().map(|(n, _)| n.to_string()).collect();
            let reader_names: Vec<String> = readers.iter().map(|(n, _)| n.to_string()).collect();

            issues.push((
                format!("Transient storage composability risk: writers {:?} and readers {:?}", writer_names, reader_names),
                writers[0].1,
                Severity::High,
                format!(
                    "Transient storage is cleared between external calls, breaking multicall patterns:\n\
                     \n\
                     Writers: {}\n\
                     Readers: {}\n\
                     \n\
                     ❌ This pattern will FAIL in multicall:\n\
                     multicall([\n\
                         contract.{}(...),  // Sets transient state\n\
                         contract.{}(...)   // State is gone!\n\
                     ]);\n\
                     \n\
                     Fix 1: Combine into single atomic function\n\
                     function atomicOperation(uint256 amount) public {{\n\
                         // Set AND use transient state in same call\n\
                         transientState = amount;\n\
                         require(transientState > 0);\n\
                         // ... logic\n\
                     }}\n\
                     \n\
                     Fix 2: Use persistent storage for multi-call scenarios\n\
                     uint256 public persistentState;  // NOT transient\n\
                     \n\
                     Fix 3: Document multicall incompatibility\n\
                     /// @notice CANNOT be used in multicall - transient storage is cleared\n\
                     function {}() public {{\n\
                         // ...\n\
                     }}",
                    writer_names.join(", "),
                    reader_names.join(", "),
                    writer_names.first().unwrap_or(&"writer".to_string()),
                    reader_names.first().unwrap_or(&"reader".to_string()),
                    reader_names.first().unwrap_or(&"reader".to_string())
                )
            ));
        }

        // Check for explicit cleanup patterns
        let has_cleanup = source.to_lowercase().contains("delete") && source.contains("transient");

        if !has_cleanup && !writers.is_empty() {
            issues.push((
                "Missing explicit transient storage cleanup".to_string(),
                writers[0].1,
                Severity::Medium,
                "Add explicit cleanup to make transient storage usage clear:\n\
                 \n\
                 function _cleanupTransientState() internal {\n\
                     delete transientState;  // Explicit cleanup\n\
                 }\n\
                 \n\
                 While transient storage auto-clears at transaction end, explicit cleanup:\n\
                 1. Makes intent clear to auditors\n\
                 2. Prevents mid-transaction state pollution\n\
                 3. Improves composability with other contracts"
                    .to_string(),
            ));
        }

        issues
    }
}

impl Default for TransientStorageComposabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TransientStorageComposabilityDetector {
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

        if !uses_transient_storage(ctx) {
            return Ok(findings);
        }

        for (title, line, severity, remediation) in self.check_contract(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(ctx, title, line, 0, 20, severity)
                .with_fix_suggestion(remediation);

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
