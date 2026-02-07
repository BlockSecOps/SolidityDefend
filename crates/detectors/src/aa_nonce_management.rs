//! Account Abstraction Advanced Nonce Management Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::modern_eip_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

pub struct NonceManagementDetector {
    base: BaseDetector,
}

impl NonceManagementDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-nonce-management-advanced".to_string()),
                "Advanced Nonce Management".to_string(),
                "Detects parallel nonce issues, key-specific nonce problems, and transaction replay risks".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    fn is_nonce_management_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("nonce") && source.contains("userop"))
            || (source.contains("validateuserop") || source.contains("executeuserop"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check validateUserOp or nonce validation functions
        if name.contains("validate") || name.contains("nonce") {
            // Check for sequential nonce enforcement (blocks parallel txs)
            let has_sequential_only = source_lower.contains("nonce++")
                || (source_lower.contains("nonce") && source_lower.contains("== currentnonce"));
            let has_parallel_support = source_lower.contains("key")
                || source_lower.contains("channel")
                || source_lower.contains("batch");

            if has_sequential_only && !has_parallel_support {
                issues.push((
                    "Sequential-only nonce (blocks parallel transactions)".to_string(),
                    Severity::Medium,
                    "Support parallel txs: uint192 key = uint192(nonce >> 64); uint64 seq = uint64(nonce); require(seq == nonces[sender][key]++);".to_string()
                ));
            }

            // Check for missing key-based nonce isolation
            if source_lower.contains("nonce") && !source_lower.contains("mapping") {
                issues.push((
                    "Single global nonce (no key-based isolation)".to_string(),
                    Severity::Low,
                    "Use key-based nonces: mapping(address => mapping(uint192 => uint64)) public nonces;".to_string()
                ));
            }

            // Check for nonce overflow protection
            let has_overflow_check = source_lower.contains("type(uint")
                || source_lower.contains("max")
                || source_lower.contains("overflow");

            if !has_overflow_check && source_lower.contains("++") {
                issues.push((
                    "No nonce overflow protection".to_string(),
                    Severity::Low,
                    "Check overflow: require(nonce < type(uint64).max, \"Nonce overflow\");"
                        .to_string(),
                ));
            }

            // Check for nonce invalidation mechanism
            let has_invalidation = source_lower.contains("invalidate")
                || source_lower.contains("cancel")
                || source_lower.contains("skip");

            if !has_invalidation {
                issues.push((
                    "No nonce invalidation mechanism (cannot cancel pending ops)".to_string(),
                    Severity::Medium,
                    "Add invalidation: function invalidateNonce(uint192 key) external { nonces[msg.sender][key] = type(uint64).max; }".to_string()
                ));
            }
        }

        // Check for getNonce function
        if name.contains("getnonce") {
            // Check if it supports key parameter
            let has_key_param = source_lower.contains("key")
                && (source_lower.contains("uint192") || source_lower.contains("uint256"));

            if !has_key_param {
                issues.push((
                    "getNonce doesn't support key parameter (no parallel nonce channels)".to_string(),
                    Severity::Low,
                    "Support keys: function getNonce(address sender, uint192 key) external view returns (uint256);".to_string()
                ));
            }
        }

        // Check executeUserOp for nonce usage
        if name.contains("execute") && source_lower.contains("userop") {
            // Check for proper nonce extraction from userOp
            let has_nonce_extraction = source_lower.contains("nonce")
                && (source_lower.contains("userop.nonce") || source_lower.contains("op.nonce"));

            if !has_nonce_extraction {
                issues.push((
                    "UserOp execution without nonce validation".to_string(),
                    Severity::High,
                    "Validate nonce: uint192 key = uint192(userOp.nonce >> 64); require(uint64(userOp.nonce) == nonces[userOp.sender][key]++);".to_string()
                ));
            }

            // Check for nonce reuse protection
            let has_used_check = source_lower.contains("used")
                || source_lower.contains("executed")
                || source_lower.contains("processed");

            if !has_used_check && !source_lower.contains("nonce++") {
                issues.push((
                    "No protection against nonce reuse".to_string(),
                    Severity::High,
                    "Prevent reuse: require(!usedNonces[nonceHash], \"Nonce already used\"); usedNonces[nonceHash] = true;".to_string()
                ));
            }
        }

        // Check for batch operations
        if name.contains("batch") || name.contains("multi") {
            // Check for independent nonce channels
            let has_batch_nonce = source_lower.contains("for") && source_lower.contains("nonce");

            if source_lower.contains("userop") && !has_batch_nonce {
                issues.push((
                    "Batch operations without per-operation nonce validation".to_string(),
                    Severity::High,
                    "Validate each: for (uint i = 0; i < ops.length; i++) { validateNonce(ops[i].sender, ops[i].nonce); }".to_string()
                ));
            }
        }

        // Check for cross-key nonce dependency
        if source_lower.contains("key") && source_lower.contains("nonce") {
            let has_dependency =
                source_lower.contains("previouskey") || source_lower.contains("dependson");

            if has_dependency {
                issues.push((
                    "Cross-key nonce dependencies (breaks parallelism)".to_string(),
                    Severity::Medium,
                    "Remove dependencies: Each nonce key should be independent for parallel execution".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for NonceManagementDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NonceManagementDetector {
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


        if !self.is_nonce_management_contract(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong meta-transaction/AA patterns (return early)
        if modern_eip_patterns::has_safe_metatx_pattern(ctx) {
            // Safe meta-tx pattern includes:
            // - Per-user nonce mapping
            // - Domain separator (EIP-712)
            // - Signature verification with nonce
            // - Replay protection
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                    .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
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
