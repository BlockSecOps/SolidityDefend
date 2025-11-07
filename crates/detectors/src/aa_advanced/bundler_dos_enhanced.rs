//! AA Bundler DOS Enhanced Detector
//!
//! Enhanced detection for bundler DOS attacks via gas griefing and computational
//! complexity attacks. Covers 2024 discovered patterns beyond the basic detector.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AABundlerDosEnhancedDetector {
    base: BaseDetector,
}

impl AABundlerDosEnhancedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-bundler-dos-enhanced".to_string()),
                "AA Bundler DOS Enhanced".to_string(),
                "Enhanced bundler DOS detection covering 2024 attack patterns".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for AABundlerDosEnhancedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AABundlerDosEnhancedDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lower = ctx.source_code.to_lowercase();

        // Check for AA wallet or paymaster
        let is_aa_contract = lower.contains("useroperation")
            || lower.contains("validateuserop")
            || lower.contains("ipaymaster")
            || lower.contains("entrypoint");

        if !is_aa_contract {
            return Ok(findings);
        }

        // Pattern 1: validateUserOp with unbounded computation
        let has_validate = lower.contains("validateuserop");
        if has_validate {
            let has_unbounded_loop = lower.contains("while (true)")
                || lower.contains("while(true)")
                || (lower.contains("for (uint256 i") && !lower.contains("i < "));

            if has_unbounded_loop {
                let finding = self.base.create_finding(
                    ctx,
                    "validateUserOp contains unbounded loop - can DOS bundler with infinite gas consumption".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add strict bounds to loops in validateUserOp; enforce maximum iteration count".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Expensive operations in validation without gas limit
        if has_validate {
            let has_expensive_op = lower.contains("keccak256")
                || lower.contains("sha256")
                || lower.contains("ecrecover")
                || lower.contains("signature");

            let has_gas_limit_check = lower.contains("gasleft()")
                || lower.contains("gas limit")
                || lower.contains("maxgas");

            if has_expensive_op && !has_gas_limit_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Expensive cryptographic operations in validation without gas limits - bundler DOS risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Limit expensive operations or check gasleft() before execution; cap total validation gas".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Storage reads from unknown contracts
        if has_validate {
            let has_external_storage_read = lower.contains(".balanceof(")
                || lower.contains(".getbalance")
                || (lower.contains("external view") && lower.contains("returns"));

            if has_external_storage_read {
                let finding = self.base.create_finding(
                    ctx,
                    "External storage reads in validation - malicious contracts can grief bundler gas estimation".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Avoid external storage reads in validation or whitelist trusted contracts only".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Paymaster validation without timeout
        let is_paymaster = lower.contains("validatepaymasteruserop");
        if is_paymaster {
            let has_timeout = lower.contains("deadline")
                || lower.contains("timeout")
                || lower.contains("validuntil")
                || lower.contains("timestamp");

            if !has_timeout {
                let finding = self.base.create_finding(
                    ctx,
                    "Paymaster validation lacks timeout - expired operations can waste bundler resources".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add validUntil timestamp to paymaster validation; reject expired operations early".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Complex signature verification schemes
        if has_validate || is_paymaster {
            let signature_complexity_count = lower.matches("ecrecover").count()
                + lower.matches("verify").count()
                + lower.matches("signature").count();

            if signature_complexity_count > 3 {
                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Complex signature verification ({} operations) - can DOS bundler with computation time",
                        signature_complexity_count
                    ),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Simplify signature verification; use single ecrecover or optimized verification library".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: initCode with CREATE2 factory without gas limits
        if is_aa_contract {
            let has_init_code = lower.contains("initcode") || lower.contains("init_code");

            let has_create2 = lower.contains("create2") || lower.contains("deploy");

            if has_init_code && has_create2 {
                let has_init_gas_limit =
                    lower.contains("initgaslimit") || lower.contains("verificationgaslimit");

                if !has_init_gas_limit {
                    let finding = self.base.create_finding(
                        ctx,
                        "initCode deployment lacks gas limits - large contract deployment can DOS bundler".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Enforce verificationGasLimit on initCode execution; reject oversized deployments".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 7: Multiple external calls during validation
        if has_validate {
            let external_call_count = lower.matches(".call(").count()
                + lower.matches(".call{").count()
                + lower.matches(".staticcall(").count();

            if external_call_count > 2 {
                let finding = self.base.create_finding(
                    ctx,
                    format!(
                        "Multiple external calls ({}) during validation - amplifies bundler DOS risk",
                        external_call_count
                    ),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Minimize external calls in validation; batch or cache results where possible".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
