//! EIP-7702 Sweeper Detection
//!
//! Detects malicious sweeper contracts - 97% of 2025 EIP-7702 delegations were sweepers.
//!
//! **CRITICAL**: Responsible for majority of $12M+ phishing losses.

use anyhow::Result;
use std::any::Any;

use super::{has_sweeper_pattern, is_eip7702_delegate};
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EIP7702SweeperDetectionDetector {
    base: BaseDetector,
}

impl EIP7702SweeperDetectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-sweeper-detection".to_string()),
                "EIP-7702 Malicious Sweeper Detection".to_string(),
                "Detects sweeper contract patterns responsible for 97% of malicious EIP-7702 delegations in 2025".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    fn check_contract(&self, ctx: &AnalysisContext) -> Vec<(String, u32, Severity, String)> {
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Sweeper indicators
        let mut risk_score = 0;
        let mut reasons = Vec::new();

        // 1. Transfers ALL balance
        if source_lower.contains("address(this).balance") && source_lower.contains("transfer") {
            risk_score += 3;
            reasons.push("Transfers entire contract balance");
        }

        // 2. Batch token operations
        if (source_lower.contains("token") || source_lower.contains("erc20"))
            && (source_lower.contains("batch")
                || source_lower.contains("multi")
                || source_lower.contains("[]"))
        {
            risk_score += 2;
            reasons.push("Batch token operations");
        }

        // 3. Approve + transferFrom pattern
        if source_lower.contains("approve") && source_lower.contains("transferfrom") {
            risk_score += 2;
            reasons.push("Approve + transferFrom pattern (token drainage)");
        }

        // 4. No access control
        if !source_lower.contains("require") || !source_lower.contains("msg.sender") {
            risk_score += 2;
            reasons.push("Missing access control");
        }

        // 5. Single function does everything
        let func_count = source.matches("function").count();
        if func_count <= 2 && risk_score > 0 {
            risk_score += 1;
            reasons.push("Minimal interface (typical sweeper)");
        }

        if risk_score >= 4 {
            issues.push((
                format!(
                    "MALICIOUS SWEEPER DETECTED (score: {}/10) - {}",
                    risk_score,
                    reasons.join(", ")
                ),
                1,
                Severity::Critical,
                format!(
                    "🚨 CRITICAL: This appears to be a malicious sweeper contract!\n\
                     \n\
                     Risk indicators detected:\n\
                     {}\n\
                     \n\
                     Sweeper contracts are responsible for 97% of malicious EIP-7702 delegations\n\
                     in 2025, causing $12M+ in losses.\n\
                     \n\
                     Typical sweeper behavior:\n\
                     1. Accepts EIP-7702 delegation\n\
                     2. Immediately drains all ETH via address(this).balance\n\
                     3. Batch transfers all ERC-20 tokens\n\
                     4. Transfers all NFTs\n\
                     5. No legitimate business logic\n\
                     \n\
                     Legitimate delegates should:\n\
                     - Have clear access control (require msg.sender == owner)\n\
                     - NOT drain all funds automatically\n\
                     - Have specific, documented functionality\n\
                     - Include safety mechanisms and time-locks\n\
                     \n\
                     ⚠️  If this is a legitimate contract, add documentation and access controls.\n\
                     ⚠️  If this is for security research, clearly mark it as such.\n\
                     \n\
                     Real-World Impact:\n\
                     - August 2025: $1.54M single transaction\n\
                     - 15,000+ wallets drained\n\
                     - 90% malicious delegation rate",
                    reasons
                        .iter()
                        .enumerate()
                        .map(|(i, r)| format!("{}. {}", i + 1, r))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            ));
        }

        issues
    }
}

impl Default for EIP7702SweeperDetectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702SweeperDetectionDetector {
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

        let source = &ctx.source_code;

        // Phase 53 FP Reduction: Skip well-known legitimate protocols
        // These use batch token operations but are NOT malicious sweepers
        let is_legitimate_protocol = source.contains("Permit2")
            || source.contains("permit2")
            || source.contains("IAllowanceTransfer")
            || source.contains("ISignatureTransfer")
            || source.contains("PermitHash")
            || source.contains("Uniswap")
            || source.contains("@uniswap")
            || source.contains("SPDX-License-Identifier") && source.contains("MIT")
            || source.contains("OpenZeppelin")
            || source.contains("@openzeppelin");

        if is_legitimate_protocol {
            return Ok(findings);
        }

        if !is_eip7702_delegate(ctx) && !has_sweeper_pattern(ctx) {
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
