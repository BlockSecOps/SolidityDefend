use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity, Confidence, SourceLocation};
use crate::defi::{DeFiDetector, GovernanceAttackDetector as DeFiGovernanceDetector};

/// Governance vulnerability detector that implements the Detector trait
pub struct GovernanceDetector {
    inner: DeFiGovernanceDetector,
}

impl GovernanceDetector {
    pub fn new() -> Self {
        Self {
            inner: DeFiGovernanceDetector,
        }
    }
}

impl Detector for GovernanceDetector {
    fn id(&self) -> DetectorId {
        DetectorId("governance-attacks".to_string())
    }

    fn name(&self) -> &str {
        "Governance Attacks"
    }

    fn description(&self) -> &str {
        "Detects vulnerabilities in DAO governance mechanisms including flash loan attacks, delegation loops, and voting manipulation"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![DetectorCategory::FlashLoan, DetectorCategory::Logic, DetectorCategory::BestPractices]
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let results = self.inner.detect_defi_vulnerabilities(ctx);
        Ok(results.into_iter().map(|r| r.finding).collect())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// External calls in loop detector for governance execution vulnerabilities
pub struct ExternalCallsLoopDetector;

impl ExternalCallsLoopDetector {
    pub fn new() -> Self {
        Self
    }

    fn has_external_calls_in_loop(&self, ctx: &AnalysisContext) -> bool {
        // Look for patterns like:
        // for (...) { target.call(...) }
        // while (...) { external_contract.function(...) }

        // Check for for/while loops with external calls
        let loop_with_calls_patterns = [
            "for (",
            "while (",
        ];

        let external_call_patterns = [
            ".call(",
            ".delegatecall(",
            ".staticcall(",
            ".transfer(",
            ".send(",
        ];

        for loop_pattern in &loop_with_calls_patterns {
            if let Some(loop_start) = ctx.source_code.find(loop_pattern) {
                // Look for the corresponding closing brace
                let mut brace_count = 0;
                let mut in_loop = false;
                let chars: Vec<char> = ctx.source_code.chars().collect();

                for i in loop_start..chars.len() {
                    match chars[i] {
                        '{' => {
                            brace_count += 1;
                            in_loop = true;
                        }
                        '}' => {
                            brace_count -= 1;
                            if brace_count == 0 && in_loop {
                                // Check if there are external calls in this loop
                                let loop_content = &ctx.source_code[loop_start..i];
                                for call_pattern in &external_call_patterns {
                                    if loop_content.contains(call_pattern) {
                                        return true;
                                    }
                                }
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        false
    }
}

impl Detector for ExternalCallsLoopDetector {
    fn id(&self) -> DetectorId {
        DetectorId("external-calls-loop".to_string())
    }

    fn name(&self) -> &str {
        "External Calls in Loop"
    }

    fn description(&self) -> &str {
        "Detects external calls within loops that can cause DoS or unexpected behavior"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![DetectorCategory::ExternalCalls, DetectorCategory::Logic]
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            if let Some(body) = &func.body {
                if self.has_external_calls_in_loop(ctx) {
                    let finding = Finding::new(
                        self.id(),
                        Severity::High,
                        Confidence::Medium,
                        format!(
                            "Function '{}' contains external calls within loops. This can lead to DoS attacks \
                            if any external call fails or consumes excessive gas, and can be exploited in \
                            governance systems to block proposal execution.",
                            func.name.as_str()
                        ),
                        SourceLocation::new(
                            ctx.file_path.clone(),
                            func.location.start().line() as u32,
                            0,
                            func.name.as_str().len() as u32,
                        ),
                    ).with_cwe(834) // CWE-834: Excessive Iteration
                    .with_fix_suggestion(
                        "Avoid external calls in loops. Consider using a withdrawal pattern, \
                        batch processing, or fail-safe mechanisms for critical operations.".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Signature replay attack detector
pub struct SignatureReplayDetector;

impl SignatureReplayDetector {
    pub fn new() -> Self {
        Self
    }

    fn has_signature_replay_vulnerability(&self, ctx: &AnalysisContext) -> bool {
        // Look for signature verification without nonce protection
        let signature_patterns = [
            "ecrecover(",
            "ECDSA.recover(",
            "verify(",
        ];

        let nonce_patterns = [
            "nonce",
            "Nonce",
            "NONCE",
            "counter",
            "Counter",
        ];

        let has_signature_verification = signature_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        );

        let has_nonce_protection = nonce_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        );

        has_signature_verification && !has_nonce_protection
    }
}

impl Detector for SignatureReplayDetector {
    fn id(&self) -> DetectorId {
        DetectorId("signature-replay".to_string())
    }

    fn name(&self) -> &str {
        "Signature Replay Attack"
    }

    fn description(&self) -> &str {
        "Detects signature verification without replay protection (nonce system)"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![DetectorCategory::Auth, DetectorCategory::BestPractices]
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            // Look for functions that verify signatures
            let func_code = ctx.source_code.clone(); // Simplified for demo

            if self.has_signature_replay_vulnerability(ctx) {
                let finding = Finding::new(
                    self.id(),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' verifies signatures without replay protection. \
                        Attackers can reuse valid signatures to perform unauthorized actions. \
                        This is particularly dangerous in governance systems for vote manipulation.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_fix_suggestion(
                    "Implement a nonce system to prevent signature replay attacks. \
                    Include a unique nonce in the signed message and track used nonces.".to_string()
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

/// Emergency pause centralization detector
pub struct EmergencyPauseCentralizationDetector;

impl EmergencyPauseCentralizationDetector {
    pub fn new() -> Self {
        Self
    }

    fn has_centralized_emergency_control(&self, ctx: &AnalysisContext) -> bool {
        let emergency_patterns = [
            "emergencyPause",
            "pause",
            "emergency",
            "guardian",
            "onlyOwner",
            "onlyAdmin",
        ];

        let multisig_patterns = [
            "multisig",
            "multiSig",
            "timelock",
            "delay",
            "consensus",
        ];

        let has_emergency_functions = emergency_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        );

        let has_multisig_protection = multisig_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        );

        has_emergency_functions && !has_multisig_protection
    }
}

impl Detector for EmergencyPauseCentralizationDetector {
    fn id(&self) -> DetectorId {
        DetectorId("emergency-pause-centralization".to_string())
    }

    fn name(&self) -> &str {
        "Emergency Pause Centralization"
    }

    fn description(&self) -> &str {
        "Detects emergency pause functionality controlled by a single entity without multisig protection"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![DetectorCategory::AccessControl, DetectorCategory::BestPractices]
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            if self.has_centralized_emergency_control(ctx) {
                let finding = Finding::new(
                    self.id(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Contract has centralized emergency pause functionality without multisig protection. \
                        A single compromised account can halt the entire system, creating a single point of failure."
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(285) // CWE-285: Improper Authorization
                .with_fix_suggestion(
                    "Implement multisig requirements for emergency functions, add time delays, \
                    or use decentralized governance for critical system controls.".to_string()
                );

                findings.push(finding);
                break; // Only report once per contract
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}