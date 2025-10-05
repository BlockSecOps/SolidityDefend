use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity, Confidence, SourceLocation};
use ast;
/// Governance vulnerability detector that implements the Detector trait
pub struct GovernanceDetector;

impl GovernanceDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for GovernanceDetector {
    fn id(&self) -> DetectorId {
        DetectorId("test-governance".to_string())
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

    fn detect(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        // Simplified for testing registration
        Ok(Vec::new())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl GovernanceDetector {
    fn detect_flash_loan_governance_attacks(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            if func.body.is_none() {
                continue;
            }

            // Look for governance functions that check current balance without snapshots
            if self.is_governance_function(func) && self.uses_current_balance_for_voting(ctx, func) {
                let finding = Finding::new(
                    self.id(),
                    Severity::Critical,
                    Confidence::High,
                    format!(
                        "Function '{}' is vulnerable to flash loan governance attacks. It uses current token balance \
                        for voting power without snapshot protection, allowing attackers to temporarily acquire \
                        large amounts of governance tokens to manipulate votes.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682) // CWE-682: Incorrect Calculation
                .with_fix_suggestion(
                    "Implement snapshot-based voting power or time-delayed voting rights for governance tokens.".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn detect_missing_snapshot_protection(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if contract has governance tokens but lacks snapshot mechanisms
        let has_governance_tokens = self.has_governance_token_patterns(ctx);
        let has_snapshot_protection = self.has_snapshot_mechanisms(ctx);

        if has_governance_tokens && !has_snapshot_protection {
            // Find the main contract for the finding location
            if let Some(main_func) = ctx.contract.functions.first() {
                let finding = Finding::new(
                    self.id(),
                    Severity::High,
                    Confidence::Medium,
                    "Contract uses governance tokens without snapshot protection mechanisms. \
                    This enables flash loan attacks where attackers can temporarily acquire \
                    tokens to manipulate governance decisions.".to_string(),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        main_func.location.start().line() as u32,
                        0,
                        20,
                    ),
                ).with_cwe(284) // CWE-284: Improper Access Control
                .with_fix_suggestion(
                    "Implement snapshot-based voting power using block-based or time-based snapshots.".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn detect_temporal_control_issues(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            if func.body.is_none() {
                continue;
            }

            if self.is_governance_function(func) && !self.has_time_delay_protection(ctx, func) {
                let finding = Finding::new(
                    self.id(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' lacks time-delay protection for governance actions. \
                        New token holders can immediately use their voting power, enabling \
                        flash loan governance attacks.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(662) // CWE-662: Improper Synchronization
                .with_fix_suggestion(
                    "Implement time-delayed voting rights requiring minimum holding periods.".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn is_governance_function(&self, func: &ast::Function) -> bool {
        let governance_patterns = [
            "propose", "vote", "castVote", "delegate", "execute", "queue"
        ];
        governance_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn uses_current_balance_for_voting(&self, ctx: &AnalysisContext, func: &ast::Function) -> bool {
        let func_start = func.location.start().line();
        let func_end = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Enhanced patterns for current balance checks without snapshot protection
        let balance_patterns = [
            "balanceOf(", ".balanceOf(", "votingToken.balanceOf", "token.balanceOf",
            "governanceToken.balanceOf", "balanceOf(msg.sender)",
            "getBalance(", "currentBalance"
        ];

        let snapshot_patterns = [
            "snapshot", "getPastVotes", "balanceOfAt", "checkpoints",
            "getVotes(", "getPriorVotes", "getPastTotalSupply", "balanceAtBlockNumber"
        ];

        let uses_balance = balance_patterns.iter().any(|&pattern| func_source.contains(pattern));
        let uses_snapshot = snapshot_patterns.iter().any(|&pattern| func_source.contains(pattern));

        // Also check for governance-related balance usage in require statements
        let has_governance_balance_check = func_source.contains("require(") &&
            (func_source.contains("balanceOf") || func_source.contains("getBalance")) &&
            (func_source.contains("threshold") || func_source.contains("minimum") ||
             func_source.contains(">=") || func_source.contains("<="));

        (uses_balance || has_governance_balance_check) && !uses_snapshot
    }

    fn has_governance_token_patterns(&self, ctx: &AnalysisContext) -> bool {
        let governance_indicators = [
            "votingToken", "governanceToken", "delegate", "proposal", "voting"
        ];
        governance_indicators.iter().any(|&indicator|
            ctx.source_code.to_lowercase().contains(&indicator.to_lowercase())
        )
    }

    fn has_snapshot_mechanisms(&self, ctx: &AnalysisContext) -> bool {
        let snapshot_patterns = [
            "snapshot", "getPastVotes", "balanceOfAt", "checkpoints",
            "timeWeighted", "historicalBalance"
        ];
        snapshot_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_time_delay_protection(&self, ctx: &AnalysisContext, _func: &ast::Function) -> bool {
        let time_delay_patterns = [
            "timelock", "delay", "holdingPeriod", "vestingPeriod",
            "minimumHolding", "lockPeriod"
        ];
        time_delay_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }
}

/// External calls in loop detector for governance execution vulnerabilities
pub struct ExternalCallsLoopDetector;

impl ExternalCallsLoopDetector {
    pub fn new() -> Self {
        Self
    }

    fn has_external_calls_in_loop(&self, func: &ast::Function, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations (not interface functions)
        if func.body.is_none() {
            return false;
        }

        // Enhanced pattern detection for external calls in loops
        let func_start_line = func.location.start().line();
        let func_end_line = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start_line >= source_lines.len() || func_end_line >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start_line..=func_end_line].join("\n");

        // Enhanced loop patterns
        let loop_patterns = [
            "for (", "for(", "while (", "while(", "do {", "foreach"
        ];
        let has_loop = loop_patterns.iter().any(|&pattern| func_source.contains(pattern));

        // Enhanced external call patterns
        let external_call_patterns = [
            ".call(", ".call{", ".delegatecall(", ".staticcall(",
            ".transfer(", ".send(", "external.call", "target.call",
            "call{value:", "(bool success", "call(data", ".call"
        ];
        let has_external_call = external_call_patterns.iter().any(|&pattern| func_source.contains(pattern));

        // Specific pattern for array iteration with external calls (like DAO execute)
        let has_array_iteration_with_calls = func_source.contains("for (") &&
            func_source.contains(".length") &&
            (func_source.contains(".call") || func_source.contains("call{"));

        // Enhanced detection for governance execution patterns
        let is_governance_execution = func.name.as_str().to_lowercase().contains("execute") &&
            has_external_call && has_loop;

        has_loop && (has_external_call || has_array_iteration_with_calls) || is_governance_execution
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
            // Skip interface functions (no body)
            if func.body.is_none() {
                continue;
            }

            if self.has_external_calls_in_loop(func, ctx) {
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

    fn has_signature_replay_vulnerability(&self, func: &ast::Function, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations (not interface functions)
        if func.body.is_none() {
            return false;
        }

        // Enhanced signature function detection
        let signature_patterns = [
            "BySig", "bySignature", "WithSignature", "Signature", "ecrecover", "recover"
        ];

        let is_signature_function = signature_patterns.iter().any(|&pattern|
            func.name.as_str().contains(pattern)
        );

        if !is_signature_function {
            // Also check if function body contains signature verification
            let func_start = func.location.start().line();
            let func_end = func.location.end().line();

            let source_lines: Vec<&str> = ctx.source_code.lines().collect();
            if func_start < source_lines.len() && func_end < source_lines.len() {
                let func_source = source_lines[func_start..=func_end].join("\n");
                let contains_signature_verification = func_source.contains("ecrecover") ||
                    func_source.contains("ECDSA.recover") ||
                    func_source.contains("verify") ||
                    func_source.contains("signature");

                if !contains_signature_verification {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check function parameters for signature components (v, r, s)
        let has_signature_params = func.parameters.iter().any(|param| {
            let param_name = param.name.as_ref().map(|n| n.as_str().to_lowercase()).unwrap_or_default();
            param_name == "v" || param_name == "r" || param_name == "s" ||
            param_name.contains("signature")
        });

        // Check if function lacks nonce protection
        let func_start = func.location.start().line();
        let func_end = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start < source_lines.len() && func_end < source_lines.len() {
            let func_source = source_lines[func_start..=func_end].join("\n");

            let nonce_patterns = [
                "nonce", "nonces", "_nonce", "counter", "replay", "used"
            ];
            let has_nonce_protection = nonce_patterns.iter().any(|&pattern|
                func_source.to_lowercase().contains(pattern)
            );

            has_signature_params && !has_nonce_protection
        } else {
            has_signature_params
        }
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
            // Skip interface functions (no body)
            if func.body.is_none() {
                continue;
            }

            if self.has_signature_replay_vulnerability(func, ctx) {
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

    fn has_centralized_emergency_control(&self, func: &ast::Function, ctx: &AnalysisContext) -> bool {
        // Only check functions with actual implementations (not interface functions)
        if func.body.is_none() {
            return false;
        }

        // Enhanced emergency function patterns
        let emergency_function_patterns = [
            "emergency", "pause", "freeze", "halt", "stop", "disable", "shutdown", "kill"
        ];

        let is_emergency_function = emergency_function_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        );

        if !is_emergency_function {
            return false;
        }

        // Check if function has centralized access control modifiers
        let has_centralized_control = func.modifiers.iter().any(|modifier| {
            let modifier_name = modifier.name.as_str().to_lowercase();
            modifier_name.contains("owner") ||
            modifier_name.contains("admin") ||
            modifier_name.contains("guardian") ||
            modifier_name == "onlyowner" ||
            modifier_name == "onlyadmin" ||
            modifier_name == "onlyguardian"
        });

        // Check if the contract lacks multisig or timelock protection
        let multisig_patterns = [
            "multisig", "timelock", "delay", "consensus", "voting", "governance"
        ];
        let has_multisig_protection = multisig_patterns.iter().any(|&pattern|
            ctx.source_code.to_lowercase().contains(pattern)
        );

        // Flag if it's an emergency function with centralized control and no multisig protection
        has_centralized_control && !has_multisig_protection
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
            // Skip interface functions (no body)
            if func.body.is_none() {
                continue;
            }

            if self.has_centralized_emergency_control(func, ctx) {
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