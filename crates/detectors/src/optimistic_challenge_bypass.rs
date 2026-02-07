use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for optimistic rollup challenge period bypass vulnerabilities
pub struct OptimisticChallengeBypassDetector {
    base: BaseDetector,
}

impl OptimisticChallengeBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("optimistic-challenge-bypass".to_string()),
                "Optimistic Rollup Challenge Period Bypass".to_string(),
                "Detects missing or insufficient challenge periods in optimistic rollup withdrawal finalization, allowing premature withdrawals before fraud proofs can be submitted".to_string(),
                vec![DetectorCategory::L2, DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for OptimisticChallengeBypassDetector {
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


        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for withdrawal finalization functions
            if self.is_withdrawal_finalization_function(function.name.name, &func_source) {
                let issues = self.check_challenge_period(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' finalizes withdrawals without proper challenge period validation. {} \
                        This allows attackers to bypass the fraud proof window and withdraw invalid state transitions.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(682) // CWE-682: Incorrect Calculation
                        .with_fix_suggestion(format!(
                            "Add challenge period validation to '{}': \
                            (1) Define minimum challenge period constant (typically 7 days = 604800 seconds), \
                            (2) Store withdrawal initiation timestamp, \
                            (3) Require block.timestamp >= withdrawalTimestamp + CHALLENGE_PERIOD, \
                            (4) Implement fraud proof submission mechanism during challenge window, \
                            (5) Add event emission for monitoring.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for state commitment functions
            if self.is_state_commitment_function(function.name.name, &func_source) {
                let issues = self.check_fraud_proof_mechanism(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' commits state without proper fraud proof mechanism. {} \
                        Missing fraud proof validation allows invalid state transitions to be finalized.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_fix_suggestion(format!(
                            "Add fraud proof support to '{}': \
                            (1) Implement challenge() function to dispute state roots, \
                            (2) Store state root with timestamp for challenge tracking, \
                            (3) Add bond requirement for challengers, \
                            (4) Implement interactive proving game or fault proof verification, \
                            (5) Add slashing mechanism for invalid challenges.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for challenge functions
            if self.is_challenge_function(function.name.name, &func_source) {
                let issues = self.check_challenge_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' handles challenges without proper validation. {} \
                        Weak challenge validation undermines the security of the optimistic rollup.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(20) // CWE-20: Improper Input Validation
                        .with_fix_suggestion(format!(
                            "Strengthen challenge validation in '{}': \
                            (1) Validate challenge is within challenge period window, \
                            (2) Require sufficient bond from challenger, \
                            (3) Verify challenger provides valid fraud proof data, \
                            (4) Implement timeout for challenge resolution, \
                            (5) Handle challenge outcome (delete invalid state or slash challenger).",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl OptimisticChallengeBypassDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    fn is_withdrawal_finalization_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "finalizeWithdrawal",
            "completeWithdrawal",
            "proveWithdrawal",
            "claimWithdrawal",
            "withdrawETH",
            "withdrawERC20",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("withdrawal") && source.contains("finalize"))
    }

    fn is_state_commitment_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "proposeStateRoot",
            "commitBatch",
            "submitStateRoot",
            "finalizeStateRoot",
            "appendStateBatch",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("stateRoot")
                && (source.contains("propose") || source.contains("commit")))
    }

    fn is_challenge_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "challengeStateRoot",
            "disputeBatch",
            "proveInvalid",
            "deleteStateRoot",
            "challenge",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || source.contains("challenge")
    }

    fn check_challenge_period(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Missing time delay check
        if !source.contains("block.timestamp")
            && !source.contains("timestamp")
            && !source.contains("time")
        {
            issues.push(
                "No timestamp validation detected. Must check withdrawal was initiated at least 7 days ago"
                    .to_string(),
            );
        }

        // Pattern 2: No challenge period constant
        let has_period_constant = source.contains("CHALLENGE_PERIOD")
            || source.contains("FINALIZATION_PERIOD")
            || source.contains("DISPUTE_PERIOD")
            || source.contains("7 days")
            || source.contains("604800");

        if !has_period_constant {
            issues.push(
                "Missing challenge period constant. Should define CHALLENGE_PERIOD = 7 days (604800 seconds)"
                    .to_string(),
            );
        }

        // Pattern 3: Check for proper time comparison
        if source.contains("timestamp") && !source.contains(">=") && !source.contains(">") {
            issues.push(
                "Timestamp present but no comparison operator. Must verify: block.timestamp >= withdrawalTime + CHALLENGE_PERIOD"
                    .to_string(),
            );
        }

        // Pattern 4: Missing withdrawal initialization tracking
        if !source.contains("withdrawalTimestamp")
            && !source.contains("initiatedAt")
            && !source.contains("proposedAt")
            && !source.contains("createdAt")
        {
            issues.push(
                "Missing withdrawal initialization tracking. Must store when withdrawal was initiated to calculate elapsed time"
                    .to_string(),
            );
        }

        // Pattern 5: Check for finalization status
        if !source.contains("finalized")
            && !source.contains("challenged")
            && !source.contains("disputed")
        {
            issues.push(
                "No finalization status check. Should verify withdrawal has not been challenged or disputed"
                    .to_string(),
            );
        }

        issues
    }

    fn check_fraud_proof_mechanism(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No challenge event emission
        if !source.contains("emit") || !source.contains("Challenge") {
            issues.push(
                "Missing challenge event emission. Should emit event to notify validators of new state commitment"
                    .to_string(),
            );
        }

        // Pattern 2: No state root storage with metadata
        if source.contains("stateRoot") && !source.contains("timestamp") {
            issues.push(
                "State root stored without timestamp metadata. Need timestamp to enforce challenge period"
                    .to_string(),
            );
        }

        // Pattern 3: Missing challenge window tracking
        if !source.contains("challengePeriod")
            && !source.contains("disputeGameFactory")
            && !source.contains("challenge")
        {
            issues.push(
                "No challenge window mechanism detected. Must allow fraud proofs during challenge period"
                    .to_string(),
            );
        }

        issues
    }

    fn check_challenge_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Missing bond requirement
        if !source.contains("bond") && !source.contains("stake") && !source.contains("deposit") {
            issues.push(
                "No bond requirement for challenges. Challengers should post bond to prevent spam"
                    .to_string(),
            );
        }

        // Pattern 2: No fraud proof validation
        if !source.contains("proof") && !source.contains("verify") {
            issues.push(
                "Missing fraud proof validation. Must verify challenger's proof of invalid state transition"
                    .to_string(),
            );
        }

        // Pattern 3: No challenge outcome handling
        if !source.contains("delete") && !source.contains("slash") && !source.contains("refund") {
            issues.push(
                "Missing challenge outcome logic. Should delete invalid state root and slash or refund based on result"
                    .to_string(),
            );
        }

        // Pattern 4: Missing time window validation
        if source.contains("challenge") && !source.contains("timestamp") {
            issues.push(
                "No time window validation. Must verify challenge is submitted within valid period"
                    .to_string(),
            );
        }

        issues
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Default for OptimisticChallengeBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = OptimisticChallengeBypassDetector::new();
        assert_eq!(detector.name(), "Optimistic Rollup Challenge Period Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "optimistic-challenge-bypass");
        assert!(detector.categories().contains(&DetectorCategory::L2));
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
    }

    #[test]
    fn test_is_withdrawal_finalization_function() {
        let detector = OptimisticChallengeBypassDetector::new();

        assert!(detector.is_withdrawal_finalization_function("finalizeWithdrawal", ""));
        assert!(detector.is_withdrawal_finalization_function("completeWithdrawal", ""));
        assert!(detector.is_withdrawal_finalization_function("proveWithdrawal", ""));
        assert!(!detector.is_withdrawal_finalization_function("deposit", ""));
    }

    #[test]
    fn test_is_state_commitment_function() {
        let detector = OptimisticChallengeBypassDetector::new();

        assert!(detector.is_state_commitment_function("proposeStateRoot", ""));
        assert!(detector.is_state_commitment_function("commitBatch", ""));
        assert!(detector.is_state_commitment_function("submitStateRoot", ""));
        assert!(!detector.is_state_commitment_function("withdraw", ""));
    }

    #[test]
    fn test_is_challenge_function() {
        let detector = OptimisticChallengeBypassDetector::new();

        assert!(detector.is_challenge_function("challengeStateRoot", ""));
        assert!(detector.is_challenge_function("disputeBatch", ""));
        assert!(detector.is_challenge_function("challenge", ""));
        assert!(!detector.is_challenge_function("propose", ""));
    }

    #[test]
    fn test_check_challenge_period_missing_timestamp() {
        let detector = OptimisticChallengeBypassDetector::new();
        let source = "function finalizeWithdrawal() public { }";
        let issues = detector.check_challenge_period(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("timestamp validation")));
    }

    #[test]
    fn test_check_challenge_period_with_validation() {
        let detector = OptimisticChallengeBypassDetector::new();
        let source = r#"
            function finalizeWithdrawal() public {
                require(block.timestamp >= withdrawalTimestamp[msg.sender] + CHALLENGE_PERIOD);
                require(!challenged[withdrawalId]);
            }
        "#;
        let issues = detector.check_challenge_period(source);

        // Should have minimal issues with proper validation
        assert!(issues.len() < 3);
    }

    #[test]
    fn test_check_fraud_proof_mechanism() {
        let detector = OptimisticChallengeBypassDetector::new();
        let source = "function proposeStateRoot(bytes32 root) public { stateRoots.push(root); }";
        let issues = detector.check_fraud_proof_mechanism(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("timestamp metadata")));
    }

    #[test]
    fn test_check_challenge_validation() {
        let detector = OptimisticChallengeBypassDetector::new();
        let source = "function challenge(bytes32 root) public { }";
        let issues = detector.check_challenge_validation(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("bond requirement")));
        assert!(issues.iter().any(|i| i.contains("fraud proof validation")));
    }
}
