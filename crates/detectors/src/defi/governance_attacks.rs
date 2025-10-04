use crate::types::{DetectorResult, AnalysisContext, Severity, Finding, DetectorId, Confidence, SourceLocation};
use ast::Function;
use crate::defi::DeFiDetector;

/// Detector for governance-related attack vulnerabilities
pub struct GovernanceAttackDetector;

impl DeFiDetector for GovernanceAttackDetector {
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Only analyze contracts with governance mechanisms
        if !self.applies_to_contract(ctx) {
            return results;
        }

        results.extend(self.detect_governance_token_flash_loan_attacks(ctx));
        results.extend(self.detect_proposal_spam_vulnerabilities(ctx));
        results.extend(self.detect_vote_buying_risks(ctx));
        results.extend(self.detect_governance_griefing_attacks(ctx));
        results.extend(self.detect_snapshot_manipulation(ctx));
        results.extend(self.detect_quorum_manipulation(ctx));
        results.extend(self.detect_proposal_frontrunning(ctx));

        results
    }

    fn name(&self) -> &'static str {
        "governance-attack-detector"
    }

    fn description(&self) -> &'static str {
        "Detects vulnerabilities in governance mechanisms and voting systems"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool {
        self.has_governance_features(ctx)
    }
}

impl GovernanceAttackDetector {
    /// Detect governance token flash loan attacks
    fn detect_governance_token_flash_loan_attacks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_voting_function(func) && self.vulnerable_to_flash_loan_voting(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Critical,
                    Confidence::High,
                    format!(
                        "Function '{}' allows voting based on current token balance without \
                        protection against flash loan attacks. Attackers can temporarily \
                        acquire large amounts of governance tokens to manipulate votes.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682)  // CWE-682: Incorrect Calculation
                .with_fix_suggestion(
                    "Implement time-weighted voting power, snapshot-based voting, or \
                    minimum holding periods for governance tokens".to_string()
                );

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Very High - Flash loan attacks require complex operations".to_string())
                    .with_suggested_fix(
                        "Implement time-weighted voting power, snapshot-based voting, or \
                        minimum holding periods for governance tokens".to_string()
                    ));
            }
        }

        results
    }

    /// Detect proposal spam vulnerabilities
    fn detect_proposal_spam_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_proposal_creation_function(func) {
                let mut vulnerabilities = Vec::new();

                if !self.has_proposal_threshold(ctx, func) {
                    vulnerabilities.push("No minimum token threshold for proposals");
                }

                if !self.has_proposal_cooldown(ctx, func) {
                    vulnerabilities.push("No cooldown period between proposals");
                }

                if !self.has_proposal_cost(ctx, func) {
                    vulnerabilities.push("No cost or deposit required for proposals");
                }

                if !self.has_spam_protection(ctx, func) {
                    vulnerabilities.push("No spam protection mechanisms");
                }

                if !vulnerabilities.is_empty() {
                    let finding = Finding::new(
                        DetectorId::new(self.name()),
                        Severity::Medium,
                        Confidence::Medium,
                        format!(
                            "Function '{}' is vulnerable to proposal spam attacks: {}. \
                            This could flood the governance system with malicious or low-quality proposals.",
                            func.name.as_str(),
                            vulnerabilities.join(", ")
                        ),
                        SourceLocation::new(
                            ctx.file_path.clone(),
                            func.location.start().line() as u32,
                            0,
                            func.name.as_str().len() as u32,
                        ),
                    ).with_cwe(770);

                    results.push(DetectorResult::new(finding)
                        .with_gas_impact("Medium - Processing many proposals increases gas costs".to_string())
                        .with_suggested_fix(
                            "Implement proposal thresholds, cooldown periods, and spam protection mechanisms".to_string()
                        ));
                }
            }
        }

        results
    }

    /// Detect vote buying risks
    fn detect_vote_buying_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.enables_vote_delegation(ctx, func) && !self.has_vote_buying_protection(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' enables vote delegation without protection against \
                        vote buying schemes. This could allow wealthy actors to purchase \
                        voting power from other token holders.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(284);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Low - Vote delegation is typically gas-efficient".to_string())
                    .with_suggested_fix(
                        "Implement reputation-based voting, identity verification, or \
                        restrictions on delegation transfers".to_string()
                    ));
            }
        }

        results
    }

    /// Detect governance griefing attacks
    fn detect_governance_griefing_attacks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_governance_execution_function(func) &&
               self.vulnerable_to_griefing(ctx, func) {

                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' can be griefed by actors who vote to pass proposals \
                        but then prevent their execution, wasting gas and blocking governance.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(400);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Failed executions waste significant gas".to_string())
                    .with_suggested_fix(
                        "Implement execution guarantees, penalty mechanisms for failed executions, \
                        or automated execution systems".to_string()
                    ));
            }
        }

        results
    }

    /// Detect snapshot manipulation vulnerabilities
    fn detect_snapshot_manipulation(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.uses_voting_snapshots(ctx, func) && self.has_snapshot_manipulation_risk(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' uses voting snapshots that can be manipulated. \
                        Attackers may be able to influence snapshot timing or content \
                        to gain unfair voting advantages.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(367);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Snapshot operations require moderate gas".to_string())
                    .with_suggested_fix(
                        "Use deterministic snapshot timing, implement snapshot validation, \
                        or use time-weighted averages instead of point-in-time snapshots".to_string()
                    ));
            }
        }

        results
    }

    /// Detect quorum manipulation vulnerabilities
    fn detect_quorum_manipulation(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.enforces_quorum(ctx, func) && self.vulnerable_to_quorum_manipulation(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' enforces quorum requirements that can be manipulated. \
                        Attackers may be able to artificially inflate or deflate participation \
                        to affect proposal outcomes.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Quorum calculations are moderately gas-intensive".to_string())
                    .with_suggested_fix(
                        "Implement robust quorum calculations, use time-weighted participation metrics, \
                        or implement adaptive quorum mechanisms".to_string()
                    ));
            }
        }

        results
    }

    /// Detect proposal frontrunning vulnerabilities
    fn detect_proposal_frontrunning(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_proposal_creation_function(func) &&
               !self.has_frontrunning_protection(ctx, func) {

                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' allows proposal creation without frontrunning protection. \
                        Attackers can observe pending proposals and front-run them with \
                        similar or competing proposals.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(362);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Frontrunning involves gas price competition".to_string())
                    .with_suggested_fix(
                        "Implement commit-reveal schemes, proposal queuing systems, \
                        or time delays for proposal submission".to_string()
                    ));
            }
        }

        results
    }

    // Helper methods for governance attack detection

    fn has_governance_features(&self, ctx: &AnalysisContext) -> bool {
        let governance_indicators = [
            "vote", "proposal", "govern", "delegate", "quorum", "snapshot",
            "ballot", "referendum", "poll", "democracy"
        ];
        governance_indicators.iter().any(|&indicator|
            ctx.source_code.to_lowercase().contains(indicator)
        )
    }

    fn is_voting_function(&self, func: &Function) -> bool {
        let voting_patterns = [
            "vote", "castVote", "submitVote", "ballot", "approve", "reject"
        ];
        voting_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn vulnerable_to_flash_loan_voting(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let uses_current_balance = ctx.source_code.contains("balanceOf(") ||
                                  ctx.source_code.contains("currentBalance") ||
                                  ctx.source_code.contains("getBalance");

        let lacks_time_protection = !self.has_time_weighted_voting(ctx) &&
                                   !self.has_snapshot_based_voting(ctx) &&
                                   !self.has_holding_period_requirement(ctx);

        uses_current_balance && lacks_time_protection
    }

    fn has_time_weighted_voting(&self, ctx: &AnalysisContext) -> bool {
        let time_weighted_patterns = [
            "timeWeighted", "averageBalance", "historicalBalance", "weightedVoting"
        ];
        time_weighted_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_snapshot_based_voting(&self, ctx: &AnalysisContext) -> bool {
        let snapshot_patterns = [
            "snapshot", "checkpointBalance", "balanceAt", "votingPower"
        ];
        snapshot_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_holding_period_requirement(&self, ctx: &AnalysisContext) -> bool {
        let holding_patterns = [
            "holdingPeriod", "lockPeriod", "vestingPeriod", "minimumHolding"
        ];
        holding_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn is_proposal_creation_function(&self, func: &Function) -> bool {
        let proposal_patterns = [
            "propose", "createProposal", "submitProposal", "addProposal"
        ];
        proposal_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(&pattern.to_lowercase())
        )
    }

    fn has_proposal_threshold(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let threshold_patterns = [
            "proposalThreshold", "minimumTokens", "requiredBalance", "threshold"
        ];
        threshold_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_proposal_cooldown(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let cooldown_patterns = [
            "cooldown", "delay", "interval", "waitPeriod", "lastProposal"
        ];
        cooldown_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_proposal_cost(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let cost_patterns = [
            "proposalFee", "deposit", "bond", "stake", "cost"
        ];
        cost_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_spam_protection(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let spam_protection_patterns = [
            "rateLimit", "maxProposals", "spamProtection", "antiSpam"
        ];
        spam_protection_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn enables_vote_delegation(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let delegation_patterns = [
            "delegate", "proxy", "representative", "assignVote"
        ];
        delegation_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn has_vote_buying_protection(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let protection_patterns = [
            "identity", "reputation", "verification", "sybilResistance", "antiVoteBuying"
        ];
        protection_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn is_governance_execution_function(&self, func: &Function) -> bool {
        let execution_patterns = [
            "execute", "implement", "enact", "apply", "fulfill"
        ];
        execution_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn vulnerable_to_griefing(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let lacks_execution_guarantee = !ctx.source_code.contains("guarantee") &&
                                       !ctx.source_code.contains("bond") &&
                                       !ctx.source_code.contains("penalty");

        let allows_execution_failure = ctx.source_code.contains("revert") ||
                                      ctx.source_code.contains("fail");

        lacks_execution_guarantee && allows_execution_failure
    }

    fn uses_voting_snapshots(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let snapshot_patterns = [
            "snapshot", "checkpoint", "balanceAt", "totalSupplyAt"
        ];
        snapshot_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn has_snapshot_manipulation_risk(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let manipulation_indicators = [
            "block.number", "block.timestamp", "now"
        ];
        manipulation_indicators.iter().any(|&indicator|
            ctx.source_code.contains(indicator)
        ) && !self.has_deterministic_snapshots(ctx)
    }

    fn has_deterministic_snapshots(&self, ctx: &AnalysisContext) -> bool {
        let deterministic_patterns = [
            "fixedSnapshot", "predeterminedSnapshot", "scheduledSnapshot"
        ];
        deterministic_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn enforces_quorum(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let quorum_patterns = [
            "quorum", "minimumParticipation", "requiredVotes", "threshold"
        ];
        quorum_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }

    fn vulnerable_to_quorum_manipulation(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let uses_simple_quorum = ctx.source_code.contains("totalSupply") &&
                                !ctx.source_code.contains("timeWeighted");

        let lacks_participation_validation = !ctx.source_code.contains("validateParticipation") &&
                                            !ctx.source_code.contains("verifyQuorum");

        uses_simple_quorum && lacks_participation_validation
    }

    fn has_frontrunning_protection(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let protection_patterns = [
            "commitReveal", "delay", "queue", "timelock", "batch"
        ];
        protection_patterns.iter().any(|&pattern|
            ctx.source_code.contains(pattern)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::*;
    use ast::{AstArena, Visibility, StateMutability};

    #[test]
    fn test_voting_function_detection() {
        let detector = GovernanceAttackDetector;
        let arena = AstArena::new();

        let function = create_mock_ast_function(
            &arena,
            "castVote",
            Visibility::External,
            StateMutability::NonPayable,
        );

        assert!(detector.is_voting_function(&function));
    }

    #[test]
    fn test_proposal_creation_detection() {
        let detector = GovernanceAttackDetector;
        let arena = AstArena::new();

        let function = create_mock_ast_function(
            &arena,
            "createProposal",
            Visibility::External,
            StateMutability::NonPayable,
        );


        assert!(detector.is_proposal_creation_function(&function));
    }

    #[test]
    fn test_flash_loan_voting_vulnerability() {
        let detector = GovernanceAttackDetector;
        let arena = AstArena::new();

        let function = create_mock_ast_function(
            &arena,
            "vote",
            Visibility::External,
            StateMutability::NonPayable,
        );

        let contract = create_mock_ast_contract(&arena, "TestContract", vec![function]);

        let ctx = AnalysisContext {
            contract: &contract,
            symbols: semantic::SymbolTable::new(),
            source_code: "function vote() { uint power = token.balanceOf(msg.sender); }".to_string(),
            file_path: "test.sol".to_string(),
        };

        assert!(detector.vulnerable_to_flash_loan_voting(&ctx, &ctx.contract.functions[0]));
    }

    #[test]
    fn test_detector_properties() {
        let detector = GovernanceAttackDetector;
        assert_eq!(detector.name(), "governance-attack-detector");
        assert_eq!(detector.severity(), Severity::High);
        assert!(!detector.description().is_empty());
    }
}