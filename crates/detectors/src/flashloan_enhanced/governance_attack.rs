//! Flash Loan Governance Attack Detector
//!
//! Detects DAO takeover attacks via flash-borrowed governance tokens.
//! Prevents temporary voting power exploits to pass malicious proposals.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct FlashLoanGovernanceAttackDetector {
    base: BaseDetector,
}

impl FlashLoanGovernanceAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flash-loan-governance-attack".to_string()),
                "Flash Loan Governance Attack".to_string(),
                "Detects DAO takeover via flash-borrowed governance tokens".to_string(),
                vec![DetectorCategory::FlashLoan, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }
}

impl Default for FlashLoanGovernanceAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashLoanGovernanceAttackDetector {
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

        // Check for governance functionality
        let is_governance = lower.contains("proposal")
            || lower.contains("vote")
            || lower.contains("governance")
            || lower.contains("propose");

        if !is_governance {
            return Ok(findings);
        }

        // Pattern 1: Voting power based on current token balance
        let has_voting = lower.contains("vote") || lower.contains("castvote");
        if has_voting {
            let uses_current_balance = lower.contains("balanceof(msg.sender)")
                || lower.contains("balanceof(voter)")
                || (lower.contains("balanceof") && lower.contains("votingpower"));

            let has_snapshot = lower.contains("snapshot")
                || lower.contains("getpriorvotes")
                || lower.contains("delegates")
                || lower.contains("checkpoint");

            if uses_current_balance && !has_snapshot {
                let finding = self.base.create_finding(
                    ctx,
                    "Voting power based on current balance - vulnerable to flash loan governance attack".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use snapshot-based voting (e.g., OpenZeppelin Governor with vote delay and checkpoints)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No vote delay between proposal and execution
        let has_propose = lower.contains("propose");
        if has_propose {
            let has_delay = lower.contains("votingdelay")
                || lower.contains("proposaldelay")
                || lower.contains("timelock")
                || lower.contains("block.timestamp + delay");

            if !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "No voting delay - proposals can be created and voted on in same transaction via flash loan".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum voting delay (e.g., 1 day) between proposal creation and voting period start".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: No minimum holding period for voting
        if has_voting {
            let has_holding_period = lower.contains("holdingperiod")
                || lower.contains("minimumstake")
                || lower.contains("lockeduntil")
                || lower.contains("vestedtokens");

            if !has_holding_period {
                let finding = self.base.create_finding(
                    ctx,
                    "No minimum token holding period - flash-borrowed tokens can vote immediately".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require minimum token holding period (e.g., 7 days) before tokens can be used for voting".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Quorum based on total supply (manipulable)
        if is_governance {
            let has_quorum = lower.contains("quorum");
            if has_quorum {
                let quorum_based_on_supply = lower.contains("totalsupply")
                    && (lower.contains("quorum") || lower.contains("threshold"));

                let has_delegation = lower.contains("delegate")
                    || lower.contains("delegated")
                    || lower.contains("votingpower");

                if quorum_based_on_supply && !has_delegation {
                    let finding = self.base.create_finding(
                        ctx,
                        "Quorum based on total supply without delegation - flash loan can inflate supply to reduce quorum".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Use fixed quorum or base quorum on circulating delegated votes, not total supply".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 5: Emergency proposals without timelock
        if has_propose {
            let has_emergency = lower.contains("emergency")
                || lower.contains("urgent")
                || lower.contains("critical");

            let has_timelock = lower.contains("timelock")
                || lower.contains("executiondelay")
                || lower.contains("queuedtransactions");

            if has_emergency && !has_timelock {
                let finding = self.base.create_finding(
                    ctx,
                    "Emergency proposals lack timelock - can be flash-loan attacked for immediate execution".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Even emergency proposals should have minimal timelock (e.g., 1 hour) and require multisig".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: Proposal execution based on vote count, not percentage
        if is_governance {
            let has_execute = lower.contains("execute") || lower.contains("executeproposal");
            if has_execute {
                let uses_absolute_votes = (lower.contains("votecount >")
                    || lower.contains("votes >="))
                    && !lower.contains("%")
                    && !lower.contains("percentage");

                if uses_absolute_votes {
                    let finding = self.base.create_finding(
                        ctx,
                        "Proposal execution based on absolute vote count - flash loan can meet threshold temporarily".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Use percentage-based thresholds (e.g., >50% of circulating votes) instead of absolute counts".to_string()
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
