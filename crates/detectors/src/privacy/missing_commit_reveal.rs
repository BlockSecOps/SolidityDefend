//! Missing Commit-Reveal Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MissingCommitRevealDetector {
    base: BaseDetector,
}

impl MissingCommitRevealDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-commit-reveal".to_string()),
                "Missing Commit-Reveal Scheme".to_string(),
                "Detects auctions/bidding without commit-reveal protection".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }
}

impl Default for MissingCommitRevealDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MissingCommitRevealDetector {
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
        let source_lower = ctx.source_code.to_lowercase();

        // Check for auction/bidding patterns without commit-reveal
        let is_auction = source_lower.contains("bid") || source_lower.contains("auction");
        let has_commit_reveal = source_lower.contains("commit") && source_lower.contains("reveal");

        if is_auction && !has_commit_reveal {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Auction/bidding without commit-reveal - bids can be front-run".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Implement commit-reveal pattern:\n\
                 \n\
                 mapping(address => bytes32) public commitments;\n\
                 mapping(address => uint256) public bids;\n\
                 uint256 public commitDeadline;\n\
                 uint256 public revealDeadline;\n\
                 \n\
                 // Phase 1: Commit (hide bid amount)\n\
                 function commitBid(bytes32 commitment) external {\n\
                     require(block.timestamp < commitDeadline);\n\
                     commitments[msg.sender] = commitment;\n\
                 }\n\
                 \n\
                 // Phase 2: Reveal (after commit deadline)\n\
                 function revealBid(uint256 amount, bytes32 salt) external payable {\n\
                     require(block.timestamp >= commitDeadline);\n\
                     require(block.timestamp < revealDeadline);\n\
                     \n\
                     bytes32 commitment = keccak256(abi.encode(amount, salt));\n\
                     require(commitment == commitments[msg.sender], \"Invalid reveal\");\n\
                     require(msg.value == amount, \"Amount mismatch\");\n\
                     \n\
                     bids[msg.sender] = amount;\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
