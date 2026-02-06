use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for proposal front-running vulnerabilities
///
/// Detects patterns where governance proposals can be front-run with
/// counter-proposals in the same block to manipulate voting outcomes.
///
/// Phase 53 FP Reduction: This detector now requires the contract to be an
/// actual governance protocol before reporting findings. It skips:
/// - Flash loan contracts (propose != governance proposal)
/// - View/pure functions (read-only, not exploitable)
/// - Non-governance contracts that happen to use "propose" or "vote" keywords
/// - Voting delay values with time units (e.g., "1 days" is not "very low")
pub struct ProposalFrontrunningDetector {
    base: BaseDetector,
}

impl Default for ProposalFrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalFrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("proposal-frontrunning"),
                "Proposal Front-running".to_string(),
                "Detects governance systems vulnerable to proposal front-running where \
                 attackers can submit counter-proposals in the same block."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Check if the contract is an actual governance contract with governance
    /// state variables and patterns (proposals mapping, voting mechanisms, etc.)
    ///
    /// This is a lighter-weight check than `utils::is_governance_protocol` that
    /// focuses on governance state rather than function signatures, to avoid
    /// false positives on flash loan or DeFi contracts that happen to have
    /// functions named "propose" or reference "vote".
    fn is_governance_contract(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Must have proposal-related state (mapping or struct)
        let has_proposals_state = source.contains("mapping")
            && (lower.contains("proposals") || lower.contains("proposal"))
            && (source.contains("struct Proposal")
                || lower.contains("proposalcount")
                || lower.contains("proposalid"));

        // Must have voting mechanism state
        let has_voting_state = lower.contains("votingdelay")
            || lower.contains("voting_delay")
            || lower.contains("votingperiod")
            || lower.contains("voting_period")
            || lower.contains("quorum")
            || lower.contains("forvotes")
            || lower.contains("againstvotes");

        // Must have at least proposals + voting state
        has_proposals_state && has_voting_state
    }

    /// Check if the contract is a flash loan contract that should be skipped.
    /// Flash loan contracts may have "propose" functions that are unrelated
    /// to governance proposals.
    fn is_flash_loan_contract(&self, ctx: &AnalysisContext) -> bool {
        utils::is_flash_loan_context(ctx) || utils::is_flash_loan_provider(ctx)
    }

    /// Check if a function declaration line is a view or pure function.
    /// View/pure functions are read-only and cannot be exploited for
    /// proposal front-running.
    fn is_view_or_pure_function(&self, lines: &[&str], func_line: usize) -> bool {
        // Check the function declaration, which may span multiple lines
        let check_end = (func_line + 5).min(lines.len());
        let decl: String = lines[func_line..check_end].join(" ");

        // Look for view/pure keywords before the opening brace
        if let Some(brace_pos) = decl.find('{') {
            let before_brace = &decl[..brace_pos];
            return before_brace.contains(" view") || before_brace.contains(" pure");
        }

        // If no brace found in the range, check the declaration line itself
        let trimmed = lines[func_line].trim();
        trimmed.contains(" view") || trimmed.contains(" pure")
    }

    /// Find proposal front-running vulnerabilities
    fn find_frontrun_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for proposal creation functions
            if trimmed.contains("function ")
                && (trimmed.contains("propose") || trimmed.contains("createProposal"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                // Phase 53: Skip view/pure functions
                if self.is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for same-block proposal prevention
                let has_block_protection = func_body.contains("lastProposalBlock")
                    || func_body.contains("block.number >")
                    || func_body.contains("proposalCooldown");

                if !has_block_protection {
                    let issue = "No same-block proposal prevention".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for commit-reveal protection
                let has_commit_reveal = func_body.contains("commit")
                    || func_body.contains("reveal")
                    || func_body.contains("sealed");

                if !has_commit_reveal {
                    let issue = "No commit-reveal scheme for proposal content".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find proposal ID prediction vulnerabilities
    fn find_proposal_id_prediction(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for predictable proposal ID generation
            // Phase 53: Only match when keccak256 is used to *assign* a proposalId,
            // not when proposalId is merely referenced alongside keccak256 (e.g., EIP-712
            // signature hashing in castVoteBySig).
            if trimmed.contains("proposalId") && trimmed.contains("keccak256") {
                // Must be an assignment to proposalId, not just a reference
                let is_proposal_id_assignment = trimmed.contains("proposalId =")
                    || trimmed.contains("proposalId=")
                    || trimmed.contains("proposalId = keccak256");

                if !is_proposal_id_assignment {
                    continue;
                }

                // Check if hash includes unpredictable components
                let context_end = (line_num + 3).min(lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                let has_randomness = context.contains("block.prevrandao")
                    || context.contains("chainlink")
                    || context.contains("VRF");

                if !has_randomness && !context.contains("msg.sender") && !context.contains("nonce")
                {
                    let func_name = self.find_containing_function(&lines, line_num);

                    // Phase 53: Skip view/pure functions
                    if self.is_view_or_pure_function_by_name(&lines, &func_name) {
                        continue;
                    }

                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find voting delay issues
    fn find_voting_delay_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for zero or very low voting delay
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if (trimmed.contains("votingDelay") || trimmed.contains("VOTING_DELAY"))
                && trimmed.contains("=")
            {
                // Phase 53: Check for zero or very low delay, but exclude values
                // with time units like "1 days", "1 hours", "1 minutes" which are
                // reasonable delays (not "very low").
                let is_zero = trimmed.contains("= 0;") || trimmed.contains("= 0 ;");
                let is_bare_one = (trimmed.contains("= 1;") || trimmed.contains("= 1 ;"))
                    && !self.has_time_unit_after_value(trimmed);

                if is_zero || is_bare_one {
                    let func_name = self.find_containing_function(&lines, line_num);

                    // Phase 53: Skip view/pure functions
                    if self.is_view_or_pure_function_by_name(&lines, &func_name) {
                        continue;
                    }

                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Check if a voting delay value has a Solidity time unit suffix.
    /// Values like "= 1 days", "= 1 hours" represent meaningful delays
    /// and should not be flagged as "very low".
    fn has_time_unit_after_value(&self, line: &str) -> bool {
        let time_units = [
            "days", "hours", "minutes", "weeks", "seconds", "day", "hour", "minute", "week",
            "second",
        ];

        for unit in &time_units {
            // Match patterns like "= 1 days" or "= 0 hours"
            if line.contains(&format!("= 0 {}", unit)) || line.contains(&format!("= 1 {}", unit)) {
                return true;
            }
        }
        false
    }

    /// Check if a function (found by name) is view or pure by scanning
    /// the source for its declaration.
    fn is_view_or_pure_function_by_name(&self, lines: &[&str], func_name: &str) -> bool {
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("function ") && trimmed.contains(func_name) {
                return self.is_view_or_pure_function(lines, i);
            }
        }
        false
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "constructor".to_string()
    }

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ProposalFrontrunningDetector {
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
        let source = &ctx.source_code;

        // Phase 53 FP Reduction: Only analyze actual governance contracts.
        // Skip flash loan contracts where "propose" has nothing to do with
        // governance proposals, and skip non-governance contracts entirely.
        if self.is_flash_loan_contract(ctx) {
            return Ok(Vec::new());
        }

        if !self.is_governance_contract(source) {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, issue) in self.find_frontrun_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' is vulnerable to proposal front-running. {}. \
                 Attackers can observe proposals in mempool and submit counter-proposals first.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect against proposal front-running:\n\n\
                     1. Implement commit-reveal for proposals\n\
                     2. Add minimum delay between proposals from same proposer\n\
                     3. Prevent multiple proposals in same block\n\
                     4. Use private mempool (Flashbots) for submission\n\n\
                     Example:\n\
                     require(block.number > lastProposalBlock[msg.sender] + 1, \
                     \"Wait before next proposal\");\n\
                     lastProposalBlock[msg.sender] = block.number;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_proposal_id_prediction(source) {
            let message = format!(
                "Proposal ID in '{}' of contract '{}' is predictable. \
                 Attackers can pre-compute IDs and prepare front-running attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Make proposal IDs less predictable:\n\n\
                     1. Include msg.sender in ID hash\n\
                     2. Add incrementing nonce per proposer\n\
                     3. Include previous proposal ID in hash chain"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_voting_delay_issues(source) {
            let message = format!(
                "Voting delay in '{}' of contract '{}' is zero or very low. \
                 This allows immediate voting after proposal, enabling front-running.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Set appropriate voting delay:\n\n\
                     1. Use minimum 1-day delay for mainnet\n\
                     2. Allow users time to review proposals\n\
                     3. Delay prevents same-block voting manipulation\n\n\
                     Example: uint256 public constant VOTING_DELAY = 7200; // ~1 day"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = ProposalFrontrunningDetector::new();
        assert_eq!(detector.name(), "Proposal Front-running");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // ---------------------------------------------------------------
    // False positive tests: flash loan contracts should produce no findings
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_flash_loan_propose_function() {
        // Flash loan contract with a "propose" function that is NOT governance
        let source = r#"
contract VulnerableGovernanceFlashLoan {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    struct Proposal {
        address proposer;
        uint256 votes;
        bool executed;
    }

    function propose(string calldata description) external returns (uint256) {
        require(votingPower[msg.sender] > 0, "No voting power");
        proposalCount++;
        return proposalCount;
    }

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
    }
}

interface IFlashBorrower {
    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32);
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Flash loan contracts with 'propose' should not trigger proposal-frontrunning. Got {} findings",
            findings.len()
        );
    }

    #[test]
    fn test_no_fp_secure_flash_loan_propose() {
        // SecureGovernanceFlashLoan-style contract with propose + flash loan patterns
        let source = r#"
contract SecureGovernanceFlashLoan {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public constant VOTING_DELAY = 1 days;

    struct Proposal {
        address proposer;
        uint256 votes;
        uint256 snapshotBlock;
        bool executed;
    }

    function propose(string calldata description) external returns (uint256) {
        require(votingPower[msg.sender] > 0, "No voting power");
        proposalCount++;
        return proposalCount;
    }

    function getSecurePrice(address token) external view returns (uint256) {
        return 1e18;
    }
}

interface IFlashBorrower {
    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32);
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Flash loan contracts should not trigger proposal-frontrunning. Got {} findings",
            findings.len()
        );
    }

    // ---------------------------------------------------------------
    // False positive tests: view/pure functions should not be flagged
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_view_function_get_past_votes() {
        // getPastVotes is a view function -- should never be flagged
        let source = r#"
contract DAOGovernance {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 3 days;
    uint256 public quorum = 4;
    uint256 public forVotes;
    uint256 public againstVotes;

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 forVotes;
    }

    function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (uint256) {
        proposalCount++;
        return proposalCount;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        proposal.forVotes = 0;
    }

    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256) {
        return 0;
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();

        // Should have findings for the propose function, but NOT for getPastVotes
        for f in &findings {
            assert!(
                !f.message.contains("getPastVotes"),
                "View function getPastVotes should not be flagged: {}",
                f.message
            );
        }
    }

    // ---------------------------------------------------------------
    // False positive tests: voting delay with time units
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_voting_delay_with_time_unit() {
        // "votingDelay = 1 days" is a reasonable delay, not "very low"
        let source = r#"
contract DAOGovernance {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 3 days;
    uint256 public quorum = 4;
    uint256 public forVotes;

    struct Proposal {
        uint256 id;
        address proposer;
    }

    function propose(address[] memory targets) external returns (uint256) {
        proposalCount++;
        return proposalCount;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function execute(uint256 proposalId) external {
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();

        for f in &findings {
            assert!(
                !f.message.contains("Voting delay"),
                "votingDelay = 1 days should not be flagged as zero/very low: {}",
                f.message
            );
        }
    }

    // ---------------------------------------------------------------
    // False positive tests: keccak256 for EIP-712, not proposal ID
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_keccak256_eip712_signature() {
        // castVoteBySig uses keccak256 for EIP-712 domain separator, not proposal ID
        let source = r#"
contract DAOGovernance {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 3 days;
    uint256 public quorum = 4;
    uint256 public forVotes;

    struct Proposal {
        uint256 id;
        address proposer;
    }

    function propose(address[] memory targets) external returns (uint256) {
        proposalCount++;
        return proposalCount;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function castVoteBySig(uint256 proposalId, uint8 support, uint8 v, bytes32 r, bytes32 s) external returns (uint256) {
        bytes32 structHash = keccak256(abi.encode(keccak256("Ballot(uint256 proposalId,uint8 support)"), proposalId, support));
        return 0;
    }

    function execute(uint256 proposalId) external {
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();

        for f in &findings {
            assert!(
                !f.message.contains("predictable") || !f.message.contains("castVoteBySig"),
                "EIP-712 keccak256 in castVoteBySig should not be flagged as predictable proposal ID: {}",
                f.message
            );
        }
    }

    // ---------------------------------------------------------------
    // False positive tests: non-governance contracts
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_non_governance_contract_with_propose() {
        // A contract that has "propose" but no governance state
        let source = r#"
contract SimpleAuction {
    mapping(address => uint256) public bids;

    function propose(uint256 amount) external {
        bids[msg.sender] = amount;
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Non-governance contract with 'propose' should not trigger findings. Got {} findings",
            findings.len()
        );
    }

    // ---------------------------------------------------------------
    // True positive tests: real governance vulnerabilities still detected
    // ---------------------------------------------------------------

    #[test]
    fn test_tp_governance_contract_without_protection() {
        // A real governance contract without front-running protection
        let source = r#"
contract VulnerableGovernor {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 0;
    uint256 public votingPeriod = 3 days;
    uint256 public quorum = 4;
    uint256 public forVotes;

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 forVotes;
    }

    function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (uint256) {
        proposalCount++;
        return proposalCount;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function execute(uint256 proposalId) external {
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            !findings.is_empty(),
            "Governance contract without protection should produce findings"
        );

        // Should flag the propose function
        let has_propose_finding = findings.iter().any(|f| f.message.contains("propose"));
        assert!(
            has_propose_finding,
            "Should flag the unprotected propose function"
        );

        // Should flag zero voting delay
        let has_delay_finding = findings.iter().any(|f| f.message.contains("Voting delay"));
        assert!(has_delay_finding, "Should flag votingDelay = 0");
    }

    #[test]
    fn test_tp_governance_contract_bare_one_delay() {
        // votingDelay = 1 (bare number, 1 block) is too low
        let source = r#"
contract VulnerableGovernor {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 1;
    uint256 public votingPeriod = 100;
    uint256 public quorum = 4;
    uint256 public forVotes;

    struct Proposal {
        uint256 id;
        address proposer;
    }

    function propose(address[] memory targets) external returns (uint256) {
        proposalCount++;
        return proposalCount;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function execute(uint256 proposalId) external {
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();

        let has_delay_finding = findings.iter().any(|f| f.message.contains("Voting delay"));
        assert!(
            has_delay_finding,
            "votingDelay = 1 (bare, 1 block) should be flagged as too low"
        );
    }

    #[test]
    fn test_tp_predictable_proposal_id() {
        // Proposal ID computed with keccak256 but no unpredictable components
        let source = r#"
contract VulnerableGovernor {
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingDelay = 0;
    uint256 public votingPeriod = 100;
    uint256 public quorum = 4;
    uint256 public forVotes;

    struct Proposal {
        uint256 id;
        address proposer;
    }

    function propose(address[] memory targets) external returns (uint256) {
        uint256 proposalId = keccak256(abi.encode(targets, block.timestamp));
        proposals[proposalId].id = proposalId;
        proposals[proposalId].proposer = address(0);
        return proposalId;
    }

    function castVote(uint256 proposalId, uint8 support) external returns (uint256) {
        return 0;
    }

    function execute(uint256 proposalId) external {
    }
}
"#;
        let detector = ProposalFrontrunningDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();

        let has_predictable_finding = findings.iter().any(|f| f.message.contains("predictable"));
        assert!(
            has_predictable_finding,
            "Predictable proposal ID should be flagged"
        );
    }
}
