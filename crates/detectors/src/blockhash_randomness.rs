use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for weak randomness using blockhash/prevrandao
///
/// Detects patterns where block.prevrandao, blockhash, or similar block
/// variables are used as sources of randomness, which can be manipulated.
pub struct BlockhashRandomnessDetector {
    base: BaseDetector,
}

impl Default for BlockhashRandomnessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockhashRandomnessDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("blockhash-randomness"),
                "Blockhash Randomness".to_string(),
                "Detects weak randomness patterns using block.prevrandao, blockhash, \
                 or other block variables that can be manipulated by miners/validators."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Check if the containing function is view or pure (informational only, not exploitable).
    fn is_view_or_pure_function(&self, lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                // Gather the full function signature which may span multiple lines
                let mut sig = trimmed.to_string();
                for j in (i + 1)..lines.len().min(i + 6) {
                    let next = lines[j].trim();
                    sig.push(' ');
                    sig.push_str(next);
                    if next.contains('{') || next.contains(';') {
                        break;
                    }
                }
                let sig_lower = sig.to_lowercase();
                return sig_lower.contains(" view") || sig_lower.contains(" pure");
            }
        }
        false
    }

    /// Extract the source body of a specific contract from the full file source.
    /// Returns (contract_source_slice, line_offset) where line_offset is the
    /// 0-based line index where the contract starts in the full file.
    fn extract_contract_source<'a>(&self, source: &'a str, contract_name: &str) -> (&'a str, u32) {
        // Look for "contract <name>" (also "abstract contract", "library", "interface")
        let patterns = [
            format!("contract {}", contract_name),
            format!("abstract contract {}", contract_name),
            format!("library {}", contract_name),
            format!("interface {}", contract_name),
        ];
        for pat in &patterns {
            if let Some(start_idx) = source.find(pat.as_str()) {
                // Count newlines before start_idx to get line offset
                let line_offset = source[..start_idx].matches('\n').count() as u32;
                // Find the opening brace
                if let Some(brace_offset) = source[start_idx..].find('{') {
                    let body_start = start_idx + brace_offset;
                    let mut depth = 0i32;
                    for (i, c) in source[body_start..].char_indices() {
                        match c {
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    return (&source[start_idx..body_start + i + 1], line_offset);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        // Fallback: return full source if contract boundary not found
        (source, 0)
    }

    /// Check if the contract source has commit-reveal or VRF patterns indicating
    /// adequate randomness protection at the contract level.
    fn has_secure_randomness_pattern(&self, contract_source: &str) -> bool {
        let lower = contract_source.to_lowercase();
        // Commit-reveal pattern: both "commit" and "reveal" must appear in function
        // names or as identifiers within THIS contract
        let has_commit_reveal =
            lower.contains("function commit") && lower.contains("function reveal");
        // VRF / Chainlink integration
        let has_vrf = lower.contains("vrfconsumerbase")
            || lower.contains("vrfcoordinator")
            || lower.contains("fulfillrandomwords")
            || lower.contains("requestrandomness")
            || lower.contains("requestrandomwords");
        has_commit_reveal || has_vrf
    }

    /// Check whether a line using keccak256 + block variables is actually for
    /// randomness versus generating a unique identifier / hash key.
    fn is_randomness_context(&self, lines: &[&str], line_num: usize) -> bool {
        let trimmed = lines[line_num].trim().to_lowercase();

        // If the result is assigned to something clearly random-related, flag it
        let randomness_indicators = [
            "random", "rand", "seed", "entropy", "winner", "lottery", "roll", "flip", "dice",
            "gambl", "lucky", "rng",
        ];
        for indicator in &randomness_indicators {
            if trimmed.contains(indicator) {
                return true;
            }
        }

        // If the result is used as a modulo operation (common randomness pattern:
        // uint256(...) % N), flag it
        if trimmed.contains("% ") || trimmed.contains("%)") {
            return true;
        }

        // Check surrounding lines (2 before, 2 after) for randomness context
        let start = line_num.saturating_sub(2);
        let end = (line_num + 3).min(lines.len());
        for i in start..end {
            if i == line_num {
                continue;
            }
            let ctx_line = lines[i].trim().to_lowercase();
            for indicator in &randomness_indicators {
                if ctx_line.contains(indicator) {
                    return true;
                }
            }
        }

        // Identification / unique-key patterns: if the result is stored in a
        // mapping, used as a key, or assigned to an "id" / "hash" / "root" variable,
        // it is not randomness.
        let id_indicators = [
            "id ", "id=", "hash", "root", "key", "upgrade", "proposal", "queue", "pending",
            "mapping", "encode(",
        ];
        for indicator in &id_indicators {
            if trimmed.contains(indicator) {
                return false;
            }
        }

        // Default: if none of the above matched, still flag it for prevrandao/difficulty
        // usage (those are almost always randomness), but not for timestamp/number
        if trimmed.contains("block.prevrandao") || trimmed.contains("block.difficulty") {
            return true;
        }

        false
    }

    /// Find weak randomness patterns
    fn find_weak_randomness(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Skip view/pure functions -- they cannot modify state and are not exploitable
            if self.is_view_or_pure_function(&lines, line_num) {
                continue;
            }

            // Detect block.prevrandao usage
            if trimmed.contains("block.prevrandao") || trimmed.contains("block.difficulty") {
                if self.is_randomness_context(&lines, line_num) {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let issue = "block.prevrandao/difficulty used as randomness source".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect blockhash usage for randomness
            if trimmed.contains("blockhash(") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if it's being used in a hash/random context
                if trimmed.contains("keccak256")
                    || trimmed.contains("random")
                    || trimmed.contains("seed")
                    || trimmed.contains("entropy")
                {
                    let issue = "blockhash used as randomness seed".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect keccak256 with block variables -- require randomness context
            if trimmed.contains("keccak256")
                && (trimmed.contains("block.timestamp")
                    || trimmed.contains("block.number")
                    || trimmed.contains("block.coinbase")
                    || trimmed.contains("block.prevrandao"))
            {
                if self.is_randomness_context(&lines, line_num) {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let issue = "keccak256 hash of block variables for randomness".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Words that, when appearing in a function name, indicate lottery/game/randomness
    /// semantics. These must be matched as whole-word boundaries to avoid false positives
    /// like "withdraw" matching "draw".
    const RANDOMNESS_FUNCTION_KEYWORDS: &'static [&'static str] = &[
        "random", "Random", "lottery", "Lottery", "winner", "roll", "flip",
    ];

    /// Check if a function name contains a randomness-related keyword as a
    /// whole word (not as a substring of another word like "withdraw").
    fn function_name_indicates_randomness(func_name: &str) -> bool {
        // Specific substring check for "draw" that must NOT be part of "withdraw"/"withdrawal"
        let lower = func_name.to_lowercase();
        for kw in Self::RANDOMNESS_FUNCTION_KEYWORDS {
            if lower.contains(&kw.to_lowercase()) {
                return true;
            }
        }
        // Special handling for "draw": must not be preceded by "with"
        if lower.contains("draw") {
            // Find all occurrences of "draw"
            let mut start = 0;
            while let Some(pos) = lower[start..].find("draw") {
                let abs_pos = start + pos;
                // Check it is not part of "withdraw"
                let is_withdraw = abs_pos >= 4 && &lower[abs_pos - 4..abs_pos] == "with";
                if !is_withdraw {
                    return true;
                }
                start = abs_pos + 4;
            }
        }
        false
    }

    /// Find randomness in critical functions
    fn find_critical_randomness_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect lottery/game/random functions
            if trimmed.contains("function ") {
                let func_name = self.extract_function_name(trimmed);

                if !Self::function_name_indicates_randomness(&func_name) {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if using weak randomness
                if (func_body.contains("block.") || func_body.contains("blockhash"))
                    && !func_body.contains("chainlink")
                    && !func_body.contains("vrf")
                    && !func_body.contains("VRF")
                    && !func_body.contains("oracle")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find predictable seed patterns.
    ///
    /// Only flag lines where the variable being assigned is clearly a randomness
    /// seed or entropy source (not a nonce used for replay protection).
    fn find_predictable_seeds(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Skip view/pure functions
            if self.is_view_or_pure_function(&lines, line_num) {
                continue;
            }

            // Only flag "seed" and "entropy" assignments with block/tx variables.
            // "nonce" is excluded because nonce management patterns (nonces[msg.sender],
            // currentNonce = nonces[...], nonce++) are overwhelmingly replay-protection
            // code, not randomness seeds. Nonce-based randomness will still be caught
            // by find_weak_randomness if it is hashed with block variables.
            let has_seed_keyword =
                trimmed.contains("seed") || trimmed.contains("Seed") || trimmed.contains("entropy");

            if !has_seed_keyword {
                continue;
            }

            if trimmed.contains("=")
                && (trimmed.contains("block.")
                    || trimmed.contains("tx.")
                    || trimmed.contains("msg.sender"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
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

impl Detector for BlockhashRandomnessDetector {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Scope analysis to only the current contract's source to avoid
        // cross-contamination in multi-contract files.
        let (contract_source, line_offset) = self.extract_contract_source(source, &contract_name);

        // If the contract uses commit-reveal or VRF patterns, skip weak-randomness
        // findings since those are adequate protection mechanisms.
        let has_secure_pattern = self.has_secure_randomness_pattern(contract_source);

        if !has_secure_pattern {
            for (line, func_name, issue) in self.find_weak_randomness(contract_source) {
                let message = format!(
                    "Function '{}' in contract '{}' uses weak randomness: {}. \
                     Miners/validators can manipulate block variables to influence outcomes.",
                    func_name, contract_name, issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line + line_offset, 1, 50)
                    .with_cwe(330)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Use secure randomness sources:\n\n\
                         1. Chainlink VRF for verifiable randomness\n\
                         2. Commit-reveal schemes with economic incentives\n\
                         3. External oracle services\n\
                         4. RANDAO with proper delay (post-merge)\n\n\
                         Example with Chainlink VRF:\n\
                         uint256 requestId = COORDINATOR.requestRandomWords(...);\n\
                         // Handle in fulfillRandomWords callback"
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        for (line, func_name) in self.find_critical_randomness_usage(contract_source) {
            let message = format!(
                "Function '{}' in contract '{}' appears to be a lottery/game function \
                 using on-chain randomness. This is exploitable by miners/validators.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line + line_offset, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Critical randomness functions require secure sources:\n\n\
                     1. Integrate Chainlink VRF v2/v2.5\n\
                     2. Use commit-reveal with bonded participants\n\
                     3. Consider hybrid approaches (VRF + commit-reveal)\n\
                     4. Add delays between action and resolution"
                        .to_string(),
                );

            findings.push(finding);
        }

        if !has_secure_pattern {
            for (line, func_name) in self.find_predictable_seeds(contract_source) {
                let message = format!(
                    "Function '{}' in contract '{}' uses predictable values for seed/entropy. \
                     Attackers can predict or influence the random outcome.",
                    func_name, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line + line_offset, 1, 50)
                    .with_cwe(330)
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Use unpredictable entropy sources:\n\n\
                         1. Chainlink VRF provides cryptographic randomness\n\
                         2. Commit-reveal prevents prediction\n\
                         3. Multiple independent entropy sources\n\
                         4. Time-delayed revelation"
                            .to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = BlockhashRandomnessDetector::new();
        assert_eq!(detector.name(), "Blockhash Randomness");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // -----------------------------------------------------------------------
    // Helper: run find_* methods directly on source strings
    // -----------------------------------------------------------------------

    #[test]
    fn test_view_function_skipped() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Test {
    function getTimestamp() public view returns (uint256) {
        return uint256(keccak256(abi.encode(block.timestamp)));
    }
}
"#;
        let findings = detector.find_weak_randomness(source);
        assert!(
            findings.is_empty(),
            "view function using block.timestamp in keccak256 should not be flagged"
        );
    }

    #[test]
    fn test_pure_function_skipped() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Test {
    function compute(uint256 ts) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(ts)));
    }
}
"#;
        let findings = detector.find_weak_randomness(source);
        assert!(findings.is_empty(), "pure function should not be flagged");
    }

    #[test]
    fn test_id_generation_not_flagged() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Upgradeable {
    function proposeUpgrade(address newImpl) external {
        bytes32 upgradeId = keccak256(abi.encode(newImpl, block.timestamp));
        pending[upgradeId] = true;
    }
}
"#;
        let findings = detector.find_weak_randomness(source);
        assert!(
            findings.is_empty(),
            "keccak256 of block.timestamp for ID generation should not be flagged"
        );
    }

    #[test]
    fn test_true_positive_randomness() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Lottery {
    function playGame(uint256 guess) external {
        uint256 randomNumber = uint256(keccak256(abi.encode(block.timestamp))) % 100;
        if (randomNumber == guess) {
            // winner
        }
    }
}
"#;
        let findings = detector.find_weak_randomness(source);
        assert!(
            !findings.is_empty(),
            "keccak256 of block.timestamp used for randomness should be flagged"
        );
    }

    #[test]
    fn test_prevrandao_in_randomness_context() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Game {
    function rollDice() external returns (uint256) {
        uint256 random = block.prevrandao % 6;
        return random;
    }
}
"#;
        let findings = detector.find_weak_randomness(source);
        assert!(
            !findings.is_empty(),
            "block.prevrandao used for randomness should be flagged"
        );
    }

    #[test]
    fn test_withdraw_not_matched_as_draw() {
        assert!(
            !BlockhashRandomnessDetector::function_name_indicates_randomness(
                "withdrawWithCooldown"
            ),
            "'withdraw' should not match the 'draw' keyword"
        );
        assert!(
            !BlockhashRandomnessDetector::function_name_indicates_randomness(
                "_removeSharesAndQueueWithdrawal"
            ),
            "'withdrawal' should not match the 'draw' keyword"
        );
        assert!(
            !BlockhashRandomnessDetector::function_name_indicates_randomness(
                "_completeQueuedWithdrawal"
            ),
            "'withdrawal' should not match the 'draw' keyword"
        );
    }

    #[test]
    fn test_draw_matched_standalone() {
        assert!(
            BlockhashRandomnessDetector::function_name_indicates_randomness("drawWinner"),
            "'drawWinner' should match the 'draw' keyword"
        );
        assert!(
            BlockhashRandomnessDetector::function_name_indicates_randomness("lotteryDraw"),
            "'lotteryDraw' should match the 'draw' keyword"
        );
    }

    #[test]
    fn test_nonce_management_not_flagged() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract MultiSig {
    mapping(address => uint256) public nonces;

    function execute(bytes memory data, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentNonce = nonces[msg.sender];
        bytes32 hash = keccak256(abi.encode(data, currentNonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid");
        nonces[msg.sender]++;
    }
}
"#;
        let findings = detector.find_predictable_seeds(source);
        assert!(
            findings.is_empty(),
            "nonce management should not be flagged as predictable seed"
        );
    }

    #[test]
    fn test_seed_with_block_variable_flagged() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Game {
    function play() external {
        uint256 seed = uint256(block.timestamp);
        uint256 result = seed % 10;
    }
}
"#;
        let findings = detector.find_predictable_seeds(source);
        assert!(
            !findings.is_empty(),
            "seed assigned from block.timestamp should be flagged"
        );
    }

    #[test]
    fn test_commit_reveal_contract_skipped() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract SecureAuction {
    mapping(address => bytes32) public commitments;

    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
        uint256 delay = uint256(keccak256(abi.encode(hash, block.timestamp)));
    }

    function reveal(uint256 bid, bytes32 nonce) external {
        bytes32 expected = keccak256(abi.encode(bid, nonce));
        require(expected == commitments[msg.sender], "bad");
    }
}
"#;
        assert!(
            detector.has_secure_randomness_pattern(source),
            "contract with commit + reveal should be recognized as secure"
        );
    }

    #[test]
    fn test_vrf_contract_skipped() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Lottery is VRFConsumerBase {
    function requestRandomness() external {
        uint256 requestId = COORDINATOR.requestRandomWords();
    }
    function fulfillRandomWords(uint256 id, uint256[] memory words) internal override {
        randomResult = words[0];
    }
}
"#;
        assert!(
            detector.has_secure_randomness_pattern(source),
            "contract using VRF should be recognized as secure"
        );
    }

    #[test]
    fn test_critical_randomness_withdraw_not_flagged() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Staking {
    function withdrawWithCooldown(uint256 amount) external {
        require(block.timestamp >= lastDeposit[msg.sender] + COOLDOWN, "wait");
        _withdraw(msg.sender, amount);
    }

    function _completeQueuedWithdrawal(bytes32 root) internal {
        require(block.number > withdrawal.startBlock + DELAY, "wait");
    }
}
"#;
        let findings = detector.find_critical_randomness_usage(source);
        assert!(
            findings.is_empty(),
            "withdraw/withdrawal functions should not be flagged as lottery/game"
        );
    }

    #[test]
    fn test_critical_randomness_lottery_flagged() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Game {
    function rollDice() external returns (uint256) {
        return uint256(blockhash(block.number - 1)) % 6;
    }
}
"#;
        let findings = detector.find_critical_randomness_usage(source);
        assert!(
            !findings.is_empty(),
            "rollDice using blockhash should be flagged"
        );
    }

    #[test]
    fn test_extract_contract_source_isolation() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract CommitRevealAuction {
    function commit(bytes32 h) external { }
    function reveal(uint256 v) external { }
}

contract WeakRandomGame {
    function play() external {
        uint256 random = uint256(keccak256(abi.encode(block.timestamp))) % 10;
    }
}
"#;
        // CommitRevealAuction has secure pattern
        let (cr_source, _) = detector.extract_contract_source(source, "CommitRevealAuction");
        assert!(
            detector.has_secure_randomness_pattern(cr_source),
            "CommitRevealAuction should be detected as secure"
        );

        // WeakRandomGame does NOT have secure pattern
        let (game_source, _) = detector.extract_contract_source(source, "WeakRandomGame");
        assert!(
            !detector.has_secure_randomness_pattern(game_source),
            "WeakRandomGame should NOT be detected as secure"
        );

        // The weak randomness in WeakRandomGame should still be flagged
        let (game_src, _) = detector.extract_contract_source(source, "WeakRandomGame");
        let findings = detector.find_weak_randomness(game_src);
        assert!(
            !findings.is_empty(),
            "WeakRandomGame's weak randomness should still be flagged"
        );
    }

    #[test]
    fn test_no_false_positive_on_nonce_with_msg_sender() {
        let detector = BlockhashRandomnessDetector::new();
        let source = r#"
contract Wallet {
    mapping(address => uint256) public nonces;

    function cancelAllBefore(uint256 newNonce) external {
        require(newNonce > nonces[msg.sender], "Must be higher");
        nonces[msg.sender] = newNonce;
    }
}
"#;
        let findings = detector.find_predictable_seeds(source);
        assert!(
            findings.is_empty(),
            "nonce assignment with msg.sender should not be flagged"
        );
    }
}
