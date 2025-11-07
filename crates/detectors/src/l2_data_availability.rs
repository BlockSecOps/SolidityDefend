use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for L2 data availability vulnerabilities
pub struct L2DataAvailabilityDetector {
    base: BaseDetector,
}

impl L2DataAvailabilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("l2-data-availability".to_string()),
                "L2 Data Availability Failure".to_string(),
                "Detects missing data publication to L1, inadequate data availability guarantees, and lack of force inclusion mechanisms that could lead to censorship or data withholding attacks".to_string(),
                vec![DetectorCategory::L2, DetectorCategory::DataAvailability],
                Severity::High,
            ),
        }
    }
}

impl Detector for L2DataAvailabilityDetector {
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

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for batch submission functions
            if self.is_batch_submission_function(function.name.name, &func_source) {
                let issues = self.check_data_commitment(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' submits batches without proper data availability guarantees. {} \
                        Missing data publication can lead to data withholding attacks and prevent users from reconstructing state.",
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
                            "Add data availability to '{}': \
                            (1) Publish transaction data as calldata to L1, \
                            (2) Store data commitment hash (keccak256 of batch data) in L1 state, \
                            (3) Emit event with data or data hash for availability, \
                            (4) Implement data availability challenge mechanism, \
                            (5) Use blob transactions (EIP-4844) for cost-efficient DA.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for sequencer functions
            if self.is_sequencer_function(function.name.name, &func_source) {
                let issues = self.check_censorship_resistance(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' processes transactions without censorship resistance. {} \
                        Lack of force inclusion allows sequencer to censor user transactions indefinitely.",
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
                        .with_cwe(284) // CWE-284: Improper Access Control
                        .with_fix_suggestion(format!(
                            "Add censorship resistance to '{}': \
                            (1) Implement force inclusion mechanism via L1, \
                            (2) Add timeout after which users can include their own transactions, \
                            (3) Track pending L1 to L2 messages with timestamps, \
                            (4) Allow anyone to execute forced inclusion after timeout, \
                            (5) Emit events for forced inclusion requests.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for data commitment functions
            if self.is_data_commitment_function(function.name.name, &func_source) {
                let issues = self.check_commitment_validity(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' handles data commitments without proper validation. {} \
                        Weak commitment validation can allow invalid or unavailable data references.",
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
                            "Strengthen data commitment in '{}': \
                            (1) Validate commitment format and length, \
                            (2) Verify commitment matches published data hash, \
                            (3) Implement data availability challenge period, \
                            (4) Allow anyone to challenge unavailable data, \
                            (5) Slash sequencer if data proves unavailable.",
                            function.name.name
                        ));

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

impl L2DataAvailabilityDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    fn is_batch_submission_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "commitBatch",
            "submitBatch",
            "appendSequencerBatch",
            "postBatch",
            "publishBatch",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("batch")
                && (source.contains("submit") || source.contains("commit")))
    }

    fn is_sequencer_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "appendSequencerBatch",
            "enqueueL2GasPrepaid",
            "sequencerCommit",
            "executeTransaction",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("sequencer") || source.contains("onlySequencer"))
    }

    fn is_data_commitment_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "verifyDataAvailability",
            "challengeDataAvailability",
            "submitDataCommitment",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("dataCommitment") || source.contains("dataHash"))
    }

    fn check_data_commitment(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No calldata publication
        // In L2s, transaction data should be in calldata for L1 DA
        if !source.contains("calldata") && !source.contains("blobhash") {
            issues.push(
                "No calldata parameter detected. L2 batch data should be published as calldata to ensure L1 data availability"
                    .to_string(),
            );
        }

        // Pattern 2: Missing data hash storage
        if !source.contains("dataHash")
            && !source.contains("batchHash")
            && !source.contains("keccak256")
        {
            issues.push(
                "No data hash commitment to L1. Should store hash of batch data on L1 for verifiability"
                    .to_string(),
            );
        }

        // Pattern 3: No data availability event
        if !source.contains("emit") {
            issues.push(
                "Missing event emission. Should emit event with data or data hash for off-chain availability monitoring"
                    .to_string(),
            );
        }

        // Pattern 4: Missing data availability check
        if !source.contains("dataAvailable")
            && !source.contains("isDataAvailable")
            && !source.contains("verifyDataAvailability")
        {
            issues.push(
                "No data availability verification. Should implement mechanism to verify data can be retrieved"
                    .to_string(),
            );
        }

        issues
    }

    fn check_censorship_resistance(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Only sequencer can submit (no force inclusion)
        if source.contains("onlySequencer") && !source.contains("forceInclude") {
            issues.push(
                "Only sequencer can submit with no force inclusion mechanism. Users cannot bypass censoring sequencer"
                    .to_string(),
            );
        }

        // Pattern 2: No timeout mechanism
        if !source.contains("timestamp")
            && !source.contains("deadline")
            && !source.contains("timeout")
        {
            issues.push(
                "Missing timeout mechanism. Should allow force inclusion after sequencer fails to include transaction"
                    .to_string(),
            );
        }

        // Pattern 3: No L1 to L2 message queue
        if !source.contains("queueIndex")
            && !source.contains("messageQueue")
            && !source.contains("enqueue")
        {
            issues.push(
                "No message queue detected. Should implement L1 to L2 message queue for force inclusion"
                    .to_string(),
            );
        }

        // Pattern 4: No force inclusion function
        if !source.contains("forceInclude")
            && !source.contains("forceInclusion")
            && !source.contains("bypass")
        {
            issues.push(
                "No force inclusion mechanism. Users need ability to include transactions via L1 if sequencer censors"
                    .to_string(),
            );
        }

        issues
    }

    fn check_commitment_validity(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No commitment format validation
        if source.contains("commitment") && !source.contains("length") {
            issues.push(
                "Missing commitment format validation. Should verify commitment length and structure"
                    .to_string(),
            );
        }

        // Pattern 2: No hash verification
        if source.contains("dataHash")
            && !source.contains("keccak256")
            && !source.contains("sha256")
        {
            issues.push(
                "No hash computation for verification. Should recompute hash to validate commitment"
                    .to_string(),
            );
        }

        // Pattern 3: Missing challenge mechanism
        if !source.contains("challenge") && !source.contains("dispute") {
            issues.push(
                "No data availability challenge mechanism. Should allow users to challenge if data is unavailable"
                    .to_string(),
            );
        }

        // Pattern 4: No challenge period
        if !source.contains("challengePeriod")
            && !source.contains("challengeWindow")
            && !source.contains("CHALLENGE_PERIOD")
        {
            issues.push(
                "Missing challenge period. Should define time window during which data availability can be challenged"
                    .to_string(),
            );
        }

        // Pattern 5: No slashing for unavailable data
        if !source.contains("slash") && !source.contains("penalty") && !source.contains("bond") {
            issues.push(
                "No slashing mechanism for data withholding. Sequencer should be slashed if data proves unavailable"
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

impl Default for L2DataAvailabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = L2DataAvailabilityDetector::new();
        assert_eq!(detector.name(), "L2 Data Availability Failure");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "l2-data-availability");
        assert!(detector.categories().contains(&DetectorCategory::L2));
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::DataAvailability)
        );
    }

    #[test]
    fn test_is_batch_submission_function() {
        let detector = L2DataAvailabilityDetector::new();

        assert!(detector.is_batch_submission_function("commitBatch", ""));
        assert!(detector.is_batch_submission_function("submitBatch", ""));
        assert!(detector.is_batch_submission_function("appendSequencerBatch", ""));
        assert!(!detector.is_batch_submission_function("withdraw", ""));
    }

    #[test]
    fn test_is_sequencer_function() {
        let detector = L2DataAvailabilityDetector::new();

        assert!(detector.is_sequencer_function("appendSequencerBatch", ""));
        assert!(detector.is_sequencer_function("sequencerCommit", ""));
        assert!(detector.is_sequencer_function("test", "modifier onlySequencer"));
        assert!(!detector.is_sequencer_function("withdraw", ""));
    }

    #[test]
    fn test_check_data_commitment_missing_calldata() {
        let detector = L2DataAvailabilityDetector::new();
        let source = "function submitBatch(bytes memory data) public { }";
        let issues = detector.check_data_commitment(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("calldata")));
    }

    #[test]
    fn test_check_data_commitment_with_calldata() {
        let detector = L2DataAvailabilityDetector::new();
        let source = r#"
            function submitBatch(bytes calldata data) public {
                bytes32 dataHash = keccak256(data);
                batchHashes[batchNumber] = dataHash;
                emit BatchSubmitted(batchNumber, dataHash);
            }
        "#;
        let issues = detector.check_data_commitment(source);

        // Should have minimal issues with proper DA
        assert!(issues.len() < 2);
    }

    #[test]
    fn test_check_censorship_resistance() {
        let detector = L2DataAvailabilityDetector::new();
        let source = "function appendSequencerBatch() public onlySequencer { }";
        let issues = detector.check_censorship_resistance(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("force inclusion")));
    }

    #[test]
    fn test_check_censorship_resistance_with_force_include() {
        let detector = L2DataAvailabilityDetector::new();
        let source = r#"
            function appendSequencerBatch() public onlySequencer {
                // Process normal batches
            }
            function forceInclude() public {
                require(block.timestamp > lastSequencerBatch + timeout);
                processMessageQueue();
            }
        "#;
        let issues = detector.check_censorship_resistance(source);

        // Should have fewer issues with force inclusion
        assert!(issues.len() < 3);
    }

    #[test]
    fn test_check_commitment_validity() {
        let detector = L2DataAvailabilityDetector::new();
        let source = "function verifyDataAvailability(bytes32 commitment) public { }";
        let issues = detector.check_commitment_validity(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("challenge")));
        assert!(issues.iter().any(|i| i.contains("slashing")));
    }

    #[test]
    fn test_check_commitment_validity_with_challenges() {
        let detector = L2DataAvailabilityDetector::new();
        let source = r#"
            function verifyDataAvailability(bytes32 commitment, uint256 length) public {
                require(length > 0 && length <= MAX_BATCH_SIZE);
                bytes32 hash = keccak256(abi.encodePacked(commitment, length));
                challengeWindow[hash] = block.timestamp + CHALLENGE_PERIOD;
            }
            function challengeDataAvailability(bytes32 hash) public {
                require(block.timestamp <= challengeWindow[hash]);
                sequencerBond[sequencer] -= SLASH_AMOUNT;
            }
        "#;
        let issues = detector.check_commitment_validity(source);

        // Should have very few issues with proper validation (no hash verification issue)
        assert!(issues.len() <= 1);
    }
}
