use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for optimistic rollup state inference attacks
///
/// Detects patterns where state can be inferred from partial commits in
/// optimistic rollups, enabling front-running or manipulation.
pub struct OptimisticInferenceAttackDetector {
    base: BaseDetector,
}

impl Default for OptimisticInferenceAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OptimisticInferenceAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("optimistic-inference-attack"),
                "Optimistic Inference Attack".to_string(),
                "Detects patterns where sensitive state can be inferred from partial \
                 commits in optimistic rollups before finalization."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Find state leakage in batch submissions
    fn find_state_leakage(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect batch submission handlers
            if trimmed.contains("function ")
                && (trimmed.contains("submitBatch")
                    || trimmed.contains("appendBatch")
                    || trimmed.contains("submitStateBatch"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for immediate state exposure
                if func_body.contains("emit") && !func_body.contains("encrypted") {
                    let issue = "Batch submission emits unencrypted state".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect state root publication
            if (trimmed.contains("stateRoot") || trimmed.contains("outputRoot"))
                && (trimmed.contains("emit") || trimmed.contains("event"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "State root publication may leak information".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Find pending state queries that leak info
    fn find_pending_state_leaks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect public getters for pending state
            if trimmed.contains("function ")
                && (trimmed.contains("getPending")
                    || trimmed.contains("viewPending")
                    || trimmed.contains("pendingState"))
                && (trimmed.contains("public") || trimmed.contains("external"))
                && trimmed.contains("view")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Detect unfinalized state exposure
            if trimmed.contains("function ")
                && trimmed.contains("unfinalized")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find transaction ordering leakage
    fn find_ordering_leaks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect queue/ordering exposure
            if trimmed.contains("function ")
                && (trimmed.contains("getQueue")
                    || trimmed.contains("transactionQueue")
                    || trimmed.contains("pendingTransactions"))
                && (trimmed.contains("public") || trimmed.contains("external"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Detect nonce/sequence exposure
            if trimmed.contains("nextNonce")
                && (trimmed.contains("public") || trimmed.contains("external"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find challenge period information leakage
    fn find_challenge_leaks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect challenge-related state exposure
            if trimmed.contains("function ")
                && (trimmed.contains("getChallengeStatus")
                    || trimmed.contains("disputeStatus")
                    || trimmed.contains("fraudProofStatus"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it reveals too much information
                if func_body.contains("return") && !func_body.contains("bool") {
                    findings.push((line_num as u32 + 1, func_name));
                }
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

impl Detector for OptimisticInferenceAttackDetector {
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

        for (line, func_name, issue) in self.find_state_leakage(source) {
            let message = format!(
                "Function '{}' in contract '{}' has state inference vulnerability: {}. \
                 Observers can extract information from partial commits before finalization.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Prevent state inference attacks:\n\n\
                     1. Encrypt sensitive state in batch submissions\n\
                     2. Use commit-reveal for state roots\n\
                     3. Delay state exposure until finalization\n\
                     4. Implement privacy-preserving proofs\n\
                     5. Consider encrypted mempools"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_pending_state_leaks(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes pending/unfinalized state publicly. \
                 This can be used to infer transaction contents before finalization.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit pending state exposure:\n\n\
                     1. Restrict pending state queries to authorized addresses\n\
                     2. Only expose aggregated/hashed pending state\n\
                     3. Add time delays before state becomes queryable\n\
                     4. Use access control for sensitive queries"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_ordering_leaks(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes transaction ordering information. \
                 This enables front-running attacks based on pending transaction knowledge.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Protect transaction ordering:\n\n\
                     1. Don't expose full transaction queues publicly\n\
                     2. Use encrypted transaction pools\n\
                     3. Implement fair ordering protocols\n\
                     4. Consider threshold encryption for pending txs"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_challenge_leaks(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes detailed challenge/dispute information. \
                 This could reveal strategic information during the challenge period.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Limit challenge information exposure:\n\n\
                     1. Only expose boolean challenge status\n\
                     2. Hide detailed dispute information until resolved\n\
                     3. Use access control for challenge queries\n\
                     4. Consider commit-reveal for challenges"
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

    #[test]
    fn test_detector_properties() {
        let detector = OptimisticInferenceAttackDetector::new();
        assert_eq!(detector.name(), "Optimistic Inference Attack");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }
}
