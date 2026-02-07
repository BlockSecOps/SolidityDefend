use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for multicall partial revert vulnerabilities
///
/// Detects patterns where partial success in multicall/batch operations
/// can cause inconsistent state due to improper error handling.
pub struct MulticallPartialRevertDetector {
    base: BaseDetector,
}

impl Default for MulticallPartialRevertDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticallPartialRevertDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("multicall-partial-revert"),
                "Multicall Partial Revert".to_string(),
                "Detects multicall/batch operations where partial success can cause \
                 inconsistent state due to improper error handling."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find multicall with try/catch that continues on failure
    fn find_multicall_continue_on_failure(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("multicall")
                    || trimmed.contains("batch")
                    || trimmed.contains("aggregate"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for try/catch with continue pattern
                if func_body.contains("try ") && func_body.contains("catch") {
                    // Check if it continues after catch (no revert)
                    if !func_body.contains("revert(")
                        && !func_body.contains("require(success")
                        && func_body.contains("for (")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find batch with optional success array
    fn find_batch_optional_success(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("batch") || trimmed.contains("multicall"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for success array without revert on failure
                if func_body.contains("bool[] ")
                    && func_body.contains(".call")
                    && !func_body.contains("require(success")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find state changes before potential revert
    fn find_state_before_revert(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("batch")
                    || trimmed.contains("multicall")
                    || trimmed.contains("aggregate"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for state changes in loop before external call
                if func_body.contains("for (") {
                    let has_state_change = func_body.contains(" += ")
                        || func_body.contains(" -= ")
                        || func_body.contains("balances[")
                        || func_body.contains("_mint(")
                        || func_body.contains("_burn(");

                    let has_external_call = func_body.contains(".call")
                        || func_body.contains("transfer(")
                        || func_body.contains("safeTransfer");

                    if has_state_change && has_external_call {
                        // Check if partial failure can leave inconsistent state
                        if !func_body.contains("try ") || !func_body.contains("catch") {
                            findings.push((line_num as u32 + 1, func_name));
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find aggregate functions returning partial results
    fn find_aggregate_partial_results(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function aggregate") || trimmed.contains("function tryAggregate") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for require(requireSuccess pattern with no protection
                if func_body.contains("requireSuccess")
                    && func_body.contains("if (")
                    && func_body.contains(".call")
                {
                    // Check if success is only conditionally required
                    if func_body.contains("!requireSuccess") || func_body.contains("|| !success") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
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

impl Detector for MulticallPartialRevertDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_multicall_continue_on_failure(source) {
            let message = format!(
                "Function '{}' in contract '{}' continues execution after call failure in multicall. \
                 Partial success can leave state inconsistent.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Handle partial failures in multicall:\n\n\
                     1. Revert entire batch on any failure:\n\
                     require(success, \"Call failed\");\n\n\
                     2. Or use atomic pattern with rollback:\n\
                     if (!success) { revert BatchFailed(i); }\n\n\
                     3. Track and report all failures to caller"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_optional_success(source) {
            let message = format!(
                "Function '{}' in contract '{}' returns success array without enforcing all-or-nothing. \
                 Callers may not check individual results.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Enforce batch atomicity:\n\n\
                     1. Add requireSuccess parameter:\n\
                     function batch(Call[] calldata calls, bool requireSuccess)\n\n\
                     2. Document partial failure behavior\n\
                     3. Consider atomic-only variant"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_state_before_revert(source) {
            let message = format!(
                "Function '{}' in contract '{}' modifies state before external calls in batch. \
                 Failed calls can leave inconsistent state.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Order operations for atomicity:\n\n\
                     1. Validate all inputs first\n\
                     2. Make all external calls\n\
                     3. Update state only after all succeed\n\n\
                     Or use commit-reveal pattern"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_aggregate_partial_results(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows partial results in aggregate call. \
                 Failed calls may go unnoticed by callers.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Ensure callers handle partial results:\n\n\
                     1. Document that results array must be checked\n\
                     2. Consider emitting events for failures\n\
                     3. Return detailed failure information"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        let detector = MulticallPartialRevertDetector::new();
        assert_eq!(detector.name(), "Multicall Partial Revert");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
