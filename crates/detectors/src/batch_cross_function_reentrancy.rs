use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for batch cross-function reentrancy vulnerabilities
///
/// Detects patterns where reentrancy can occur between different functions
/// called within a multicall/batch operation.
pub struct BatchCrossFunctionReentrancyDetector {
    base: BaseDetector,
}

impl Default for BatchCrossFunctionReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchCrossFunctionReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("batch-cross-function-reentrancy"),
                "Batch Cross-Function Reentrancy".to_string(),
                "Detects reentrancy vulnerabilities between functions called within \
                 multicall/batch operations where one call can reenter another."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find multicall that calls multiple state-changing functions
    fn find_multicall_state_sharing(&self, source: &str) -> Vec<(u32, String)> {
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

                // Check for delegatecall pattern (common in multicall)
                if func_body.contains("delegatecall") && func_body.contains("for (") {
                    // Check if no reentrancy guard
                    if !func_body.contains("nonReentrant")
                        && !func_body.contains("_status")
                        && !func_body.contains("locked")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find functions sharing state that can be batched
    fn find_shared_state_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Find all external/public functions that modify shared state
        let mut state_funcs: Vec<(usize, String, bool)> = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if function modifies shared state
                let modifies_state = func_body.contains("balances[")
                    || func_body.contains("_balances[")
                    || func_body.contains("totalSupply")
                    || func_body.contains("reserves")
                    || func_body.contains("liquidity");

                let has_external_call = func_body.contains(".call")
                    || func_body.contains("transfer(")
                    || func_body.contains("safeTransfer");

                if modifies_state && has_external_call {
                    state_funcs.push((line_num, func_name, true));
                }
            }
        }

        // If we have multiple functions that can be batched and share state
        if state_funcs.len() > 1 {
            // Check if contract has multicall
            if source.contains("multicall") || source.contains("batch") {
                for (line_num, func_name, _) in state_funcs {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find permit + transfer batching (common attack vector)
    fn find_permit_transfer_batch(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract has both permit and transfer functions
        let has_permit = source.contains("function permit");
        let has_transfer = source.contains("function transferFrom")
            || source.contains("function safeTransferFrom");
        let has_multicall =
            source.contains("multicall") || source.contains("batch") || source.contains("execute");

        if has_permit && has_transfer && has_multicall {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function permit") {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find swap functions that can be batched
    fn find_batchable_swaps(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function swap") || trimmed.contains("function exactInput") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if swap can be called in batch and has callback
                if (func_body.contains("callback") || func_body.contains("Callback"))
                    && !func_body.contains("nonReentrant")
                {
                    findings.push((line_num as u32 + 1, func_name));
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

impl Detector for BatchCrossFunctionReentrancyDetector {
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

        for (line, func_name) in self.find_multicall_state_sharing(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses delegatecall in multicall without reentrancy guard. \
                 Cross-function reentrancy is possible between batched calls.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect against cross-function reentrancy in multicall:\n\n\
                     1. Add reentrancy guard to multicall function:\n\
                     function multicall(...) external nonReentrant { ... }\n\n\
                     2. Use function-level locking for state-changing operations\n\
                     3. Consider disabling multicall for sensitive functions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_shared_state_functions(source) {
            let message = format!(
                "Function '{}' in contract '{}' modifies shared state and can be batched. \
                 Cross-function reentrancy between batched calls can corrupt state.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect shared state in batchable functions:\n\n\
                     1. Apply reentrancy guards to all state-changing functions\n\
                     2. Use checks-effects-interactions pattern\n\
                     3. Consider read-write locking for critical state\n\
                     4. Document batch safety requirements"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_permit_transfer_batch(source) {
            let message = format!(
                "Function '{}' in contract '{}' can be batched with transfer operations. \
                 Permit + transferFrom in same batch enables signature replay attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect permit from batch attacks:\n\n\
                     1. Use separate nonce tracking for permit\n\
                     2. Consider disabling permit in multicall\n\
                     3. Add deadline checks\n\
                     4. Validate msg.sender in permit call"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batchable_swaps(source) {
            let message = format!(
                "Function '{}' in contract '{}' has callback and no reentrancy guard. \
                 Batched swaps can enable cross-function reentrancy via callbacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect swap callbacks from reentrancy:\n\n\
                     1. Add nonReentrant modifier\n\
                     2. Lock during callback execution\n\
                     3. Validate callback source\n\
                     4. Complete state updates before callback"
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
        let detector = BatchCrossFunctionReentrancyDetector::new();
        assert_eq!(detector.name(), "Batch Cross-Function Reentrancy");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
