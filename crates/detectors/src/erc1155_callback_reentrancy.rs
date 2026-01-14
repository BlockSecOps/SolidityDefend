use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ERC1155 callback reentrancy vulnerabilities
///
/// Detects patterns where ERC1155 batch callbacks can be exploited
/// for reentrancy through onERC1155Received/onERC1155BatchReceived.
pub struct Erc1155CallbackReentrancyDetector {
    base: BaseDetector,
}

impl Default for Erc1155CallbackReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Erc1155CallbackReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("erc1155-callback-reentrancy"),
                "ERC1155 Callback Reentrancy".to_string(),
                "Detects ERC1155 callback patterns vulnerable to reentrancy through \
                 onERC1155Received and onERC1155BatchReceived callbacks."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find safeTransferFrom with state changes after
    fn find_safetransfer_state_after(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for ERC1155 transfers
                if func_body.contains("safeTransferFrom")
                    || func_body.contains("safeBatchTransferFrom")
                {
                    // Find position of transfer
                    if let Some(transfer_pos) = func_body.find("safeTransfer") {
                        let after_transfer = &func_body[transfer_pos..];

                        // Check for state changes after transfer
                        let has_state_after = after_transfer.contains(" = ")
                            && !after_transfer.contains("==")
                            && (after_transfer.contains("balance")
                                || after_transfer.contains("total")
                                || after_transfer.contains("count")
                                || after_transfer.contains("[msg.sender]"));

                        if has_state_after && !func_body.contains("nonReentrant") {
                            findings.push((line_num as u32 + 1, func_name));
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find batch operations vulnerable to reentrancy
    fn find_batch_callback_vulnerability(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("batch") || trimmed.contains("Batch"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for batch mint/transfer with loop
                if func_body.contains("for (")
                    && (func_body.contains("_mint")
                        || func_body.contains("safeTransferFrom")
                        || func_body.contains("_safeTransferFrom"))
                {
                    if !func_body.contains("nonReentrant") && !func_body.contains("_status") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find _mint with callback in ERC1155
    fn find_mint_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function mint") || trimmed.contains("function _mint") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if mint has callback
                if func_body.contains("onERC1155Received")
                    || func_body.contains("_doSafeTransferAcceptanceCheck")
                {
                    // Check for state updates after callback position
                    if let Some(callback_pos) = func_body.find("onERC1155") {
                        let after_callback = &func_body[callback_pos..];
                        if after_callback.contains(" = ")
                            || after_callback.contains(" += ")
                            || after_callback.contains(" -= ")
                        {
                            if !func_body.contains("nonReentrant") {
                                findings.push((line_num as u32 + 1, func_name));
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find receiver implementation with external calls
    fn find_receiver_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function onERC1155Received")
                || trimmed.contains("function onERC1155BatchReceived")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for external calls in receiver
                let has_external_call = func_body.contains(".call")
                    || func_body.contains("transfer(")
                    || func_body.contains("safeTransfer")
                    || func_body.contains("swap(")
                    || func_body.contains("this.");

                if has_external_call {
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

impl Detector for Erc1155CallbackReentrancyDetector {
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

        for (line, func_name) in self.find_safetransfer_state_after(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates state after ERC1155 safeTransfer. \
                 onERC1155Received callback can reenter before state update.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Follow checks-effects-interactions for ERC1155:\n\n\
                     // Update state BEFORE transfer\n\
                     balances[from] -= amount;\n\
                     balances[to] += amount;\n\
                     safeTransferFrom(from, to, id, amount, data);\n\n\
                     // Or add nonReentrant modifier"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_callback_vulnerability(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs batch operations without reentrancy guard. \
                 Each item in batch triggers callback, multiplying reentrancy risk.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect batch operations:\n\n\
                     1. Add reentrancy guard:\n\
                     function batchTransfer(...) external nonReentrant { ... }\n\n\
                     2. Update all state before any transfer\n\
                     3. Consider limiting batch sizes"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_mint_callback(source) {
            let message = format!(
                "Function '{}' in contract '{}' has state updates after ERC1155 callback. \
                 Minting callback can reenter before state is finalized.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Update state before callback in _mint:\n\n\
                     // Update balances first\n\
                     _balances[id][to] += amount;\n\
                     // Then do callback\n\
                     _doSafeTransferAcceptanceCheck(...);"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_receiver_external_calls(source) {
            let message = format!(
                "Function '{}' in contract '{}' makes external calls in ERC1155 receiver. \
                 This creates complex reentrancy chains.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Minimize external calls in receivers:\n\n\
                     1. Only update local state in receiver\n\
                     2. Use pull pattern for any transfers\n\
                     3. Add reentrancy guards\n\
                     4. Validate caller (operator) strictly"
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
        let detector = Erc1155CallbackReentrancyDetector::new();
        assert_eq!(detector.name(), "ERC1155 Callback Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
