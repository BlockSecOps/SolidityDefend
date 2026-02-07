use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for bundle inclusion information leakage
///
/// Detects patterns that leak information about pending transactions
/// enabling MEV searchers to predict and front-run bundle contents.
pub struct BundleInclusionLeakDetector {
    base: BaseDetector,
}

impl Default for BundleInclusionLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleInclusionLeakDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("bundle-inclusion-leak"),
                "Bundle Inclusion Information Leak".to_string(),
                "Detects patterns that leak information about pending transactions \
                 or bundles, enabling MEV searchers to predict transaction contents \
                 and execute front-running attacks."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find predictable nonce patterns
    fn find_predictable_nonces(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for sequential nonces
            if trimmed.contains("nonce++") || trimmed.contains("nonce += 1") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Look for predictable nonce generation
            if trimmed.contains("nonce") && trimmed.contains("block.") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find observable state that reveals intent
    fn find_intent_leakage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for pending order storage
            if trimmed.contains("pendingOrders")
                || trimmed.contains("queuedTrades")
                || trimmed.contains("pendingSwaps")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Look for public intent mapping
            if trimmed.contains("mapping")
                && trimmed.contains("public")
                && (trimmed.contains("intent") || trimmed.contains("order"))
            {
                findings.push((line_num as u32 + 1, "state_variable".to_string()));
            }
        }

        findings
    }

    /// Find events that leak sensitive information
    fn find_leaky_events(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for events that reveal trade intent
            if trimmed.contains("emit ")
                && (trimmed.contains("OrderCreated")
                    || trimmed.contains("SwapIntent")
                    || trimmed.contains("TradeQueued")
                    || trimmed.contains("PendingTrade"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find timing-based information leaks
    fn find_timing_leaks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for scheduled execution patterns
            if trimmed.contains("executeAt")
                || trimmed.contains("scheduledTime")
                || trimmed.contains("executeAfter")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Look for public timing state
            if trimmed.contains("public")
                && (trimmed.contains("nextExecution")
                    || trimmed.contains("lastUpdate")
                    || trimmed.contains("updateTime"))
            {
                findings.push((line_num as u32 + 1, "state_variable".to_string()));
            }
        }

        findings
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for BundleInclusionLeakDetector {
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

        // Find predictable nonces
        for (line, func_name) in self.find_predictable_nonces(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses predictable nonce patterns. \
                 Searchers can predict future transaction ordering.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use unpredictable nonces:\n\n\
                     bytes32 nonce = keccak256(abi.encodePacked(\n\
                         block.prevrandao,\n\
                         msg.sender,\n\
                         userNonce[msg.sender]++\n\
                     ));"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Find intent leakage
        for (line, func_name) in self.find_intent_leakage(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes pending trade intents. \
                 Searchers can monitor and front-run these orders.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Hide trade intents until execution:\n\n\
                     1. Use commit-reveal scheme for orders\n\
                     2. Store hashed intents, not plaintext\n\
                     3. Use private mempools (Flashbots)\n\
                     4. Implement encrypted order books"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find leaky events
        for (line, func_name) in self.find_leaky_events(source) {
            let message = format!(
                "Function '{}' in contract '{}' emits events revealing trade intent. \
                 Bots can monitor events to predict and front-run trades.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(200)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Delay or encrypt sensitive event data:\n\n\
                     // Emit only after execution\n\
                     function executeOrder() external {\n\
                         // ... execute ...\n\
                         emit OrderExecuted(orderId);  // Post-execution only\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Find timing leaks
        for (line, func_name) in self.find_timing_leaks(source) {
            let message = format!(
                "Function '{}' in contract '{}' leaks timing information. \
                 Attackers can predict when operations will occur.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(208)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add randomness to execution timing:\n\n\
                     1. Use variable delays\n\
                     2. Batch multiple operations\n\
                     3. Don't expose next execution time publicly"
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
        let detector = BundleInclusionLeakDetector::new();
        assert_eq!(detector.name(), "Bundle Inclusion Information Leak");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_intent_leakage() {
        let detector = BundleInclusionLeakDetector::new();

        let vulnerable = r#"
            contract Exchange {
                mapping(address => Order) public pendingOrders;
            }
        "#;
        let findings = detector.find_intent_leakage(vulnerable);
        assert!(!findings.is_empty());
    }
}
