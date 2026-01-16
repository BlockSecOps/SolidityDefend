use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for improper Chainlink VRF integration
///
/// Detects patterns where Chainlink VRF is used incorrectly, such as
/// not waiting for the callback or using requestId incorrectly.
pub struct ChainlinkVrfMisuseDetector {
    base: BaseDetector,
}

impl Default for ChainlinkVrfMisuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainlinkVrfMisuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("chainlink-vrf-misuse"),
                "Chainlink VRF Misuse".to_string(),
                "Detects improper Chainlink VRF integration patterns that could \
                 compromise randomness guarantees or cause operational issues."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }

    /// Find VRF request without proper callback handling
    fn find_callback_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract uses VRF
        let has_vrf = source.contains("VRFConsumerBase") ||
                      source.contains("VRFConsumerBaseV2") ||
                      source.contains("VRFV2WrapperConsumerBase") ||
                      source.contains("requestRandomWords") ||
                      source.contains("requestRandomness");

        if !has_vrf {
            return findings;
        }

        // Check for fulfillRandomWords/fulfillRandomness implementation
        let has_callback = source.contains("fulfillRandomWords") ||
                          source.contains("fulfillRandomness") ||
                          source.contains("rawFulfillRandomWords");

        if !has_callback {
            // Find the request function
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if (trimmed.contains("requestRandomWords") || trimmed.contains("requestRandomness"))
                    && !trimmed.starts_with("//")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let issue = "VRF request without callback implementation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find immediate use of request ID
    fn find_immediate_use(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect functions that request and immediately use randomness
            if trimmed.contains("function ") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if both request and state change happen in same function
                if (func_body.contains("requestRandomWords") || func_body.contains("requestRandomness"))
                    && (func_body.contains("winner") || func_body.contains("selected") ||
                        func_body.contains("transfer(") || func_body.contains("mint("))
                    && !func_body.contains("pending") && !func_body.contains("await")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find subscription/funding issues
    fn find_funding_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if using VRF v2
        let uses_v2 = source.contains("VRFConsumerBaseV2") ||
                      source.contains("VRFCoordinatorV2");

        if !uses_v2 {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for hardcoded subscription ID
            if trimmed.contains("s_subscriptionId") && trimmed.contains("=") &&
               !trimmed.contains("constructor") && !trimmed.contains("function")
            {
                // Check if it's a constant assignment
                if trimmed.contains("uint64") && (trimmed.contains("constant") ||
                   trimmed.matches(char::is_numeric).count() > 0)
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find re-request vulnerabilities
    fn find_rerequest_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect requestRandomWords in external/public functions without guards
            if trimmed.contains("function ") &&
               (trimmed.contains("external") || trimmed.contains("public")) &&
               !trimmed.contains("onlyOwner") && !trimmed.contains("internal")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if (func_body.contains("requestRandomWords") || func_body.contains("requestRandomness"))
                    && !func_body.contains("require") && !func_body.contains("revert")
                {
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

impl Detector for ChainlinkVrfMisuseDetector {
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

        for (line, func_name, issue) in self.find_callback_issues(source) {
            let message = format!(
                "Contract '{}' has VRF issue in '{}': {}. \
                 VRF requires callback implementation to receive randomness.",
                contract_name, func_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement VRF callback properly:\n\n\
                     function fulfillRandomWords(\n\
                         uint256 requestId,\n\
                         uint256[] memory randomWords\n\
                     ) internal override {\n\
                         // Use randomWords here\n\
                         s_randomWord = randomWords[0];\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_immediate_use(source) {
            let message = format!(
                "Function '{}' in contract '{}' requests VRF and immediately uses result. \
                 VRF is asynchronous - randomness arrives in callback, not immediately.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "VRF is asynchronous:\n\n\
                     1. requestRandomWords() returns a requestId\n\
                     2. Store pending state with requestId\n\
                     3. Wait for fulfillRandomWords callback\n\
                     4. Complete action in callback with actual randomness"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_funding_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' may have VRF subscription issues. \
                 Hardcoded subscription IDs can cause deployment problems.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Configure subscription ID properly:\n\n\
                     1. Pass subscription ID in constructor\n\
                     2. Add function to update subscription ID\n\
                     3. Ensure subscription is funded with LINK"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_rerequest_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows unrestricted VRF requests. \
                 Attackers could drain LINK or cause unexpected behavior.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add guards to VRF request functions:\n\n\
                     1. Add access control (onlyOwner or role-based)\n\
                     2. Add rate limiting or cooldown\n\
                     3. Check for pending requests before new ones\n\
                     4. Require payment to cover LINK costs"
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
        let detector = ChainlinkVrfMisuseDetector::new();
        assert_eq!(detector.name(), "Chainlink VRF Misuse");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }
}
