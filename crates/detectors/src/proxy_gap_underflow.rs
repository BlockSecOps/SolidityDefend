use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for proxy storage gap underflow vulnerabilities
///
/// Detects patterns where __gap arrays in upgradeable contracts are smaller
/// than needed, risking storage collisions during upgrades.
pub struct ProxyGapUnderflowDetector {
    base: BaseDetector,
}

impl Default for ProxyGapUnderflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyGapUnderflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("proxy-gap-underflow"),
                "Proxy Gap Underflow".to_string(),
                "Detects __gap arrays in upgradeable contracts that may be too small, \
                 risking storage collisions when new state variables are added."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    fn is_upgradeable_contract(&self, source: &str) -> bool {
        source.contains("Upgradeable") ||
        source.contains("UUPS") ||
        source.contains("Transparent") ||
        source.contains("Initializable") ||
        source.contains("__gap") ||
        source.contains("ERC1967")
    }

    fn find_gap_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut state_var_count = 0;
        let mut gap_size: Option<u32> = None;
        let mut gap_line: Option<u32> = None;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Count state variables (rough heuristic)
            if self.is_state_variable(trimmed) {
                state_var_count += 1;
            }

            // Detect __gap array
            if trimmed.contains("__gap") && trimmed.contains("[") {
                if let Some(size) = self.extract_gap_size(trimmed) {
                    gap_size = Some(size);
                    gap_line = Some(line_num as u32 + 1);
                }
            }

            // Detect missing __gap in inheritance
            if trimmed.contains("contract ") && trimmed.contains(" is ") {
                if source.contains("Upgradeable") && !source.contains("__gap") {
                    let contract_name = self.extract_contract_name(trimmed);
                    let issue = "Upgradeable contract missing __gap for future storage expansion".to_string();
                    findings.push((line_num as u32 + 1, contract_name, issue));
                }
            }
        }

        // Check if gap is undersized
        if let (Some(size), Some(line)) = (gap_size, gap_line) {
            // Standard is 50 slots, warn if smaller
            if size < 50 {
                let issue = format!(
                    "__gap size {} is smaller than recommended 50 slots",
                    size
                );
                findings.push((line, "__gap".to_string(), issue));
            }

            // Check if gap + state vars != 50 (inheritance calculation)
            let expected_gap = 50u32.saturating_sub(state_var_count);
            if size != expected_gap && state_var_count > 0 && size < 50 {
                let issue = format!(
                    "__gap[{}] may not account for {} state variables properly",
                    size, state_var_count
                );
                findings.push((line, "__gap".to_string(), issue));
            }
        }

        // Detect gap that doesn't use uint256
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("__gap") && trimmed.contains("[") {
                if !trimmed.contains("uint256") {
                    let issue = "__gap should use uint256 for full slot alignment".to_string();
                    findings.push((line_num as u32 + 1, "__gap".to_string(), issue));
                }
            }
        }

        findings
    }

    fn find_inheritance_gap_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect contracts inheriting from Upgradeable bases without gaps
            if trimmed.contains("contract ") && trimmed.contains(" is ") {
                let inherits_upgradeable = trimmed.contains("Upgradeable") ||
                    trimmed.contains("UUPS") ||
                    trimmed.contains("Initializable");

                if inherits_upgradeable {
                    // Check if this contract adds state but parent might not have gap
                    let contract_start = line_num;
                    let contract_end = self.find_contract_end(&lines, contract_start);
                    let contract_body = lines[contract_start..contract_end].join("\n");

                    // Count new state variables in this contract
                    let mut new_state_vars = 0;
                    for contract_line in lines[contract_start..contract_end].iter() {
                        if self.is_state_variable(contract_line.trim()) {
                            new_state_vars += 1;
                        }
                    }

                    // If adding state vars but no gap adjustment visible
                    if new_state_vars > 0 && !contract_body.contains("__gap") {
                        let contract_name = self.extract_contract_name(trimmed);
                        findings.push((line_num as u32 + 1, contract_name));
                    }
                }
            }
        }

        findings
    }

    fn is_state_variable(&self, line: &str) -> bool {
        // Heuristic for state variable detection
        let is_declaration = (line.contains("uint") || line.contains("int") ||
            line.contains("address") || line.contains("bool") ||
            line.contains("bytes") || line.contains("string") ||
            line.contains("mapping")) &&
            line.contains(";") &&
            !line.contains("function") &&
            !line.contains("memory") &&
            !line.contains("calldata") &&
            !line.contains("return");

        is_declaration
    }

    fn extract_gap_size(&self, line: &str) -> Option<u32> {
        // Extract number from __gap[N]
        if let Some(start) = line.find('[') {
            if let Some(end) = line.find(']') {
                let num_str = &line[start + 1..end];
                return num_str.trim().parse().ok();
            }
        }
        None
    }

    fn extract_contract_name(&self, line: &str) -> String {
        if let Some(contract_start) = line.find("contract ") {
            let after = &line[contract_start + 9..];
            if let Some(space) = after.find(|c: char| c.is_whitespace() || c == '{') {
                return after[..space].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_contract_end(&self, lines: &[&str], start: usize) -> usize {
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

impl Detector for ProxyGapUnderflowDetector {
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

        if !self.is_upgradeable_contract(source) {
            return Ok(findings);
        }

        for (line, item, issue) in self.find_gap_issues(source) {
            let message = format!(
                "Storage gap issue in '{}' of contract '{}': {}. \
                 Incorrect gaps can cause storage collisions during upgrades.",
                item, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(119)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Properly size storage gaps:\n\n\
                     1. Use uint256[50] private __gap; as standard\n\
                     2. Reduce gap size by 1 for each new state variable\n\
                     3. Example: 3 state vars → uint256[47] private __gap;\n\
                     4. Always use uint256 for full slot alignment\n\
                     5. Document gap calculations in comments"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, contract) in self.find_inheritance_gap_issues(source) {
            let message = format!(
                "Contract '{}' in '{}' adds state variables without gap management. \
                 Parent contract gaps may not account for these additions.",
                contract, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(119)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Manage storage gaps in inheritance:\n\n\
                     1. Each upgradeable contract should have its own __gap\n\
                     2. Coordinate gap sizes across inheritance chain\n\
                     3. Use storage layout tools to verify alignment\n\
                     4. Consider using storage namespacing (EIP-7201)"
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
        let detector = ProxyGapUnderflowDetector::new();
        assert_eq!(detector.name(), "Proxy Gap Underflow");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
