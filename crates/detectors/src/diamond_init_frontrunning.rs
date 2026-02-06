use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for Diamond initialization frontrunning vulnerabilities
///
/// Detects patterns where DiamondCut initialization can be frontrun,
/// allowing attackers to initialize facets with malicious parameters.
pub struct DiamondInitFrontrunningDetector {
    base: BaseDetector,
}

impl Default for DiamondInitFrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DiamondInitFrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("diamond-init-frontrunning"),
                "Diamond Init Frontrunning".to_string(),
                "Detects DiamondCut initialization patterns that can be frontrun, \
                 allowing attackers to initialize facets with malicious parameters."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    fn is_diamond_contract(&self, source: &str) -> bool {
        source.contains("diamondCut")
            || source.contains("DiamondCut")
            || source.contains("FacetCut")
            || source.contains("IDiamond")
    }

    fn find_frontrunning_risks(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Detect diamondCut with init data but no access control
            if trimmed.contains("diamondCut") && trimmed.contains("_init") {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Check for missing access control
                let has_access_control = func_body.contains("onlyOwner")
                    || func_body.contains("onlyAdmin")
                    || func_body.contains("require(msg.sender")
                    || func_body.contains("_checkOwner")
                    || func_body.contains("onlyRole");

                if !has_access_control {
                    let issue = "diamondCut with init callable without access control".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect initialization without two-step process
            if trimmed.contains("function init") || trimmed.contains("function initialize") {
                if source.contains("DiamondCut") || source.contains("FacetCut") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let func_start = self.find_function_start(&lines, line_num);
                    let func_body = self.get_function_body(&lines, func_start);

                    // Check for single-step initialization
                    let has_pending_init = func_body.contains("pendingInit")
                        || func_body.contains("_pendingOwner")
                        || func_body.contains("pendingAdmin")
                        || func_body.contains("initDelay");

                    let has_timelock = func_body.contains("timelock")
                        || func_body.contains("TimeLock")
                        || func_body.contains("block.timestamp >=");

                    if !has_pending_init && !has_timelock {
                        let issue =
                            "Facet initialization without timelock or two-step process".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Detect unprotected facet addition
            if (trimmed.contains("FacetCutAction.Add") || trimmed.contains("Add"))
                && trimmed.contains("facet")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Check if in mempool-visible function
                let is_external = func_body.contains("external") || func_body.contains("public");
                let has_commit_reveal = func_body.contains("commit")
                    || func_body.contains("hash")
                    || func_body.contains("nonce");

                if is_external && !has_commit_reveal {
                    let issue = "Facet addition exposed to mempool frontrunning".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
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

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
    }

    fn get_function_body(&self, lines: &[&str], start: usize) -> String {
        let mut depth = 0;
        let mut started = false;
        let mut end = lines.len();

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
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if started && depth == 0 {
                break;
            }
        }

        lines[start..end].join("\n")
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DiamondInitFrontrunningDetector {
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

        if !self.is_diamond_contract(source) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_frontrunning_risks(source) {
            let message = format!(
                "Function '{}' in contract '{}' has Diamond init frontrunning risk: {}. \
                 Attackers can frontrun initialization to gain control.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect Diamond initialization from frontrunning:\n\n\
                     1. Use a two-step initialization process\n\
                     2. Add timelock delays for facet additions\n\
                     3. Implement access control on diamondCut\n\
                     4. Use commit-reveal for sensitive upgrades\n\
                     5. Consider using CREATE2 with salt for deterministic addresses"
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
        let detector = DiamondInitFrontrunningDetector::new();
        assert_eq!(detector.name(), "Diamond Init Frontrunning");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
