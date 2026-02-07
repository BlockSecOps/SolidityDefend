use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for proxy double initialization vulnerabilities
///
/// Detects patterns where proxy contracts can be initialized multiple times,
/// including via beacon downgrades or implementation changes.
pub struct ProxyDoubleInitializeDetector {
    base: BaseDetector,
}

impl Default for ProxyDoubleInitializeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyDoubleInitializeDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("proxy-double-initialize"),
                "Proxy Double Initialize".to_string(),
                "Detects patterns where proxy contracts can be initialized multiple times, \
                 including via beacon downgrades, implementation changes, or missing guards."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    fn is_proxy_contract(&self, source: &str) -> bool {
        source.contains("Initializable")
            || source.contains("initializer")
            || source.contains("Proxy")
            || source.contains("UUPS")
            || source.contains("Beacon")
            || source.contains("ERC1967")
    }

    fn find_double_init_risks(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Detect initialize function without initializer modifier
            if (trimmed.contains("function initialize") || trimmed.contains("function init("))
                && !trimmed.contains("initializer")
                && !trimmed.contains("reinitializer")
            {
                let func_name = self.extract_function_name(trimmed);

                // Check for manual initialization guard
                let func_start = line_num;
                let func_body = self.get_function_body(&lines, func_start);

                let has_guard = func_body.contains("_initialized")
                    || func_body.contains("initialized = true")
                    || func_body.contains("require(!initialized")
                    || func_body.contains("if (initialized)");

                if !has_guard {
                    let issue =
                        "Initialize function without initializer modifier or guard".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect missing _disableInitializers in constructor
            if trimmed.contains("constructor") && trimmed.contains("(") {
                let func_body = self.get_function_body(&lines, line_num);

                if source.contains("Initializable") && !func_body.contains("_disableInitializers") {
                    let issue = "Constructor missing _disableInitializers() call".to_string();
                    findings.push((line_num as u32 + 1, "constructor".to_string(), issue));
                }
            }

            // Detect beacon upgrade without init protection
            if trimmed.contains("upgradeTo") || trimmed.contains("upgradeBeacon") {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Check if there's re-initialization possible after upgrade
                let has_init_check = func_body.contains("_initialized")
                    || func_body.contains("reinitializer")
                    || func_body.contains("_getInitializedVersion");

                if !has_init_check && func_body.contains("delegatecall") {
                    let issue = "Upgrade function may allow re-initialization".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect reinitializer without version check
            if trimmed.contains("reinitializer") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if version is validated
                if !trimmed.contains("reinitializer(") {
                    let issue = "reinitializer without explicit version".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    fn find_beacon_downgrade_risks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect beacon implementation changes
            if trimmed.contains("_setBeacon") || trimmed.contains("setBeacon") {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Check for version tracking
                let tracks_version = func_body.contains("_getInitializedVersion")
                    || func_body.contains("implementationVersion")
                    || func_body.contains("version >=");

                if !tracks_version {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect implementation slot writes without version check
            if trimmed.contains("IMPLEMENTATION_SLOT") && trimmed.contains("sstore") {
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

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") || trimmed.contains("constructor") {
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

impl Detector for ProxyDoubleInitializeDetector {
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

        if !self.is_proxy_contract(source) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_double_init_risks(source) {
            let message = format!(
                "Function '{}' in contract '{}' has double initialization risk: {}. \
                 Attackers can re-initialize to take control.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(665)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent double initialization:\n\n\
                     1. Use OpenZeppelin's Initializable with initializer modifier\n\
                     2. Call _disableInitializers() in implementation constructor\n\
                     3. Use reinitializer(version) for upgrades\n\
                     4. Track initialization version in storage\n\
                     5. Verify: require(_getInitializedVersion() < version)"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_beacon_downgrade_risks(source) {
            let message = format!(
                "Function '{}' in contract '{}' may allow beacon downgrade without version check. \
                 Downgrading could re-expose uninitialized state.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(665)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect against beacon downgrades:\n\n\
                     1. Track implementation versions\n\
                     2. Prevent downgrades: require(newVersion > currentVersion)\n\
                     3. Use monotonically increasing version numbers\n\
                     4. Consider disabling downgrades entirely"
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
        let detector = ProxyDoubleInitializeDetector::new();
        assert_eq!(detector.name(), "Proxy Double Initialize");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
