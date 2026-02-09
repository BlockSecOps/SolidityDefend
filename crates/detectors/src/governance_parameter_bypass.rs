use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for governance parameter bypass vulnerabilities
///
/// Detects patterns where governance parameters can be changed before
/// timelock restrictions take effect, bypassing governance controls.
pub struct GovernanceParameterBypassDetector {
    base: BaseDetector,
}

impl Default for GovernanceParameterBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceParameterBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("governance-parameter-bypass"),
                "Governance Parameter Bypass".to_string(),
                "Detects governance parameters that can be changed before timelock \
                 restrictions apply, enabling admins to bypass governance controls."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if a line is a state variable declaration rather than an assignment
    fn is_state_variable_declaration(&self, trimmed: &str) -> bool {
        let type_prefixes = [
            "uint256", "uint128", "uint64", "uint32", "uint16", "uint8", "uint", "int256",
            "int128", "int64", "int32", "int16", "int8", "int", "address", "bool", "bytes32",
            "bytes", "string", "mapping",
        ];
        for prefix in &type_prefixes {
            if trimmed.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Check if a function signature contains access control modifiers
    fn has_access_control(&self, func_sig: &str) -> bool {
        let access_modifiers = [
            "onlyOwner",
            "onlyAdmin",
            "onlyRole",
            "onlyGovernor",
            "onlyGovernance",
            "onlyGuardian",
            "onlyTimelock",
            "onlyController",
            "onlyAuthorized",
            "onlyOperator",
            "onlyMinter",
            "requiresAuth",
        ];
        for modifier in &access_modifiers {
            if func_sig.contains(modifier) {
                return true;
            }
        }
        false
    }

    /// Check if a function name represents a governance mechanism itself
    /// (these functions ARE the governance process, not a bypass of it)
    fn is_governance_mechanism(&self, func_name: &str) -> bool {
        let gov_mechanisms = [
            "propose",
            "vote",
            "castVote",
            "execute",
            "queue",
            "cancel",
            "_castVote",
            "_execute",
            "_queue",
            "_cancel",
            "updateParameters",
            "initialize",
        ];
        let name_lower = func_name.to_lowercase();
        for mechanism in &gov_mechanisms {
            if name_lower == mechanism.to_lowercase() {
                return true;
            }
        }
        false
    }

    /// Check if a line is inside an interface definition (not a contract body)
    fn is_inside_interface(&self, lines: &[&str], line_num: usize) -> bool {
        let mut depth: i32 = 0;
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            for c in trimmed.chars().rev() {
                match c {
                    '}' => depth += 1,
                    '{' => {
                        depth -= 1;
                        if depth < 0 {
                            if trimmed.starts_with("interface ") || trimmed.contains(" interface ")
                            {
                                return true;
                            }
                            if i > 0 {
                                let prev = lines[i - 1].trim();
                                if prev.starts_with("interface ") || prev.contains(" interface ") {
                                    return true;
                                }
                            }
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Returns the full function signature line containing the given line number
    fn find_containing_function_signature(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                let mut sig = trimmed.to_string();
                if sig.contains('{') || sig.contains(';') {
                    return sig;
                }
                for j in (i + 1)..lines.len().min(i + 10) {
                    let next = lines[j].trim();
                    sig.push(' ');
                    sig.push_str(next);
                    if next.contains('{') || next.contains(';') {
                        break;
                    }
                }
                return sig;
            }
        }
        String::new()
    }

    /// Find parameter changes without timelock
    fn find_untimelocked_params(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Track if contract has timelock
        let has_timelock = source.contains("TimelockController")
            || source.contains("timelock")
            || source.contains("Timelock");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip lines inside interface definitions
            if self.is_inside_interface(&lines, line_num) {
                continue;
            }

            // Look for setter functions for governance parameters
            if trimmed.contains("function set")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);

                // Check if it's a governance parameter
                let is_gov_param = func_name.to_lowercase().contains("quorum")
                    || func_name.to_lowercase().contains("threshold")
                    || func_name.to_lowercase().contains("delay")
                    || func_name.to_lowercase().contains("period")
                    || func_name.to_lowercase().contains("fee")
                    || func_name.to_lowercase().contains("rate")
                    || func_name.to_lowercase().contains("limit");

                if is_gov_param {
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    // Check for timelock protection
                    let has_timelock_check = func_body.contains("onlyTimelock")
                        || func_body.contains("timelockController")
                        || func_body.contains("require(msg.sender == timelock")
                        || func_body.contains("_checkTimelock");

                    // Check for access control modifiers on the setter itself
                    let has_access_ctrl = self.has_access_control(trimmed);

                    // FP Reduction: Skip fee setters that have explicit bounds checks.
                    // require(newFee <= MAX_FEE) or similar bounds enforcement is
                    // sufficient protection for non-governance fee parameters.
                    let has_fee_bounds = func_body.contains("MAX_FEE")
                        || func_body.contains("MAX_RATE")
                        || func_body.contains("maxFee")
                        || func_body.contains("FEE_LIMIT")
                        || (func_body.contains("require(") && func_body.contains("<="));

                    if !has_timelock_check && !has_timelock && !has_access_ctrl && !has_fee_bounds {
                        let issue =
                            "No timelock protection on governance parameter setter".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Look for direct state changes to governance variables
            if (trimmed.contains("votingDelay =")
                || trimmed.contains("votingPeriod =")
                || trimmed.contains("quorumNumerator =")
                || trimmed.contains("proposalThreshold ="))
                && !trimmed.starts_with("//")
            {
                // Skip state variable declarations (e.g., "uint256 public votingDelay = 1 days;")
                if self.is_state_variable_declaration(trimmed) {
                    continue;
                }

                // Get the containing function's full signature to check access control
                let func_sig = self.find_containing_function_signature(&lines, line_num);
                let func_name = self.extract_function_name(&func_sig);

                // Skip if the containing function has access control modifiers
                if self.has_access_control(&func_sig) {
                    continue;
                }

                // Skip if the function IS a governance mechanism (propose, vote, execute, etc.)
                if self.is_governance_mechanism(&func_name) {
                    continue;
                }

                let issue = "Direct governance parameter modification".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Find emergency parameter changes
    fn find_emergency_bypasses(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for emergency functions that bypass governance
            if trimmed.contains("function ")
                && (trimmed.contains("emergency") || trimmed.contains("Emergency"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if emergency function modifies governance params
                if func_body.contains("votingDelay")
                    || func_body.contains("votingPeriod")
                    || func_body.contains("quorum")
                    || func_body.contains("threshold")
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

    fn _find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
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

impl Detector for GovernanceParameterBypassDetector {
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

        for (line, func_name, issue) in self.find_untimelocked_params(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows governance parameter changes without \
                 timelock protection. {}. Admins can bypass governance by changing parameters \
                 before proposals execute.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect governance parameter changes:\n\n\
                     1. Route all parameter changes through timelock\n\
                     2. Use onlyTimelock modifier for setters\n\
                     3. Implement parameter change proposals\n\
                     4. Add minimum delay before changes take effect\n\n\
                     Example:\n\
                     function setVotingDelay(uint256 newDelay) external onlyTimelock {\n\
                         _setVotingDelay(newDelay);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_emergency_bypasses(source) {
            let message = format!(
                "Emergency function '{}' in contract '{}' can modify governance parameters, \
                 potentially bypassing governance controls during emergencies.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit emergency function scope:\n\n\
                     1. Emergency functions should only pause, not modify parameters\n\
                     2. Require multi-sig for emergency parameter changes\n\
                     3. Log all emergency actions with events\n\
                     4. Add cool-down periods after emergency use"
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
        let detector = GovernanceParameterBypassDetector::new();
        assert_eq!(detector.name(), "Governance Parameter Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    #[test]
    fn test_skips_state_variable_declarations() {
        let detector = GovernanceParameterBypassDetector::new();
        assert!(detector.is_state_variable_declaration("uint256 public votingDelay = 1 days;"));
        assert!(detector.is_state_variable_declaration("uint256 public votingPeriod = 3 days;"));
        assert!(
            detector.is_state_variable_declaration("uint256 public proposalThreshold = 100000e18;")
        );
        assert!(!detector.is_state_variable_declaration("votingDelay = _votingDelay;"));
        assert!(!detector.is_state_variable_declaration("proposalThreshold = newThreshold;"));
    }

    #[test]
    fn test_has_access_control() {
        let detector = GovernanceParameterBypassDetector::new();
        assert!(
            detector
                .has_access_control("function updateParameters(uint256 x) external onlyOwner {")
        );
        assert!(detector.has_access_control("function setFee(uint256 x) external onlyGuardian {"));
        assert!(
            detector.has_access_control("function setDelay(uint256 x) external onlyGovernance {")
        );
        assert!(!detector.has_access_control("function setDelay(uint256 x) external {"));
        assert!(!detector.has_access_control("function setDelay(uint256 x) public {"));
    }

    #[test]
    fn test_is_governance_mechanism() {
        let detector = GovernanceParameterBypassDetector::new();
        assert!(detector.is_governance_mechanism("propose"));
        assert!(detector.is_governance_mechanism("execute"));
        assert!(detector.is_governance_mechanism("queue"));
        assert!(detector.is_governance_mechanism("cancel"));
        assert!(detector.is_governance_mechanism("castVote"));
        assert!(detector.is_governance_mechanism("updateParameters"));
        assert!(!detector.is_governance_mechanism("setFee"));
        assert!(!detector.is_governance_mechanism("withdrawFunds"));
    }

    #[test]
    fn test_is_inside_interface() {
        let detector = GovernanceParameterBypassDetector::new();
        let source = "interface IERC20 {\n    function transfer(address to, uint256 amount) external returns (bool);\n    function balanceOf(address account) external view returns (uint256);\n}\n\ncontract MyContract {\n    uint256 public votingDelay = 1 days;\n}";
        let lines: Vec<&str> = source.lines().collect();
        assert!(detector.is_inside_interface(&lines, 1));
        assert!(detector.is_inside_interface(&lines, 2));
        assert!(!detector.is_inside_interface(&lines, 6));
    }

    #[test]
    fn test_no_fp_on_access_controlled_assignments() {
        let detector = GovernanceParameterBypassDetector::new();
        let source = "contract Gov {\n    uint256 public votingDelay = 1 days;\n    uint256 public votingPeriod = 3 days;\n\n    function updateParameters(uint256 _delay, uint256 _period) external onlyOwner {\n        votingDelay = _delay;\n        votingPeriod = _period;\n    }\n}";
        let findings = detector.find_untimelocked_params(source);
        assert!(
            findings.is_empty(),
            "Should not flag access-controlled assignments, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_detects_unprotected_setter() {
        let detector = GovernanceParameterBypassDetector::new();
        let source = "contract Gov {\n    uint256 public votingDelay;\n\n    function setDelay(uint256 _delay) external {\n        votingDelay = _delay;\n    }\n}";
        let findings = detector.find_untimelocked_params(source);
        assert!(
            !findings.is_empty(),
            "Should flag unprotected direct modification"
        );
    }
}
