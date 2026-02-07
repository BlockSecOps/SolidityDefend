use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for timelock bypass via delegatecall vulnerabilities
///
/// Detects patterns where timelock guards can be bypassed through
/// delegatecall via proxy contracts.
pub struct TimelockBypassDelegatecallDetector {
    base: BaseDetector,
}

impl Default for TimelockBypassDelegatecallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelockBypassDelegatecallDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("timelock-bypass-delegatecall"),
                "Timelock Bypass via Delegatecall".to_string(),
                "Detects patterns where timelock restrictions can be bypassed by \
                 routing calls through proxy contracts with delegatecall."
                    .to_string(),
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::Upgradeable,
                ],
                Severity::Critical,
            ),
        }
    }

    /// Check if source has strong timelock context in actual code (not just comments).
    /// Requires actual timelock mechanisms: delay variables, scheduled operations,
    /// TimelockController usage, or onlyTimelock modifiers in code lines.
    fn has_strong_timelock_context(source: &str) -> bool {
        let code_lines: Vec<&str> = source
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.starts_with("//")
                    && !t.starts_with("*")
                    && !t.starts_with("/**")
                    && !t.starts_with("///")
            })
            .collect();
        let code = code_lines.join("\n");

        // Require actual timelock code patterns, not mere mentions in comments
        let has_timelock_type = code.contains("TimelockController")
            || code.contains("ITimelock")
            || code.contains("onlyTimelock");

        let has_delay_mechanism = code.contains("UPGRADE_DELAY")
            || code.contains("MIN_DELAY")
            || code.contains("executionDelay")
            || code.contains("block.timestamp + ")
            || code.contains("block.timestamp >=");

        let has_scheduled_ops = code.contains("scheduleBatch")
            || code.contains("schedule(")
            || code.contains("executeAfter")
            || code.contains("pendingUpgrade")
            || code.contains("PendingUpgrade")
            || code.contains("proposeUpgrade");

        has_timelock_type || (has_delay_mechanism && has_scheduled_ops)
    }

    /// Check if a function has proper access control (modifier or inline check).
    /// Both func_header and func_body are checked since multi-line function
    /// declarations may place modifiers beyond the first few lines.
    fn function_has_access_control(func_header: &str, func_body: &str) -> bool {
        // Check for access control modifiers -- search both header and body
        // because multi-line signatures may place modifiers on later lines
        let access_modifiers = [
            "onlyOwner",
            "onlyAdmin",
            "ifAdmin",
            "onlyRole",
            "onlyGovernance",
            "onlyTimelock",
            "onlyAuthorized",
            "onlyProxy",
            "requiresAuth",
        ];
        for m in &access_modifiers {
            if func_header.contains(m) || func_body.contains(m) {
                return true;
            }
        }

        // Check for inline access control in the body
        let access_checks = [
            "require(msg.sender ==",
            "if (msg.sender ==",
            "if(msg.sender ==",
            "_checkOwner()",
            "_checkRole(",
        ];
        for c in &access_checks {
            if func_body.contains(c) {
                return true;
            }
        }

        false
    }

    /// Find delegatecall timelock bypass patterns
    fn find_delegatecall_bypass(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Require strong timelock context -- not just the word in a comment
        if !Self::has_strong_timelock_context(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for delegatecall patterns
            if trimmed.contains("delegatecall") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Skip fallback/receive -- handled by find_proxy_bypass
                if func_name == "unknown" || func_name.is_empty() {
                    continue;
                }

                // Get the function header and body for access control check
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_function_end(&lines, func_start);
                let func_header: String =
                    lines[func_start..func_start.saturating_add(3).min(lines.len())].join(" ");
                let func_body: String = lines[func_start..func_end].join("\n");

                // Skip if the function has proper access control
                if Self::function_has_access_control(&func_header, &func_body) {
                    continue;
                }

                // Skip view/pure functions (no state change possible)
                if func_header.contains("view") || func_header.contains("pure") {
                    continue;
                }

                let issue = "Delegatecall without timelock verification".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Look for execute functions that might bypass timelock
            if trimmed.contains("function execute")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_header: String =
                    lines[line_num..line_num.saturating_add(3).min(lines.len())].join(" ");

                // Check if execute uses delegatecall without any access control
                if func_body.contains("delegatecall")
                    && !Self::function_has_access_control(&func_header, &func_body)
                {
                    let issue = "Execute function with delegatecall lacks timelock".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find proxy pattern vulnerabilities
    fn find_proxy_bypass(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Only relevant if the contract actually has timelock context
        if !Self::has_strong_timelock_context(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for fallback functions with delegatecall
            if (trimmed.contains("fallback()") || trimmed.contains("receive()"))
                && (trimmed.contains("external") || trimmed.contains("payable"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for delegatecall to implementation
                if func_body.contains("delegatecall") {
                    // Skip if fallback has transparent proxy pattern (admin check)
                    if func_body.contains("msg.sender == _getAdmin()")
                        || func_body.contains("msg.sender == admin")
                        || func_body.contains("_getAdmin()")
                        || func_body.contains("ifAdmin")
                    {
                        continue;
                    }

                    // Skip if there is proper access control on upgrade functions
                    let has_protected_upgrade = {
                        let upgrade_patterns =
                            ["upgradeTo", "setImplementation", "_setImplementation"];
                        let access_patterns = [
                            "onlyOwner",
                            "onlyAdmin",
                            "ifAdmin",
                            "onlyTimelock",
                            "onlyRole",
                            "onlyGovernance",
                            "requiresAuth",
                        ];
                        upgrade_patterns.iter().any(|up| {
                            // Find the upgradeTo function and check for access control
                            if let Some(pos) = source.find(up) {
                                let region_start = pos.saturating_sub(200);
                                let region_end = (pos + 200).min(source.len());
                                let region = &source[region_start..region_end];
                                access_patterns.iter().any(|ac| region.contains(ac))
                            } else {
                                false
                            }
                        })
                    };

                    if has_protected_upgrade {
                        continue;
                    }

                    findings.push((line_num as u32 + 1, "fallback".to_string()));
                }
            }
        }

        findings
    }

    /// Find msg.sender confusion in delegatecall
    fn find_sender_confusion(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Only relevant if the contract actually has timelock context
        if !Self::has_strong_timelock_context(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comment lines
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Look for timelock checks that might be bypassed
            if trimmed.contains("msg.sender == timelock")
                || trimmed.contains("msg.sender == address(timelock)")
            {
                // Check if this function body actually contains delegatecall
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_function_end(&lines, func_start);
                let func_body: String = lines[func_start..func_end].join("\n");

                // Only flag if the function itself uses delegatecall or is
                // explicitly callable via delegatecall (has no address(this) guard)
                if func_body.contains("delegatecall") {
                    let func_name = self.find_containing_function(&lines, line_num);
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

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    /// Find the line number where the containing function starts
    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ")
                || trimmed.contains("fallback()")
                || trimmed.contains("receive()")
            {
                return i;
            }
        }
        0
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

impl Detector for TimelockBypassDelegatecallDetector {
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

        for (line, func_name, issue) in self.find_delegatecall_bypass(source) {
            let message = format!(
                "Function '{}' in contract '{}' may bypass timelock via delegatecall. {}. \
                 Attackers can route timelocked operations through proxy to skip delays.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent timelock bypass via delegatecall:\n\n\
                     1. Apply timelock checks to all entry points\n\
                     2. Verify msg.sender in implementation, not just proxy\n\
                     3. Disable delegatecall for timelocked functions\n\
                     4. Use explicit function calls instead of delegatecall\n\n\
                     Example:\n\
                     modifier onlyTimelock() {\n\
                         require(msg.sender == address(timelock), \"Not timelock\");\n\
                         require(address(this) == implementation, \"No delegatecall\");\n\
                         _;\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_proxy_bypass(source) {
            let message = format!(
                "Proxy {} in contract '{}' can bypass timelock through implementation switch. \
                 Admins can change implementation to bypass timelocked functions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect proxy implementation changes:\n\n\
                     1. Require timelock for implementation upgrades\n\
                     2. Add upgrade delay longer than max proposal timelock\n\
                     3. Emit events for all implementation changes"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_sender_confusion(source) {
            let message = format!(
                "Timelock check in '{}' of contract '{}' may be confused in delegatecall context. \
                 msg.sender preservation in delegatecall can bypass authorization.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Verify delegatecall context:\n\n\
                     require(address(this) == expectedAddress, \"Direct call only\");"
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
        let detector = TimelockBypassDelegatecallDetector::new();
        assert_eq!(detector.name(), "Timelock Bypass via Delegatecall");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    // --- has_strong_timelock_context tests ---

    #[test]
    fn test_no_timelock_context() {
        // Plain proxy with no timelock -- should NOT trigger
        let source = r#"
contract SimpleProxy {
    address public implementation;
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"#;
        assert!(!TimelockBypassDelegatecallDetector::has_strong_timelock_context(source));
    }

    #[test]
    fn test_timelock_only_in_comments() {
        // The word "timelock" only in comments -- should NOT count
        let source = r#"
contract ProxyUpgrade {
    // Should ideally use timelock for upgrades
    address public implementation;
    function upgradeTo(address newImpl) external onlyAdmin {
        implementation = newImpl;
    }
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
        }
    }
}
"#;
        assert!(!TimelockBypassDelegatecallDetector::has_strong_timelock_context(source));
    }

    #[test]
    fn test_strong_timelock_with_controller() {
        let source = r#"
contract TimelockProxy {
    TimelockController public timelock;
    function execute(bytes calldata data) external {
        (bool s,) = impl.delegatecall(data);
    }
}
"#;
        assert!(TimelockBypassDelegatecallDetector::has_strong_timelock_context(source));
    }

    #[test]
    fn test_strong_timelock_with_delay_and_schedule() {
        let source = r#"
contract TimelockProxy {
    uint256 public constant UPGRADE_DELAY = 2 days;
    mapping(bytes32 => PendingUpgrade) public pendingUpgrades;
    function proposeUpgrade(address newImpl) external {
        uint256 executeAfter = block.timestamp + UPGRADE_DELAY;
    }
    function executeUpgrade(bytes32 id) external {
        require(block.timestamp >= pending.executeAfter, "too early");
    }
}
"#;
        assert!(TimelockBypassDelegatecallDetector::has_strong_timelock_context(source));
    }

    // --- find_delegatecall_bypass tests ---

    #[test]
    fn test_delegatecall_bypass_no_timelock_context_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Contract without timelock context should produce zero findings
        let source = r#"
contract Proxy {
    address public implementation;
    function execute(bytes calldata data) external {
        (bool s,) = implementation.delegatecall(data);
        require(s);
    }
}
"#;
        let findings = detector.find_delegatecall_bypass(source);
        assert!(
            findings.is_empty(),
            "Should not fire without timelock context"
        );
    }

    #[test]
    fn test_delegatecall_bypass_with_access_control_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Has timelock context but delegatecall has onlyAdmin -- safe
        let source = r#"
contract TimelockProxy {
    TimelockController public timelock;
    address public impl;
    function upgradeToAndCall(address newImpl, bytes memory data) external onlyAdmin {
        (bool s,) = newImpl.delegatecall(data);
        require(s);
    }
}
"#;
        let findings = detector.find_delegatecall_bypass(source);
        assert!(
            findings.is_empty(),
            "Should not fire when access control is present"
        );
    }

    #[test]
    fn test_delegatecall_bypass_unprotected_fires() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Has timelock context and unprotected delegatecall -- should fire
        let source = r#"
contract TimelockProxy {
    TimelockController public timelock;
    address public impl;
    function execute(bytes calldata data) external {
        (bool s,) = impl.delegatecall(data);
        require(s);
    }
}
"#;
        let findings = detector.find_delegatecall_bypass(source);
        assert!(
            !findings.is_empty(),
            "Should fire for unprotected delegatecall in timelock context"
        );
    }

    // --- find_proxy_bypass tests ---

    #[test]
    fn test_proxy_bypass_no_timelock_context_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Standard proxy without timelock -- should NOT fire
        let source = r#"
contract Proxy {
    address public implementation;
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(implementation.slot), 0, calldatasize(), 0, 0)
        }
    }
}
"#;
        let findings = detector.find_proxy_bypass(source);
        assert!(
            findings.is_empty(),
            "Should not fire without timelock context"
        );
    }

    #[test]
    fn test_proxy_bypass_with_admin_check_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Transparent proxy with admin guard -- should NOT fire
        let source = r#"
contract TimelockProxy {
    TimelockController public timelock;
    fallback() external payable {
        if (msg.sender == _getAdmin()) { return; }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"#;
        let findings = detector.find_proxy_bypass(source);
        assert!(
            findings.is_empty(),
            "Should not fire when transparent proxy pattern is used"
        );
    }

    #[test]
    fn test_proxy_bypass_with_protected_upgrade_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Timelock context but upgrade is protected by onlyOwner -- safe
        let source = r#"
contract TimelockProxy {
    TimelockController public timelock;
    address public impl;
    function upgradeTo(address newImpl) external onlyOwner {
        impl = newImpl;
    }
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(impl.slot), 0, calldatasize(), 0, 0)
        }
    }
}
"#;
        let findings = detector.find_proxy_bypass(source);
        assert!(
            findings.is_empty(),
            "Should not fire when upgrade function has access control"
        );
    }

    // --- find_sender_confusion tests ---

    #[test]
    fn test_sender_confusion_no_timelock_context_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // No timelock context at all
        let source = r#"
contract Proxy {
    address public admin;
    function check() external {
        require(msg.sender == admin);
    }
}
"#;
        let findings = detector.find_sender_confusion(source);
        assert!(
            findings.is_empty(),
            "Should not fire without timelock context"
        );
    }

    #[test]
    fn test_sender_confusion_with_delegatecall_fires() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Timelock check inside a function that also uses delegatecall -- should fire
        let source = r#"
contract TimelockImpl {
    TimelockController public timelock;
    function executeAction(bytes calldata data) external {
        require(msg.sender == address(timelock), "not timelock");
        (bool s,) = target.delegatecall(data);
    }
}
"#;
        let findings = detector.find_sender_confusion(source);
        assert!(
            !findings.is_empty(),
            "Should fire when timelock check is in function with delegatecall"
        );
    }

    #[test]
    fn test_sender_confusion_no_delegatecall_in_function_no_findings() {
        let detector = TimelockBypassDelegatecallDetector::new();
        // Timelock check but no delegatecall in the same function
        let source = r#"
contract TimelockImpl {
    TimelockController public timelock;
    function setParam(uint256 val) external {
        require(msg.sender == address(timelock), "not timelock");
        param = val;
    }
    function otherFunc(bytes calldata data) external {
        (bool s,) = target.delegatecall(data);
    }
}
"#;
        let findings = detector.find_sender_confusion(source);
        assert!(
            findings.is_empty(),
            "Should not fire when delegatecall is in a different function"
        );
    }
}
