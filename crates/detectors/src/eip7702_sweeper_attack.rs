use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_test_contract, is_eip7702_context};

/// Detector for EIP-7702 sweeper attack vulnerabilities
///
/// Detects contracts designed to drain assets from delegating EOAs
/// when used as EIP-7702 delegation targets.
///
/// Vulnerable pattern:
/// ```solidity
/// // Malicious sweeper contract
/// contract Sweeper {
///     address attacker;
///
///     function sweep() external {
///         // Drain all ETH
///         payable(attacker).transfer(address(this).balance);
///
///         // Drain all tokens
///         for (address token in tokens) {
///             IERC20(token).transfer(attacker, IERC20(token).balanceOf(address(this)));
///         }
///     }
/// }
/// ```
pub struct Eip7702SweeperAttackDetector {
    base: BaseDetector,
}

impl Default for Eip7702SweeperAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip7702SweeperAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip7702-sweeper-attack"),
                "EIP-7702 Sweeper Attack".to_string(),
                "Detects contracts that could be used to sweep/drain all assets from \
                 an EOA when used as an EIP-7702 delegation target. These patterns \
                 enable attackers to steal all funds after gaining delegation."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Find functions that transfer entire ETH balance
    fn find_eth_sweep(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for full balance transfers
            if (trimmed.contains(".transfer(") || trimmed.contains(".call{value:"))
                && (trimmed.contains("address(this).balance")
                    || trimmed.contains("balance"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Look for send with full balance
            if trimmed.contains(".send(") && trimmed.contains("balance") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find functions that transfer entire token balance
    fn find_token_sweep(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for transferring balanceOf results
            if trimmed.contains(".transfer(") || trimmed.contains(".transferFrom(") {
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = std::cmp::min(line_num + 2, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Suspicious if using balanceOf in transfer amount
                if context.contains("balanceOf(") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Look for safeTransfer with balance
            if trimmed.contains("safeTransfer") && trimmed.contains("balance") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find hardcoded attacker addresses
    fn find_hardcoded_recipient(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for hardcoded addresses in state variables
            if trimmed.contains("address")
                && (trimmed.contains("0x") || trimmed.contains("payable"))
                && (trimmed.contains("recipient")
                    || trimmed.contains("beneficiary")
                    || trimmed.contains("owner")
                    || trimmed.contains("admin")
                    || trimmed.contains("treasury"))
            {
                // Check if it's immutable/constant with hardcoded value
                if trimmed.contains("immutable") || trimmed.contains("constant") {
                    if trimmed.contains("0x") {
                        findings.push((line_num as u32 + 1, "hardcoded_recipient".to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Find batch sweep patterns
    fn find_batch_sweep(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for loops with transfers
            if (trimmed.starts_with("for ") || trimmed.starts_with("for("))
                && trimmed.contains("token")
            {
                let func_end = self.find_loop_end(&lines, line_num);
                let loop_body: String = lines[line_num..func_end].join("\n");

                if loop_body.contains("transfer(")
                    || loop_body.contains("transferFrom(")
                    || loop_body.contains("safeTransfer")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find sweep function names
    fn find_sweep_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let lower = trimmed.to_lowercase();
                if lower.contains("sweep")
                    || lower.contains("drain")
                    || lower.contains("withdraw")
                    || lower.contains("rescue")
                    || lower.contains("recover")
                    || lower.contains("extract")
                {
                    // Check function body for transfer patterns
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    if func_body.contains("transfer(")
                        || func_body.contains(".call{value:")
                        || func_body.contains("safeTransfer")
                    {
                        let func_name = self.extract_function_name(trimmed);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    /// Find end of a function
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

    /// Find end of a loop
    fn find_loop_end(&self, lines: &[&str], start: usize) -> usize {
        self.find_function_end(lines, start)
    }

    /// Find the line number of the function containing a given line
    fn find_function_line(&self, lines: &[&str], from_line: usize) -> usize {
        for i in (0..=from_line).rev() {
            if i < lines.len() && lines[i].contains("function ") {
                return i;
            }
        }
        0
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }

    /// Check if contract appears to be an EIP-7702 delegation target
    fn is_eip7702_context(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Strong EIP-7702 signals
        lower.contains("eip7702")
            || lower.contains("eip-7702")
            || source.contains("AUTH")
            || source.contains("AUTHCALL")
            || source.contains("setCode")
            || source.contains("SET_CODE")
            || lower.contains("delegatecode")
            || lower.contains("executeas")
    }

    /// Check if a function has access control modifiers
    fn function_has_access_control(&self, lines: &[&str], func_line: usize) -> bool {
        // Look at the function declaration line
        if func_line < lines.len() {
            let line = lines[func_line].to_lowercase();
            // Common access control modifiers
            if line.contains("onlyowner")
                || line.contains("only_owner")
                || line.contains("onlyadmin")
                || line.contains("onlyminter")
                || line.contains("onlyauthorized")
                || line.contains("onlyrole")
                || line.contains("whennotpaused")
                || line.contains("nonreentrant")
                || line.contains("auth")
                || line.contains("restricted")
            {
                return true;
            }
        }

        // Also check the function body for require(msg.sender == owner) patterns
        let func_end = self.find_function_end(lines, func_line);
        let func_body: String = lines[func_line..func_end].join("\n").to_lowercase();

        func_body.contains("require(msg.sender ==")
            || func_body.contains("require(_msgSender() ==")
            || func_body.contains("if (msg.sender !=")
            || func_body.contains("hasrole(")
            || func_body.contains("onlyowner")
    }
}

impl Detector for Eip7702SweeperAttackDetector {
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
        let lines: Vec<&str> = source.lines().collect();

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Use shared EIP-7702 context detection (requires 2+ indicators)
        // Only flag if contract appears to be EIP-7702 related
        // Otherwise these are legitimate rescue/recovery functions
        let is_7702_context = is_eip7702_context(ctx);

        // Find sweep function patterns
        // Phase 6.1 FP Reduction: Only report sweep functions if in EIP-7702 context
        // Otherwise these are legitimate rescue/recovery functions commonly used in DeFi
        let sweep_funcs = self.find_sweep_functions(source);
        for (line, func_name) in &sweep_funcs {
            // Skip functions with access control - they are legitimate rescue functions
            let func_line_idx = (*line as usize).saturating_sub(1);
            if self.function_has_access_control(&lines, func_line_idx) {
                continue;
            }

            // Phase 6.1: Require EIP-7702 context for ALL sweep function findings
            // Without EIP-7702 context, these are legitimate rescue/recovery functions
            if !is_7702_context {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' has sweeper-like naming and contains asset \
                 transfers. If used as an EIP-7702 delegation target, this could allow \
                 draining all assets from the delegating EOA.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(306) // CWE-306: Missing Authentication for Critical Function
                .with_confidence(if is_7702_context {
                    Confidence::High
                } else {
                    Confidence::Medium
                })
                .with_fix_suggestion(
                    "If this is a legitimate rescue function:\n\n\
                     1. Add strict access control (onlyOwner, multi-sig)\n\
                     2. Add timelock delays for large withdrawals\n\
                     3. Emit events for all asset movements\n\
                     4. Consider withdrawal limits\n\
                     5. Document the function's intended use\n\n\
                     NEVER use as EIP-7702 delegation target without safeguards."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find ETH sweep patterns - only report if in EIP-7702 context or no access control
        if is_7702_context {
            let eth_sweeps = self.find_eth_sweep(source);
            for (line, func_name) in eth_sweeps {
                if sweep_funcs.iter().any(|(l, _)| *l == line) {
                    continue;
                }

                // Skip if function has access control
                let func_line_idx = self.find_function_line(&lines, (line as usize).saturating_sub(1));
                if self.function_has_access_control(&lines, func_line_idx) {
                    continue;
                }

                let message = format!(
                    "Function '{}' in contract '{}' transfers the entire ETH balance. \
                     This pattern could be exploited in EIP-7702 delegation to drain \
                     all ETH from a user's account.",
                    func_name, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 50)
                    .with_cwe(306)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Avoid transferring full balance:\n\n\
                         1. Use specific amounts instead of address(this).balance\n\
                         2. Add withdrawal limits and rate limiting\n\
                         3. Require multi-sig approval for large transfers"
                            .to_string(),
                    );

                findings.push(finding);
            }

            // Find token sweep patterns
            let token_sweeps = self.find_token_sweep(source);
            for (line, func_name) in token_sweeps {
                // Skip if function has access control
                let func_line_idx = self.find_function_line(&lines, (line as usize).saturating_sub(1));
                if self.function_has_access_control(&lines, func_line_idx) {
                    continue;
                }

                let message = format!(
                    "Function '{}' in contract '{}' transfers entire token balances. \
                     This pattern could be exploited in EIP-7702 delegation to drain \
                     all tokens from a user's account.",
                    func_name, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 50)
                    .with_cwe(306)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Avoid transferring full token balance:\n\n\
                         1. Use specific amounts instead of balanceOf()\n\
                         2. Add per-token and total limits\n\
                         3. Implement allowlist of transferable tokens"
                            .to_string(),
                    );

                findings.push(finding);
            }

            // Find batch sweep patterns
            let batch_sweeps = self.find_batch_sweep(source);
            for (line, func_name) in batch_sweeps {
                // Skip if function has access control
                let func_line_idx = self.find_function_line(&lines, (line as usize).saturating_sub(1));
                if self.function_has_access_control(&lines, func_line_idx) {
                    continue;
                }

                let message = format!(
                    "Function '{}' in contract '{}' contains a loop that transfers tokens. \
                     This batch sweep pattern is highly dangerous in EIP-7702 delegation \
                     as it can drain multiple token types in one transaction.",
                    func_name, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 50)
                    .with_cwe(306)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Batch sweep patterns are extremely dangerous:\n\n\
                         1. Remove batch functionality if possible\n\
                         2. Add per-token approval requirements\n\
                         3. Implement strict access control\n\
                         4. Add delays between batch operations"
                            .to_string(),
                    );

                findings.push(finding);
            }
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
        let detector = Eip7702SweeperAttackDetector::new();
        assert_eq!(detector.name(), "EIP-7702 Sweeper Attack");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_eth_sweep() {
        let detector = Eip7702SweeperAttackDetector::new();

        let vulnerable = r#"
            contract Sweeper {
                function sweep() external {
                    payable(owner).transfer(address(this).balance);
                }
            }
        "#;
        let findings = detector.find_eth_sweep(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_token_sweep() {
        let detector = Eip7702SweeperAttackDetector::new();

        let vulnerable = r#"
            contract Sweeper {
                function sweepToken(address token) external {
                    uint256 balance = IERC20(token).balanceOf(address(this));
                    IERC20(token).transfer(owner, balance);
                }
            }
        "#;
        let findings = detector.find_token_sweep(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_sweep_function_name() {
        let detector = Eip7702SweeperAttackDetector::new();

        let vulnerable = r#"
            contract Sweeper {
                function sweep(address token) external {
                    IERC20(token).transfer(owner, 100);
                }
            }
        "#;
        let findings = detector.find_sweep_functions(vulnerable);
        assert!(!findings.is_empty());
    }
}
