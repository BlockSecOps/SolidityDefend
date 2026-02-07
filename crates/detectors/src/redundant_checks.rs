use anyhow::Result;
use std::any::Any;
use std::collections::HashSet;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for redundant validation checks that waste gas
pub struct RedundantChecksDetector {
    base: BaseDetector,
}

impl Default for RedundantChecksDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RedundantChecksDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("redundant-checks".to_string()),
                "Redundant Checks".to_string(),
                "Detects redundant validation checks that unnecessarily waste gas, including duplicate require statements, unnecessary overflow checks, and redundant modifiers".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Low,
            ),
        }
    }
}

impl Detector for RedundantChecksDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
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


        for function in ctx.get_functions() {
            if let Some(redundant_issues) = self.check_redundant_checks(function, ctx) {
                for issue_desc in redundant_issues {
                    let message = format!(
                        "Function '{}' contains redundant checks. {} \
                        Redundant checks waste gas and increase transaction costs unnecessarily.",
                        function.name.name, issue_desc
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                        .with_fix_suggestion(format!(
                            "Remove redundant checks in '{}'. \
                        Consider: (1) Eliminate duplicate require() statements, \
                        (2) Combine multiple checks into single require(), \
                        (3) Remove overflow checks in Solidity >=0.8, \
                        (4) Avoid checking same condition in modifier and function, \
                        (5) Use custom errors instead of require with strings.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Represents a group of redundant consecutive require statements
/// that check overlapping conditions on the same variable.
struct RedundantGroup {
    /// Number of redundant conditions found
    count: usize,
    /// The variable or identifier that is redundantly checked
    variable: String,
}

impl RedundantChecksDetector {
    fn check_redundant_checks(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<Vec<String>> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let mut issues = Vec::new();

        // Pattern 1: Duplicate require statements
        let require_statements = self.extract_requires(&func_source);
        for (i, req1) in require_statements.iter().enumerate() {
            for req2 in require_statements.iter().skip(i + 1) {
                if self.are_similar_checks(req1, req2) {
                    issues.push(format!(
                        "Duplicate require check: '{}' appears multiple times",
                        req1.trim()
                    ));
                    break;
                }
            }
        }

        // Pattern 2: Redundant overflow checks in Solidity >=0.8
        let contract_source = ctx.source_code.as_str();
        let is_solidity_08_plus = contract_source.contains("pragma solidity ^0.8")
            || contract_source.contains("pragma solidity 0.8")
            || contract_source.contains("pragma solidity >=0.8");

        if is_solidity_08_plus
            && func_source.contains("require(")
            && (func_source.contains(" + ") || func_source.contains(" - "))
            && (func_source.contains("overflow") || func_source.contains("underflow"))
        {
            issues.push("Manual overflow/underflow check in Solidity 0.8+. Built-in protection makes this redundant".to_string());
        }

        // Pattern 3: Checking same condition in modifier and function
        if let Some(modifiers) = self.extract_modifiers(&func_source) {
            for modifier in modifiers {
                let modifier_source = self.find_modifier_source(contract_source, &modifier);
                if !modifier_source.is_empty() {
                    for req in &require_statements {
                        if modifier_source.contains(req.trim()) {
                            issues.push(format!(
                                "Redundant check in function body. Already validated by modifier '{}'",
                                modifier
                            ));
                        }
                    }
                }
            }
        }

        // Pattern 4: Unnecessary zero checks for unsigned integers
        if func_source.contains("require(")
            && func_source.contains(">= 0")
            && (func_source.contains("uint")
                || func_source.contains("amount >= 0")
                || func_source.contains("value >= 0"))
        {
            issues.push(
                "Redundant check: uint >= 0 is always true for unsigned integers".to_string(),
            );
        }

        // Pattern 5: Multiple consecutive requires checking the SAME variable/condition
        // Skip functions that are well-known validation-heavy patterns where
        // multiple distinct require statements are expected (governance, proxy,
        // paymaster, bridge, flash loan functions).
        if !self.is_validation_heavy_function(&function.name.name, &func_source) {
            if let Some(redundant_group) = self.find_redundant_consecutive_requires(&func_source) {
                issues.push(format!(
                    "{} consecutive require statements check overlapping conditions on '{}'. \
                     Consider combining into fewer checks",
                    redundant_group.count, redundant_group.variable
                ));
            }
        }

        // Pattern 6: Checking msg.sender != address(0)
        if func_source.contains("require(msg.sender != address(0)")
            || func_source.contains("require(msg.sender != 0")
        {
            issues.push("Redundant check: msg.sender can never be address(0)".to_string());
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn extract_requires(&self, source: &str) -> Vec<String> {
        let mut requires = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("require(") {
                if let Some(end) = trimmed.find(");") {
                    requires.push(trimmed[8..end].to_string());
                }
            }
        }

        requires
    }

    fn are_similar_checks(&self, check1: &str, check2: &str) -> bool {
        // Normalize whitespace for comparison
        let normalized1: String = check1.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized2: String = check2.split_whitespace().collect::<Vec<_>>().join(" ");

        normalized1 == normalized2
    }

    fn extract_modifiers(&self, source: &str) -> Option<Vec<String>> {
        // Look for function declaration line with modifiers
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            if line.contains("function ") {
                let modifiers: Vec<String> = line
                    .split_whitespace()
                    .filter(|word| {
                        !word.starts_with("function")
                            && !word.starts_with("(")
                            && !word.starts_with("public")
                            && !word.starts_with("private")
                            && !word.starts_with("external")
                            && !word.starts_with("internal")
                            && !word.starts_with("view")
                            && !word.starts_with("pure")
                            && !word.starts_with("payable")
                            && !word.starts_with("returns")
                            && !word.starts_with("{")
                            && word.chars().next().unwrap_or(' ').is_alphabetic()
                    })
                    .skip(1) // Skip function name
                    .map(|s| s.to_string())
                    .collect();

                if !modifiers.is_empty() {
                    return Some(modifiers);
                }
            }
        }
        None
    }

    fn find_modifier_source(&self, contract_source: &str, modifier_name: &str) -> String {
        let lines: Vec<&str> = contract_source.lines().collect();
        let mut in_modifier = false;
        let mut modifier_lines = Vec::new();
        let mut brace_count = 0;

        for line in lines {
            if line
                .trim()
                .starts_with(&format!("modifier {}", modifier_name))
            {
                in_modifier = true;
                brace_count = 0;
            }

            if in_modifier {
                modifier_lines.push(line);
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if brace_count <= 0 && line.contains('}') {
                    break;
                }
            }
        }

        modifier_lines.join("\n")
    }

    /// Check if a function name or context indicates a validation-heavy pattern
    /// where multiple distinct require statements are expected and appropriate.
    fn is_validation_heavy_function(&self, func_name: &str, func_source: &str) -> bool {
        let name_lower = func_name.to_lowercase();
        let source_lower = func_source.to_lowercase();

        // Governance / proposal functions
        if name_lower.contains("propose")
            || name_lower.contains("proposal")
            || name_lower.contains("vote")
            || name_lower.contains("execute")
        {
            return true;
        }

        // Proxy upgrade functions
        if name_lower.contains("upgrade")
            || name_lower.contains("upgradetoandinitialize")
            || name_lower.contains("_authorizeupgrade")
        {
            return true;
        }

        // Paymaster / account abstraction validation
        if name_lower.contains("validatepaymaster")
            || name_lower.contains("validateuserop")
            || name_lower.contains("paymaster")
            || name_lower.contains("sessionkey")
        {
            return true;
        }

        // Bridge / cross-chain message validation
        if name_lower.contains("receivemessage")
            || name_lower.contains("processmessage")
            || name_lower.contains("relayermessage")
            || name_lower.contains("verifymessage")
        {
            return true;
        }

        // Flash loan execution
        if name_lower.contains("flashloan") || name_lower.contains("flash_loan") {
            if source_lower.contains("flashloan") || source_lower.contains("flash") {
                return true;
            }
        }

        // AMM pool swap/mint/burn functions
        if name_lower.contains("swap") || name_lower.contains("mint") || name_lower.contains("burn") {
            if source_lower.contains("reserve") || source_lower.contains("liquidity") || source_lower.contains("amm") || source_lower.contains("invariant") {
                return true;
            }
        }

        // Generic multi-step validation patterns detected by context
        // EIP-1967 proxy patterns
        if source_lower.contains("implementation_slot")
            || source_lower.contains("eip1967")
            || source_lower.contains("erc1967")
        {
            return true;
        }

        // Governance context
        if source_lower.contains("proposalstate")
            || source_lower.contains("quorum")
            || source_lower.contains("votingdelay")
        {
            return true;
        }

        // Paymaster context
        if source_lower.contains("useroperation") || source_lower.contains("entrypoint") {
            return true;
        }

        false
    }

    /// Find groups of consecutive requires that check overlapping conditions
    /// (same primary variable). Returns None if all consecutive requires
    /// check different variables/conditions (which is valid input validation).
    fn find_redundant_consecutive_requires(&self, source: &str) -> Option<RedundantGroup> {
        let lines: Vec<&str> = source.lines().collect();
        let mut current_group: Vec<String> = Vec::new();
        let mut best_redundant: Option<RedundantGroup> = None;

        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("require(") {
                if let Some(end) = trimmed.find(");") {
                    let condition = trimmed[8..end].to_string();
                    current_group.push(condition);
                } else {
                    current_group.push(trimmed.to_string());
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
                if let Some(group) = self.check_group_for_redundancy(&current_group) {
                    if best_redundant
                        .as_ref()
                        .map_or(true, |best| group.count > best.count)
                    {
                        best_redundant = Some(group);
                    }
                }
                current_group.clear();
            }
        }

        // Check the last group
        if let Some(group) = self.check_group_for_redundancy(&current_group) {
            if best_redundant
                .as_ref()
                .map_or(true, |best| group.count > best.count)
            {
                best_redundant = Some(group);
            }
        }

        best_redundant
    }

    /// Check a group of consecutive require conditions for redundancy.
    /// Returns Some if multiple conditions check the same primary variable.
    /// A group must have at least 3 conditions with at least 3 sharing a variable.
    fn check_group_for_redundancy(&self, conditions: &[String]) -> Option<RedundantGroup> {
        if conditions.len() < 3 {
            return None;
        }

        // Extract primary variables from each condition
        let variables: Vec<Option<String>> = conditions
            .iter()
            .map(|c| self.extract_primary_variable(c))
            .collect();

        // Count how many conditions reference each variable
        let mut var_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for var in &variables {
            if let Some(v) = var {
                *var_counts.entry(v.clone()).or_insert(0) += 1;
            }
        }

        // Find the variable with the most overlapping checks
        // Only flag if a variable appears in 3+ consecutive requires
        let mut best_var: Option<(String, usize)> = None;
        for (var, count) in &var_counts {
            if *count >= 3 {
                if best_var
                    .as_ref()
                    .map_or(true, |(_, best_count)| count > best_count)
                {
                    best_var = Some((var.clone(), *count));
                }
            }
        }

        // Also check for truly duplicate conditions (exact same condition text)
        let unique_conditions: HashSet<String> = conditions
            .iter()
            .map(|c| c.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();

        let duplicate_count = conditions.len() - unique_conditions.len();
        if duplicate_count >= 2 {
            // Multiple exact duplicates detected
            return Some(RedundantGroup {
                count: conditions.len(),
                variable: "duplicate conditions".to_string(),
            });
        }

        best_var.map(|(var, count)| RedundantGroup {
            count,
            variable: var,
        })
    }

    /// Extract the primary variable being checked in a require condition.
    /// For example:
    ///   "amount > 0" -> Some("amount")
    ///   "msg.sender == owner" -> Some("msg.sender")
    ///   "balances[msg.sender] >= amount" -> Some("balances")
    fn extract_primary_variable(&self, condition: &str) -> Option<String> {
        // Remove the error message string part (everything after the last comma
        // before a string literal)
        let cond = if let Some(comma_idx) = condition.rfind(", \"") {
            &condition[..comma_idx]
        } else if let Some(comma_idx) = condition.rfind(", '") {
            &condition[..comma_idx]
        } else {
            condition
        };

        let cond = cond.trim();
        if cond.is_empty() {
            return None;
        }

        // Split on common comparison operators to get the left-hand side
        let lhs = if let Some(idx) = cond.find("!=") {
            &cond[..idx]
        } else if let Some(idx) = cond.find(">=") {
            &cond[..idx]
        } else if let Some(idx) = cond.find("<=") {
            &cond[..idx]
        } else if let Some(idx) = cond.find("==") {
            &cond[..idx]
        } else if let Some(idx) = cond.find('>') {
            &cond[..idx]
        } else if let Some(idx) = cond.find('<') {
            &cond[..idx]
        } else {
            // No comparison operator found; the whole condition is the variable
            // (e.g., a boolean expression like `isActive`)
            cond
        };

        let lhs = lhs.trim();
        if lhs.is_empty() {
            return None;
        }

        // Handle negation: "!paused" -> "paused", "!isActive" -> "isActive"
        let lhs = if lhs.starts_with('!') {
            lhs.trim_start_matches('!').trim()
        } else {
            lhs
        };

        if lhs.is_empty() {
            return None;
        }

        // Extract the base identifier (before any brackets, dots after first segment, etc.)
        // "balances[msg.sender]" -> "balances"
        // "msg.sender" -> "msg.sender" (keep as compound)
        // "token.balanceOf(address(this))" -> "token"
        let base = if lhs.starts_with("msg.") || lhs.starts_with("block.") || lhs.starts_with("tx.")
        {
            // Keep Solidity globals as compound identifiers
            if let Some(space_idx) = lhs.find(' ') {
                &lhs[..space_idx]
            } else {
                lhs
            }
        } else if let Some(bracket_idx) = lhs.find('[') {
            &lhs[..bracket_idx]
        } else if let Some(dot_idx) = lhs.find('.') {
            // Part before dot (e.g., "token" from "token.balanceOf()")
            &lhs[..dot_idx]
        } else if let Some(paren_idx) = lhs.find('(') {
            &lhs[..paren_idx]
        } else {
            lhs
        };

        let base = base.trim();
        if base.is_empty() {
            return None;
        }

        Some(base.to_string())
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(detector.name(), "Redundant Checks");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_extract_primary_variable_simple_comparison() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("amount > 0"),
            Some("amount".to_string())
        );
        assert_eq!(
            detector.extract_primary_variable("amount >= minAmount"),
            Some("amount".to_string())
        );
        assert_eq!(
            detector.extract_primary_variable("value != 0"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_msg_sender() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("msg.sender == owner"),
            Some("msg.sender".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_mapping_access() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("balances[msg.sender] >= amount"),
            Some("balances".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_with_error_message() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("amount > 0, \"Amount must be positive\""),
            Some("amount".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_function_call() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("token.balanceOf(address(this)) >= amount"),
            Some("token".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_negation() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("!paused"),
            Some("paused".to_string())
        );
    }

    #[test]
    fn test_extract_primary_variable_block_global() {
        let detector = RedundantChecksDetector::new();
        assert_eq!(
            detector.extract_primary_variable("block.timestamp >= deadline"),
            Some("block.timestamp".to_string())
        );
    }

    #[test]
    fn test_validation_heavy_governance_propose() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("propose", "function propose()"));
    }

    #[test]
    fn test_validation_heavy_proxy_upgrade() {
        let detector = RedundantChecksDetector::new();
        assert!(
            detector
                .is_validation_heavy_function("upgradeTo", "function upgradeTo(address newImpl)")
        );
    }

    #[test]
    fn test_validation_heavy_paymaster_validate() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("validatePaymasterUserOp", ""));
    }

    #[test]
    fn test_validation_heavy_session_key() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("executeWithSessionKey", ""));
    }

    #[test]
    fn test_validation_heavy_bridge_receive() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("receiveMessage", ""));
    }

    #[test]
    fn test_not_validation_heavy_simple_transfer() {
        let detector = RedundantChecksDetector::new();
        assert!(!detector.is_validation_heavy_function(
            "transfer",
            "function transfer(address to, uint256 amount)"
        ));
    }

    #[test]
    fn test_not_validation_heavy_deposit() {
        let detector = RedundantChecksDetector::new();
        assert!(
            !detector.is_validation_heavy_function("deposit", "function deposit(uint256 amount)")
        );
    }

    #[test]
    fn test_no_redundancy_different_variables() {
        let detector = RedundantChecksDetector::new();
        let source = "function execute(address target, uint256 amount, bytes calldata data) external {\n\
                       require(target != address(0), \"Invalid target\");\n\
                       require(amount > 0, \"Invalid amount\");\n\
                       require(data.length > 0, \"Empty data\");\n\
                       // do something\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag 3 consecutive requires checking different variables"
        );
    }

    #[test]
    fn test_no_redundancy_proxy_upgrade_different_checks() {
        let detector = RedundantChecksDetector::new();
        let source = "function upgradeTo(address newImplementation) external {\n\
                       require(msg.sender == admin, \"Not admin\");\n\
                       require(newImplementation != address(0), \"Zero address\");\n\
                       require(newImplementation.code.length > 0, \"Not a contract\");\n\
                       _upgradeTo(newImplementation);\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag proxy upgrade with distinct checks"
        );
    }

    #[test]
    fn test_no_redundancy_flash_loan_execute() {
        let detector = RedundantChecksDetector::new();
        let source = "function execute(address token, uint256 amount, address receiver) external {\n\
                       require(token != address(0), \"Invalid token\");\n\
                       require(amount > 0, \"Zero amount\");\n\
                       require(receiver != address(0), \"Invalid receiver\");\n\
                       // flash loan logic\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag flash loan execute with distinct input validation"
        );
    }

    #[test]
    fn test_no_redundancy_paymaster_validation() {
        let detector = RedundantChecksDetector::new();
        let source = "function validatePaymasterUserOp(UserOperation calldata userOp) external {\n\
                       require(msg.sender == entryPoint, \"Not entry point\");\n\
                       require(userOp.paymasterAndData.length >= 20, \"Invalid data\");\n\
                       require(deposits[userOp.sender] >= userOp.maxCost, \"Insufficient deposit\");\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag paymaster validation with distinct checks"
        );
    }

    #[test]
    fn test_no_redundancy_bridge_message_validation() {
        let detector = RedundantChecksDetector::new();
        let source = "function receiveMessage(bytes calldata message) external {\n\
                       require(msg.sender == relayer, \"Not relayer\");\n\
                       require(message.length > 0, \"Empty message\");\n\
                       require(!processedMessages[keccak256(message)], \"Already processed\");\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag bridge message validation with distinct checks"
        );
    }

    #[test]
    fn test_redundancy_same_variable_three_times() {
        let detector = RedundantChecksDetector::new();
        let source = "function setAmount(uint256 amount) external {\n\
                       require(amount > 0, \"Must be positive\");\n\
                       require(amount < 1000, \"Too large\");\n\
                       require(amount != 500, \"Not 500\");\n\
                       // do something\n\
                       }";
        let result = detector.find_redundant_consecutive_requires(source);
        assert!(
            result.is_some(),
            "Should flag 3 consecutive requires all checking 'amount'"
        );
        let group = result.unwrap();
        assert_eq!(group.variable, "amount");
        assert_eq!(group.count, 3);
    }

    #[test]
    fn test_redundancy_duplicate_conditions() {
        let detector = RedundantChecksDetector::new();
        let source = "function withdraw(uint256 amount) external {\n\
                       require(amount > 0, \"Must be positive\");\n\
                       require(amount > 0, \"Must be positive\");\n\
                       require(amount > 0, \"Must be positive\");\n\
                       // do something\n\
                       }";
        let result = detector.find_redundant_consecutive_requires(source);
        assert!(
            result.is_some(),
            "Should flag exact duplicate require conditions"
        );
    }

    #[test]
    fn test_no_redundancy_two_requires_below_threshold() {
        let detector = RedundantChecksDetector::new();
        let source = "function transfer(address to, uint256 amount) external {\n\
                       require(to != address(0), \"Invalid address\");\n\
                       require(amount > 0, \"Invalid amount\");\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag only 2 consecutive requires"
        );
    }

    #[test]
    fn test_no_redundancy_four_different_variables() {
        let detector = RedundantChecksDetector::new();
        let source = "function complexOp(address to, uint256 amount, bytes calldata data, uint256 deadline) external {\n\
                       require(to != address(0), \"Invalid address\");\n\
                       require(amount > 0, \"Invalid amount\");\n\
                       require(data.length > 0, \"Empty data\");\n\
                       require(block.timestamp <= deadline, \"Expired\");\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Should NOT flag 4 consecutive requires checking 4 different variables"
        );
    }

    #[test]
    fn test_group_redundancy_all_same_var() {
        let detector = RedundantChecksDetector::new();
        let conditions = vec![
            "amount > 0".to_string(),
            "amount < 1000".to_string(),
            "amount != 500".to_string(),
        ];
        let result = detector.check_group_for_redundancy(&conditions);
        assert!(result.is_some());
        assert_eq!(result.unwrap().variable, "amount");
    }

    #[test]
    fn test_group_no_redundancy_all_different() {
        let detector = RedundantChecksDetector::new();
        let conditions = vec![
            "target != address(0)".to_string(),
            "amount > 0".to_string(),
            "msg.sender == owner".to_string(),
        ];
        let result = detector.check_group_for_redundancy(&conditions);
        assert!(result.is_none());
    }

    #[test]
    fn test_group_below_threshold() {
        let detector = RedundantChecksDetector::new();
        let conditions = vec!["amount > 0".to_string(), "amount < 1000".to_string()];
        let result = detector.check_group_for_redundancy(&conditions);
        assert!(result.is_none(), "Groups of 2 should be below threshold");
    }

    #[test]
    fn test_fp_regression_dao_governance_propose() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("propose", ""));
    }

    #[test]
    fn test_fp_regression_eip1967_proxy_upgrade() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("upgradeTo", ""));
    }

    #[test]
    fn test_fp_regression_secure_paymaster() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("validatePaymasterUserOp", ""));
    }

    #[test]
    fn test_fp_regression_session_key_execute() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("executeWithSessionKey", ""));
    }

    #[test]
    fn test_fp_regression_receive_message() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("receiveMessage", ""));
    }

    #[test]
    fn test_fp_regression_flash_loan_execute() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.is_validation_heavy_function("execute", ""));
    }

    #[test]
    fn test_still_flags_truly_redundant_checks() {
        let detector = RedundantChecksDetector::new();
        let source = "function setPrice(uint256 price) external {\n\
                       require(price > 0, \"Must be positive\");\n\
                       require(price < MAX_PRICE, \"Too high\");\n\
                       require(price != 0, \"Cannot be zero\");\n\
                       // set price\n\
                       }";
        let result = detector.find_redundant_consecutive_requires(source);
        assert!(
            result.is_some(),
            "Should still flag 3 requires all checking 'price'"
        );
    }

    #[test]
    fn test_empty_source() {
        let detector = RedundantChecksDetector::new();
        assert!(detector.find_redundant_consecutive_requires("").is_none());
    }

    #[test]
    fn test_no_requires() {
        let detector = RedundantChecksDetector::new();
        let source = "function simple() external {\n    x = 1;\n    y = 2;\n}";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none()
        );
    }

    #[test]
    fn test_single_require() {
        let detector = RedundantChecksDetector::new();
        let source = "function simple(uint256 x) external {\n\
                       require(x > 0, \"Invalid\");\n\
                       doSomething(x);\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none()
        );
    }

    #[test]
    fn test_non_consecutive_requires_not_grouped() {
        let detector = RedundantChecksDetector::new();
        let source = "function transfer(uint256 amount) external {\n\
                       require(amount > 0, \"Invalid\");\n\
                       uint256 balance = getBalance();\n\
                       require(balance >= amount, \"Insufficient\");\n\
                       doTransfer(amount);\n\
                       require(getBalance() == balance - amount, \"Invariant\");\n\
                       }";
        assert!(
            detector
                .find_redundant_consecutive_requires(source)
                .is_none(),
            "Non-consecutive requires should not be grouped together"
        );
    }

    #[test]
    fn test_extract_requires_basic() {
        let detector = RedundantChecksDetector::new();
        let source =
            "require(x > 0);\nrequire(y != address(0));\ndoSomething();\nrequire(z < 100);";
        let requires = detector.extract_requires(source);
        assert_eq!(requires.len(), 3);
        assert_eq!(requires[0], "x > 0");
        assert_eq!(requires[1], "y != address(0)");
        assert_eq!(requires[2], "z < 100");
    }
}
