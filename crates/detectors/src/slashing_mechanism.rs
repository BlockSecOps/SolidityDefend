use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for slashing mechanism vulnerabilities in staking systems
pub struct SlashingMechanismDetector {
    base: BaseDetector,
}

impl Default for SlashingMechanismDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SlashingMechanismDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("slashing-mechanism".to_string()),
                "Slashing Mechanism Vulnerability".to_string(),
                "Detects vulnerabilities in validator slashing mechanisms that can lead to unfair penalties or griefing attacks".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for SlashingMechanismDetector {
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

        for function in ctx.get_functions() {
            if let Some(slashing_issue) = self.check_slashing_vulnerability(function, ctx) {
                let message = format!(
                    "Function '{}' has slashing mechanism vulnerability. {} \
                    Improper slashing logic can lead to validator griefing, unfair penalties, or loss of staked funds.",
                    function.name.name, slashing_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_fix_suggestion(format!(
                    "Fix slashing mechanism in '{}'. \
                    Implement cooldown periods between slashings, add maximum slashing limits per period, \
                    require evidence verification with dispute periods, implement progressive penalties, \
                    add multi-signature requirements for large slashings, and protect against double-slashing.",
                    function.name.name
                ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SlashingMechanismDetector {
    /// Check for slashing mechanism vulnerabilities
    fn check_slashing_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // --- Context-aware pre-filters to reduce false positives ---

        // Skip view/pure functions: read-only functions cannot execute slashing
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Skip internal/private helper functions that are not direct slashing entry points
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // The function name itself must indicate a slashing or penalizing action.
        // Merely mentioning "slash" in comments or variable names within the body
        // does not make a function a slashing function (e.g., getSlashingFactor,
        // queueWithdrawals, _delegate).
        let name_indicates_slashing =
            func_name_lower.contains("slash") || func_name_lower.contains("penali");

        if !name_indicates_slashing {
            return None;
        }

        // Skip getter/query functions whose names start with "get", "is", "has",
        // "calculate", or "convert" -- these are read helpers even if public.
        if func_name_lower.starts_with("get")
            || func_name_lower.starts_with("is")
            || func_name_lower.starts_with("has")
            || func_name_lower.starts_with("calculate")
            || func_name_lower.starts_with("convert")
            || func_name_lower.starts_with("compute")
        {
            return None;
        }

        // Require the contract itself to be a staking/slashing system.
        // Contracts that are vaults, AMMs, governance, proxies, bridges, flash loan
        // providers, or EIP-7702 delegation contracts should not trigger this detector.
        if !self.is_staking_contract(ctx) {
            return None;
        }

        // Require that the function body actually modifies stake-related state
        // (subtracting, reducing, or transferring staked amounts). Without this,
        // the function is not performing slashing even if it is named "slash*".
        if !self.has_stake_modification(&func_source) {
            return None;
        }

        // Skip functions that already have access control modifiers (the function
        // is restricted to authorized callers, reducing the attack surface).
        if self.has_access_control(function, &func_source) {
            return None;
        }

        // --- Vulnerability pattern checks (only on confirmed slashing functions) ---

        // Pattern 1: No cooldown between slashing events
        let has_cooldown = func_source.contains("lastSlash")
            || func_source.contains("slashTime")
            || func_source.contains("cooldown")
            || func_source.contains("SLASH_DELAY");

        if !has_cooldown && (func_source.contains("stake") || func_source.contains("balance")) {
            return Some(
                "No cooldown period between slashing events, \
                allows rapid repeated slashing of same validator (griefing attack)"
                    .to_string(),
            );
        }

        // Pattern 2: No maximum slashing limit per period
        let has_max_limit = func_source.contains("MAX_SLASH")
            || func_source.contains("maxSlash")
            || func_source.contains("slashLimit")
            || func_source.contains("MAX_PENALTY");

        if !has_max_limit && (func_source.contains("amount") || func_source.contains("stake")) {
            return Some(
                "No maximum slashing amount limit per time period, \
                validator can lose entire stake from single event"
                    .to_string(),
            );
        }

        // Pattern 3: Slashing without evidence verification
        let has_evidence_check = func_source.contains("proof")
            || func_source.contains("evidence")
            || func_source.contains("verify")
            || func_source.contains("signature");

        if !has_evidence_check && func_source.contains("require") {
            return Some(
                "Slashing triggered without evidence verification, \
                allows arbitrary slashing without proof of misbehavior"
                    .to_string(),
            );
        }

        // Pattern 4: No dispute or appeal period
        let has_dispute_period = func_source.contains("dispute")
            || func_source.contains("appeal")
            || func_source.contains("challenge")
            || func_source.contains("DISPUTE_PERIOD");

        if !has_dispute_period && func_source.contains("stake") {
            return Some(
                "Slashing executes immediately without dispute period, \
                no mechanism for validators to challenge false accusations"
                    .to_string(),
            );
        }

        // Pattern 5: Single address can trigger slashing (checked via source text
        // for inline checks like require(msg.sender == ...) since AST modifiers
        // were already checked above)
        let has_caller_restriction = func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("multisig")
            || func_source.contains("quorum")
            || func_source.contains("msg.sender ==");

        if !has_caller_restriction && func_source.contains("external") {
            return Some(
                "Single address can trigger slashing without multi-signature, \
                centralization risk and potential for malicious slashing"
                    .to_string(),
            );
        }

        // Pattern 6: No double-slashing protection
        let has_double_slash_protection = func_source.contains("slashed[")
            || func_source.contains("hasBeenSlashed")
            || func_source.contains("alreadySlashed");

        if !has_double_slash_protection && func_source.contains("mapping") {
            return Some(
                "No protection against double-slashing for same offense, \
                validator can be penalized multiple times for single misbehavior"
                    .to_string(),
            );
        }

        // Pattern 7: Slashing amount not proportional
        let has_proportional_logic = func_source.contains("percentage")
            || func_source.contains("percent")
            || func_source.contains("multiplier")
            || func_source.contains("severity");

        if !has_proportional_logic && func_source.contains("amount") {
            return Some(
                "Slashing amount not proportional to offense severity, \
                fixed penalty may be too harsh for minor violations"
                    .to_string(),
            );
        }

        // Pattern 8: No grace period for first offenses
        let has_grace_period = func_source.contains("firstOffense")
            || func_source.contains("offenseCount")
            || func_source.contains("violations")
            || func_source.contains("strikes");

        if !has_grace_period && func_source.contains("slash") {
            return Some(
                "No grace period or warning system for first offenses, \
                harsh penalties applied immediately without progressive discipline"
                    .to_string(),
            );
        }

        // Pattern 9: Slashing affects delegators unfairly
        let affects_delegators =
            func_source.contains("delegator") || func_source.contains("Delegator");

        if affects_delegators
            && !func_source.contains("delegatorProtection")
            && !func_source.contains("insurance")
        {
            return Some(
                "Validator slashing affects delegators without protection, \
                delegators punished for validator misbehavior they cannot control"
                    .to_string(),
            );
        }

        // Pattern 10: Slashing burns funds instead of redistributing
        let burns_funds = func_source.contains("burn") || func_source.contains("address(0)");

        if burns_funds && !func_source.contains("distribute") && !func_source.contains("reward") {
            return Some(
                "Slashed funds burned instead of redistributed to honest validators, \
                reduces economic security and validator incentives"
                    .to_string(),
            );
        }

        None
    }

    /// Check if the contract is a staking/slashing system based on contract-level
    /// indicators. Returns false for vaults, AMMs, governance, proxies, bridges,
    /// flash loan providers, and EIP-7702 delegation contracts.
    fn is_staking_contract(&self, ctx: &AnalysisContext) -> bool {
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // Negative indicators: contract is a non-staking DeFi pattern.
        // Check both the AST contract name and the source-level contract declaration.
        let non_staking_keywords = [
            "vault",
            "amm",
            "pool",
            "swap",
            "bridge",
            "flashloan",
            "flash_loan",
            "governance",
            "governor",
            "proxy",
            "eip7702",
            "erc4626",
        ];
        for keyword in &non_staking_keywords {
            if contract_name_lower.contains(keyword)
                || source_lower.contains(&format!("contract {}", keyword))
            {
                return false;
            }
        }
        // Also check for contract declarations containing non-staking patterns
        // by scanning "contract <Name>" declarations in the source
        if self.source_has_non_staking_contract(&source_lower) {
            return false;
        }

        // Positive indicators: contract is related to staking/slashing/validation
        let has_staking_context = contract_name_lower.contains("stak")
            || contract_name_lower.contains("slash")
            || contract_name_lower.contains("validator")
            || contract_name_lower.contains("operator")
            || contract_name_lower.contains("restaking")
            || contract_name_lower.contains("avs")
            || contract_name_lower.contains("delegation")
            || source_lower.contains("mapping(address => uint256) public stakes")
            || source_lower.contains("mapping(address => stake)")
            || source_lower.contains("slashablesstakes")
            || source_lower.contains("slashablestake");

        has_staking_context
    }

    /// Check if the source code declares a contract whose name indicates a
    /// non-staking DeFi pattern (e.g., "contract AMMPool", "contract VaultManager").
    fn source_has_non_staking_contract(&self, source_lower: &str) -> bool {
        let non_staking_keywords = [
            "vault",
            "amm",
            "pool",
            "swap",
            "bridge",
            "flashloan",
            "governance",
            "governor",
            "proxy",
            "eip7702",
            "erc4626",
        ];
        for line in source_lower.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("contract ") || trimmed.contains(" contract ") {
                for keyword in &non_staking_keywords {
                    if trimmed.contains(keyword) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if the function body modifies stake-related state (subtraction,
    /// reduction, or transfer of staked amounts).
    fn has_stake_modification(&self, func_source: &str) -> bool {
        // Direct stake subtraction patterns
        func_source.contains("-=")
            || func_source.contains("= 0")
            || (func_source.contains("stake") && func_source.contains("transfer"))
            || (func_source.contains("slash") && func_source.contains("amount"))
    }

    /// Check if the function has access control via AST modifiers or inline checks.
    fn has_access_control(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // Check AST-level modifiers
        let has_modifier = function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("only")
                || name_lower.contains("auth")
                || name_lower.contains("restricted")
                || name_lower.contains("admin")
                || name_lower.contains("owner")
                || name_lower.contains("role")
                || name_lower.contains("manager")
                || name_lower.contains("operator")
                || name_lower.contains("guardian")
                || name_lower.contains("governance")
        });

        if has_modifier {
            return true;
        }

        // Check inline access control patterns in source
        func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("onlyRole")
            || func_source.contains("onlyOperator")
            || func_source.contains("onlyManager")
            || func_source.contains("onlyAllocation")
            || func_source.contains("onlyGovernance")
            || func_source.contains("onlyGuardian")
            || func_source.contains("hasRole")
    }

    /// Get function source code
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
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = SlashingMechanismDetector::new();
        assert_eq!(detector.name(), "Slashing Mechanism Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    // --- Helper method tests (is_staking_contract) ---

    #[test]
    fn test_is_staking_contract_by_source_stakes_mapping() {
        let detector = SlashingMechanismDetector::new();
        // Source contains "mapping(address => uint256) public stakes" which
        // triggers the source-level staking context check.
        let source = r#"
contract VulnerableStaking {
    mapping(address => uint256) public stakes;
    function slash(address user, uint256 amount) external {
        stakes[user] -= amount;
    }
}
"#;
        let ctx = create_test_context(source);
        assert!(
            detector.is_staking_contract(&ctx),
            "Source with stakes mapping should be identified as staking"
        );
    }

    #[test]
    fn test_is_staking_contract_negative_vault() {
        let detector = SlashingMechanismDetector::new();
        let source = "contract VaultManager { }";
        let ctx = create_test_context(source);
        assert!(
            !detector.is_staking_contract(&ctx),
            "VaultManager should not be identified as staking"
        );
    }

    #[test]
    fn test_is_staking_contract_negative_flashloan() {
        let detector = SlashingMechanismDetector::new();
        let source = "contract FlashLoanProvider { }";
        let ctx = create_test_context(source);
        assert!(
            !detector.is_staking_contract(&ctx),
            "FlashLoanProvider should not be identified as staking"
        );
    }

    #[test]
    fn test_is_staking_contract_negative_amm() {
        let detector = SlashingMechanismDetector::new();
        let source = "contract AMMPool { mapping(address => uint256) public stakes; }";
        let ctx = create_test_context(source);
        // Even though source has "stakes", "pool" in contract name is a negative indicator
        assert!(
            !detector.is_staking_contract(&ctx),
            "AMMPool should not be identified as staking"
        );
    }

    #[test]
    fn test_is_staking_contract_negative_no_context() {
        let detector = SlashingMechanismDetector::new();
        let source =
            "contract SimpleToken { function transfer(address to, uint256 amount) external { } }";
        let ctx = create_test_context(source);
        assert!(
            !detector.is_staking_contract(&ctx),
            "SimpleToken with no staking context should not be identified as staking"
        );
    }

    // --- Helper method tests (has_stake_modification) ---

    #[test]
    fn test_has_stake_modification_subtraction() {
        let detector = SlashingMechanismDetector::new();
        assert!(detector.has_stake_modification("stakes[user] -= amount;"));
    }

    #[test]
    fn test_has_stake_modification_zero_assignment() {
        let detector = SlashingMechanismDetector::new();
        assert!(detector.has_stake_modification("stake.amount = 0;"));
    }

    #[test]
    fn test_has_stake_modification_slash_amount() {
        let detector = SlashingMechanismDetector::new();
        assert!(detector.has_stake_modification("uint256 slashAmount = amount * percentage;"));
    }

    #[test]
    fn test_has_stake_modification_no_modification() {
        let detector = SlashingMechanismDetector::new();
        assert!(!detector.has_stake_modification("return stakes[operator];"));
    }

    // --- Helper method tests (has_access_control via source text) ---

    #[test]
    fn test_has_access_control_only_admin() {
        let detector = SlashingMechanismDetector::new();
        let arena = ast::AstArena::new();
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "slash",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(detector.has_access_control(&func, "function slash() external onlyAdmin {"));
    }

    #[test]
    fn test_has_access_control_only_allocation() {
        let detector = SlashingMechanismDetector::new();
        let arena = ast::AstArena::new();
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "slash",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(
            detector.has_access_control(&func, "function slash() external onlyAllocationManager {")
        );
    }

    #[test]
    fn test_has_access_control_none() {
        let detector = SlashingMechanismDetector::new();
        let arena = ast::AstArena::new();
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "slash",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        assert!(!detector.has_access_control(&func, "function slash() external {"));
    }

    // --- End-to-end detect() tests via create_test_context ---
    // Note: create_test_context does not populate AST functions, so
    // detect() returns empty findings. These tests verify the detector
    // does not crash and returns no findings when there are no AST functions.

    #[test]
    fn test_detect_no_functions_no_crash() {
        let detector = SlashingMechanismDetector::new();
        let source = r#"
contract StakingManager {
    mapping(address => uint256) public stakes;
}
"#;
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(findings.is_empty(), "No AST functions means no findings");
    }
}
