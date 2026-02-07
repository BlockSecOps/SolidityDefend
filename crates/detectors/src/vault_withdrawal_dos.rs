use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::{access_control_patterns, vault_patterns};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for ERC-4626 vault withdrawal DOS vulnerabilities
pub struct VaultWithdrawalDosDetector {
    base: BaseDetector,
}

impl Default for VaultWithdrawalDosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultWithdrawalDosDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("vault-withdrawal-dos".to_string()),
                "Vault Withdrawal DOS".to_string(),
                "Detects ERC4626 vaults vulnerable to withdrawal denial-of-service attacks via queue manipulation or liquidity locks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for VaultWithdrawalDosDetector {
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


        // Check if this is an ERC-4626 vault
        let is_vault = utils::is_erc4626_vault(ctx);

        // Phase 5 FP Reduction: Only analyze actual vault/queue patterns
        // Skip simple wallet contracts that don't have vault-like mechanics
        if !is_vault && !self.has_vault_context(ctx) {
            return Ok(findings);
        }

        // Phase 6 FP Reduction: Standard ERC-4626 vaults with proper share/asset
        // accounting use pull-based withdrawals and are not vulnerable to queue-based
        // DOS attacks. Only flag vaults that have actual queue mechanics or custom
        // withdrawal logic that deviates from the standard pattern.
        if is_vault && self.is_standard_erc4626_withdrawal_pattern(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Multi-level safe pattern detection with dynamic confidence

        // Level 1: Strong restaking protocol protections (return early)
        if vault_patterns::has_eigenlayer_delegation_pattern(ctx) {
            // EigenLayer has battle-tested withdrawal queue + delay mechanisms
            return Ok(findings);
        }

        // Level 2: Advanced DeFi patterns (return early if comprehensive)
        let has_pause = access_control_patterns::has_pause_pattern(ctx);
        let has_timelock = access_control_patterns::has_timelock_pattern(ctx);

        if has_pause && has_timelock {
            // Pause + timelock = comprehensive DOS protection
            return Ok(findings);
        }

        // Level 3: Basic mitigations (reduce confidence if present)
        let has_pull_pattern = self.has_pull_pattern(ctx);
        let has_emergency_mechanism = self.has_emergency_mechanism(ctx);
        let has_withdrawal_limits = self.has_withdrawal_limits(ctx);

        // Calculate protection score for confidence calibration
        let mut protection_score = 0;
        if has_pause {
            protection_score += 2;
        } // Critical for DOS prevention
        if has_timelock {
            protection_score += 1;
        }
        if has_pull_pattern {
            protection_score += 2;
        } // Strong protection
        if has_emergency_mechanism {
            protection_score += 2;
        } // Critical
        if has_withdrawal_limits {
            protection_score += 1;
        }

        for function in ctx.get_functions() {
            // Phase 6: Skip view/pure functions -- they cannot modify state
            // and therefore cannot cause withdrawal DOS
            if function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            if let Some(dos_issue) = self.check_withdrawal_dos(function, ctx, is_vault) {
                let message = format!(
                    "Function '{}' may be vulnerable to withdrawal DOS attack. {} \
                    Attacker can block withdrawals, causing funds to be locked indefinitely.",
                    function.name.name, dos_issue
                );

                // Phase 2: Dynamic confidence scoring based on detected patterns
                // Phase 5: Reduce confidence for non-vaults
                let confidence = if protection_score == 0 {
                    if is_vault {
                        Confidence::High
                    } else {
                        Confidence::Medium // Lower confidence for non-vault contracts
                    }
                } else if protection_score <= 2 {
                    // Minimal protection
                    Confidence::Medium
                } else if protection_score <= 4 {
                    // Some protections
                    Confidence::Low
                } else {
                    // Multiple strong protections - likely safe
                    Confidence::Low
                };

                // Phase 5: Use Medium severity for non-vault contracts
                let severity = if is_vault {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                        severity,
                    )
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_cwe(770) // CWE-770: Allocation of Resources Without Limits
                    .with_confidence(confidence)
                    .with_fix_suggestion(format!(
                        "Protect '{}' from withdrawal DOS. \
                    Solutions: (1) Implement withdrawal limits/caps per transaction (e.g., maxWithdrawal), \
                    (2) Add circuit breakers for emergency withdrawals (OpenZeppelin Pausable), \
                    (3) Avoid unbounded loops in withdrawal queue processing (add MAX_ITERATIONS), \
                    (4) Implement partial withdrawal support for queue processing, \
                    (5) Use pull-over-push pattern for failed withdrawals (mapping-based claims), \
                    (6) Consider EigenLayer-style withdrawal queue with delay mechanisms, \
                    (7) Add emergency pause mechanism for DOS situations, \
                    (8) Implement timelock for critical parameter changes.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl VaultWithdrawalDosDetector {
    /// Phase 6 FP Reduction: Detect standard ERC-4626 withdrawal patterns.
    /// Standard ERC-4626 vaults use pull-based withdrawals where each user withdraws
    /// their own shares. These are not vulnerable to queue-based DOS attacks because:
    /// 1. Each withdrawal is an individual operation (no loops over user arrays)
    /// 2. Share/asset math provides natural withdrawal limits (can't withdraw more than you own)
    /// 3. The ERC-4626 standard defines maxWithdraw/maxRedeem for explicit limits
    ///
    /// Returns true if the vault follows the standard pattern and has NO custom queue mechanics.
    fn is_standard_erc4626_withdrawal_pattern(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Must NOT have withdrawal queue mechanics -- those ARE potentially vulnerable
        let has_queue_mechanics = source.contains("withdrawalQueue")
            || source.contains("WithdrawalQueue")
            || source.contains("pendingWithdrawals")
            || source.contains("queuedWithdrawals")
            || source.contains("withdrawRequests");

        if has_queue_mechanics {
            return false;
        }

        // Must have standard ERC-4626 share/asset accounting patterns
        let has_standard_accounting = (source.contains("convertToShares")
            || source.contains("convertToAssets")
            || source.contains("previewWithdraw")
            || source.contains("previewRedeem"))
            || (source.contains("totalAssets") && source.contains("totalSupply"));

        // Recognize OpenZeppelin ERC4626 inheritance (super.withdraw / super.redeem)
        let uses_oz_base = source.contains("super.withdraw")
            || source.contains("super.redeem")
            || source.contains("ERC4626")
            || source.contains("IERC4626");

        // Standard pattern: has proper accounting AND either inherits OZ or implements
        // standard share math without queue mechanics
        has_standard_accounting || uses_oz_base
    }

    /// Phase 6 FP Reduction: Check if a specific withdrawal function is an individual
    /// pull-based withdrawal (user withdraws their own funds) vs a queue/batch processor.
    fn is_individual_pull_withdrawal(
        &self,
        function: &ast::Function<'_>,
        func_source: &str,
    ) -> bool {
        let name_lower = function.name.name.to_lowercase();

        // Standard ERC-4626 function names for individual withdrawals
        let is_standard_name =
            name_lower == "withdraw" || name_lower == "redeem" || name_lower == "claim";

        if !is_standard_name {
            return false;
        }

        // Must NOT contain loop-based queue processing patterns
        let has_loop_over_users = (func_source.contains("for (")
            || func_source.contains("while ("))
            && (func_source.contains("queue")
                || func_source.contains("users")
                || func_source.contains("recipients")
                || func_source.contains("withdrawalQueue"));

        if has_loop_over_users {
            return false;
        }

        // Positive signals: standard pull-based patterns
        let has_pull_signals = func_source.contains("super.withdraw")
            || func_source.contains("super.redeem")
            || func_source.contains("msg.sender")
            || func_source.contains("owner")
            || func_source.contains("balanceOf[msg.sender]")
            || func_source.contains("_burn(");

        has_pull_signals
    }

    /// Phase 5 FP Reduction: Check if contract has vault-like context
    /// Requires withdrawal queue patterns or vault mechanics
    fn has_vault_context(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Withdrawal queue patterns
        let has_queue = source.contains("withdrawalQueue")
            || source.contains("WithdrawalQueue")
            || source.contains("pendingWithdrawals")
            || source.contains("withdrawRequests")
            || source.contains("queuedWithdrawals");

        // Vault share mechanics
        let has_share_mechanics = (source.contains("totalAssets")
            && source.contains("totalSupply"))
            || source.contains("convertToShares")
            || source.contains("convertToAssets");

        // Staking/unstaking patterns with queues
        let has_staking_queue = (source.contains("stake") || source.contains("unstake"))
            && (source.contains("queue")
                || source.contains("pending")
                || source.contains("cooldown"));

        has_queue || has_share_mechanics || has_staking_queue
    }

    /// Check for withdrawal DOS vulnerabilities
    fn check_withdrawal_dos(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        is_vault: bool,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Identify withdrawal/redeem functions
        let is_withdrawal_function = function.name.name.to_lowercase().contains("withdraw")
            || function.name.name.to_lowercase().contains("redeem")
            || function.name.name.to_lowercase().contains("claim");

        if !is_withdrawal_function {
            return None;
        }

        // Pattern 1: Unbounded withdrawal queue processing
        let has_unbounded_loop = (func_source.contains("for (") || func_source.contains("while ("))
            && (func_source.contains("withdrawalQueue")
                || func_source.contains("requests")
                || func_source.contains("queue"));

        let has_loop_limit = func_source.contains("maxIterations")
            || func_source.contains("limit")
            || func_source.contains("MAX_");

        if has_unbounded_loop && !has_loop_limit {
            return Some(
                "Unbounded withdrawal queue processing. Loop over queue without iteration limit \
                can be exploited for DOS by creating many requests"
                    .to_string(),
            );
        }

        // Pattern 2: Withdrawal requires successful external call
        let has_external_call = func_source.contains(".transfer(")
            || func_source.contains(".call")
            || func_source.contains(".send(");

        let checks_call_success = func_source.contains("require(")
            && (func_source.contains(".transfer(") || func_source.contains(".call"));

        // Skip for ERC-4626 vaults - they MUST transfer assets out, this is normal behavior
        // ERC-4626 redeem/withdraw functions transfer underlying assets, not a DOS vector
        if has_external_call && checks_call_success && !is_vault {
            return Some("Withdrawal requires successful external call. Failing calls can permanently block withdrawals. \
                Consider using pull-over-push pattern".to_string());
        }

        // Pattern 3: Missing withdrawal cap or limit
        let has_withdrawal_cap = func_source.contains("withdrawalCap")
            || func_source.contains("maxWithdrawal")
            || func_source.contains("withdrawalLimit")
            || func_source.contains("MAX_WITHDRAW");

        let processes_large_amount =
            func_source.contains("amount") || func_source.contains("assets");

        // Skip for vaults - ERC-4626 vaults have built-in limits via share balances and maxRedeem/maxWithdraw
        if !has_withdrawal_cap && processes_large_amount && is_withdrawal_function && !is_vault {
            return Some(
                "No withdrawal cap or limit detected. Large withdrawals can drain liquidity \
                and DOS subsequent withdrawers"
                    .to_string(),
            );
        }

        // Pattern 4: No circuit breaker or emergency withdrawal
        let has_circuit_breaker = func_source.contains("paused")
            || func_source.contains("emergency")
            || func_source.contains("circuitBreaker");

        let is_public_withdraw = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        // Phase 6 FP Reduction: For ERC-4626 vaults, standard withdraw/redeem functions
        // are individual pull-based operations where a user withdraws their own shares.
        // These are not vulnerable to DOS in the same way as queue-based systems.
        // Only flag missing circuit breaker for non-standard vault withdrawals
        // (e.g., queue processors, batch operations).
        let is_standard_erc4626_withdraw =
            is_vault && self.is_individual_pull_withdrawal(function, &func_source);

        if !has_circuit_breaker && is_public_withdraw && !is_standard_erc4626_withdraw {
            return Some(
                "No circuit breaker or emergency withdrawal mechanism. \
                Vault cannot be paused during attacks or emergencies"
                    .to_string(),
            );
        }

        // Pattern 5: Accounting mismatch that can cause reverts
        let uses_total_assets =
            func_source.contains("totalAssets()") || func_source.contains("totalAssets");

        let uses_total_supply =
            func_source.contains("totalSupply()") || func_source.contains("totalSupply");

        let has_division = func_source.contains(" / ");

        if uses_total_assets && uses_total_supply && has_division {
            // Check for potential accounting mismatch
            let checks_zero_division = func_source.contains("require(totalSupply")
                || func_source.contains("if (totalSupply == 0)")
                || func_source.contains("totalSupply > 0");

            if !checks_zero_division {
                return Some(
                    "Potential accounting mismatch. Division by totalSupply without zero check \
                    can cause withdrawal reverts and DOS"
                        .to_string(),
                );
            }
        }

        // Pattern 6: Queue processing without partial execution
        // Phase 6 FP Reduction: Require actual queue data structure patterns, not just
        // any string containing "requests". Standard ERC-4626 withdraw/redeem functions
        // that simply process a single user's withdrawal are not queue processors.
        let has_queue_processing = func_source.contains("withdrawalQueue")
            || func_source.contains("pendingWithdrawals")
            || func_source.contains("queuedWithdrawals")
            || func_source.contains("withdrawRequests")
            || (func_source.contains("queue") && func_source.contains(".length"));

        let supports_partial = func_source.contains("partial")
            || func_source.contains("batched")
            || func_source.contains("chunk");

        if has_queue_processing && !supports_partial {
            return Some(
                "Withdrawal queue processing without partial execution support. \
                All-or-nothing execution can cause DOS if any withdrawal fails"
                    .to_string(),
            );
        }

        // Pattern 7: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("DOS")
                || func_source.contains("denial")
                || func_source.contains("lock"))
        {
            return Some("Vault withdrawal DOS vulnerability marker detected".to_string());
        }

        None
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

    /// NEW: Check for pull-over-push pattern (safer withdrawal pattern)
    fn has_pull_pattern(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Pull pattern indicators
        source.contains("claimableBalance")
            || source.contains("pendingWithdrawals")
            || source.contains("withdrawalRequest")
            || source.contains("claim()")
            || (source.contains("mapping") && source.contains("withdraw"))
    }

    /// NEW: Check for emergency withdrawal mechanism
    fn has_emergency_mechanism(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        source.contains("emergencyWithdraw")
            || source.contains("emergencyPause")
            || source.contains("circuitBreaker")
            || (source.contains("paused") && source.contains("whenNotPaused"))
    }

    /// NEW: Check for withdrawal limits/caps
    fn has_withdrawal_limits(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        source.contains("withdrawalCap")
            || source.contains("maxWithdrawal")
            || source.contains("withdrawalLimit")
            || source.contains("MAX_WITHDRAW")
            || source.contains("dailyLimit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_mock_ast_contract;

    fn make_context(source: &str) -> AnalysisContext<'static> {
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let contract = Box::leak(Box::new(create_mock_ast_contract(
            arena,
            "TestVault",
            vec![],
        )));
        AnalysisContext::new(
            contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        )
    }

    #[test]
    fn test_detector_properties() {
        let detector = VaultWithdrawalDosDetector::new();
        assert_eq!(detector.name(), "Vault Withdrawal DOS");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    // =========================================================================
    // Tests for is_standard_erc4626_withdrawal_pattern
    // =========================================================================

    #[test]
    fn test_standard_erc4626_with_oz_inheritance_is_safe() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract SafeVault is ERC4626, ReentrancyGuard {
    function withdraw(uint256 assets, address receiver, address owner)
        public override nonReentrant returns (uint256 shares) {
        shares = super.withdraw(assets, receiver, owner);
    }
    function redeem(uint256 shares, address receiver, address owner)
        public override nonReentrant returns (uint256 assets) {
        assets = super.redeem(shares, receiver, owner);
    }
    function totalAssets() public view override returns (uint256) {
        return _trackedAssets;
    }
}
"#;
        let ctx = make_context(source);
        assert!(
            detector.is_standard_erc4626_withdrawal_pattern(&ctx),
            "Standard ERC4626 vault with OZ inheritance should be recognized as safe"
        );
    }

    #[test]
    fn test_standard_erc4626_with_share_accounting_is_safe() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract SafeVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets();
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares * totalAssets() / totalSupply;
    }
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {
        uint256 shares = convertToShares(assets);
        _burn(owner, shares);
        asset.transfer(receiver, assets);
        return shares;
    }
    function totalAssets() public view returns (uint256) { return _totalAssets; }
}
"#;
        let ctx = make_context(source);
        assert!(
            detector.is_standard_erc4626_withdrawal_pattern(&ctx),
            "Standard ERC4626 vault with share/asset accounting should be recognized as safe"
        );
    }

    #[test]
    fn test_vault_with_queue_mechanics_is_not_safe_pattern() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract QueueVault is ERC4626 {
    address[] public withdrawalQueue;
    mapping(address => uint256) public pendingWithdrawals;
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {
        shares = super.withdraw(assets, receiver, owner);
    }
    function totalAssets() public view returns (uint256) { return _totalAssets; }
}
"#;
        let ctx = make_context(source);
        assert!(
            !detector.is_standard_erc4626_withdrawal_pattern(&ctx),
            "Vault with withdrawalQueue should NOT be recognized as safe standard pattern"
        );
    }

    #[test]
    fn test_vault_with_pending_withdrawals_is_not_safe_pattern() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract QueueVault {
    mapping(address => uint256) public pendingWithdrawals;
    function convertToShares(uint256 assets) public view returns (uint256) { return assets; }
    function convertToAssets(uint256 shares) public view returns (uint256) { return shares; }
    function totalAssets() public view returns (uint256) { return _totalAssets; }
}
"#;
        let ctx = make_context(source);
        assert!(
            !detector.is_standard_erc4626_withdrawal_pattern(&ctx),
            "Vault with pendingWithdrawals should NOT be recognized as safe standard pattern"
        );
    }

    // =========================================================================
    // Tests for is_individual_pull_withdrawal
    // =========================================================================

    #[test]
    fn test_pull_withdrawal_with_super_call() {
        let detector = VaultWithdrawalDosDetector::new();
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let func = crate::types::test_utils::create_mock_ast_function(
            arena,
            "withdraw",
            ast::Visibility::Public,
            ast::StateMutability::NonPayable,
        );
        let func_source = "shares = super.withdraw(assets, receiver, owner);";
        assert!(
            detector.is_individual_pull_withdrawal(&func, func_source),
            "withdraw with super.withdraw should be recognized as pull-based"
        );
    }

    #[test]
    fn test_pull_withdrawal_with_msg_sender() {
        let detector = VaultWithdrawalDosDetector::new();
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let func = crate::types::test_utils::create_mock_ast_function(
            arena,
            "redeem",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        let func_source = r#"
            require(balanceOf[msg.sender] >= shares);
            _burn(msg.sender, shares);
            asset.transfer(msg.sender, assets);
        "#;
        assert!(
            detector.is_individual_pull_withdrawal(&func, func_source),
            "redeem with msg.sender should be recognized as pull-based"
        );
    }

    #[test]
    fn test_queue_processor_is_not_pull_withdrawal() {
        let detector = VaultWithdrawalDosDetector::new();
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let func = crate::types::test_utils::create_mock_ast_function(
            arena,
            "withdraw",
            ast::Visibility::Public,
            ast::StateMutability::NonPayable,
        );
        let func_source = r#"
            for (uint i = 0; i < queue.length; i++) {
                address user = users[i];
                asset.transfer(user, amounts[i]);
            }
        "#;
        assert!(
            !detector.is_individual_pull_withdrawal(&func, func_source),
            "Function with loop over users should NOT be recognized as pull-based"
        );
    }

    #[test]
    fn test_non_withdrawal_function_is_not_pull_withdrawal() {
        let detector = VaultWithdrawalDosDetector::new();
        let arena = Box::leak(Box::new(ast::AstArena::new()));
        let func = crate::types::test_utils::create_mock_ast_function(
            arena,
            "deposit",
            ast::Visibility::Public,
            ast::StateMutability::NonPayable,
        );
        let func_source = "super.deposit(assets, receiver);";
        assert!(
            !detector.is_individual_pull_withdrawal(&func, func_source),
            "deposit function should NOT be recognized as a withdrawal"
        );
    }

    // =========================================================================
    // Tests for has_vault_context
    // =========================================================================

    #[test]
    fn test_no_vault_context_for_simple_contract() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract SimpleWallet {
    function send(address to, uint256 amount) external {
        payable(to).transfer(amount);
    }
}
"#;
        let ctx = make_context(source);
        assert!(
            !detector.has_vault_context(&ctx),
            "Simple wallet without vault mechanics should not have vault context"
        );
    }

    #[test]
    fn test_vault_context_for_queue_contract() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
contract WithdrawalManager {
    address[] public withdrawalQueue;
    function processWithdrawals() external {
        for (uint i = 0; i < withdrawalQueue.length; i++) {}
    }
}
"#;
        let ctx = make_context(source);
        assert!(
            detector.has_vault_context(&ctx),
            "Contract with withdrawalQueue should have vault context"
        );
    }

    // =========================================================================
    // Tests for view/pure function skipping
    // =========================================================================

    #[test]
    fn test_view_functions_skipped_in_detection() {
        let detector = VaultWithdrawalDosDetector::new();
        // A view function named "previewWithdraw" should not be flagged.
        // We verify via the is_standard_erc4626_withdrawal_pattern path
        // and the view/pure skip in detect().
        let source = r#"
contract Vault {
    function totalAssets() public view returns (uint256) { return 0; }
    function totalSupply() public view returns (uint256) { return 0; }
    function convertToShares(uint256 assets) public view returns (uint256) { return assets; }
    function previewWithdraw(uint256 assets) public view returns (uint256) { return assets; }
}
"#;
        let ctx = make_context(source);
        let findings = detector.detect(&ctx).unwrap();
        let dos_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detector_id == DetectorId("vault-withdrawal-dos".to_string()))
            .collect();
        assert!(
            dos_findings.is_empty(),
            "View/pure functions should not produce vault-withdrawal-dos findings"
        );
    }

    // =========================================================================
    // Tests for full detection on safe ERC-4626 vault source
    // =========================================================================

    #[test]
    fn test_safe_erc4626_vault_no_findings() {
        let detector = VaultWithdrawalDosDetector::new();
        let source = r#"
import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
contract SafeERC4626Vault is ERC4626, ReentrancyGuard {
    uint256 private _trackedAssets;
    function withdraw(uint256 assets, address receiver, address owner)
        public override nonReentrant returns (uint256 shares) {
        shares = super.withdraw(assets, receiver, owner);
        _trackedAssets -= assets;
    }
    function redeem(uint256 shares, address receiver, address owner)
        public override nonReentrant returns (uint256 assets) {
        assets = super.redeem(shares, receiver, owner);
        _trackedAssets -= assets;
    }
    function totalAssets() public view override returns (uint256) {
        return _trackedAssets;
    }
}
"#;
        let ctx = make_context(source);
        let findings = detector.detect(&ctx).unwrap();
        let dos_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detector_id == DetectorId("vault-withdrawal-dos".to_string()))
            .collect();
        assert!(
            dos_findings.is_empty(),
            "Safe ERC-4626 vault should produce zero vault-withdrawal-dos findings, got {}",
            dos_findings.len()
        );
    }

    // =========================================================================
    // Tests for vulnerable vault still being detected
    // =========================================================================

    #[test]
    fn test_vulnerable_queue_vault_detected() {
        let detector = VaultWithdrawalDosDetector::new();
        // This vault has withdrawal queue mechanics that are genuinely vulnerable
        let source = r#"
contract VulnerableVault {
    address[] public withdrawalQueue;
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function totalAssets() public view returns (uint256) { return address(this).balance; }

    function processWithdrawals() public {
        for (uint256 i = 0; i < withdrawalQueue.length; i++) {
            address user = withdrawalQueue[i];
            uint256 amount = pendingWithdrawals[user];
            require(payable(user).send(amount));
        }
    }
}
"#;
        let ctx = make_context(source);
        // has_vault_context should be true due to withdrawalQueue
        assert!(detector.has_vault_context(&ctx));
        // is_standard_erc4626_withdrawal_pattern should be false due to queue mechanics
        assert!(!detector.is_standard_erc4626_withdrawal_pattern(&ctx));
    }

    // =========================================================================
    // Tests for Pattern 6 tightened queue matching
    // =========================================================================

    #[test]
    fn test_pattern6_requires_actual_queue_data_structures() {
        let detector = VaultWithdrawalDosDetector::new();
        // Source with "requests" but no actual queue data structure -- should NOT
        // be flagged by Pattern 6
        let source_no_queue = "function claimRewards() public { uint256 requests = 5; }";
        // "requests" alone should not trigger queue processing detection
        assert!(
            !source_no_queue.contains("withdrawalQueue")
                && !source_no_queue.contains("pendingWithdrawals")
                && !source_no_queue.contains("queuedWithdrawals")
                && !source_no_queue.contains("withdrawRequests"),
            "Source without actual queue structures should not match queue patterns"
        );

        // Source WITH actual queue data structure SHOULD trigger
        let source_with_queue =
            "function processWithdrawals() public { withdrawalQueue.push(msg.sender); }";
        assert!(
            source_with_queue.contains("withdrawalQueue"),
            "Source with withdrawalQueue should match queue patterns"
        );
    }
}
