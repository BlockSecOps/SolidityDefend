//! Flash Mint Token Inflation Detector
//!
//! Detects flash mint vulnerabilities:
//! - Uncapped flash mint amount (unlimited minting)
//! - No flash mint fee (free mints enable spam)
//! - No rate limiting (DoS via spam)
//!
//! Severity: HIGH
//! Context: MakerDAO flash mint used in Euler $200M exploit
//!
//! v1.10.17 FP fixes:
//! - Only flag actual flash MINT functions (that mint new tokens), not flash loan functions
//! - Skip flash loan consumers/borrowers (contracts implementing onFlashLoan callbacks)
//! - Skip nested flash loan functions (fee handled by outer loan)
//! - Require minting indicators (_mint, totalSupply increase) for flashLoan-named functions
//! - Skip utility/view functions that merely reference "flashloan" in their name

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct FlashmintTokenInflationDetector {
    base: BaseDetector,
}

impl FlashmintTokenInflationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashmint-token-inflation".to_string()),
                "Flash Mint Token Inflation Attack".to_string(),
                "Detects flash mint vulnerabilities allowing unlimited minting and spam"
                    .to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Check if the contract is a flash loan consumer/borrower rather than a provider.
    /// Consumers implement onFlashLoan callbacks and call external flash loan providers,
    /// but they do not mint tokens themselves and should not be flagged.
    fn is_flash_loan_consumer(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Contract implements onFlashLoan callback (borrower pattern)
        let has_on_flash_loan_callback = source_lower.contains("function onflashloan(")
            || source_lower.contains("function onflashloan (");

        // Contract calls an external flash loan provider (e.g., IFlashLoanProvider.flashLoan)
        let calls_external_provider = source.contains("IFlashLoanProvider")
            || source.contains("IFlashLender")
            || source_lower.contains("getflashloanprovider")
            || source_lower.contains("flashloanprovider");

        // Contract is an arbitrage or strategy contract (consumer pattern)
        let is_strategy_contract = source_lower.contains("arbitrage")
            || source_lower.contains("strategy")
            || source_lower.contains("liquidat");

        // If contract has onFlashLoan callback, it is a consumer
        if has_on_flash_loan_callback && !self.contract_has_minting(ctx) {
            return true;
        }

        // If contract calls external providers and does not mint, it is a consumer
        if calls_external_provider && !self.contract_has_minting(ctx) {
            return true;
        }

        // If contract is a strategy/arbitrage contract without minting, it is a consumer
        if is_strategy_contract && !self.contract_has_minting(ctx) {
            return true;
        }

        false
    }

    /// Check if the contract contains actual token minting logic.
    /// Flash mints create new tokens (increasing totalSupply), while flash loans
    /// lend existing tokens from the pool.
    fn contract_has_minting(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Direct minting calls
        source_lower.contains("_mint(")
            || source_lower.contains("_mint (")
            || source_lower.contains(".mint(")
            // totalSupply modifications (minting increases supply)
            || source_lower.contains("totalsupply +=")
            || source_lower.contains("totalsupply+=")
            || source_lower.contains("totalsupply = totalsupply +")
            // ERC20 internal mint patterns
            || source_lower.contains("balanceof[") && source_lower.contains("totalsupply +=")
    }

    /// Check if a specific function contains minting indicators in its body.
    fn function_has_minting(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();

        func_lower.contains("_mint(")
            || func_lower.contains("_mint (")
            || func_lower.contains(".mint(")
            || func_lower.contains("totalsupply +=")
            || func_lower.contains("totalsupply+=")
            || func_lower.contains("totalsupply = totalsupply +")
    }

    /// Check if a function is a nested/delegating flash loan function.
    /// These functions simply call another flash loan function and inherit
    /// its fee structure, so they should not be flagged independently.
    fn is_nested_flash_loan(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();

        // Function delegates to another flash loan (e.g., this.flashLoan(...))
        (func_lower.contains("this.flashloan(")
            || func_lower.contains("this.flashmint(")
            || func_lower.contains("self.flashloan(")
            || func_lower.contains("_flashloan(")
            || func_lower.contains("_flashmint("))
            // And does NOT itself contain minting logic
            && !self.function_has_minting(function, ctx)
    }

    /// Check if a function is a utility/view/getter that merely references
    /// "flashloan" or "flashmint" in its name but is not an actual flash
    /// mint entry point (e.g., getFlashLoanProvider, isInFlashLoan).
    fn is_utility_function(&self, function: &ast::Function) -> bool {
        let func_name = function.name.name.to_lowercase();

        // Getter/view functions that reference flash loans
        func_name.starts_with("get")
            || func_name.starts_with("is")
            || func_name.starts_with("has")
            || func_name.starts_with("can")
            || func_name.starts_with("check")
            || func_name.starts_with("_get")
            || func_name.starts_with("_is")
            // Common utility patterns
            || func_name.contains("provider")
            || func_name.contains("status")
            || func_name.contains("available")
            || func_name.contains("enabled")
    }

    /// Determine if a function is a true flash mint entry point that should be checked.
    /// Returns true only for functions that actually mint new tokens as part of a flash
    /// operation.
    fn is_flash_mint_function(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_name = function.name.name.to_lowercase();

        // Skip utility/view/getter functions
        if self.is_utility_function(function) {
            return false;
        }

        // Skip nested/delegating flash loan functions
        if self.is_nested_flash_loan(function, ctx) {
            return false;
        }

        // Case 1: Explicitly named "flashMint" - high confidence this is a flash mint
        if func_name.contains("flashmint") {
            return true;
        }

        // Case 2: Named "flashLoan" - only flag if function body actually mints tokens
        // Standard flash loans lend existing tokens and should not be flagged
        if func_name.contains("flashloan") {
            return self.function_has_minting(function, ctx);
        }

        false
    }

    fn has_flash_mint_cap(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check for MAX_FLASH_MINT or similar constant
        (source_lower.contains("max") && source_lower.contains("flash"))
            || source_lower.contains("flashlimit")
            || source_lower.contains("maxflashloan")
    }

    fn get_function_source<'a>(
        &self,
        function: &ast::Function,
        ctx: &'a AnalysisContext,
    ) -> &'a str {
        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return "";
        }

        &source[func_start..func_end.min(source.len())]
    }

    fn has_flash_mint_fee(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // --- Function-level checks ---

        // Check 1: Function body contains fee arithmetic (original check)
        if func_lower.contains("fee")
            && (func_lower.contains("*") || func_lower.contains("/") || func_lower.contains("mul"))
        {
            return true;
        }

        // Check 2: Function calls a flashFee() or similar fee-computing function
        if func_lower.contains("flashfee(")
            || func_lower.contains("flash_fee(")
            || func_lower.contains("getfee(")
            || func_lower.contains("calculatefee(")
            || func_lower.contains("_fee(")
        {
            return true;
        }

        // Check 3: Function body references fee state variables or constants
        if func_lower.contains("flashloanfee")
            || func_lower.contains("flashmintfee")
            || func_lower.contains("flash_loan_fee")
            || func_lower.contains("flash_mint_fee")
            || func_lower.contains("flashloan_premium")
            || func_lower.contains("flash_premium")
            || func_lower.contains("feerate")
            || func_lower.contains("fee_rate")
            || func_lower.contains("basis_points")
            || func_lower.contains("fee_bps")
        {
            return true;
        }

        // Check 4: Function has repayment validation that includes a fee
        // e.g., amount + fee, balanceBefore + fee, require(repayment >= ...)
        if func_lower.contains("amount + fee")
            || func_lower.contains("amount +fee")
            || func_lower.contains("amount+fee")
            || (func_lower.contains("balancebefore") && func_lower.contains("+ fee"))
            || (func_lower.contains("repay") && func_lower.contains("fee"))
        {
            return true;
        }

        // Check 5: Function has a fee parameter (e.g., onFlashLoan's fee param)
        for param in function.parameters.iter() {
            if let Some(ref name) = param.name {
                let param_lower = name.name.to_lowercase();
                if param_lower == "fee"
                    || param_lower == "_fee"
                    || param_lower.contains("flashfee")
                    || param_lower.contains("flash_fee")
                {
                    return true;
                }
            }
        }

        // --- Contract-level checks ---

        // Check 6: Contract has a flashFee() function (ERC-3156 standard)
        if source_lower.contains("function flashfee(")
            || source_lower.contains("function flash_fee(")
            || source_lower.contains("function _flashfee(")
        {
            return true;
        }

        // Check 7: Contract has fee state variables or constants
        if source_lower.contains("flashloanfee")
            || source_lower.contains("flashmintfee")
            || source_lower.contains("flash_loan_fee")
            || source_lower.contains("flash_mint_fee")
            || source_lower.contains("flashloan_premium")
        {
            return true;
        }

        // Check 8: Contract has fee-bounding constants (MAX_FEE, BASIS_POINTS)
        if (source_lower.contains("max_fee")
            || source_lower.contains("maxfee")
            || source_lower.contains("maxflashloanfee")
            || source_lower.contains("max_flash_loan_fee"))
            && (source_lower.contains("basis_points")
                || source_lower.contains("bps")
                || source_lower.contains("10000")
                || source_lower.contains("1e4"))
        {
            return true;
        }

        // Check 9: Contract is ERC-3156 compliant (inherently has fee handling)
        if (ctx.source_code.contains("IERC3156FlashLender")
            || ctx.source_code.contains("IERC3156FlashBorrower")
            || ctx.source_code.contains("ERC3156"))
            && ctx.source_code.contains("CALLBACK_SUCCESS")
        {
            return true;
        }

        // Check 10: Contract has explicit fee require/validation
        if source_lower.contains("require(fee") || source_lower.contains("require(_fee") {
            return true;
        }

        false
    }
}

impl Default for FlashmintTokenInflationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashmintTokenInflationDetector {
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

        // Early exit: skip flash loan consumer/borrower contracts entirely.
        // These contracts use flash loans from external providers but do not
        // mint tokens themselves, so flash mint fee checks are irrelevant.
        if self.is_flash_loan_consumer(ctx) {
            return Ok(findings);
        }

        // Find flash mint functions (not just any function with "flashloan" in the name)
        for function in ctx.get_functions() {
            // Only check functions that are actual flash mint entry points
            if !self.is_flash_mint_function(function, ctx) {
                continue;
            }

            let line = function.name.location.start().line() as u32;

            // Check 1: Flash mint cap
            if !self.has_flash_mint_cap(ctx) {
                findings.push(
                    self.base
                        .create_finding_with_severity(
                            ctx,
                            "Uncapped flash mint - unlimited token minting possible".to_string(),
                            line,
                            0,
                            20,
                            Severity::High,
                        )
                        .with_fix_suggestion(
                            "Add MAX_FLASH_MINT constant and validate amount".to_string(),
                        ),
                );
            }

            // Check 2: Flash mint fee
            if !self.has_flash_mint_fee(function, ctx) {
                findings.push(
                    self.base
                        .create_finding_with_severity(
                            ctx,
                            "No flash mint fee - free flash mints enable spam".to_string(),
                            line,
                            0,
                            20,
                            Severity::Medium,
                        )
                        .with_fix_suggestion(
                            "Add flash mint fee (e.g., 0.05% like MakerDAO)".to_string(),
                        ),
                );
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
    use crate::detector::Detector;
    use crate::types::test_utils::create_test_context;

    // ========================================================================
    // Helper to run the detector on source code
    // ========================================================================

    fn run_detector(source: &str) -> Vec<Finding> {
        let ctx = create_test_context(source);
        let detector = FlashmintTokenInflationDetector::new();
        detector.detect(&ctx).unwrap()
    }

    fn count_findings_with_message(findings: &[Finding], needle: &str) -> usize {
        findings
            .iter()
            .filter(|f| f.message.to_lowercase().contains(&needle.to_lowercase()))
            .count()
    }

    // ========================================================================
    // TRUE POSITIVE: Actual flash mint without fee should still be flagged
    // ========================================================================

    #[test]
    fn test_tp_vulnerable_flash_mint_no_fee() {
        // This is a genuine flash mint: function named flashMint that calls _mint
        let source = r#"
            pragma solidity ^0.8.20;
            contract VulnerableFlashMint {
                uint256 public totalSupply;
                mapping(address => uint256) public balanceOf;

                function flashMint(address receiver, uint256 amount, bytes calldata data) external {
                    totalSupply += amount;
                    balanceOf[receiver] += amount;
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    totalSupply -= amount;
                    balanceOf[receiver] -= amount;
                }
            }
        "#;

        let detector = FlashmintTokenInflationDetector::new();
        let ctx = create_test_context(source);

        // Contract has minting
        assert!(
            detector.contract_has_minting(&ctx),
            "Should detect minting in flash mint contract"
        );

        // Should not be classified as consumer (it mints tokens)
        assert!(
            !detector.is_flash_loan_consumer(&ctx),
            "Flash mint provider should not be classified as consumer"
        );
    }

    // ========================================================================
    // FALSE POSITIVE: flash loan (not mint) should NOT be flagged
    // ========================================================================

    #[test]
    fn test_fp_flash_loan_not_flash_mint() {
        // This is a standard flash loan: transfers existing tokens, no _mint call
        let source = r#"
            pragma solidity ^0.8.20;
            contract VulnerableFlashLoanCallback {
                mapping(address => uint256) public deposits;

                function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = address(this).balance;
                    payable(receiver).transfer(amount);
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    uint256 balanceAfter = address(this).balance;
                    require(balanceAfter >= balanceBefore, "Flash loan not repaid");
                }
            }
        "#;

        let findings = run_detector(source);

        let fee_findings = count_findings_with_message(&findings, "flash mint fee");
        assert_eq!(
            fee_findings, 0,
            "Flash loan (not mint) should not be flagged for missing flash mint fee, got {} findings",
            fee_findings
        );
    }

    #[test]
    fn test_fp_nested_flash_loan() {
        // Nested flash loan that delegates to the parent - should not be flagged
        let source = r#"
            pragma solidity ^0.8.20;
            contract FlashLoanProvider {
                function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = address(this).balance;
                    payable(receiver).transfer(amount);
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    require(address(this).balance >= balanceBefore, "Not repaid");
                }

                function nestedFlashLoan(address receiver, uint256 amount) external {
                    this.flashLoan(receiver, amount, "");
                }
            }
        "#;

        let findings = run_detector(source);

        let fee_findings = count_findings_with_message(&findings, "flash mint fee");
        assert_eq!(
            fee_findings, 0,
            "Nested flash loan should not be flagged, got {} findings",
            fee_findings
        );
    }

    // ========================================================================
    // FALSE POSITIVE: flash loan consumer/borrower should NOT be flagged
    // ========================================================================

    #[test]
    fn test_fp_flash_loan_consumer_arbitrage() {
        // FlashLoanArbitrage: a consumer that borrows via external flash loan provider
        let source = r#"
            pragma solidity ^0.8.20;
            import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

            contract FlashLoanArbitrage is ReentrancyGuard {
                bool private inFlashLoan;

                function executeArbitrage(uint256 amount) external {
                    IFlashLoanProvider(getFlashLoanProvider()).flashLoan(address(this), amount, "");
                }

                function onFlashLoan(
                    address asset,
                    uint256 amount,
                    uint256 fee,
                    bytes calldata data
                ) external nonReentrant returns (bool) {
                    inFlashLoan = true;
                    // ... arbitrage logic ...
                    inFlashLoan = false;
                    return true;
                }

                function getFlashLoanProvider() public pure returns (address) {
                    return 0x1234567890123456789012345678901234567890;
                }

                function isInFlashLoan() external view returns (bool) {
                    return inFlashLoan;
                }
            }

            interface IFlashLoanProvider {
                function flashLoan(address borrower, uint256 amount, bytes calldata data) external;
            }
        "#;

        let detector = FlashmintTokenInflationDetector::new();
        let ctx = create_test_context(source);

        // Should be classified as consumer
        assert!(
            detector.is_flash_loan_consumer(&ctx),
            "Arbitrage contract with onFlashLoan callback should be classified as consumer"
        );

        let findings = run_detector(source);
        assert_eq!(
            findings.len(),
            0,
            "Flash loan consumer should produce zero findings, got {}",
            findings.len()
        );
    }

    // ========================================================================
    // FALSE POSITIVE: utility functions with "flashloan" in name
    // ========================================================================

    #[test]
    fn test_fp_utility_functions_with_flashloan_name() {
        // Utility functions like getFlashLoanProvider and isInFlashLoan should not be flagged
        let source = r#"
            pragma solidity ^0.8.20;
            contract FlashLoanUtils {
                bool private inFlashLoan;

                function getFlashLoanProvider() public pure returns (address) {
                    return 0x1234567890123456789012345678901234567890;
                }

                function isInFlashLoan() external view returns (bool) {
                    return inFlashLoan;
                }

                function hasFlashLoanCapacity() external view returns (bool) {
                    return true;
                }
            }
        "#;

        let findings = run_detector(source);
        assert_eq!(
            findings.len(),
            0,
            "Utility/view functions should not be flagged, got {} findings",
            findings.len()
        );
    }

    // ========================================================================
    // Verify that is_utility_function works correctly
    // ========================================================================

    #[test]
    fn test_is_utility_function_detection() {
        let detector = FlashmintTokenInflationDetector::new();
        let arena = Box::leak(Box::new(ast::AstArena::new()));

        let utility_names = [
            "getFlashLoanProvider",
            "isInFlashLoan",
            "hasFlashLoanCapacity",
            "canFlashLoan",
            "checkFlashLoanStatus",
        ];

        for name in &utility_names {
            let func = crate::types::test_utils::create_mock_ast_function(
                arena,
                arena.alloc_str(name),
                ast::Visibility::Public,
                ast::StateMutability::View,
            );
            assert!(
                detector.is_utility_function(&func),
                "'{}' should be detected as utility function",
                name
            );
        }

        // These should NOT be classified as utility
        let non_utility_names = ["flashMint", "flashLoan", "executeFlashMint"];
        for name in &non_utility_names {
            let func = crate::types::test_utils::create_mock_ast_function(
                arena,
                arena.alloc_str(name),
                ast::Visibility::Public,
                ast::StateMutability::NonPayable,
            );
            assert!(
                !detector.is_utility_function(&func),
                "'{}' should NOT be detected as utility function",
                name
            );
        }
    }

    // ========================================================================
    // Verify contract_has_minting detection
    // ========================================================================

    #[test]
    fn test_contract_has_minting_positive() {
        let detector = FlashmintTokenInflationDetector::new();

        let with_mint = create_test_context(
            r#"
            contract Token {
                function flashMint(uint256 amount) external {
                    _mint(msg.sender, amount);
                }
            }
        "#,
        );
        assert!(
            detector.contract_has_minting(&with_mint),
            "Should detect _mint() call"
        );

        let with_totalsupply = create_test_context(
            r#"
            contract Token {
                uint256 public totalSupply;
                function flashMint(uint256 amount) external {
                    totalSupply += amount;
                }
            }
        "#,
        );
        assert!(
            detector.contract_has_minting(&with_totalsupply),
            "Should detect totalSupply increment"
        );
    }

    #[test]
    fn test_contract_has_minting_negative() {
        let detector = FlashmintTokenInflationDetector::new();

        let without_mint = create_test_context(
            r#"
            contract Pool {
                function flashLoan(address to, uint256 amount) external {
                    payable(to).transfer(amount);
                    require(address(this).balance >= amount, "Not repaid");
                }
            }
        "#,
        );
        assert!(
            !detector.contract_has_minting(&without_mint),
            "Flash loan without minting should return false"
        );
    }

    // ========================================================================
    // Verify is_flash_loan_consumer detection
    // ========================================================================

    #[test]
    fn test_is_flash_loan_consumer_with_callback() {
        let detector = FlashmintTokenInflationDetector::new();

        let consumer = create_test_context(
            r#"
            contract Borrower {
                function onFlashLoan(
                    address initiator,
                    address token,
                    uint256 amount,
                    uint256 fee,
                    bytes calldata data
                ) external returns (bytes32) {
                    return keccak256("ERC3156FlashBorrower.onFlashLoan");
                }
            }
        "#,
        );
        assert!(
            detector.is_flash_loan_consumer(&consumer),
            "Contract with onFlashLoan callback and no minting should be a consumer"
        );
    }

    #[test]
    fn test_is_not_consumer_when_minting() {
        let detector = FlashmintTokenInflationDetector::new();

        // A provider that also has onFlashLoan referenced should NOT be a consumer
        // if it actually mints tokens
        let provider = create_test_context(
            r#"
            contract FlashMintProvider {
                uint256 public totalSupply;
                mapping(address => uint256) public balanceOf;

                function flashMint(address to, uint256 amount) external {
                    totalSupply += amount;
                    balanceOf[to] += amount;
                    IFlashBorrower(to).onFlashLoan(msg.sender, address(this), amount, 0, "");
                    totalSupply -= amount;
                    balanceOf[to] -= amount;
                }
            }
        "#,
        );
        assert!(
            !detector.is_flash_loan_consumer(&provider),
            "Contract that mints tokens should NOT be classified as consumer"
        );
    }

    #[test]
    fn test_is_consumer_arbitrage_pattern() {
        let detector = FlashmintTokenInflationDetector::new();

        let arb = create_test_context(
            r#"
            contract FlashLoanArbitrage {
                function executeArbitrage(uint256 amount) external {
                    IFlashLoanProvider(provider).flashLoan(address(this), amount, "");
                }

                function onFlashLoan(address, uint256, uint256, bytes calldata) external returns (bool) {
                    return true;
                }
            }

            interface IFlashLoanProvider {
                function flashLoan(address, uint256, bytes calldata) external;
            }
        "#,
        );
        assert!(
            detector.is_flash_loan_consumer(&arb),
            "Arbitrage contract should be classified as consumer"
        );
    }

    // ========================================================================
    // Verify flash loan without minting is not flagged
    // (replicates the exact FP scenario from VulnerableFlashLoan.sol)
    // ========================================================================

    #[test]
    fn test_fp_vulnerable_flash_loan_callback_contract() {
        // Exact pattern from VulnerableFlashLoan.sol VulnerableFlashLoanCallback contract
        let source = r#"
            pragma solidity ^0.8.20;
            contract VulnerableFlashLoanCallback {
                mapping(address => uint256) public deposits;
                bool private locked;

                function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = address(this).balance;
                    payable(receiver).transfer(amount);
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    uint256 balanceAfter = address(this).balance;
                    require(balanceAfter >= balanceBefore, "Flash loan not repaid");
                }

                function withdraw(uint256 amount) external {
                    require(deposits[msg.sender] >= amount, "Insufficient balance");
                    deposits[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }

                function nestedFlashLoan(address receiver, uint256 amount) external {
                    this.flashLoan(receiver, amount, "");
                }
            }

            interface IFlashBorrower {
                function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32);
            }
        "#;

        let findings = run_detector(source);

        let fee_findings = count_findings_with_message(&findings, "flash mint fee");
        let cap_findings = count_findings_with_message(&findings, "uncapped flash mint");

        assert_eq!(
            fee_findings, 0,
            "Flash loan (not mint) should not trigger 'no flash mint fee' finding"
        );
        assert_eq!(
            cap_findings, 0,
            "Flash loan (not mint) should not trigger 'uncapped flash mint' finding"
        );
    }
}
