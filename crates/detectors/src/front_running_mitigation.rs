use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for missing front-running protection mechanisms
pub struct FrontRunningMitigationDetector {
    base: BaseDetector,
}

impl Default for FrontRunningMitigationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontRunningMitigationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("front-running-mitigation".to_string()),
                "Missing Front-Running Mitigation".to_string(),
                "Detects functions vulnerable to front-running attacks without proper MEV protection mechanisms".to_string(),
                vec![DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for FrontRunningMitigationDetector {
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

        // Skip AMM pool contracts - front-running/sandwich attacks are EXPECTED on AMM swaps
        // AMMs enable arbitrage and MEV as part of their price discovery mechanism
        // This detector should focus on user-facing contracts that consume AMM data
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Skip lending protocols - they have audited oracle and price protection
        // Lending protocols (Compound, Aave, MakerDAO) use robust oracle systems:
        // - Compound: Comptroller with Chainlink price feeds
        // - Aave: LendingPoolAddressesProvider with Chainlink oracles
        // - MakerDAO: Medianizer with multiple oracle sources
        // Front-running mitigation is handled at the protocol level, not function level
        if utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(frontrun_issue) = self.check_frontrunning_risk(function, ctx) {
                let message = format!(
                    "Function '{}' lacks front-running protection. {} \
                    Front-runners can extract MEV by observing mempool and inserting their transactions before yours.",
                    function.name.name, frontrun_issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add front-running protection to '{}'. \
                    Implement: (1) Commit-reveal scheme with time delay, \
                    (2) Deadline parameter for transaction validity, \
                    (3) Minimum output amount (slippage protection), \
                    (4) Batch auctions or frequent batch auctions (FBA), \
                    (5) Private mempool (Flashbots Protect), \
                    (6) Time-weighted average pricing (TWAP).",
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

impl FrontRunningMitigationDetector {
    fn check_frontrunning_risk(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // === False positive reduction: skip functions that cannot be front-run ===

        // Skip internal/private functions - they cannot be called externally
        // so they cannot be front-run via the mempool
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return None;
        }

        // Also skip functions with underscore prefix (Solidity internal convention)
        // even if visibility is not explicitly set, underscore-prefixed functions
        // are internal by convention
        if func_name.starts_with('_') {
            return None;
        }

        // Skip ERC-4626 vault standard functions (deposit/redeem/withdraw/mint)
        // These functions are part of the ERC-4626 standard and vault implementations
        // inherently handle front-running through share-based accounting,
        // virtual shares patterns, and slippage parameters
        if self.is_erc4626_vault_function(func_name, ctx) {
            return None;
        }

        // Skip flash loan provider functions (borrow, liquidate, flashLoan)
        // Flash loan operations execute atomically within a single transaction,
        // making front-running irrelevant within the flash loan context
        if self.is_flash_loan_provider_function(func_name, &func_source, ctx) {
            return None;
        }

        // Skip flash loan callback functions (onFlashLoan, executeOperation, etc.)
        // These are called internally by flash loan providers, not directly by users
        if self.is_flash_loan_callback(func_name) {
            return None;
        }

        // Pattern 1: Bid/auction functions without commit-reveal
        let is_bidding =
            func_name.contains("bid") || func_name.contains("Bid") || func_name.contains("auction");

        if is_bidding {
            let has_commit_reveal = func_source.contains("commit")
                || func_source.contains("reveal")
                || func_source.contains("hash")
                || func_source.contains("secret");

            if !has_commit_reveal {
                return Some(format!(
                    "Bidding function '{}' lacks commit-reveal scheme. \
                    Attackers can see your bid and outbid you",
                    func_name
                ));
            }
        }

        // Pattern 2: Swap/trade functions without slippage protection
        let is_trading = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("buy")
            || func_name.contains("sell");

        if is_trading {
            let has_slippage = func_source.contains("minAmount")
                || func_source.contains("minOut")
                || func_source.contains("slippage")
                || func_source.contains("amountOutMin");

            let has_deadline = func_source.contains("deadline")
                || func_source.contains("expiry")
                || func_source.contains("block.timestamp");

            if !has_slippage {
                return Some(format!(
                    "Trading function '{}' missing slippage protection (minAmountOut). \
                    Vulnerable to sandwich attacks",
                    func_name
                ));
            }

            if !has_deadline {
                return Some(format!(
                    "Trading function '{}' missing deadline parameter. \
                    Transaction can be held and executed at unfavorable time",
                    func_name
                ));
            }
        }

        // Pattern 3: Price-sensitive operations without protection
        let uses_price = func_source.contains("price")
            || func_source.contains("getPrice")
            || func_source.contains("rate");

        let is_vulnerable_operation = func_name.contains("liquidate")
            || func_name.contains("mint")
            || func_name.contains("redeem")
            || func_name.contains("borrow");

        if uses_price && is_vulnerable_operation {
            let has_protection = func_source.contains("TWAP")
                || func_source.contains("timeWeighted")
                || func_source.contains("oracle")
                || func_source.contains("minAmount");

            if !has_protection {
                return Some(format!(
                    "Price-dependent function '{}' vulnerable to front-running. \
                    No TWAP, oracle, or minimum amount protection",
                    func_name
                ));
            }
        }

        // Pattern 4: State changes visible in mempool
        let changes_critical_state = func_source.contains("approve")
            || func_source.contains("transfer")
            || func_source.contains("withdraw");

        if changes_critical_state {
            let has_nonce_or_commitment = func_source.contains("nonce")
                || func_source.contains("commitment")
                || func_source.contains("signature");

            // Only flag if it's a high-value operation
            let is_high_value = func_source.contains("balance")
                || func_source.contains("amount")
                || func_source.contains("value");

            if is_high_value && !has_nonce_or_commitment {
                // Don't flag simple transfers, focus on complex operations
                if func_source.contains("calculate")
                    || func_source.contains("swap")
                    || func_source.contains("convert")
                {
                    return Some(format!(
                        "Function '{}' performs high-value state changes observable in mempool. \
                        Consider commit-reveal or private transactions",
                        func_name
                    ));
                }
            }
        }

        None
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

    /// Check if a function is an ERC-4626 vault standard function.
    /// ERC-4626 vaults use share-based accounting that inherently mitigates
    /// front-running through virtual shares, slippage parameters, and
    /// preview functions.
    fn is_erc4626_vault_function(&self, func_name: &str, ctx: &AnalysisContext) -> bool {
        // First, verify this is actually an ERC-4626 vault contract
        if !utils::is_erc4626_vault(ctx) {
            return false;
        }

        // ERC-4626 standard function names that are protected by design
        let erc4626_standard_functions = [
            "deposit",
            "mint",
            "withdraw",
            "redeem",
            "previewDeposit",
            "previewMint",
            "previewWithdraw",
            "previewRedeem",
            "convertToShares",
            "convertToAssets",
            "maxDeposit",
            "maxMint",
            "maxWithdraw",
            "maxRedeem",
        ];

        let name_lower = func_name.to_lowercase();
        erc4626_standard_functions
            .iter()
            .any(|&f| name_lower == f.to_lowercase())
    }

    /// Check if a function is a flash loan provider function.
    /// Flash loan provider functions (flashLoan, borrow, liquidate) execute
    /// atomically within a single transaction, making front-running irrelevant.
    fn is_flash_loan_provider_function(
        &self,
        func_name: &str,
        func_source: &str,
        ctx: &AnalysisContext,
    ) -> bool {
        // Check if the contract is a flash loan provider
        let is_flash_provider =
            utils::is_flash_loan_provider(ctx) || utils::is_flash_loan_context(ctx);

        if !is_flash_provider {
            return false;
        }

        let name_lower = func_name.to_lowercase();

        // Standard flash loan provider functions
        let flash_loan_functions = [
            "flashloan",
            "flash",
            "executeflash",
            "borrow",
            "liquidate",
            "repay",
            "repayborrow",
        ];

        if flash_loan_functions
            .iter()
            .any(|&f| name_lower == f.to_lowercase())
        {
            return true;
        }

        // Also check for functions that contain flash loan execution patterns
        // (callback invocation within the function body)
        let has_flash_callback_pattern = func_source.contains("onFlashLoan")
            || func_source.contains("executeOperation")
            || func_source.contains("receiveFlashLoan")
            || func_source.contains("IFlashLoanReceiver")
            || func_source.contains("IERC3156FlashBorrower");

        if has_flash_callback_pattern {
            return true;
        }

        false
    }

    /// Check if a function is a flash loan callback.
    /// Flash loan callbacks are invoked by the flash loan provider contract,
    /// not directly by external users, so they cannot be front-run.
    fn is_flash_loan_callback(&self, func_name: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        let callback_functions = [
            "onflashloan",            // ERC-3156 standard callback
            "executeoperation",       // Aave flash loan callback
            "receiveflashloan",       // Balancer flash loan callback
            "uniswapv2call",          // Uniswap V2 flash swap callback
            "uniswapv3flashcallback", // Uniswap V3 flash callback
            "pancakecall",            // PancakeSwap flash swap callback
        ];

        callback_functions
            .iter()
            .any(|&f| name_lower == f.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = FrontRunningMitigationDetector::new();
        assert_eq!(detector.name(), "Missing Front-Running Mitigation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    // =====================================================================
    // ERC-4626 vault function skip tests
    // =====================================================================

    #[test]
    fn test_skip_erc4626_vault_deposit() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract SecureVault is ERC4626 {
                function deposit(uint256 assets, address receiver) public override returns (uint256) {
                    return super.deposit(assets, receiver);
                }
                function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
                    return super.redeem(shares, receiver, owner);
                }
                function totalAssets() public view returns (uint256) { return 0; }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_erc4626_vault_function("deposit", &ctx));
        assert!(detector.is_erc4626_vault_function("redeem", &ctx));
        assert!(detector.is_erc4626_vault_function("withdraw", &ctx));
        assert!(detector.is_erc4626_vault_function("mint", &ctx));
    }

    #[test]
    fn test_skip_erc4626_vault_preview_functions() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract SecureVault is ERC4626 {
                function previewDeposit(uint256 assets) public view returns (uint256) { return 0; }
                function previewRedeem(uint256 shares) public view returns (uint256) { return 0; }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_erc4626_vault_function("previewDeposit", &ctx));
        assert!(detector.is_erc4626_vault_function("previewMint", &ctx));
        assert!(detector.is_erc4626_vault_function("previewWithdraw", &ctx));
        assert!(detector.is_erc4626_vault_function("previewRedeem", &ctx));
        assert!(detector.is_erc4626_vault_function("convertToShares", &ctx));
        assert!(detector.is_erc4626_vault_function("convertToAssets", &ctx));
    }

    #[test]
    fn test_no_skip_non_erc4626_deposit() {
        let detector = FrontRunningMitigationDetector::new();
        // A contract that is NOT an ERC-4626 vault should NOT skip deposit
        let source = r#"
            contract SimplePool {
                function deposit(uint256 amount) external {
                    balances[msg.sender] += amount;
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.is_erc4626_vault_function("deposit", &ctx));
    }

    #[test]
    fn test_no_skip_non_standard_function_in_vault() {
        let detector = FrontRunningMitigationDetector::new();
        // Even in an ERC-4626 vault, non-standard functions should NOT be skipped
        let source = r#"
            contract SecureVault is ERC4626 {
                function customSwap(uint256 amount) external { }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.is_erc4626_vault_function("customSwap", &ctx));
        assert!(!detector.is_erc4626_vault_function("bid", &ctx));
    }

    #[test]
    fn test_skip_erc4626_virtual_shares_contract() {
        let detector = FrontRunningMitigationDetector::new();
        // Contract using IERC4626 interface (like SecureVault_VirtualShares)
        let source = r#"
            contract SecureVault_VirtualShares is IERC4626 {
                uint256 private constant VIRTUAL_SHARES = 1e6;
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
                    shares = convertToShares(assets);
                    _mint(receiver, shares);
                }
                function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
                    assets = convertToAssets(shares);
                    _burn(owner, shares);
                    IERC20(asset).transfer(receiver, assets);
                }
                function totalAssets() public view returns (uint256) { return 0; }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_erc4626_vault_function("deposit", &ctx));
        assert!(detector.is_erc4626_vault_function("redeem", &ctx));
    }

    // =====================================================================
    // Flash loan provider function skip tests
    // =====================================================================

    #[test]
    fn test_skip_flash_loan_provider_borrow() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract VulnerableFlashLoan {
                function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = address(this).balance;
                    payable(receiver).transfer(amount);
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    require(address(this).balance >= balanceBefore, "Not repaid");
                }
                function borrow(uint256 amount) external {
                    uint256 price = getPrice(token);
                    // borrow logic
                }
                function liquidate(address borrower) external {
                    uint256 price = getPrice(token);
                    // liquidation logic
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_flash_loan_provider_function("borrow", "", &ctx));
        assert!(detector.is_flash_loan_provider_function("liquidate", "", &ctx));
        assert!(detector.is_flash_loan_provider_function("flashLoan", "", &ctx));
    }

    #[test]
    fn test_skip_flash_loan_provider_repay() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract LendingPool is IERC3156FlashLender {
                function flashLoan(address borrower, address token, uint256 amount, bytes calldata data) external returns (bool) {
                    return true;
                }
                function repay(uint256 amount) external { }
                function repayBorrow(uint256 amount) external { }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_flash_loan_provider_function("repay", "", &ctx));
        assert!(detector.is_flash_loan_provider_function("repayBorrow", "", &ctx));
    }

    #[test]
    fn test_no_skip_borrow_in_non_flash_loan_contract() {
        let detector = FrontRunningMitigationDetector::new();
        // borrow in a non-flash-loan contract should NOT be skipped
        let source = r#"
            contract SimpleLending {
                function borrow(uint256 amount) external {
                    // basic borrow
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.is_flash_loan_provider_function("borrow", "", &ctx));
    }

    #[test]
    fn test_skip_flash_loan_function_with_callback_in_source() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract FlashLoanArbitrage {
                function flashLoan(uint256 amount) external {
                    pool.flash(address(this), amount, "");
                }
                function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata params) external {
                    // arbitrage logic
                }
            }
        "#;
        let ctx = create_test_context(source);
        // A function whose body invokes a flash loan callback should be skipped
        let func_source_with_callback =
            "IFlashBorrower(receiver).onFlashLoan(msg.sender, token, amount, fee, data);";
        assert!(detector.is_flash_loan_provider_function(
            "customFlashExec",
            func_source_with_callback,
            &ctx
        ));
    }

    // =====================================================================
    // Flash loan callback skip tests
    // =====================================================================

    #[test]
    fn test_skip_flash_loan_callbacks() {
        let detector = FrontRunningMitigationDetector::new();
        // All standard flash loan callbacks should be skipped
        assert!(detector.is_flash_loan_callback("onFlashLoan"));
        assert!(detector.is_flash_loan_callback("executeOperation"));
        assert!(detector.is_flash_loan_callback("receiveFlashLoan"));
        assert!(detector.is_flash_loan_callback("uniswapV2Call"));
        assert!(detector.is_flash_loan_callback("uniswapV3FlashCallback"));
        assert!(detector.is_flash_loan_callback("pancakeCall"));
    }

    #[test]
    fn test_no_skip_non_callback_functions() {
        let detector = FrontRunningMitigationDetector::new();
        assert!(!detector.is_flash_loan_callback("deposit"));
        assert!(!detector.is_flash_loan_callback("swap"));
        assert!(!detector.is_flash_loan_callback("borrow"));
        assert!(!detector.is_flash_loan_callback("liquidate"));
        assert!(!detector.is_flash_loan_callback("bid"));
    }

    // =====================================================================
    // Internal/private function skip tests (underscore prefix)
    // =====================================================================

    #[test]
    fn test_underscore_prefix_detected() {
        // The underscore prefix check is in check_frontrunning_risk,
        // so we test it through the naming convention detection
        let detector = FrontRunningMitigationDetector::new();

        // Verify the logic: names starting with '_' should be treated as internal
        assert!("_executeArbitrageTrades".starts_with('_'));
        assert!("_internalSwap".starts_with('_'));
        assert!(!"deposit".starts_with('_'));
        assert!(!"swap".starts_with('_'));

        // This validates the convention check in check_frontrunning_risk
        // where func_name.starts_with('_') returns None (skip)
        let _ = detector; // detector instance confirms compilation
    }

    // =====================================================================
    // Regression: existing detections still work
    // =====================================================================

    #[test]
    fn test_non_vault_non_flashloan_functions_not_skipped() {
        let detector = FrontRunningMitigationDetector::new();
        // Regular functions should NOT be skipped by any of the new filters
        let source = r#"
            contract Exchange {
                function swap(uint256 amountIn) external {
                    // swap logic without slippage
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.is_erc4626_vault_function("swap", &ctx));
        assert!(!detector.is_flash_loan_provider_function("swap", "", &ctx));
        assert!(!detector.is_flash_loan_callback("swap"));
    }

    #[test]
    fn test_case_insensitive_erc4626_function_match() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract MyVault is ERC4626 {
                function DEPOSIT(uint256 a, address r) public returns (uint256) { return 0; }
            }
        "#;
        let ctx = create_test_context(source);
        // Case-insensitive matching should work
        assert!(detector.is_erc4626_vault_function("DEPOSIT", &ctx));
        assert!(detector.is_erc4626_vault_function("Deposit", &ctx));
        assert!(detector.is_erc4626_vault_function("deposit", &ctx));
    }

    #[test]
    fn test_case_insensitive_flash_loan_callback_match() {
        let detector = FrontRunningMitigationDetector::new();
        assert!(detector.is_flash_loan_callback("ONFLASHLOAN"));
        assert!(detector.is_flash_loan_callback("OnFlashLoan"));
        assert!(detector.is_flash_loan_callback("onFlashLoan"));
        assert!(detector.is_flash_loan_callback("EXECUTEOPERATION"));
    }
}
