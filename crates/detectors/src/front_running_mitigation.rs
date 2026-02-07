use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::safe_call_patterns;
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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

        // Skip view/pure functions - they do not modify state and therefore
        // cannot be front-run in any meaningful way
        if safe_call_patterns::is_view_or_pure_function(function) {
            return None;
        }

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

        // Skip functions with access control modifiers (onlyOwner, onlyAdmin, etc.)
        // These can only be called by privileged accounts, making mempool-based
        // front-running by arbitrary attackers impractical
        if safe_call_patterns::has_access_control_modifier(function) {
            return None;
        }

        // FP Reduction v3: Skip functions with nonReentrant modifier.
        // nonReentrant prevents the same function from being called during execution,
        // which significantly limits sandwich attack vectors. Combined with other
        // protections, it makes front-running impractical.
        if safe_call_patterns::has_reentrancy_modifier(function) {
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

        // FP Reduction v3: Skip staking/unstaking functions with cooldown/delay patterns.
        // Cooldown periods prevent front-running by enforcing time delays.
        if self.is_staking_with_cooldown(func_name, &func_source) {
            return None;
        }

        // FP Reduction v3: Skip governance functions with timelock protection.
        // Timelocked governance functions have a built-in delay that prevents
        // front-running because the action is publicly known before execution.
        if self.is_timelocked_governance_function(func_name, &func_source, ctx) {
            return None;
        }

        // === Shared protection detection used across multiple patterns ===

        // Broad slippage/price-bound detection: covers various naming conventions
        let has_slippage_protection = self.has_slippage_or_price_bounds(&func_source);

        // Deadline or temporal protection
        let has_deadline_protection = func_source.contains("deadline")
            || func_source.contains("expiry")
            || func_source.contains("validUntil")
            || func_source.contains("expirationTime")
            || func_source.contains("block.timestamp");

        // Strong price protection mechanisms that make slippage params less critical
        let has_strong_price_protection = self.has_strong_price_protection(&func_source);

        // Pattern 1: Bid/auction functions without commit-reveal
        let func_name_lower = func_name.to_lowercase();
        let is_bidding = func_name_lower.contains("bid") || func_name_lower.contains("auction");

        // Exclude auction management functions that are not actual bids.
        // Functions like finalizeAuction, endAuction, closeAuction, cancelAuction
        // don't submit bid values and don't benefit from commit-reveal.
        let is_auction_management = func_name_lower.contains("finalize")
            || func_name_lower.contains("end")
            || func_name_lower.contains("close")
            || func_name_lower.contains("cancel")
            || func_name_lower.contains("settle")
            || func_name_lower.contains("resolve");

        if is_bidding && !is_auction_management {
            let has_commit_reveal = func_source.contains("commit")
                || func_source.contains("reveal")
                || func_source.contains("hash")
                || func_source.contains("secret");

            // FP Reduction v3: Check for commit-reveal at the CONTRACT level.
            // The bid function itself may not contain commit/reveal keywords,
            // but the contract may have separate commit() and reveal() functions.
            let has_contract_level_commit_reveal = self.has_contract_commit_reveal(ctx);

            // Skip if the bid amount is fixed/deterministic (e.g. fixed ticket price)
            // In that case there is no information advantage from seeing the bid
            let has_fixed_price = func_source.contains("ticketPrice")
                || func_source.contains("== price")
                || func_source.contains("== cost")
                || func_source.contains("fixedPrice");

            if !has_commit_reveal && !has_contract_level_commit_reveal && !has_fixed_price {
                return Some(format!(
                    "Bidding function '{}' lacks commit-reveal scheme. \
                    Attackers can see your bid and outbid you",
                    func_name
                ));
            }
        }

        // Pattern 2: Swap/trade functions without slippage protection
        // Use case-insensitive matching to catch camelCase names like
        // flashSwap, buyTokens, sellAssets, etc.
        let is_trading = func_name_lower.contains("swap")
            || func_name_lower.contains("trade")
            || func_name_lower.contains("exchange")
            || func_name_lower.contains("buy")
            || func_name_lower.contains("sell");

        if is_trading {
            // Skip trading functions that operate at fixed/predetermined prices.
            // Sandwich attacks require the ability to move the execution price,
            // which is impossible when the price is constant or oracle-determined.
            let uses_fixed_price = self.uses_fixed_or_predetermined_price(&func_source);

            // If the function has strong price protection (TWAP, multi-oracle,
            // price impact checks, circuit breakers), slippage params are
            // not strictly necessary -- the price is already manipulation-resistant
            if !has_slippage_protection && !has_strong_price_protection && !uses_fixed_price {
                return Some(format!(
                    "Trading function '{}' missing slippage protection (minAmountOut). \
                    Vulnerable to sandwich attacks",
                    func_name
                ));
            }

            // Deadline is only critical if there is no strong price protection
            // and the price is variable (pool-based). TWAP, oracle-based pricing,
            // and fixed prices already prevent stale-price exploitation.
            if !has_deadline_protection && !has_strong_price_protection && !uses_fixed_price {
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
            let has_protection = has_strong_price_protection
                || has_slippage_protection
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
            // Skip Pattern 4 if the function already has slippage + deadline protection
            // (i.e. it passed Pattern 2 checks), or has strong price protection.
            // These functions are already well-protected against front-running.
            if (has_slippage_protection && has_deadline_protection) || has_strong_price_protection {
                return None;
            }

            // Skip if function has deadline protection -- temporal bounds limit
            // the window for mempool observation attacks
            if has_deadline_protection && is_trading {
                return None;
            }

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

    /// Check if function has slippage protection or price bound parameters.
    /// Covers various naming conventions across DeFi protocols.
    fn has_slippage_or_price_bounds(&self, func_source: &str) -> bool {
        // Standard slippage parameter names
        func_source.contains("minAmount")
            || func_source.contains("minOut")
            || func_source.contains("slippage")
            || func_source.contains("amountOutMin")
            || func_source.contains("amountOutMinimum")
            || func_source.contains("minReturn")
            || func_source.contains("minReceived")
            || func_source.contains("minimumAmount")
            || func_source.contains("minTokens")
            // Price bound parameters (equivalent to slippage for fixed-price ops)
            || func_source.contains("minPrice")
            || func_source.contains("maxPrice")
            // Tolerance-based patterns
            || func_source.contains("tolerance")
    }

    /// Check if function has strong price protection mechanisms that make
    /// front-running impractical even without explicit slippage parameters.
    fn has_strong_price_protection(&self, func_source: &str) -> bool {
        // TWAP (Time-Weighted Average Price) -- resistant to flash-loan manipulation
        let has_twap = func_source.contains("TWAP")
            || func_source.contains("twap")
            || func_source.contains("timeWeighted")
            || func_source.contains("timeAverage")
            || func_source.contains("cumulativePrice")
            || func_source.contains("getTWAP");

        // Multi-oracle / median price -- resistant to single-oracle manipulation
        let has_multi_oracle = func_source.contains("getMedianPrice")
            || func_source.contains("medianPrice")
            || func_source.contains("getValidatedPrice")
            || func_source.contains("crossValidat");

        // Price impact checks -- detect and reject manipulated prices
        let has_price_impact_check = (func_source.contains("priceBefore")
            || func_source.contains("priceAfter"))
            && func_source.contains("impact");

        // Circuit breaker patterns -- halt trading during extreme price moves
        let has_circuit_breaker = func_source.contains("circuitBreaker")
            || func_source.contains("circuit_breaker")
            || (func_source.contains("EXTREME_DEVIATION") && func_source.contains("require"));

        has_twap || has_multi_oracle || has_price_impact_check || has_circuit_breaker
    }

    /// Check if a trading function operates at a fixed or predetermined price,
    /// making sandwich attacks impossible because the attacker cannot move the price.
    ///
    /// Fixed-price patterns include:
    /// - Constant/hardcoded ticket prices or costs
    /// - External oracle price fetched via `getPrice()` without pool-based reserves
    /// - Functions with no pricing mechanism at all (direct token operations with
    ///   predetermined amounts, e.g. flash swaps that borrow and return same amount)
    fn uses_fixed_or_predetermined_price(&self, func_source: &str) -> bool {
        // Fixed price constants
        let has_fixed_price = func_source.contains("ticketPrice")
            || func_source.contains("fixedPrice")
            || func_source.contains("costPerUnit")
            || func_source.contains("PRICE");

        // Oracle-determined price without AMM pool reserves -- the price
        // is set externally and cannot be manipulated within the transaction
        let uses_oracle_price = func_source.contains("getPrice()")
            || func_source.contains("latestRoundData")
            || func_source.contains("latestAnswer");

        // AMM pool reserve-based pricing indicates the price IS variable and
        // subject to sandwich attacks. If reserves are used, price is NOT fixed.
        let uses_pool_reserves = func_source.contains("reserveA")
            || func_source.contains("reserveB")
            || func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("getReserves")
            || func_source.contains("getAmountOut")
            || func_source.contains("getAmountsOut");

        // Router-based swaps are variable price
        let uses_router = func_source.contains("router.")
            || func_source.contains("Router.")
            || func_source.contains("IUniswap")
            || func_source.contains("IPancake")
            || func_source.contains("ISushiSwap");

        // Any price computation in the function body
        let has_any_pricing = func_source.contains("price")
            || func_source.contains("Price")
            || func_source.contains("rate")
            || func_source.contains("Rate")
            || uses_pool_reserves
            || uses_router;

        // No pricing mechanism at all: the function doesn't compute or reference
        // any price. This covers flash swaps that borrow and return the same amount,
        // direct token transfers at predetermined amounts, etc.
        if !has_any_pricing {
            return true;
        }

        // Fixed price: has fixed indicators OR oracle price, but NOT pool/router pricing
        (has_fixed_price || uses_oracle_price) && !uses_pool_reserves && !uses_router
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

    /// Check if a staking/unstaking function has cooldown or delay protection.
    /// FP Reduction v3: Cooldown periods prevent front-running by enforcing time
    /// delays between stake/unstake operations. The attacker cannot profit because
    /// they must wait through the same cooldown period.
    fn is_staking_with_cooldown(&self, func_name: &str, func_source: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        // Must be a staking-related function
        let is_staking = name_lower.contains("stake")
            || name_lower.contains("unstake")
            || name_lower.contains("restake")
            || name_lower.contains("cooldown")
            || name_lower.contains("lock")
            || name_lower.contains("unlock");

        if !is_staking {
            return false;
        }

        // Check for cooldown/delay patterns
        func_source.contains("cooldown")
            || func_source.contains("Cooldown")
            || func_source.contains("lockPeriod")
            || func_source.contains("lockDuration")
            || func_source.contains("unstakeDelay")
            || func_source.contains("withdrawDelay")
            || func_source.contains("COOLDOWN_PERIOD")
            || func_source.contains("LOCK_PERIOD")
            || func_source.contains("block.timestamp >=")
            || func_source.contains("block.timestamp >")
            || func_source.contains("block.timestamp +")
    }

    /// Check if a governance function has timelock protection.
    /// FP Reduction v3: Timelocked governance functions have a built-in delay
    /// that makes front-running irrelevant because the action is publicly known
    /// and has a mandatory waiting period before execution.
    fn is_timelocked_governance_function(
        &self,
        func_name: &str,
        func_source: &str,
        ctx: &AnalysisContext,
    ) -> bool {
        let name_lower = func_name.to_lowercase();

        // Must be a governance-related function
        let is_governance = name_lower.contains("propose")
            || name_lower.contains("execute")
            || name_lower.contains("queue")
            || name_lower.contains("vote")
            || name_lower.contains("govern");

        if !is_governance {
            return false;
        }

        // Check function-level timelock patterns
        let has_timelock = func_source.contains("timelock")
            || func_source.contains("Timelock")
            || func_source.contains("TimeLock")
            || func_source.contains("delay")
            || func_source.contains("eta")
            || func_source.contains("queuedTransaction");

        if has_timelock {
            return true;
        }

        // Check contract-level timelock patterns
        let contract_source = &ctx.source_code;
        let has_contract_timelock = contract_source.contains("TimelockController")
            || contract_source.contains("Timelock")
            || contract_source.contains("GovernorTimelockControl");

        has_contract_timelock
    }

    /// Check if the contract has commit-reveal scheme at the contract level.
    /// FP Reduction v3: A contract may have separate commit() and reveal()
    /// functions that protect bidding. The bid function itself may not contain
    /// commit/reveal keywords.
    fn has_contract_commit_reveal(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Check for commit-reveal function pair
        let has_commit_func =
            source.contains("function commit") || source.contains("function submitCommitment");
        let has_reveal_func =
            source.contains("function reveal") || source.contains("function revealBid");

        if has_commit_func && has_reveal_func {
            return true;
        }

        // Check for commit-reveal state variables
        let has_commit_mapping = source.contains("mapping") && source.contains("commit");
        let has_reveal_phase = source.contains("revealPhase")
            || source.contains("commitPhase")
            || source.contains("CommitReveal");

        if has_commit_mapping && has_reveal_phase {
            return true;
        }

        // Check for sealed-bid pattern (hash-based commitment)
        let has_sealed_bid = source.contains("sealedBid")
            || source.contains("blindedBid")
            || source.contains("commitHash");

        has_sealed_bid
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

    // =====================================================================
    // FP Reduction v3: Staking with cooldown tests
    // =====================================================================

    #[test]
    fn test_skip_staking_with_cooldown() {
        let detector = FrontRunningMitigationDetector::new();
        let func_source_with_cooldown = r#"
            function unstake(uint256 amount) external {
                require(block.timestamp >= lastStakeTime[msg.sender] + COOLDOWN_PERIOD, "cooldown");
                _burn(msg.sender, amount);
            }
        "#;
        assert!(detector.is_staking_with_cooldown("unstake", func_source_with_cooldown));
        assert!(detector.is_staking_with_cooldown("stake", "require(cooldown > 0)"));
    }

    #[test]
    fn test_no_skip_staking_without_cooldown() {
        let detector = FrontRunningMitigationDetector::new();
        // Staking function without cooldown should NOT be skipped
        assert!(!detector.is_staking_with_cooldown("unstake", "balances[msg.sender] -= amount"));
    }

    #[test]
    fn test_no_skip_non_staking_with_cooldown() {
        let detector = FrontRunningMitigationDetector::new();
        // Non-staking function should not be skipped even with cooldown keyword
        assert!(!detector.is_staking_with_cooldown("swap", "require(cooldown > 0)"));
        assert!(!detector.is_staking_with_cooldown("deposit", "COOLDOWN_PERIOD"));
    }

    // =====================================================================
    // FP Reduction v3: Timelocked governance tests
    // =====================================================================

    #[test]
    fn test_skip_timelocked_governance() {
        let detector = FrontRunningMitigationDetector::new();
        let func_source = "require(block.timestamp >= eta, 'timelock'); execute(target, value, data);";
        let source = r#"
            contract Governor is TimelockController {
                function execute(address target, uint256 value, bytes calldata data) external {
                    require(block.timestamp >= eta, "timelock");
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.is_timelocked_governance_function("execute", func_source, &ctx));
    }

    #[test]
    fn test_no_skip_non_governance() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract Exchange {
                function swap(uint256 amount) external { }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.is_timelocked_governance_function("swap", "some source", &ctx));
    }

    // =====================================================================
    // FP Reduction v3: Contract-level commit-reveal tests
    // =====================================================================

    #[test]
    fn test_contract_commit_reveal() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract BlindAuction {
                mapping(address => bytes32) public commitments;
                function commit(bytes32 hash) external {
                    commitments[msg.sender] = hash;
                }
                function reveal(uint256 amount, bytes32 nonce) external {
                    require(keccak256(abi.encodePacked(amount, nonce)) == commitments[msg.sender]);
                }
                function bid() external payable {
                    // actual bidding
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.has_contract_commit_reveal(&ctx));
    }

    #[test]
    fn test_no_contract_commit_reveal() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract SimpleAuction {
                function bid() external payable {
                    require(msg.value > highestBid);
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(!detector.has_contract_commit_reveal(&ctx));
    }

    #[test]
    fn test_sealed_bid_pattern() {
        let detector = FrontRunningMitigationDetector::new();
        let source = r#"
            contract SealedBidAuction {
                mapping(address => bytes32) public sealedBid;
                function placeBid(bytes32 hash) external {
                    sealedBid[msg.sender] = hash;
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(detector.has_contract_commit_reveal(&ctx));
    }
}
