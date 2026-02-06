use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::mev_protection_patterns;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for generalized MEV extraction vulnerabilities
pub struct MevExtractableValueDetector {
    base: BaseDetector,
}

impl Default for MevExtractableValueDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MevExtractableValueDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-extractable-value".to_string()),
                "MEV Extractable Value".to_string(),
                "Detects contracts with extractable MEV through front-running, back-running, or transaction ordering manipulation".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for MevExtractableValueDetector {
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

        // Phase 9 FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Skip if this is an AMM pool - AMM pools INTENTIONALLY expose MEV
        // MEV extraction (arbitrage, liquidations) is how AMM pools maintain efficient pricing.
        // This detector should focus on contracts that CONSUME AMM data unsafely.
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip standard token contracts
        // ERC20/ERC721 tokens themselves are not MEV targets
        if utils::is_standard_token(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(mev_issue) = self.check_mev_extractable(function, ctx) {
                let func_source = self.get_function_source(function, ctx);

                // NEW: Calculate confidence based on protections
                let confidence = self.calculate_confidence(function, &func_source);

                let message = format!(
                    "Function '{}' has extractable MEV. {} \
                    Searchers can extract value through transaction ordering, front-running, or back-running.",
                    function.name.name, mev_issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_confidence(confidence) // NEW: Set confidence
                    .with_fix_suggestion(format!(
                        "Reduce MEV extractability in '{}'. \
                    Implement: (1) Commit-reveal schemes, (2) Batch processing/auctions, \
                    (3) Private transaction pools (Flashbots), (4) Time-weighted mechanisms, \
                    (5) MEV-resistant AMM curves, (6) Encrypted mempools.",
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

impl MevExtractableValueDetector {
    /// Check for MEV extraction opportunities
    fn check_mev_extractable(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // Phase 52 FP Reduction: Skip internal/private functions
        // Internal/private functions cannot be called directly, so they're not MEV entry points
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Phase 52 FP Reduction: Skip view/pure functions
        // View/pure functions cannot modify state, so they're not MEV-exploitable
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Skip if this is an ERC-4337 paymaster/account abstraction contract
        // Paymaster functions (recovery, session keys, nonce management) are not MEV-vulnerable
        // They're administrative operations that don't involve extractable value
        let is_paymaster = utils::is_erc4337_paymaster(ctx);
        if is_paymaster {
            return None; // Paymaster operations are not MEV targets
        }

        // FP Reduction: Skip ALL functions with access control modifiers (not just admin)
        // Functions restricted by onlyOwner, onlyAdmin, onlyRole, etc. cannot be called by
        // arbitrary MEV bots, so they are not MEV extraction targets.
        let has_access_control_modifier = function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("only")
                || name_lower.contains("admin")
                || name_lower.contains("owner")
                || name_lower.contains("role")
                || name_lower.contains("auth")
                || name_lower.contains("guardian")
                || name_lower.contains("governance")
                || name_lower.contains("restricted")
                || name_lower.contains("authorized")
                || name_lower.contains("keeper")
                || name_lower.contains("operator")
                || name_lower.contains("whitelisted")
                || name_lower.contains("whennotpaused")
        });

        // Any function with access control modifiers is not an MEV target.
        // MEV requires permissionless access -- if only trusted parties can call it,
        // there is no MEV extraction vector for third-party searchers.
        if has_access_control_modifier {
            return None;
        }

        // FP Reduction: Skip functions that check msg.sender against a trusted role
        // Functions with inline access control (require(msg.sender == owner)) are also
        // not exploitable by arbitrary MEV bots.
        if self.has_inline_access_control(&func_source) {
            return None;
        }

        // FP Reduction: Skip functions that have slippage protection parameters
        // Functions with minAmountOut, deadline, etc. already have MEV protection built in.
        if self.has_slippage_parameters(function) {
            return None;
        }

        // Skip standard ERC20/ERC721/ERC1155 token functions EARLY - these are NOT MEV targets
        // MEV occurs when these are USED in price-sensitive contexts, not in the token itself.
        // Check this before trading-name detection to avoid false matches on "transferFrom" etc.
        if self.is_standard_token_function(&func_name_lower) {
            return None;
        }

        // Phase 16 Recall Recovery: Check trading functions first for better recall
        // Trading functions by name require slippage protection regardless of other protections
        let is_trading_by_name = func_name_lower.contains("swap")
            || func_name_lower.contains("trade")
            || func_name_lower.contains("exchange")
            || func_name_lower.contains("arbitrage")
            || func_name_lower.contains("liquidat")
            || func_name_lower.contains("flashloan")
            || func_name_lower.contains("flash");

        // For trading functions, ALWAYS require slippage protection
        // Access control alone doesn't protect against sandwich attacks
        if is_trading_by_name && !mev_protection_patterns::has_slippage_protection(&func_source) {
            return Some(format!(
                "Trading/arbitrage function '{}' lacks slippage protection. \
                Access control modifiers don't protect against MEV - without minAmountOut \
                or similar protection, trades are vulnerable to sandwich attacks.",
                function.name.name
            ));
        }

        // For non-trading functions, use standard protection check
        if !is_trading_by_name {
            if mev_protection_patterns::has_sufficient_mev_protection(function, &func_source, ctx) {
                return None; // Protected - no MEV risk
            }
        }

        // Skip simple deposit/withdraw functions that don't involve price calculations
        // These are user operations that don't expose extractable MEV
        let is_simple_deposit_withdraw = (func_name_lower == "deposit"
            || func_name_lower == "withdraw")
            && !self.is_price_sensitive(&func_source);

        if is_simple_deposit_withdraw {
            return None; // Simple deposits/withdrawals without price exposure
        }

        // Phase 5 FP Reduction: Skip user-specific claim operations
        // Operations on msg.sender's own balance are not MEV targets
        let is_user_specific_operation = func_name_lower == "claim"
            || func_name_lower == "claimrewards"
            || func_name_lower == "harvest"
            || func_name_lower == "stake"
            || func_name_lower == "unstake"
            || func_name_lower == "redeem";

        let operates_on_user_balance = func_source.contains("[msg.sender]")
            && (func_source.contains("balance")
                || func_source.contains("reward")
                || func_source.contains("earned")
                || func_source.contains("stake")
                || func_source.contains("share"));

        if is_user_specific_operation && operates_on_user_balance {
            return None; // User claiming their own rewards is not MEV-vulnerable
        }

        // Pattern 1: Public DEX/trading function with value transfer without protection (TIGHTENED)
        // Only flag if it looks like a DEX/trading operation with actual trading-context indicators
        let is_public = function.visibility == ast::Visibility::Public
            || function.visibility == ast::Visibility::External;

        let is_trading_context = self.is_trading_context(&func_source, &func_name_lower);

        // Only flag if there is BOTH a trading context AND a value transfer
        // The trading context check ensures we only flag actual DEX/swap operations,
        // not standard token transfers or approvals
        if is_public && is_trading_context {
            let has_value_transfer = func_source.contains(".transfer(")
                || func_source.contains(".send(")
                || func_source.contains("call{value:");

            let lacks_mev_protection = has_value_transfer
                && !mev_protection_patterns::has_slippage_protection(&func_source)
                && !mev_protection_patterns::has_deadline_protection(&func_source)
                && !mev_protection_patterns::is_user_operation(&func_source, function.name.name);

            if lacks_mev_protection {
                return Some("DEX/trading function with value transfer lacks MEV protection (no slippage/deadline checks), \
                    enabling front-running and back-running attacks".to_string());
            }
        }

        // Pattern 2: Profitable liquidation without auction mechanism
        let is_liquidation = func_source.contains("liquidat")
            || function.name.name.to_lowercase().contains("liquidat");

        let has_profit = func_source.contains("bonus")
            || func_source.contains("reward")
            || func_source.contains("incentive");

        let no_auction = is_liquidation
            && has_profit
            && !func_source.contains("auction")
            && !func_source.contains("bid")
            && !func_source.contains("dutch");

        if no_auction {
            return Some(
                "Profitable liquidation without auction mechanism, \
                enabling MEV extraction through priority gas auctions (PGA)"
                    .to_string(),
            );
        }

        // Pattern 3: Arbitrage-able price differences
        let has_pricing = func_source.contains("price") || func_source.contains("getAmount");

        let has_swap = func_source.contains("swap") || func_source.contains("exchange");

        let arbitrage_opportunity = has_pricing
            && has_swap
            && !func_source.contains("TWAP")
            && !func_source.contains("oracle")
            && !func_source.contains("batch");

        if arbitrage_opportunity {
            return Some(
                "Swap function with spot pricing creates arbitrage opportunities, \
                MEV bots can profit from price differences"
                    .to_string(),
            );
        }

        // Pattern 4: State changes visible in mempool before execution (TIGHTENED)
        // Only flag if it modifies reserve/price state in a price-sensitive context.
        // Standard token supply changes (totalSupply via mint/burn) are NOT MEV targets.
        let changes_global_pricing_state = (func_source.contains("reserve0")
            || func_source.contains("reserve1")
            || func_source.contains("globalPrice"))
            && !func_source.contains("[msg.sender]");

        // Only flag global pricing state changes, not totalSupply changes.
        // totalSupply changes happen in normal mint/burn operations and are not
        // inherently MEV-exploitable without a pricing mechanism.
        let is_mev_vulnerable_state_change = is_public
            && changes_global_pricing_state
            && !mev_protection_patterns::is_user_operation(&func_source, function.name.name)
            && !func_source.contains("private")
            && !func_source.contains("encrypted");

        if is_mev_vulnerable_state_change {
            return Some("State changes to global pricing state (reserves/price) visible in public mempool, \
                allowing MEV bots to react and extract value".to_string());
        }

        // Pattern 5: Reward distribution without commit-reveal
        // Phase 5 FP Reduction: Exempt user-specific claims (balances[msg.sender])
        // These are user-specific operations that don't expose third-party MEV
        let distributes_rewards = func_source.contains("reward")
            || func_source.contains("distribute")
            || func_source.contains("claim");

        let is_user_specific_claim = func_source.contains("[msg.sender]")
            || func_source.contains("balanceOf[msg.sender]")
            || func_source.contains("rewards[msg.sender]")
            || func_source.contains("claimable[msg.sender]")
            || func_source.contains("earned[msg.sender]");

        let no_commit_reveal = distributes_rewards
            && !func_source.contains("commit")
            && !func_source.contains("reveal")
            && !func_source.contains("hash")
            && !is_user_specific_claim; // Phase 5: Exempt user-specific claims

        if no_commit_reveal {
            // Phase 5 FP Reduction: Require global reward pool (not user-specific)
            let has_global_pool = func_source.contains("totalRewards")
                || func_source.contains("rewardPool")
                || func_source.contains("distributeToAll")
                || (func_source.contains("for") && func_source.contains("reward"));

            if has_global_pool {
                return Some(
                    "Reward distribution from global pool without commit-reveal, \
                    enables front-running of reward claims"
                        .to_string(),
                );
            }
        }

        // Pattern 6: First-come-first-served with high value
        let is_fcfs =
            func_source.contains("first") || function.name.name.to_lowercase().contains("first");

        let high_value = func_source.contains("mint")
            || func_source.contains("claim")
            || func_source.contains("buy");

        let fcfs_mev = is_fcfs
            && high_value
            && !func_source.contains("queue")
            && !func_source.contains("lottery");

        if fcfs_mev {
            return Some(
                "First-come-first-served mechanism for high-value operations, \
                creates priority gas auction (PGA) MEV"
                    .to_string(),
            );
        }

        // Pattern 7: Oracle update function without access control (TIGHTENED)
        // Only match functions that are actually oracle updaters, not any function
        // whose name contains "update". Require both an oracle-update indicator AND
        // price/rate modification in the source.
        let is_oracle_update_function = func_source.contains("updatePrice")
            || func_source.contains("setPrice")
            || func_source.contains("updateOracle")
            || func_source.contains("submitPrice")
            || (func_name_lower.contains("update")
                && (func_name_lower.contains("price")
                    || func_name_lower.contains("oracle")
                    || func_name_lower.contains("rate")));

        let modifies_pricing_state = is_oracle_update_function
            && (func_source.contains("price") || func_source.contains("rate"));

        if modifies_pricing_state && is_public {
            return Some("Public oracle update function without access control enables MEV through oracle manipulation, \
                can be front-run or back-run for profit".to_string());
        }

        // Pattern 8: Multi-step operation without atomicity
        let has_multiple_calls = func_source.matches(".call(").count() > 1
            || func_source.matches(".transfer(").count() > 1;

        let lacks_atomicity = has_multiple_calls
            && !func_source.contains("require")
            && !func_source.contains("revert");

        if lacks_atomicity {
            return Some(
                "Multi-step operation without atomicity guarantees, \
                enables MEV through transaction insertion between steps"
                    .to_string(),
            );
        }

        // Pattern 9: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("MEV")
                || func_source.contains("front-run")
                || func_source.contains("extractable"))
        {
            return Some("MEV extractable value vulnerability marker detected".to_string());
        }

        None
    }

    /// Calculate confidence based on number of MEV protections
    fn calculate_confidence(&self, function: &ast::Function<'_>, func_source: &str) -> Confidence {
        let protection_count =
            mev_protection_patterns::count_mev_protections(function, func_source);

        match protection_count {
            0 => Confidence::High,   // No protections - high confidence in MEV risk
            1 => Confidence::Medium, // Some protection - medium confidence
            _ => Confidence::Low, // Multiple protections - low confidence (may be false positive)
        }
    }

    /// Check if function has inline access control (msg.sender checks against trusted roles)
    /// Functions that verify msg.sender == owner/admin/etc. are not exploitable by MEV bots
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        // Check for direct msg.sender comparisons against trusted roles
        let has_sender_check = func_source.contains("require(msg.sender ==")
            || func_source.contains("require(msg.sender!=") // inverted check with revert
            || func_source.contains("if (msg.sender !=")
            || func_source.contains("if(msg.sender !=")
            || func_source.contains("msg.sender == owner")
            || func_source.contains("msg.sender == admin")
            || func_source.contains("msg.sender == governance")
            || func_source.contains("msg.sender == controller")
            || func_source.contains("msg.sender == manager")
            || func_source.contains("msg.sender == guardian");

        // Check for hasRole / isAuthorized patterns
        let has_role_check = func_source.contains("hasRole(")
            || func_source.contains("isAuthorized(")
            || func_source.contains("_checkRole(")
            || func_source.contains("_checkOwner(")
            || func_source.contains("isOwner(")
            || func_source.contains("isAdmin(");

        has_sender_check || has_role_check
    }

    /// Check if function parameters include slippage/deadline protection
    /// Functions that accept minAmountOut, deadline, etc. already have MEV protection
    fn has_slippage_parameters(&self, function: &ast::Function<'_>) -> bool {
        let slippage_param_names = [
            "minamountout",
            "amountoutmin",
            "minoutput",
            "minimumamount",
            "minreturn",
            "minreceived",
            "minamountreceived",
            "amountoutminimum",
            "mintokensout",
            "maxamountin",
            "amountinmax",
            "deadline",
            "validuntil",
            "expiry",
            "expirationtime",
            "maxslippage",
            "slippagetolerance",
        ];

        for param in &function.parameters {
            let param_name_lower = param
                .name
                .as_ref()
                .map(|n| n.name.to_lowercase())
                .unwrap_or_default();
            if slippage_param_names
                .iter()
                .any(|&s| param_name_lower.contains(s))
            {
                return true;
            }
        }

        false
    }

    /// Check if function name matches standard ERC20/ERC721/ERC1155 token functions
    /// These are NOT MEV targets by themselves -- MEV only occurs when they are
    /// used in price-sensitive contexts (e.g., within a DEX swap)
    fn is_standard_token_function(&self, func_name_lower: &str) -> bool {
        matches!(
            func_name_lower,
            "transfer"
                | "transferfrom"
                | "approve"
                | "safetransfer"
                | "safetransferfrom"
                | "mint"
                | "burn"
                | "burnfrom"
                | "permit"
                | "allowance"
                | "balanceof"
                | "totalsupply"
                | "decimals"
                | "name"
                | "symbol"
                // ERC721/ERC1155 specific
                | "setapprovalforall"
                | "isapprovedforall"
                | "getapproved"
                | "ownerof"
                | "tokenuri"
                | "safebatchtransferfrom"
                | "batchtransfer"
                | "supportsinterface"
                // ERC721 enumerable
                | "tokenbyindex"
                | "tokenofownerbyindex"
                // Common internal-like public helpers
                | "increaseallowance"
                | "decreaseallowance"
        )
    }

    /// Get function source code (cleaned to avoid FPs from comments/strings)
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            // Clean source to avoid FPs from comments/strings
            utils::clean_source_for_search(&raw_source)
        } else {
            String::new()
        }
    }

    /// Check if function is in a DEX/trading context (where MEV is a real concern)
    fn is_trading_context(&self, func_source: &str, func_name: &str) -> bool {
        // Function name indicates trading operation
        let name_indicates_trading = func_name.contains("swap")
            || func_name.contains("trade")
            || func_name.contains("exchange")
            || func_name.contains("buy")
            || func_name.contains("sell")
            || func_name.contains("addliquidity")
            || func_name.contains("removeliquidity");

        // Source code indicates trading context -- require specific DEX/AMM indicators,
        // not just generic terms like "reserves" that could appear in non-trading contexts
        let source_indicates_trading = func_source.contains("getAmountOut")
            || func_source.contains("getAmountsOut")
            || func_source.contains("getAmountIn")
            || func_source.contains("swapExact")
            || func_source.contains("IUniswap")
            || func_source.contains("IPancake")
            || func_source.contains("ISushiSwap")
            || func_source.contains("ICurve")
            || func_source.contains("IBalancer")
            || func_source.contains(".swap(")
            || func_source.contains("amountOutMin")
            || func_source.contains("amountInMax")
            || func_source.contains("sqrtPrice")
            || func_source.contains("tickSpacing");

        name_indicates_trading || source_indicates_trading
    }

    /// Check if function involves price-sensitive operations
    fn is_price_sensitive(&self, func_source: &str) -> bool {
        func_source.contains("price")
            || func_source.contains("rate")
            || func_source.contains("getAmount")
            || func_source.contains("calculateAmount")
            || func_source.contains("exchange")
            || func_source.contains("swap")
            || func_source.contains("oracle")
            || func_source.contains("quoter")
            || func_source.contains("slippage")
            || func_source.contains("minAmount")
            || func_source.contains("maxAmount")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = MevExtractableValueDetector::new();
        assert_eq!(detector.name(), "MEV Extractable Value");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
