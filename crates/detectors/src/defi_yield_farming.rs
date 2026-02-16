//! DeFi Yield Farming Exploits Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct YieldFarmingDetector {
    base: BaseDetector,
}

impl YieldFarmingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("defi-yield-farming-exploits".to_string()),
                "Yield Farming Exploits".to_string(),
                "Detects missing deposit/withdrawal fee validation, reward calculation errors, and share price manipulation".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if the contract is an ERC-4626 vault contract.
    /// ERC-4626 vaults have their own dedicated detectors (vault-share-inflation,
    /// vault-donation-attack, etc.) and should NOT be analyzed by the yield farming
    /// detector. This prevents false positives on vault contracts that share keywords
    /// like "deposit", "shares", "totalAssets" with yield farming patterns.
    ///
    /// Exception: If the contract also has yield farming infrastructure (Masterchef-style
    /// patterns like accRewardPerShare, rewardDebt, allocPoint, PoolInfo), it IS a yield
    /// farming contract that happens to use ERC-4626, so we should NOT exclude it.
    fn is_erc4626_vault_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Check for explicit ERC-4626 markers
        let has_erc4626_explicit = source.contains("ERC4626")
            || source.contains("IERC4626")
            || source.contains("ERC-4626");

        // Check for ERC-4626 standard function signatures
        let has_deposit = source.contains("function deposit(");
        let has_redeem = source.contains("function redeem(");
        let has_total_assets = source.contains("function totalAssets(");
        let has_shares = lower.contains("shares");
        let has_convert = lower.contains("converttoshares") || lower.contains("converttoassets");
        let has_preview = lower.contains("previewdeposit") || lower.contains("previewredeem");

        // Check for yield farming infrastructure (Masterchef-style patterns).
        // If the contract has these, it is a yield farming contract that may also
        // implement ERC-4626, so we should NOT exclude it from this detector.
        let has_reward_per_share =
            lower.contains("accrewardpershare") || lower.contains("rewardpershare");
        let has_alloc_point = lower.contains("allocpoint");
        let has_reward_per_block = lower.contains("rewardperblock") || lower.contains("rewardrate");
        let has_pool_info = lower.contains("poolinfo");
        let has_user_reward_debt = lower.contains("rewarddebt") && lower.contains("userinfo");

        let yield_farming_signals = [
            has_reward_per_share,
            has_alloc_point,
            has_reward_per_block,
            has_pool_info,
            has_user_reward_debt,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        // If contract has yield farming infrastructure, it is NOT a pure ERC-4626 vault
        if yield_farming_signals >= 2 {
            return false;
        }

        // Path 1: Explicit ERC-4626 inheritance/interface
        if has_erc4626_explicit {
            return true;
        }

        // Path 2: ERC-4626 standard function signature pattern
        // Need at least 2 of deposit/redeem/totalAssets + shares + conversion or preview
        let vault_function_count = [has_deposit, has_redeem, has_total_assets]
            .iter()
            .filter(|&&x| x)
            .count();

        if vault_function_count >= 2 && has_shares && (has_convert || has_preview) {
            return true;
        }

        // Path 3: Vault-like with deposit(uint256, address receiver) + redeem(uint256, address receiver) + totalAssets + shares
        let has_vault_deposit_sig = source.contains("deposit(uint256")
            && (source.contains("address receiver") || source.contains("address _receiver"));
        let has_vault_redeem_sig =
            source.contains("redeem(uint256") && source.contains("address receiver");

        if has_vault_deposit_sig && has_vault_redeem_sig && has_total_assets && has_shares {
            return true;
        }

        false
    }

    /// Check if the contract is primarily a non-yield-farming contract type.
    /// These contracts may incidentally contain words like "deposit" or "shares"
    /// but are not yield farming vaults and should not be analyzed by this detector.
    fn is_non_yield_farming_contract(&self, ctx: &AnalysisContext) -> bool {
        // ERC-4626 vaults have their own dedicated detectors
        if self.is_erc4626_vault_contract(ctx) {
            return true;
        }

        let source = &ctx.source_code.to_lowercase();
        let contract_source = &crate::utils::get_contract_source(ctx).to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Delegation/operator management contracts (e.g. EigenLayer DelegationManager)
        if source.contains("delegationmanager") || source.contains("delegationdirectory") {
            return true;
        }

        // Strategy management contracts that manage strategy whitelists, not vaults
        if source.contains("strategymanager") && source.contains("whitelisted") {
            return true;
        }

        // Restaking contracts have dedicated detectors (restaking-withdrawal-delays,
        // lrt-share-inflation). "restaking" contains "staking" as a substring,
        // causing false matches on the staking+reward strong signal path.
        if contract_name.contains("restake")
            || contract_name.contains("restaking")
            || contract_source.contains("restake")
            || contract_source.contains("restaking")
        {
            return true;
        }

        // Liquid staking token contracts (e.g., ezETH, stETH) have deposit/withdraw/shares
        // but are token contracts, not yield farming vaults. They have their own detectors.
        if (contract_name.contains("token") || contract_name.ends_with("eth"))
            && contract_source.contains("totalsupply")
            && contract_source.contains("balanceof")
            && contract_source.contains("transfer")
            && !contract_source.contains("rewardpertoken")
            && !contract_source.contains("accrewardpershare")
        {
            return true;
        }

        // Reentrancy demonstration contracts
        if contract_name.contains("reentrancy") {
            return true;
        }

        // Delegation-focused contracts (EIP-7702, etc.)
        if contract_name.contains("delegation") {
            return true;
        }

        // Bridge contracts
        if source.contains("bridge") && source.contains("relay") {
            return true;
        }

        // Pure governance contracts
        if source.contains("governor") && source.contains("proposal") && !source.contains("vault") {
            return true;
        }

        false
    }

    fn is_yield_vault(&self, ctx: &AnalysisContext) -> bool {
        // First, exclude contracts that are clearly not yield farming
        if self.is_non_yield_farming_contract(ctx) {
            return false;
        }

        // FP Reduction: Require the contract to have yield-relevant functions.
        // This prevents cross-contract FPs in multi-contract files.
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let has_yield_fn = if contract_func_names.is_empty() {
            // Fallback to source-based detection when no parsed functions
            // (e.g., unit test contexts where the parser is not invoked)
            let src = ctx.source_code.to_lowercase();
            src.contains("function deposit")
                || src.contains("function withdraw")
                || src.contains("function stake")
                || src.contains("function unstake")
                || src.contains("function redeem")
                || src.contains("function harvest")
                || src.contains("function claim")
                || src.contains("function compound")
                || src.contains("function reward")
        } else {
            contract_func_names.iter().any(|n| {
                n.contains("deposit")
                    || n.contains("withdraw")
                    || n.contains("stake")
                    || n.contains("unstake")
                    || n.contains("redeem")
                    || n.contains("harvest")
                    || n.contains("claim")
                    || n.contains("compound")
                    || n.contains("reward")
            })
        };
        if !has_yield_fn {
            return false;
        }

        // FP Reduction: Use contract source instead of file source to prevent
        // cross-contract FPs in multi-contract files where sibling contracts
        // have "vault"/"shares"/"deposit" keywords.
        // Fall back to full source when contract source extraction returns very little
        // (e.g., test contexts where AST location spans a single line).
        let contract_source = crate::utils::get_contract_source(ctx).to_lowercase();
        let source_owned = if contract_source.len() < 20 {
            ctx.source_code.to_lowercase()
        } else {
            contract_source
        };
        let source = &source_owned;

        // Strong signals - any of these is definitive
        // Fix: parenthesize the OR properly so "vault && shares" is grouped
        if source.contains("erc4626") || (source.contains("vault") && source.contains("shares")) {
            return true;
        }

        // Staking + reward is a strong signal, but only if the contract actually
        // has deposit/stake functions (not just a reward claim contract).
        // Exclude "restaking"/"unstaking" substrings to avoid cross-domain FPs.
        let has_standalone_staking = {
            let cleaned = source.replace("restaking", "").replace("unstaking", "");
            cleaned.contains("staking")
        };
        let has_standalone_stake_fn = {
            let cleaned = source.replace("unstake(", "");
            cleaned.contains("stake(")
        };
        if has_standalone_staking
            && source.contains("reward")
            && (source.contains("deposit") || has_standalone_stake_fn)
        {
            return true;
        }

        // Count medium-strength indicators -- require stronger evidence
        let mut indicator_count = 0;

        // Deposit + shares is a signal for vault-like contracts
        if source.contains("deposit") && source.contains("shares") {
            indicator_count += 1;
        }

        // Withdraw + shares is a signal for vault-like contracts
        if source.contains("withdraw") && source.contains("shares") {
            indicator_count += 1;
        }

        if source.contains("totalassets") {
            indicator_count += 1;
        }

        if source.contains("rewardpertoken") || source.contains("rewardrate") {
            indicator_count += 1;
        }

        // Require actual "stake(" that isn't just "unstake("
        let has_stake_fn = {
            let cleaned = source.replace("unstake(", "");
            cleaned.contains("stake(")
        };
        if has_stake_fn && source.contains("unstake") {
            indicator_count += 1;
        }

        // Require 2+ medium-strength indicators
        indicator_count >= 2
    }

    /// Check if a function name indicates an admin/governance function
    /// that should not be analyzed for yield farming vulnerabilities.
    fn is_admin_function(&self, func_name: &str) -> bool {
        let name = func_name.to_lowercase();

        // Whitelist/config management
        if name.starts_with("set") || name.starts_with("add") || name.starts_with("remove") {
            // These are admin functions unless they are core vault operations
            // like "addLiquidity" or "removeLiquidity"
            if name.contains("liquidity") {
                return false;
            }
            return true;
        }

        // Pause/unpause
        if name == "pause" || name == "unpause" {
            return true;
        }

        // Ownership transfer
        if name.contains("transferownership") || name.contains("renounceownership") {
            return true;
        }

        // Initialize/upgrade
        if name == "initialize" || name == "reinitialize" || name.contains("upgrade") {
            return true;
        }

        false
    }

    /// Check if a function delegates to a parent implementation via super.
    /// When this happens, the parent (e.g. OpenZeppelin ERC4626) handles
    /// share/asset calculations, so we should skip redundant checks.
    fn delegates_to_super(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();
        lower.contains("super.deposit(")
            || lower.contains("super.withdraw(")
            || lower.contains("super.redeem(")
            || lower.contains("super.mint(")
    }

    /// Check if the function is a queuing/batching mechanism rather than
    /// a direct share-to-asset redemption.
    fn is_queue_or_batch_function(&self, func_name: &str) -> bool {
        let name = func_name.to_lowercase();
        name.contains("queue")
            || name.contains("request")
            || name.contains("process")
            || name.contains("complete")
            || name.contains("batch")
    }

    /// Check if a reward/claim function is a simple claim-from-mapping pattern
    /// that does not perform reward calculations (just reads and transfers).
    fn is_simple_reward_claim(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Simple pattern: reads from mapping, zeroes it, transfers
        // e.g. uint256 amount = rewards[msg.sender]; rewards[msg.sender] = 0; token.transfer(...)
        let has_mapping_read = lower.contains("rewards[") || lower.contains("lockedrewards[");
        let has_zeroing = lower.contains("] = 0");
        let has_transfer = lower.contains("transfer(") || lower.contains("transferfrom(");

        // If it reads from a mapping, zeros it, and transfers, it's a simple claim
        if has_mapping_read && has_zeroing && has_transfer {
            return true;
        }

        // If the function is very short (few lines) and just does mapping read + transfer
        let line_count = lower.lines().count();
        if line_count <= 10 && has_mapping_read && has_transfer {
            return true;
        }

        false
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

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        skip_inflation_checks: bool,
        has_contract_min_deposit: bool,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();

        // Get function body specifically, not entire source code
        let func_source = self.get_function_source(function, ctx);
        let source_lower = func_source.to_lowercase();

        // Also get contract-level source for things like state variable checks
        let contract_source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // Skip if function delegates to super (parent handles share math)
        let uses_super = self.delegates_to_super(&func_source);

        // Check deposit functions
        // Use exact name matching: the function name should BE a deposit-like
        // function, not merely contain "deposit" as a substring in a longer name
        if self.is_deposit_function(&name) {
            // Skip inflation-related checks if contract has protection patterns
            if !skip_inflation_checks && !uses_super {
                // Check for share inflation attack protection (check function body)
                let has_min_deposit = has_contract_min_deposit
                    || source_lower.contains("minimum")
                    || source_lower.contains("min_deposit")
                    || (source_lower.contains("require") && source_lower.contains("amount >"))
                    || source_lower.contains("amount >= min");

                if !has_min_deposit {
                    issues.push((
                        "No minimum deposit (share inflation attack risk)".to_string(),
                        Severity::Critical,
                        "Add minimum: require(amount >= MIN_DEPOSIT, \"Amount too small\"); // e.g., MIN_DEPOSIT = 1e6".to_string()
                    ));
                }

                // Check for first depositor protection (in function body)
                let has_first_deposit_lock = source_lower.contains("totalsupply == 0")
                    || source_lower.contains("totalsupply() == 0")
                    || source_lower.contains("initialdeposit")
                    || contract_source_lower.contains("_initialdeposit"); // contract-level check

                if !has_first_deposit_lock && source_lower.contains("shares") {
                    issues.push((
                        "No first depositor protection (inflation attack on vault initialization)".to_string(),
                        Severity::Critical,
                        "Lock initial shares: if (totalSupply() == 0) { _mint(address(0), INITIAL_SHARES); }".to_string()
                    ));
                }
            }

            // Skip share calculation checks if delegating to super
            if !uses_super {
                // Check for share calculation (in function body)
                let has_share_calc = source_lower.contains("totalsupply")
                    && (source_lower.contains("totalassets") || source_lower.contains("balance"));

                // Only flag if function explicitly deals with shares
                if source_lower.contains("shares =") && !has_share_calc {
                    issues.push((
                        "Share calculation doesn't use totalSupply and totalAssets".to_string(),
                        Severity::High,
                        "Calculate shares: shares = (amount * totalSupply()) / totalAssets();"
                            .to_string(),
                    ));
                }

                // Check for rounding errors (only if shares are calculated in this function)
                if source_lower.contains("shares =") {
                    let has_rounding_check = source_lower.contains("shares > 0")
                        || source_lower.contains("require(shares");

                    if !has_rounding_check {
                        issues.push((
                            "No zero-share validation (rounding error exploitation)".to_string(),
                            Severity::High,
                            "Validate shares: require(shares > 0, \"Shares must be non-zero\");"
                                .to_string(),
                        ));
                    }
                }
            }

            // Check for fee-on-transfer token support (only for functions using transferFrom)
            // Skip if delegating to super (parent handles token transfer)
            if !uses_super && source_lower.contains("transferfrom") {
                let has_actual_amount = source_lower.contains("balancebefore")
                    || source_lower.contains("balanceafter")
                    || source_lower.contains("balance -");

                if !has_actual_amount {
                    issues.push((
                        "Doesn't handle fee-on-transfer tokens (accounting mismatch)".to_string(),
                        Severity::Medium,
                        "Handle fees: uint256 balanceBefore = token.balanceOf(address(this)); token.transferFrom(msg.sender, address(this), amount); uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;".to_string()
                    ));
                }
            }
        }

        // Check withdraw functions
        // Use exact name matching for withdrawal functions
        if self.is_withdraw_function(&name) {
            // Skip queue/batch mechanisms -- these are not direct redemptions
            if !self.is_queue_or_batch_function(&name) && !uses_super {
                // NOTE: Withdrawal fees are a design choice, not a vulnerability
                // Removed the withdrawal fee check as it created false positives

                // FP Reduction: Skip share/asset calculation checks for
                // Masterchef-style staking withdrawals. These use amount-based
                // accounting (user.amount) with rewardDebt, not share-to-asset
                // conversion. Only ERC4626-style vaults need these checks.
                let is_masterchef_withdraw = source_lower.contains("rewarddebt")
                    || source_lower.contains("accrewardpershare")
                    || source_lower.contains("totalstaked")
                    || contract_source_lower.contains("accrewardpershare");

                if !is_masterchef_withdraw {
                    // Check for asset calculation -- only if the function actually
                    // does share-to-asset conversion (contains "shares" reference)
                    if source_lower.contains("shares") {
                        let has_asset_calc = source_lower.contains("totalsupply")
                            || source_lower.contains("totalassets");

                        if !has_asset_calc {
                            issues.push((
                                "Asset calculation missing totalSupply/totalAssets".to_string(),
                                Severity::High,
                                "Calculate assets: assets = (shares * totalAssets()) / totalSupply();"
                                    .to_string(),
                            ));
                        }
                    }

                    // Check for zero-asset validation -- only if function references "assets"
                    // as a variable (not just in comments or event names)
                    if source_lower.contains("assets =") || source_lower.contains("assets;") {
                        let has_zero_check = source_lower.contains("assets > 0")
                            || source_lower.contains("assets != 0")
                            || (source_lower.contains("require") && source_lower.contains("!= 0"));

                        if !has_zero_check {
                            issues.push((
                                "No validation for zero assets on withdrawal".to_string(),
                                Severity::Medium,
                                "Validate assets: require(assets > 0, \"Assets must be non-zero\");"
                                    .to_string(),
                            ));
                        }
                    }

                    // Check for slippage protection
                    let has_min_output = source_lower.contains("minassets")
                        || source_lower.contains("minamount")
                        || (source_lower.contains("amount") && source_lower.contains(">="));

                    if !has_min_output {
                        issues.push((
                            "No slippage protection on withdrawal".to_string(),
                            Severity::Medium,
                            "Add slippage: require(assets >= minAssets, \"Slippage too high\");"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Check reward calculation functions
        // Only flag if the function actually performs reward math, not simple claims
        // FP Reduction: Require the function name to START with these keywords, not just
        // contain them. This avoids flagging functions like "getRewardDebt" or "earnedRewards"
        // that are view helpers, not actual reward calculation entry points.
        if name.starts_with("reward")
            || name.starts_with("earn")
            || name.starts_with("claim")
            || name == "harvest"
        {
            // Skip simple claim-from-mapping patterns
            if !self.is_simple_reward_claim(&func_source) {
                // FP Reduction: Check contract-level source for reward infrastructure.
                // Masterchef-style contracts use accRewardPerShare + rewardDebt at
                // the contract level, and individual functions reference them via
                // struct access (e.g., user.rewardDebt, pool.accRewardPerShare).
                // These should not be flagged for missing reward accounting.
                let has_masterchef_pattern = contract_source_lower.contains("accrewardpershare")
                    || contract_source_lower.contains("rewardpershare")
                    || (contract_source_lower.contains("rewarddebt")
                        && contract_source_lower.contains("accumulatedrewards"));

                // Also check if the function itself references reward infrastructure
                // via struct member access (e.g., user.rewardDebt, pool.accRewardPerShare)
                let func_has_reward_infra = source_lower.contains("rewarddebt")
                    || source_lower.contains("accrewardpershare")
                    || source_lower.contains("rewardpershare")
                    || source_lower.contains("accumulatedrewards")
                    || source_lower.contains("pending");

                // Skip all reward sub-checks if contract uses Masterchef pattern
                // or the function references established reward infrastructure
                if !has_masterchef_pattern && !func_has_reward_infra {
                    // Check for reward per token calculation
                    let has_reward_calc = source_lower.contains("rewardpertoken")
                        || (source_lower.contains("reward")
                            && source_lower.contains("totalsupply"));

                    if !has_reward_calc {
                        issues.push((
                            "Reward calculation doesn't account for totalSupply".to_string(),
                            Severity::High,
                            "Calculate rewards: rewardPerToken = (rewardRate * timeDelta * 1e18) / totalSupply;".to_string()
                        ));
                    }

                    // Check for timestamp validation
                    let has_time_check = source_lower.contains("lastupdatetime")
                        || source_lower.contains("lastclaimtime")
                        || source_lower.contains("lastupdate")
                        || source_lower.contains("lastrewardtime")
                        || (source_lower.contains("timestamp") && source_lower.contains("require"));

                    if !has_time_check {
                        issues.push((
                            "No timestamp tracking for reward accrual".to_string(),
                            Severity::High,
                            "Track time: lastUpdateTime = block.timestamp; Use for accurate reward calculation".to_string()
                        ));
                    }

                    // Check for reward debt accounting
                    let has_reward_debt =
                        source_lower.contains("rewarddebt") || source_lower.contains("paidreward");

                    if !has_reward_debt {
                        issues.push((
                            "Missing reward debt tracking (double-claim risk)".to_string(),
                            Severity::Critical,
                            "Track debt: userRewardDebt[user] = (userBalance * rewardPerToken) / 1e18;"
                                .to_string(),
                        ));
                    }

                    // Check for precision loss
                    let has_precision =
                        source_lower.contains("1e18") || source_lower.contains("precision");

                    if !has_precision {
                        issues.push((
                            "Reward calculation without precision multiplier (rounding errors)".to_string(),
                            Severity::Medium,
                            "Add precision: Use 1e18 multiplier for reward calculations to minimize rounding errors".to_string()
                        ));
                    }
                }
            }
        }

        // Check harvest/compound functions
        // FP Reduction: Only match exact function names, not substrings
        if name == "harvest" || name == "compound" || name == "compoundrewards" {
            // Check for reentrancy protection
            let has_reentrancy_guard =
                source_lower.contains("nonreentrant") || source_lower.contains("locked");

            if !has_reentrancy_guard {
                issues.push((
                    "Harvest function without reentrancy protection".to_string(),
                    Severity::Critical,
                    "Add guard: Use nonReentrant modifier or ReentrancyGuard".to_string(),
                ));
            }

            // NOTE: Performance fees are a design choice, not a vulnerability
            // Removed the performance fee check as it created false positives
        }

        // Check updateReward modifier or function
        if name.contains("update") && source_lower.contains("reward") {
            // FP Reduction: Skip if the function already has zero-supply
            // guard via early return or lpSupply check (Masterchef pattern:
            // "if (lpSupply == 0) { ... return; }")
            let has_zero_supply = source_lower.contains("totalsupply() == 0")
                || source_lower.contains("totalsupply > 0")
                || source_lower.contains("totalsupply() > 0")
                || source_lower.contains("lpsupply == 0")
                || source_lower.contains("lpsupply != 0")
                || (source_lower.contains("== 0") && source_lower.contains("return"));

            if !has_zero_supply {
                issues.push((
                    "Reward update doesn't handle zero totalSupply (division by zero)".to_string(),
                    Severity::High,
                    "Handle zero: if (totalSupply() > 0) { rewardPerToken = ...; }".to_string(),
                ));
            }
        }

        issues
    }

    /// Check if a function name represents a deposit-like operation.
    /// Uses tighter matching to avoid false positives on admin functions
    /// whose names merely contain "deposit" as a substring.
    fn is_deposit_function(&self, name: &str) -> bool {
        // Exact matches for common deposit function names
        if name == "deposit" || name == "stake" || name == "depositassets" {
            return true;
        }

        // Functions that start with "deposit" and are actual deposit operations
        if name.starts_with("deposit") {
            // Exclude admin/config functions that happen to start with "deposit"
            let suffix = &name["deposit".len()..];
            if suffix.is_empty()
                || suffix.starts_with("into")
                || suffix.starts_with("for")
                || suffix.starts_with("with")
                || suffix.starts_with("eth")
                || suffix.starts_with("token")
            {
                return true;
            }
        }

        // Functions named "stake" with suffixes
        if name.starts_with("stake") && !name.contains("whitelist") {
            return true;
        }

        false
    }

    /// Check if a function name represents a withdrawal-like operation.
    /// Uses tighter matching to avoid false positives on admin functions
    /// and queue/batch mechanisms.
    fn is_withdraw_function(&self, name: &str) -> bool {
        // Exact matches
        if name == "withdraw" || name == "unstake" || name == "redeem" {
            return true;
        }

        // Functions that start with "withdraw" -- actual withdrawal operations
        if name.starts_with("withdraw") {
            let suffix = &name["withdraw".len()..];
            if suffix.is_empty()
                || suffix.starts_with("token")
                || suffix.starts_with("eth")
                || suffix.starts_with("asset")
                || suffix.starts_with("share")
                || suffix.starts_with("for")
            {
                return true;
            }
        }

        // Emergency withdrawals are legitimate withdrawal functions
        if name.starts_with("emergency") && name.contains("withdraw") {
            return true;
        }

        // Redeem variants
        if name.starts_with("redeem") {
            return true;
        }

        false
    }
}

impl Default for YieldFarmingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for YieldFarmingDetector {
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

        // FP Reduction: Skip secure example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        if !self.is_yield_vault(ctx) {
            return Ok(findings);
        }

        // Check for vault inflation protection patterns
        // These reduce false positives for share inflation attacks
        let has_inflation_protection = vault_patterns::has_inflation_protection(ctx);
        let has_dead_shares = vault_patterns::has_dead_shares_pattern(ctx);
        let has_virtual_shares = vault_patterns::has_virtual_shares_pattern(ctx);
        let has_min_deposit = vault_patterns::has_minimum_deposit_pattern(ctx);

        // If vault has comprehensive inflation protection, skip inflation-related checks
        let skip_inflation_checks =
            has_inflation_protection || has_dead_shares || has_virtual_shares;

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Skip view/pure functions - they don't modify state
            if function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            // Skip standard token functions that aren't yield-specific
            let func_name_lower = function.name.name.to_lowercase();
            if func_name_lower == "transfer"
                || func_name_lower == "transferfrom"
                || func_name_lower == "approve"
                || func_name_lower == "allowance"
                || func_name_lower == "balanceof"
            {
                continue;
            }

            // Skip admin/governance functions
            if self.is_admin_function(&func_name_lower) {
                continue;
            }

            let issues = self.check_function(function, ctx, skip_inflation_checks, has_min_deposit);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(191) // CWE-191: Integer Underflow
                    .with_fix_suggestion(remediation);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Detector;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_detector_properties() {
        let detector = YieldFarmingDetector::new();
        assert_eq!(detector.name(), "Yield Farming Exploits");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    // -- is_yield_vault tests --

    #[test]
    fn test_erc4626_vault_not_yield_farming() {
        // ERC-4626 vaults should NOT be classified as yield farming vaults.
        // They have their own dedicated detectors (vault-share-inflation, etc.)
        let detector = YieldFarmingDetector::new();
        let ctx = create_context("contract MyVault is ERC4626 { function deposit() {} }");
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_vault_with_shares_detected() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context("contract MyVault { uint256 shares; function deposit() {} }");
        assert!(detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_staking_reward_with_deposit_detected() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context("contract Staking { function deposit() {} uint256 reward; }");
        assert!(detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_delegation_manager_excluded() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            "contract DelegationManager { \
             function deposit() {} \
             uint256 shares; \
             function withdraw() {} \
             mapping(address => uint256) rewards; \
             }",
        );
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_strategy_manager_with_whitelist_excluded() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            "contract StrategyManager { \
             mapping(address => bool) whitelisted; \
             function deposit() {} \
             uint256 shares; \
             }",
        );
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_simple_contract_not_detected() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context("contract SimpleToken { function transfer() {} }");
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_staking_without_deposit_not_detected() {
        let detector = YieldFarmingDetector::new();
        // staking + reward but no deposit/stake function
        let ctx = create_context(
            "contract RewardClaim { \
             string public name = 'staking reward'; \
             function claimRewards() {} \
             }",
        );
        assert!(!detector.is_yield_vault(&ctx));
    }

    // -- ERC-4626 vault exclusion tests --

    #[test]
    fn test_erc4626_explicit_inheritance_excluded() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract SecureVault is ERC4626 {
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
                    shares = previewDeposit(assets);
                    _mint(receiver, shares);
                }
                function withdraw(uint256 assets) public returns (uint256 shares) {}
                function totalAssets() public view returns (uint256) {}
                function convertToShares(uint256 assets) public view returns (uint256) {}
            }
            "#,
        );
        assert!(detector.is_erc4626_vault_contract(&ctx));
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_ierc4626_interface_excluded() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract VaultImpl is IERC4626 {
                function deposit(uint256 assets, address receiver) external returns (uint256) {}
                function redeem(uint256 shares, address receiver, address owner) external returns (uint256) {}
                function totalAssets() external view returns (uint256) {}
            }
            "#,
        );
        assert!(detector.is_erc4626_vault_contract(&ctx));
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_erc4626_function_signatures_excluded() {
        // Contract without explicit ERC4626 inheritance but with standard ERC-4626 signatures
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract CustomVault {
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
                    shares = convertToShares(assets);
                    _mint(receiver, shares);
                }
                function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
                    assets = convertToAssets(shares);
                    _burn(owner, shares);
                }
                function totalAssets() public view returns (uint256) {
                    return token.balanceOf(address(this));
                }
                function convertToShares(uint256 assets) public view returns (uint256) {}
                function convertToAssets(uint256 shares) public view returns (uint256) {}
            }
            "#,
        );
        assert!(detector.is_erc4626_vault_contract(&ctx));
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_erc4626_with_preview_functions_excluded() {
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract PreviewVault {
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {}
                function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {}
                function totalAssets() public view returns (uint256) {}
                function previewDeposit(uint256 assets) public view returns (uint256) {}
                function previewRedeem(uint256 shares) public view returns (uint256) {}
            }
            "#,
        );
        assert!(detector.is_erc4626_vault_contract(&ctx));
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_masterchef_with_erc4626_not_excluded() {
        // A yield farming contract that happens to use ERC-4626 should NOT be excluded
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract FarmVault is ERC4626 {
                struct PoolInfo { uint256 allocPoint; uint256 accRewardPerShare; }
                struct UserInfo { uint256 amount; uint256 rewardDebt; }
                uint256 public rewardPerBlock;
                mapping(uint256 => PoolInfo) public poolInfo;
                mapping(uint256 => mapping(address => UserInfo)) public userInfo;
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {}
                function totalAssets() public view returns (uint256) {}
            }
            "#,
        );
        // Should NOT be classified as a pure ERC-4626 vault because it has Masterchef patterns
        assert!(!detector.is_erc4626_vault_contract(&ctx));
        // Should be classified as a yield farming contract
        assert!(detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_vulnerable_vault_with_deposit_receiver_excluded() {
        // Simulate a vulnerable ERC-4626 vault (no inflation protection) -- should still
        // be excluded from yield farming detector because it IS an ERC-4626 vault
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract VulnerableVault {
                function deposit(uint256 assets, address _receiver) public returns (uint256 shares) {
                    shares = assets * totalSupply() / totalAssets();
                    _mint(_receiver, shares);
                }
                function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
                    assets = shares * totalAssets() / totalSupply();
                    _burn(owner, shares);
                    token.transfer(receiver, assets);
                }
                function totalAssets() public view returns (uint256) {
                    return token.balanceOf(address(this));
                }
                function previewDeposit(uint256 assets) public view returns (uint256) {}
            }
            "#,
        );
        assert!(detector.is_erc4626_vault_contract(&ctx));
        assert!(!detector.is_yield_vault(&ctx));
    }

    #[test]
    fn test_plain_staking_contract_not_erc4626() {
        // Plain staking contract without ERC-4626 signatures should NOT be excluded
        let detector = YieldFarmingDetector::new();
        let ctx = create_context(
            r#"
            contract StakingPool {
                uint256 public totalStaked;
                uint256 public rewardRate;
                mapping(address => uint256) public balances;
                function stake(uint256 amount) public {
                    balances[msg.sender] += amount;
                    totalStaked += amount;
                }
                function unstake(uint256 amount) public {
                    balances[msg.sender] -= amount;
                    totalStaked -= amount;
                }
            }
            "#,
        );
        assert!(!detector.is_erc4626_vault_contract(&ctx));
    }

    // -- Admin function tests --

    #[test]
    fn test_admin_function_detection() {
        let detector = YieldFarmingDetector::new();
        assert!(detector.is_admin_function("setMaxDepositLimit"));
        assert!(detector.is_admin_function("addStrategiesToDepositWhitelist"));
        assert!(detector.is_admin_function("removeStrategiesFromDepositWhitelist"));
        assert!(detector.is_admin_function("setEmergencyWithdraw"));
        assert!(detector.is_admin_function("pause"));
        assert!(detector.is_admin_function("initialize"));
    }

    #[test]
    fn test_non_admin_functions_not_excluded() {
        let detector = YieldFarmingDetector::new();
        assert!(!detector.is_admin_function("deposit"));
        assert!(!detector.is_admin_function("withdraw"));
        assert!(!detector.is_admin_function("stake"));
        assert!(!detector.is_admin_function("redeem"));
        assert!(!detector.is_admin_function("claimRewards"));
        assert!(!detector.is_admin_function("harvest"));
        // addLiquidity should NOT be treated as admin
        assert!(!detector.is_admin_function("addLiquidity"));
    }

    // -- Deposit function name tests --

    #[test]
    fn test_deposit_function_matching() {
        let detector = YieldFarmingDetector::new();
        assert!(detector.is_deposit_function("deposit"));
        assert!(detector.is_deposit_function("stake"));
        assert!(detector.is_deposit_function("depositinto"));
        assert!(detector.is_deposit_function("depositforuser"));
        assert!(detector.is_deposit_function("depositwithpermit"));
        assert!(detector.is_deposit_function("depositeth"));
    }

    #[test]
    fn test_non_deposit_function_not_matched() {
        let detector = YieldFarmingDetector::new();
        // Admin functions that contain "deposit" should NOT match
        assert!(!detector.is_deposit_function("removedeposit"));
        assert!(!detector.is_deposit_function("unstake"));
    }

    // -- Withdraw function name tests --

    #[test]
    fn test_withdraw_function_matching() {
        let detector = YieldFarmingDetector::new();
        assert!(detector.is_withdraw_function("withdraw"));
        assert!(detector.is_withdraw_function("unstake"));
        assert!(detector.is_withdraw_function("redeem"));
        assert!(detector.is_withdraw_function("emergencywithdraw"));
        assert!(detector.is_withdraw_function("redeemshares"));
    }

    // -- Simple reward claim tests --

    #[test]
    fn test_simple_claim_pattern_detected() {
        let detector = YieldFarmingDetector::new();
        let source = r#"
            uint256 amount = rewards[msg.sender];
            rewards[msg.sender] = 0;
            token.transfer(msg.sender, amount);
        "#;
        assert!(detector.is_simple_reward_claim(source));
    }

    #[test]
    fn test_complex_reward_not_simple_claim() {
        let detector = YieldFarmingDetector::new();
        let source = r#"
            uint256 accumulatedReward = userBalance * rewardPerToken / 1e18;
            uint256 pending = accumulatedReward - userRewardDebt[msg.sender];
            if (pending > 0) {
                rewardToken.transfer(msg.sender, pending);
                userRewardDebt[msg.sender] = accumulatedReward;
                totalRewardsPaid += pending;
                emit RewardClaimed(msg.sender, pending);
            }
        "#;
        assert!(!detector.is_simple_reward_claim(source));
    }

    // -- Queue/batch function tests --

    #[test]
    fn test_queue_functions_detected() {
        let detector = YieldFarmingDetector::new();
        assert!(detector.is_queue_or_batch_function("queueWithdrawals"));
        assert!(detector.is_queue_or_batch_function("requestWithdrawal"));
        assert!(detector.is_queue_or_batch_function("completeQueuedWithdrawal"));
        assert!(detector.is_queue_or_batch_function("processWithdrawals"));
        assert!(detector.is_queue_or_batch_function("batchWithdraw"));
    }

    #[test]
    fn test_direct_withdraw_not_queue() {
        let detector = YieldFarmingDetector::new();
        assert!(!detector.is_queue_or_batch_function("withdraw"));
        assert!(!detector.is_queue_or_batch_function("redeem"));
        assert!(!detector.is_queue_or_batch_function("unstake"));
    }

    // -- Super delegation tests --

    #[test]
    fn test_super_delegation_detected() {
        let detector = YieldFarmingDetector::new();
        assert!(detector.delegates_to_super("shares = super.deposit(assets, receiver);"));
        assert!(detector.delegates_to_super("shares = super.withdraw(assets, receiver, owner);"));
        assert!(detector.delegates_to_super("assets = super.redeem(shares, receiver, owner);"));
    }

    #[test]
    fn test_no_super_delegation() {
        let detector = YieldFarmingDetector::new();
        assert!(!detector.delegates_to_super("shares = amount * totalSupply() / totalAssets();"));
    }
}
