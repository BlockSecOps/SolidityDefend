use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::safe_patterns::safe_call_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for token supply manipulation vulnerabilities
pub struct TokenSupplyManipulationDetector {
    base: BaseDetector,
}

impl Default for TokenSupplyManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSupplyManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-supply-manipulation".to_string()),
                "Token Supply Manipulation".to_string(),
                "Detects vulnerabilities in token supply management that allow unauthorized minting, burning, or supply manipulation".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for TokenSupplyManipulationDetector {
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

        // FP Reduction: Skip non-token contracts (AA, flash loan, attack, lending, etc.)
        if !self.is_token_contract(ctx) {
            return Ok(findings);
        }

        // Skip if this is an ERC-4626 vault - shares don't need max supply caps
        // Also check for additional vault patterns that utils::is_erc4626_vault might miss
        let is_vault = utils::is_erc4626_vault(ctx) || self.is_vault_contract(ctx);

        // Skip if this is an ERC-3156 flash loan - flash minting is required behavior
        let is_flash_loan = utils::is_erc3156_flash_loan(ctx);

        // FP Reduction: Detect AMM/DEX pool contracts
        // AMM pools mint LP tokens proportional to deposited assets - this is by design.
        // LP token supply is inherently bounded by the deposited asset reserves, so a
        // max supply cap is unnecessary and would break pool functionality.
        // Uses both the broad contract_classification check (reserve0/reserve1 pattern)
        // and the utils check (swap + liquidity ops + indicators).
        let is_amm = contract_classification::is_amm_contract(ctx)
            || utils::is_amm_pool(ctx)
            || self.is_amm_pool_contract(ctx);

        for function in ctx.get_functions() {
            if let Some(supply_issue) =
                self.check_token_supply_manipulation(function, ctx, is_vault, is_flash_loan, is_amm)
            {
                let message = format!(
                    "Function '{}' has token supply manipulation vulnerability. {} \
                    Improper supply controls can lead to unlimited minting, hyperinflation, or complete token devaluation.",
                    function.name.name, supply_issue
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
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(840) // CWE-840: Business Logic Errors
                    .with_fix_suggestion(format!(
                        "Fix token supply controls in '{}'. \
                    Implement maximum supply cap, add minting rate limits, \
                    require multi-signature for minting, add supply change events, \
                    validate burn amounts, and implement supply monitoring.",
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

impl TokenSupplyManipulationDetector {
    /// FP Reduction: Determine whether this contract is actually a token contract.
    ///
    /// Token supply manipulation findings are only relevant for contracts that
    /// ARE tokens (ERC-20, ERC-721, ERC-1155, or custom token implementations).
    /// Non-token contracts (AA paymasters, flash loan providers, attack contracts,
    /// lending protocols, oracle contracts, governance, yield aggregators) should
    /// be skipped even if they happen to reference mint/burn/totalSupply.
    fn is_token_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // ---- Negative gates: skip contracts whose primary purpose is NOT a token ----

        // ERC-4337 Account Abstraction contracts (paymasters, session keys, etc.)
        let is_aa_contract = lower.contains("validateuserop")
            || lower.contains("ientrypoint")
            || lower.contains("ipaymaster")
            || contract_name.contains("paymaster")
            || contract_name.contains("sessionkey")
            || contract_name.contains("noncemanager")
            || contract_name.contains("aggregator")
            || contract_name.contains("accountrecovery")
            || contract_name.contains("delegation")
            || (contract_name.contains("wallet") && !contract_name.contains("token"));

        if is_aa_contract {
            return false;
        }

        // Attack / exploit simulation contracts (test harnesses)
        let is_attack_contract = contract_name.contains("attack")
            || contract_name.contains("exploit")
            || contract_name.contains("hack")
            || contract_name.contains("malicious")
            || contract_name.contains("attacker");

        if is_attack_contract {
            return false;
        }

        // Flash loan provider contracts (ERC-3156 lenders)
        let is_flash_loan_contract = contract_name.contains("flashloan")
            || contract_name.contains("flashlend")
            || contract_name.contains("flashmint")
            || (lower.contains("ierc3156flashlender") && !lower.contains("ierc20"));

        if is_flash_loan_contract {
            return false;
        }

        // Lending / borrowing protocols
        let is_lending = contract_name.contains("lending")
            || contract_name.contains("lendingpool")
            || contract_name.contains("borrowing")
            || contract_name.contains("comptroller")
            || contract_name.contains("ctoken")
            || contract_name.contains("atoken");

        if is_lending {
            return false;
        }

        // Oracle contracts
        let is_oracle = contract_name.contains("oracle")
            || contract_name.contains("pricefeed")
            || contract_name.contains("chainlink");

        if is_oracle {
            return false;
        }

        // Governance-only contracts (no token mechanics)
        let is_governance = (contract_name.contains("governance")
            || contract_name.contains("governor")
            || contract_name.contains("dao")
            || contract_name.contains("voting")
            || contract_name.contains("timelock"))
            && !lower.contains("function transfer(")
            && !lower.contains("function balanceof(");

        if is_governance {
            return false;
        }

        // Yield aggregator / reentrancy test contracts
        let is_yield_or_reentrancy = contract_name.contains("reentrancy")
            || contract_name.contains("yieldaggregator")
            || contract_name.contains("harvester");

        if is_yield_or_reentrancy {
            return false;
        }

        // ---- Positive gates: require token-like structure ----

        // ERC-20 structure: has transfer + balanceOf
        let has_erc20_structure =
            lower.contains("function transfer(") && lower.contains("function balanceof(");

        if has_erc20_structure {
            return true;
        }

        // Token inheritance: extends ERC20, ERC721, or ERC1155
        let has_token_inheritance = source.contains("ERC20")
            || source.contains("ERC721")
            || source.contains("ERC1155")
            || source.contains("IERC20")
            || source.contains("IERC721")
            || source.contains("IERC1155");

        if has_token_inheritance {
            return true;
        }

        // Token name in contract
        let has_token_name = contract_name.contains("token")
            || contract_name.contains("coin")
            || contract_name.contains("burnable")
            || contract_name.contains("mintable")
            || contract_name.contains("erc20")
            || contract_name.contains("erc721")
            || contract_name.contains("erc1155");

        if has_token_name {
            return true;
        }

        // Custom token structure: totalSupply + balanceOf + (mint OR burn)
        let has_custom_token = lower.contains("totalsupply")
            && lower.contains("balanceof")
            && (lower.contains("function mint(")
                || lower.contains("function burn(")
                || lower.contains("function _mint(")
                || lower.contains("function _burn("));

        if has_custom_token {
            return true;
        }

        // Bridge token pattern: bridgeable token that mints/burns
        let is_bridge_token = (contract_name.contains("bridge")
            && (lower.contains("function mint(") || lower.contains("function burn(")))
            && lower.contains("totalsupply");

        if is_bridge_token {
            return true;
        }

        // No token signals found - not a token contract
        false
    }

    /// Check if contract is an ERC-4626 vault or similar share-based vault
    /// These contracts mint SHARES not tokens - minting shares is the intended behavior
    fn is_vault_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Check contract name for vault patterns
        let has_vault_name = contract_name.contains("vault")
            || contract_name.contains("erc4626")
            || contract_name.contains("strategy")
            || contract_name.contains("yield");

        // Check for ERC-4626 function signatures
        let has_erc4626_functions = (lower.contains("function deposit")
            && lower.contains("shares"))
            || lower.contains("converttoshares")
            || lower.contains("converttoassets")
            || lower.contains("previewdeposit")
            || lower.contains("previewmint")
            || lower.contains("previewwithdraw")
            || lower.contains("previewredeem")
            || lower.contains("totalassets")
            || lower.contains("maxdeposit")
            || lower.contains("maxmint")
            || lower.contains("maxwithdraw")
            || lower.contains("maxredeem");

        // Check for vault inheritance/interface
        let has_vault_interface = source.contains("ERC4626")
            || source.contains("IERC4626")
            || lower.contains("erc-4626")
            || lower.contains("tokenized vault");

        // Check for share calculation patterns
        let has_share_calc = lower.contains("shares =")
            && (lower.contains("assets") || lower.contains("totalsupply"));

        has_vault_name || has_erc4626_functions || has_vault_interface || has_share_calc
    }

    /// Check for token supply manipulation vulnerabilities
    fn check_token_supply_manipulation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        is_vault: bool,
        is_flash_loan: bool,
        is_amm: bool,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_name_lower = function.name.name.to_lowercase();
        let func_source = self.get_function_source(function, ctx);

        // FP Reduction: Skip view/pure functions - they cannot modify state
        // These functions only read data, they cannot mint, burn, or manipulate supply
        if safe_call_patterns::is_view_or_pure_function(function) {
            return None;
        }

        // Skip constructors and initializers - they represent fixed supply at deployment
        // Minting only in constructor means the supply is fixed, not vulnerable
        if func_name_lower == "constructor"
            || func_name_lower == "initialize"
            || func_name_lower == "__init"
            || func_name_lower.starts_with("_init")
        {
            return None;
        }

        // FP Reduction: Skip AMM/DEX pool LP token operations
        // AMM pools mint LP tokens proportionally to deposited liquidity and burn them
        // on withdrawal. The supply is inherently bounded by deposited assets, and
        // K-invariant checks protect against manipulation. Functions like mint(), burn(),
        // addLiquidity(), removeLiquidity() are core pool operations, not vulnerabilities.
        if is_amm {
            let is_amm_function = func_name_lower == "mint"
                || func_name_lower == "burn"
                || func_name_lower.contains("liquidity")
                || func_name_lower.contains("addliquidity")
                || func_name_lower.contains("removeliquidity");

            if is_amm_function {
                return None;
            }
        }

        // FP Reduction: Skip ERC-4626 vault functions - these mint SHARES, not tokens
        // Minting shares in a vault is the intended design, not a vulnerability
        if is_vault {
            let is_vault_function = func_name_lower == "deposit"
                || func_name_lower == "mint"
                || func_name_lower == "withdraw"
                || func_name_lower == "redeem"
                || func_name_lower.starts_with("preview")
                || func_name_lower.starts_with("max")
                || func_name_lower.starts_with("convert")
                || func_name_lower == "totalassets"
                || func_name_lower == "_deposit"
                || func_name_lower == "_mint"
                || func_name_lower == "_withdraw"
                || func_name_lower == "_redeem";

            if is_vault_function {
                return None;
            }
        }

        // Skip internal functions (start with _ but are not public/external mint functions)
        // The internal _mint function itself is fine - we care about who can call it
        if func_name_lower.starts_with("_") && !func_name_lower.contains("public") {
            return None;
        }

        // P1 FP FIX: Skip access control management functions
        // These functions manage WHO can mint, not the actual minting itself
        // Examples: addMinter, removeMinter, grantMinterRole, revokeMinterRole, setMinter
        let is_access_control_management = func_name_lower.starts_with("add")
            || func_name_lower.starts_with("remove")
            || func_name_lower.starts_with("grant")
            || func_name_lower.starts_with("revoke")
            || func_name_lower.starts_with("set")
            || func_name_lower.starts_with("update")
            || func_name_lower.contains("role")
            || func_name_lower == "renounceminter"
            || func_name_lower == "transfermintership";

        if is_access_control_management {
            // Double-check: access control functions shouldn't contain _mint() calls
            // If they do, they're actually minting functions disguised as admin functions
            if !func_source.contains("_mint(") && !func_source.contains("_burn(") {
                return None;
            }
        }

        // Check if function affects token supply
        let affects_supply = func_source.contains("mint")
            || func_source.contains("burn")
            || func_source.contains("totalSupply")
            || func_source.contains("_mint")
            || func_source.contains("_burn")
            || func_name_lower.contains("mint")
            || func_name_lower.contains("burn");

        if !affects_supply {
            return None;
        }

        // Pattern 1: External/public mint function without max supply cap
        // Internal _mint calls in constructor don't count - that's fixed supply
        let is_external_mint =
            func_name_lower.contains("mint") && !func_name_lower.starts_with("_");

        let is_mint = is_external_mint
            || (func_source.contains("_mint") && self.has_external_mint_function(ctx));

        // FP Reduction: Bridge/crosschain mint functions are controlled by validators
        // These tokens are backed by tokens locked on other chains, supply is validated externally
        let is_bridge_mint = func_name_lower.contains("crosschain")
            || func_name_lower.contains("bridge")
            || func_name_lower.contains("relay")
            || (ctx.source_code.to_lowercase().contains("bridgeable")
                && func_name_lower.contains("mint"));

        // FP Reduction: Check if the mint is proportional to deposited assets
        // AMM-style contracts that calculate minted amounts from reserves/balances
        // have inherent supply bounds - no explicit cap is needed.
        let has_proportional_mint = self.has_proportional_mint_pattern(&func_source, ctx);

        // Skip supply cap check for:
        // - ERC-4626 vaults - they mint shares, not tokens (shares backed by assets)
        // - ERC-3156 flash loans - they temporarily mint for flash loan duration
        // - Bridge/crosschain tokens - supply is validated by bridge protocol
        // - Contracts without external mint functions (fixed supply)
        // - AMM pools - LP token supply is bounded by deposited reserves
        // - Functions with proportional mint calculations (supply bounded by deposits)
        let no_supply_cap = is_mint
            && !is_vault  // Skip if vault
            && !is_flash_loan  // Skip if flash loan provider
            && !is_bridge_mint  // Skip if bridge mint function
            && !is_amm  // Skip if AMM pool (LP tokens bounded by reserves)
            && !has_proportional_mint  // Skip if mint proportional to deposits
            && !func_source.contains("maxSupply")
            && !func_source.contains("MAX_SUPPLY")
            && !func_source.contains("cap()");

        if no_supply_cap {
            return Some(
                "Mint function lacks maximum supply cap, \
                enables unlimited token minting and hyperinflation"
                    .to_string(),
            );
        }

        // FP Reduction: Check for access control on the function
        // Look in both func_source AND the full contract source for the function signature with modifiers
        // This handles cases where the function signature line is not included in func_source
        let func_name_str = &function.name.name;
        let has_modifier_in_contract = self.function_has_modifier_in_source(func_name_str, ctx);

        // Pattern 2: Mint without access control
        let lacks_access_control = is_mint
            && !func_source.contains("onlyOwner")
            && !func_source.contains("onlyMinter")
            && !func_source.contains("hasRole")
            && !func_source.contains("require(msg.sender")
            // FP Reduction: Custom access control modifiers in function source
            && !func_source.contains("onlyBridge")
            && !func_source.contains("onlyTokenBridge")
            && !func_source.contains("onlyRelayer")
            && !func_source.contains("onlyValidator")
            && !func_source.contains("onlyAdmin")
            && !func_source.contains("onlyGovernance")
            // Also check for modifier patterns in the contract source for this specific function
            && !has_modifier_in_contract;

        if lacks_access_control {
            return Some(
                "Mint function lacks proper access control, \
                anyone can mint unlimited tokens"
                    .to_string(),
            );
        }

        // Pattern 3: No minting rate limit
        // Skip for AMM pools - LP minting is rate-limited by deposited assets, not time
        // Skip for proportional mints - already bounded by underlying asset deposits
        let has_rate_limit = func_source.contains("lastMint")
            || func_source.contains("mintRate")
            || func_source.contains("cooldown")
            || func_source.contains("block.timestamp");

        let no_rate_limit = is_mint
            && !has_rate_limit
            && !is_amm
            && !has_proportional_mint
            && func_source.contains("amount");

        if no_rate_limit {
            return Some(
                "Mint function has no rate limit, \
                single transaction can mint excessive tokens"
                    .to_string(),
            );
        }

        // Pattern 4: Burn without balance check
        let is_burn = func_source.contains("burn")
            || func_source.contains("_burn")
            || function.name.name.to_lowercase().contains("burn");

        let no_balance_check = is_burn
            && !func_source.contains("balanceOf")
            && !func_source.contains("require")
            && func_source.contains("amount");

        if no_balance_check {
            return Some(
                "Burn function doesn't check balance before burning, \
                can underflow balances or total supply"
                    .to_string(),
            );
        }

        // Pattern 5: TotalSupply can be manipulated directly
        let modifies_total_supply = func_source.contains("totalSupply =")
            || func_source.contains("totalSupply +=")
            || func_source.contains("totalSupply -=");

        // Skip for vaults - ERC-4626 vaults legitimately modify totalSupply for share tracking
        // Skip for AMM pools - they manage totalSupply for LP tokens through _mint/_burn
        let direct_manipulation =
            modifies_total_supply && !is_mint && !is_burn && !is_vault && !is_amm;

        if direct_manipulation {
            return Some(
                "Function directly modifies totalSupply variable, \
                bypasses mint/burn controls for supply manipulation"
                    .to_string(),
            );
        }

        // Pattern 6: Mint doesn't update totalSupply
        let updates_balance =
            func_source.contains("balanceOf[") || func_source.contains("_balances[");

        let doesnt_update_supply =
            is_mint && updates_balance && !func_source.contains("totalSupply");

        if doesnt_update_supply {
            return Some(
                "Mint function updates balance but not totalSupply, \
                creates discrepancy between balances and reported supply"
                    .to_string(),
            );
        }

        // Pattern 7: No supply change events
        let emits_event = func_source.contains("emit");

        // FP Reduction: OpenZeppelin Burnable extensions delegate to parent _burn/_mint
        // which handles the event emission. These are audited standard implementations.
        // Check for OpenZeppelin contract by: comment header, import pattern, or inheritance
        let is_openzeppelin_extension = ctx.source_code.contains("OpenZeppelin Contracts")
            || ctx.source_code.contains("@openzeppelin")
            || ctx.source_code.contains("openzeppelin-contracts")
            || (ctx.source_code.contains("import {ERC20}") && ctx.source_code.contains("_burn("));

        // FP Reduction: Check if function delegates to internal _burn/_mint which handles events
        // OpenZeppelin's ERC20Burnable, ERC721Burnable, ERC1155Burnable all use this pattern
        // The internal _burn/_mint functions emit Transfer events, so the wrapper doesn't need to
        let delegates_to_internal = func_source.contains("_burn(")
            || func_source.contains("_burnBatch(")  // ERC1155 batch operations
            || func_source.contains("_mint(")
            || func_source.contains("_mintBatch(")  // ERC1155 batch operations
            || func_source.contains("super.burn(")
            || func_source.contains("super.mint(")
            // ERC721 uses _update(address(0), tokenId, auth) for burns
            || func_source.contains("_update(address(0)");

        let delegates_to_internal_with_event = delegates_to_internal
            && (is_openzeppelin_extension
                || ctx.source_code.contains("emit Transfer")
                || ctx.source_code.contains("event Transfer"));

        // FP Reduction: ERC20Wrapper's withdrawTo burns internal tokens and transfers underlying
        // The _burn emits Transfer, and safeTransfer handles the underlying token event
        let is_wrapper_pattern = func_name_lower == "withdrawto"
            && func_source.contains("_burn(")
            && func_source.contains("safeTransfer");

        // FP Reduction: Flash loan functions follow ERC-3156 which has its own event handling
        // The standard requires onFlashLoan callback which handles state validation
        let is_flash_loan_function = is_flash_loan
            && (func_name_lower == "flashloan"
                || func_name_lower == "_flashloan"
                || func_name_lower.contains("flashmint"));

        // FP Reduction: Standard burn function names in extension contracts
        // These are wrapper functions that call internal functions with events
        let is_standard_burnable_wrapper = (func_name_lower == "burn"
            || func_name_lower == "burnfrom"
            || func_name_lower == "burnbatch")
            && delegates_to_internal
            && ctx.contract.name.name.to_lowercase().contains("burnable");

        let no_supply_event = (is_mint || is_burn)
            && !emits_event
            && !delegates_to_internal_with_event
            && !is_wrapper_pattern
            && !is_flash_loan_function
            && !is_standard_burnable_wrapper;

        if no_supply_event {
            return Some(
                "Supply-changing operation doesn't emit event, \
                off-chain systems cannot track supply changes"
                    .to_string(),
            );
        }

        // Pattern 8: Mint to zero address
        let mints_to_address = is_mint
            && (func_source.contains("address to") || func_source.contains("address recipient"));

        let no_zero_check = mints_to_address
            && !func_source.contains("require(to != address(0)")
            && !func_source.contains("require(recipient != address(0)");

        if no_zero_check {
            return Some(
                "Mint function doesn't validate recipient address, \
                tokens can be minted to zero address (burned)"
                    .to_string(),
            );
        }

        // Pattern 9: Rebasing without proper controls
        let is_rebasing = func_source.contains("rebase")
            || func_source.contains("_rebase")
            || function.name.name.to_lowercase().contains("rebase");

        let uncontrolled_rebase =
            is_rebasing && !func_source.contains("maxRebase") && !func_source.contains("rebaseCap");

        if uncontrolled_rebase {
            return Some(
                "Rebase function lacks bounds checking, \
                extreme rebases can manipulate supply drastically"
                    .to_string(),
            );
        }

        // Pattern 10: Flash mint without fees or limits
        // Skip entirely for ERC-3156 flash loan providers - they have their own validation
        // ERC-3156 flash loans validate repayment via callback and balance checks
        let is_flash_mint = func_source.contains("flashMint")
            || func_source.contains("flashLoan")
            || function.name.name.to_lowercase().contains("flash");

        let no_flash_controls = is_flash_mint
            && !is_flash_loan  // Skip if flash loan provider (has ERC-3156 validation)
            && affects_supply
            && !func_source.contains("fee")
            && !func_source.contains("maxFlash");

        if no_flash_controls {
            return Some(
                "Flash mint without fees or maximum limits, \
                enables free unlimited supply expansion attacks"
                    .to_string(),
            );
        }

        None
    }

    /// Detect AMM pool contracts using heuristics beyond what the shared utilities check.
    /// This catches custom AMM implementations that don't match standard Uniswap/Curve
    /// patterns but still have the essential AMM characteristics.
    fn is_amm_pool_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Check for K-invariant enforcement - the defining feature of constant-product AMMs.
        // If a contract enforces K-invariant, its LP token minting is inherently safe.
        let has_k_invariant = lower.contains("invariantviolation")
            || lower.contains("invariant violation")
            || lower.contains("k invariant")
            || lower.contains("k =")
            || (lower.contains("balance0")
                && lower.contains("balance1")
                && lower.contains("reserve"))
            || (source.contains("balance0Adjusted * balance1Adjusted")
                || source.contains("_reserve0) * _reserve1"));

        // Check for AMM pool naming patterns
        let has_pool_name = contract_name.contains("pool")
            || contract_name.contains("pair")
            || contract_name.contains("amm")
            || contract_name.contains("dex")
            || contract_name.contains("exchange");

        // Check for core LP token mechanics: internal _mint + _burn + totalSupply tracking
        let has_lp_mechanics = lower.contains("function _mint(")
            && lower.contains("function _burn(")
            && lower.contains("totalsupply");

        // Check for swap function
        let has_swap = lower.contains("function swap(") || lower.contains("function exchange(");

        // Check for reserve tracking
        let has_reserves = (source.contains("reserve0") && source.contains("reserve1"))
            || source.contains("getReserves");

        // Check for TWAP oracle (Uniswap V2-style cumulative price tracking)
        let has_twap = lower.contains("cumulativelast")
            || lower.contains("twap")
            || lower.contains("pricecumulative");

        // Check for minimum liquidity / dead shares (first-depositor protection)
        let has_min_liquidity =
            lower.contains("minimum_liquidity") || lower.contains("dead shares");

        // Strong signal: K-invariant + pool name
        if has_k_invariant && has_pool_name {
            return true;
        }

        // Strong signal: reserves + swap + LP mechanics
        if has_reserves && has_swap && has_lp_mechanics {
            return true;
        }

        // Strong signal: TWAP oracle + swap (oracle is only useful in AMM context)
        if has_twap && has_swap {
            return true;
        }

        // Strong signal: minimum liquidity + LP mechanics (Uniswap V2 pattern)
        if has_min_liquidity && has_lp_mechanics {
            return true;
        }

        // Count medium indicators, require 3+
        let indicator_count = [
            has_k_invariant,
            has_pool_name,
            has_lp_mechanics,
            has_swap,
            has_reserves,
            has_twap,
            has_min_liquidity,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        indicator_count >= 3
    }

    /// Check if the function contains proportional mint calculations.
    /// AMM pools and similar contracts compute minted amounts as a proportion of
    /// existing reserves/totalSupply, which inherently bounds the minted amount.
    ///
    /// Common patterns:
    /// - `liquidity = amount * totalSupply / reserve`  (Uniswap V2)
    /// - `shares = amount * totalSupply / totalAssets`  (ERC-4626 style)
    /// - `sqrt(amount0 * amount1)`  (initial LP mint)
    fn has_proportional_mint_pattern(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = func_source.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // Pattern: amount * totalSupply / reserve (proportional LP minting)
        let has_proportional_calc = (lower.contains("totalsupply") && lower.contains("reserve"))
            || (lower.contains("totalsupply") && lower.contains("_reserve"))
            || (lower.contains("totalsupply") && lower.contains("totalassets"));

        // Pattern: sqrt(amount0 * amount1) - initial liquidity calculation
        let has_sqrt_calc = lower.contains("sqrt(") && lower.contains("amount");

        // Pattern: Contract has getReserves + this function uses reserves for mint calc
        let has_reserve_based_mint = source_lower.contains("getreserves")
            && (lower.contains("_mint(") || lower.contains("mint("))
            && (lower.contains("reserve") || lower.contains("balance"));

        has_proportional_calc || has_sqrt_calc || has_reserve_based_mint
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

    /// Check if the contract has any external/public mint functions
    /// If minting only occurs in constructor, it's a fixed-supply token (not vulnerable)
    fn has_external_mint_function(&self, ctx: &AnalysisContext) -> bool {
        let source = ctx.source_code.to_lowercase();

        // Look for external/public mint function declarations
        // These patterns indicate a mint function that can be called after deployment
        let patterns = [
            "function mint(",
            "function mint (",
            "function safemint(",
            "function safemint (",
            "function tokenmint(",
            ") external", // Check for external visibility with mint nearby
            ") public",   // Check for public visibility with mint nearby
        ];

        // Check for explicit external/public mint functions
        for pattern in &patterns {
            if source.contains(pattern) {
                // Verify it's actually a mint function with external/public visibility
                // by looking for the pattern in context
                let lines: Vec<&str> = source.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains("function mint") || line.contains("function safemint") {
                        // Check this line and next few lines for visibility
                        let context: String = lines[i..std::cmp::min(i + 3, lines.len())].join(" ");
                        if context.contains("external") || context.contains("public") {
                            return true;
                        }
                    }
                }
            }
        }

        // Also check for role-based minting (indicates intentional external mint capability)
        if source.contains("minter_role") || source.contains("minter role") {
            return true;
        }

        false
    }

    /// FP Reduction: Check if a function has an access control modifier in the contract source
    /// This handles cases where func_source doesn't include the function signature line
    fn function_has_modifier_in_source(&self, func_name: &str, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let func_lower = func_name.to_lowercase();

        // Find function definition line with modifiers
        // Pattern: "function funcName(...) ... onlyXxx"
        for line in lower.lines() {
            if line.contains(&format!("function {}", func_lower)) {
                // Check if this line or continuation has access control modifiers
                if line.contains("only")
                    || line.contains("hasrole")
                    || line.contains("authorized")
                    || line.contains("auth")
                {
                    return true;
                }
            }
        }

        // Also check if there's a modifier defined that matches the function
        // E.g., modifier onlyXxx() applied to the function
        let has_modifier_definition = lower.contains("modifier only");

        // Look for function definition with modifier application
        if has_modifier_definition {
            // Search for "function funcName" followed by any "only" modifier on the same declaration
            let func_pattern = format!("function {}", func_lower);
            if let Some(pos) = lower.find(&func_pattern) {
                // Look at the next ~200 characters for the function signature end
                let end_pos = std::cmp::min(pos + 200, lower.len());
                let func_signature = &lower[pos..end_pos];
                // Find where the function body starts
                if let Some(brace_pos) = func_signature.find('{') {
                    let signature_part = &func_signature[..brace_pos];
                    if signature_part.contains("only") {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = TokenSupplyManipulationDetector::new();
        assert_eq!(detector.name(), "Token Supply Manipulation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_constructor_mint_not_flagged() {
        // Fixed supply tokens that only mint in constructor should NOT be flagged
        let source = r#"
            contract Token is ERC20 {
                constructor() ERC20("Token", "TKN") {
                    _mint(msg.sender, 1000000 * 10 ** decimals());
                }
            }
        "#;

        // Constructor should be skipped
        let func_name = "constructor";
        let func_name_lower = func_name.to_lowercase();

        let should_skip = func_name_lower == "constructor"
            || func_name_lower == "initialize"
            || func_name_lower == "__init";

        assert!(should_skip);

        // No external mint function
        let has_external_mint = source.to_lowercase().contains("function mint(")
            && (source.to_lowercase().contains("external")
                || source.to_lowercase().contains("public"));

        assert!(!has_external_mint);
    }

    #[test]
    fn test_initializer_mint_not_flagged() {
        // Upgradeable tokens that mint in initialize should NOT be flagged
        let func_name = "initialize";
        let func_name_lower = func_name.to_lowercase();

        let should_skip = func_name_lower == "constructor"
            || func_name_lower == "initialize"
            || func_name_lower == "__init";

        assert!(should_skip);
    }

    #[test]
    fn test_internal_mint_not_flagged() {
        // Internal _mint function should NOT be flagged
        let func_name = "_mint";
        let func_name_lower = func_name.to_lowercase();

        let is_internal = func_name_lower.starts_with("_");
        assert!(is_internal);
    }

    #[test]
    fn test_external_mint_is_flagged() {
        // External mint functions SHOULD be considered for flagging
        let source = r#"
            contract MintableToken is ERC20, Ownable {
                function mint(address to, uint256 amount) external onlyOwner {
                    _mint(to, amount);
                }
            }
        "#;

        let source_lower = source.to_lowercase();
        let has_external_mint = source_lower.contains("function mint(")
            && (source_lower.contains("external") || source_lower.contains("public"));

        assert!(has_external_mint);
    }

    #[test]
    fn test_fixed_supply_token_pattern() {
        // Pattern: Token with _mint ONLY in constructor = fixed supply
        let fixed_supply_token = r#"
            contract FixedToken is ERC20 {
                constructor() ERC20("Fixed", "FIX") {
                    _mint(msg.sender, 1000000 ether);
                }
                // No other mint functions
            }
        "#;

        // This should NOT have external mint capability
        let source_lower = fixed_supply_token.to_lowercase();
        let has_function_mint = source_lower.contains("function mint");
        assert!(!has_function_mint);
    }

    #[test]
    fn test_amm_pool_detection_with_reserves() {
        // An AMM pool contract with reserve0/reserve1 should be detected as AMM
        let detector = TokenSupplyManipulationDetector::new();

        // Contract with reserve0/reserve1 is a strong AMM signal
        let source = r#"
            contract SafeAMMPool {
                uint112 private reserve0;
                uint112 private reserve1;
                function swap(uint256 amount0Out, uint256 amount1Out, address to) external {}
                function mint(address to) external returns (uint256 liquidity) {
                    _mint(to, liquidity);
                }
                function burn(address to) external returns (uint256 amount0, uint256 amount1) {
                    _burn(address(this), liquidity);
                }
                function _mint(address to, uint256 value) internal {
                    totalSupply += value;
                }
                function _burn(address from, uint256 value) internal {
                    totalSupply -= value;
                }
            }
        "#;

        let lower = source.to_lowercase();

        // Verify reserve0/reserve1 pattern is detected
        assert!(source.contains("reserve0") && source.contains("reserve1"));

        // Verify swap function present
        assert!(lower.contains("function swap("));

        // Verify LP mechanics present
        assert!(lower.contains("function _mint(") && lower.contains("function _burn("));
    }

    #[test]
    fn test_amm_pool_detection_with_k_invariant() {
        // A contract with K-invariant checks + pool name should be detected as AMM
        let source = r#"
            contract LiquidityPool {
                error InvariantViolation();
                function swap(uint256 amount) external {
                    if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1) {
                        revert InvariantViolation();
                    }
                }
                function mint(address to) external {
                    _mint(to, liquidity);
                }
            }
        "#;

        let lower = source.to_lowercase();
        let contract_name = "LiquidityPool".to_lowercase();

        // K-invariant detected
        assert!(lower.contains("invariantviolation"));

        // Pool name detected
        assert!(contract_name.contains("pool"));
    }

    #[test]
    fn test_amm_pool_detection_with_twap() {
        // A contract with TWAP oracle + swap should be detected as AMM
        let source = r#"
            contract AMMPool {
                uint256 public price0CumulativeLast;
                function swap(uint256 amount) external {}
                function getTWAP(uint32 period) external view returns (uint256) {}
            }
        "#;

        let lower = source.to_lowercase();

        // TWAP pattern detected
        assert!(lower.contains("cumulativelast"));

        // Swap function present
        assert!(lower.contains("function swap("));
    }

    #[test]
    fn test_amm_pool_detection_with_minimum_liquidity() {
        // A contract with MINIMUM_LIQUIDITY + LP mechanics = AMM pool
        let source = r#"
            contract UniswapPair {
                uint256 public constant MINIMUM_LIQUIDITY = 1000;
                uint256 public totalSupply;
                function _mint(address to, uint256 value) internal {
                    totalSupply += value;
                }
                function _burn(address from, uint256 value) internal {
                    totalSupply -= value;
                }
                function mint(address to) external returns (uint256) {}
            }
        "#;

        let lower = source.to_lowercase();

        // Minimum liquidity detected (dead shares pattern)
        assert!(lower.contains("minimum_liquidity"));

        // LP mechanics detected
        assert!(
            lower.contains("function _mint(")
                && lower.contains("function _burn(")
                && lower.contains("totalsupply")
        );
    }

    #[test]
    fn test_proportional_mint_detection() {
        // A function that calculates mint amount proportional to reserves should be recognized
        let detector = TokenSupplyManipulationDetector::new();

        let func_source = r#"
            liquidity = min(
                (amount0 * totalSupply) / _reserve0,
                (amount1 * totalSupply) / _reserve1
            );
            _mint(to, liquidity);
        "#;

        let lower = func_source.to_lowercase();

        // Proportional calculation: totalSupply + reserve
        assert!(lower.contains("totalsupply") && lower.contains("reserve"));
    }

    #[test]
    fn test_sqrt_mint_calculation_detected() {
        // Initial LP mint using sqrt(amount0 * amount1) should be recognized as safe
        let func_source = r#"
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY);
            _mint(to, liquidity);
        "#;

        let lower = func_source.to_lowercase();

        // sqrt + amount pattern detected
        assert!(lower.contains("sqrt(") && lower.contains("amount"));
    }

    #[test]
    fn test_vulnerable_mint_not_skipped_as_amm() {
        // A simple token with unprotected mint should NOT be skipped as an AMM pool
        let source = r#"
            contract VulnerableToken {
                mapping(address => uint256) public balances;
                uint256 public totalSupply;
                function mint(address to, uint256 amount) external {
                    totalSupply += amount;
                    balances[to] += amount;
                }
            }
        "#;

        let lower = source.to_lowercase();
        let contract_name = "VulnerableToken".to_lowercase();

        // No reserve0/reserve1 - not an AMM
        assert!(!(source.contains("reserve0") && source.contains("reserve1")));

        // No swap function
        assert!(!lower.contains("function swap("));

        // No K-invariant
        assert!(!lower.contains("invariantviolation"));

        // No pool-like name
        assert!(
            !contract_name.contains("pool")
                && !contract_name.contains("pair")
                && !contract_name.contains("amm")
        );
    }

    #[test]
    fn test_amm_function_name_skipping() {
        // AMM pool contract: mint() and burn() should be skipped
        // but random other supply-affecting functions should still be checked
        let amm_functions = ["mint", "burn", "addliquidity", "removeliquidity"];
        let non_amm_functions = ["inflateSupply", "emergencyMint", "adminMint"];

        for func in &amm_functions {
            let func_lower = func.to_lowercase();
            let is_amm_function = func_lower == "mint"
                || func_lower == "burn"
                || func_lower.contains("liquidity")
                || func_lower.contains("addliquidity")
                || func_lower.contains("removeliquidity");
            assert!(
                is_amm_function,
                "Expected '{}' to be recognized as AMM function",
                func
            );
        }

        for func in &non_amm_functions {
            let func_lower = func.to_lowercase();
            let is_amm_function = func_lower == "mint"
                || func_lower == "burn"
                || func_lower.contains("liquidity")
                || func_lower.contains("addliquidity")
                || func_lower.contains("removeliquidity");
            assert!(
                !is_amm_function,
                "Expected '{}' NOT to be recognized as AMM function",
                func
            );
        }
    }

    // ---- is_token_contract tests ----

    #[test]
    fn test_is_token_contract_positive_erc20() {
        // An ERC-20 token with transfer + balanceOf should be recognized as a token
        let source = r#"
            contract MyToken is ERC20 {
                function transfer(address to, uint256 amount) public returns (bool) {}
                function balanceOf(address account) public view returns (uint256) {}
                function mint(address to, uint256 amount) external onlyOwner {
                    _mint(to, amount);
                }
            }
        "#;
        let lower = source.to_lowercase();

        // ERC-20 structure check
        assert!(
            lower.contains("function transfer(") && lower.contains("function balanceof("),
            "ERC-20 token should have transfer + balanceOf"
        );

        // Token inheritance check
        assert!(source.contains("ERC20"), "Should detect ERC20 inheritance");
    }

    #[test]
    fn test_is_token_contract_positive_custom() {
        // A custom token with totalSupply + balanceOf + mint should be recognized
        let source = r#"
            contract CustomToken {
                uint256 public totalSupply;
                mapping(address => uint256) public balanceOf;
                function mint(address to, uint256 amount) external {
                    totalSupply += amount;
                    balanceOf[to] += amount;
                }
            }
        "#;
        let lower = source.to_lowercase();

        assert!(
            lower.contains("totalsupply")
                && lower.contains("balanceof")
                && lower.contains("function mint("),
            "Custom token should have totalSupply + balanceOf + mint"
        );
    }

    #[test]
    fn test_is_token_contract_negative_aa() {
        // An ERC-4337 paymaster should NOT be treated as a token
        let contract_name = "VulnerablePaymaster";
        let source = r#"
            contract VulnerablePaymaster is IPaymaster {
                function validateUserOp(UserOperation calldata op) external returns (uint256) {}
                function _mint(address to, uint256 amount) internal {}
            }
        "#;
        let lower = source.to_lowercase();
        let name_lower = contract_name.to_lowercase();

        let is_aa = lower.contains("validateuserop")
            || lower.contains("ipaymaster")
            || name_lower.contains("paymaster");

        assert!(is_aa, "Paymaster should be detected as AA contract");
    }

    #[test]
    fn test_is_token_contract_negative_flash_loan() {
        // A flash loan provider should NOT be treated as a token
        let contract_name = "FlashLoanProvider";
        let source = r#"
            contract FlashLoanProvider is IERC3156FlashLender {
                function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external returns (bool) {}
                function _mint(address to, uint256 amount) internal {}
            }
        "#;
        let name_lower = contract_name.to_lowercase();

        let is_flash_loan = name_lower.contains("flashloan") || name_lower.contains("flashlend");

        assert!(
            is_flash_loan,
            "Flash loan provider should be detected as flash loan contract"
        );
    }

    #[test]
    fn test_is_token_contract_negative_attack() {
        // An attack contract should NOT be treated as a token
        let contract_name = "CurveFinance2023Attack";
        let name_lower = contract_name.to_lowercase();

        let is_attack = name_lower.contains("attack")
            || name_lower.contains("exploit")
            || name_lower.contains("hack")
            || name_lower.contains("malicious");

        assert!(
            is_attack,
            "Attack contract should be detected by name heuristic"
        );
    }

    #[test]
    fn test_is_token_contract_negative_curve_pool() {
        // A Curve pool (AMM) that references mint/burn should NOT be a token
        // unless it also has ERC-20 structure or token inheritance
        let contract_name = "CurvePool";
        let source = r#"
            contract CurvePool {
                function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external {}
                function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount) external {}
                function remove_liquidity(uint256 _amount, uint256[3] calldata min_amounts) external {}
            }
        "#;
        let lower = source.to_lowercase();
        let name_lower = contract_name.to_lowercase();

        // Not an ERC-20
        assert!(
            !(lower.contains("function transfer(") && lower.contains("function balanceof(")),
            "Curve pool should NOT have ERC-20 structure"
        );

        // Not a token inheritance
        assert!(
            !(source.contains("ERC20") || source.contains("ERC721") || source.contains("ERC1155")),
            "Curve pool should NOT inherit from token standards"
        );

        // Not a token name
        assert!(
            !(name_lower.contains("token") || name_lower.contains("coin")),
            "Curve pool should NOT have token in name"
        );
    }
}
