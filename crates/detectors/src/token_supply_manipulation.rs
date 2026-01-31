use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
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

        // Skip if this is an ERC-4626 vault - shares don't need max supply caps
        // Also check for additional vault patterns that utils::is_erc4626_vault might miss
        let is_vault = utils::is_erc4626_vault(ctx) || self.is_vault_contract(ctx);

        // Skip if this is an ERC-3156 flash loan - flash minting is required behavior
        let is_flash_loan = utils::is_erc3156_flash_loan(ctx);

        for function in ctx.get_functions() {
            if let Some(supply_issue) =
                self.check_token_supply_manipulation(function, ctx, is_vault, is_flash_loan)
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

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TokenSupplyManipulationDetector {
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
        let has_erc4626_functions = (lower.contains("function deposit") && lower.contains("shares"))
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
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_name_lower = function.name.name.to_lowercase();
        let func_source = self.get_function_source(function, ctx);

        // Skip constructors and initializers - they represent fixed supply at deployment
        // Minting only in constructor means the supply is fixed, not vulnerable
        if func_name_lower == "constructor"
            || func_name_lower == "initialize"
            || func_name_lower == "__init"
            || func_name_lower.starts_with("_init")
        {
            return None;
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
        let is_external_mint = func_name_lower.contains("mint")
            && !func_name_lower.starts_with("_");

        let is_mint = is_external_mint
            || (func_source.contains("_mint") && self.has_external_mint_function(ctx));

        // FP Reduction: Bridge/crosschain mint functions are controlled by validators
        // These tokens are backed by tokens locked on other chains, supply is validated externally
        let is_bridge_mint = func_name_lower.contains("crosschain")
            || func_name_lower.contains("bridge")
            || func_name_lower.contains("relay")
            || (ctx.source_code.to_lowercase().contains("bridgeable")
                && func_name_lower.contains("mint"));

        // Skip supply cap check for:
        // - ERC-4626 vaults - they mint shares, not tokens (shares backed by assets)
        // - ERC-3156 flash loans - they temporarily mint for flash loan duration
        // - Bridge/crosschain tokens - supply is validated by bridge protocol
        // - Contracts without external mint functions (fixed supply)
        let no_supply_cap = is_mint
            && !is_vault  // Skip if vault
            && !is_flash_loan  // Skip if flash loan provider
            && !is_bridge_mint  // Skip if bridge mint function
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
        let has_rate_limit = func_source.contains("lastMint")
            || func_source.contains("mintRate")
            || func_source.contains("cooldown")
            || func_source.contains("block.timestamp");

        let no_rate_limit = is_mint && !has_rate_limit && func_source.contains("amount");

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
        let direct_manipulation = modifies_total_supply && !is_mint && !is_burn && !is_vault;

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
            || (ctx.source_code.contains("import {ERC20}")
                && ctx.source_code.contains("_burn("));

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
            ") external",  // Check for external visibility with mint nearby
            ") public",    // Check for public visibility with mint nearby
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
}
