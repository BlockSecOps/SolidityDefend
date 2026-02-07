use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for Compound-style callback chain vulnerabilities
///
/// Detects patterns in cToken/lending protocols where callback chains
/// can be exploited for reentrancy and market manipulation.
pub struct CompoundCallbackChainDetector {
    base: BaseDetector,
}

impl Default for CompoundCallbackChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CompoundCallbackChainDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("compound-callback-chain"),
                "Compound Callback Chain".to_string(),
                "Detects Compound-style lending protocol callback chain vulnerabilities \
                 through cToken interactions and market manipulation."
                    .to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    /// Find mint/redeem without reentrancy protection
    fn find_unprotected_mint_redeem(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if (trimmed.contains("function mint") || trimmed.contains("function redeem"))
                && !trimmed.contains("internal")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for external call before state update
                let has_transfer = func_body.contains("doTransferIn")
                    || func_body.contains("doTransferOut")
                    || func_body.contains("transfer(")
                    || func_body.contains("safeTransfer");

                let has_state_update = func_body.contains("totalSupply")
                    || func_body.contains("accountTokens")
                    || func_body.contains("totalBorrows");

                if has_transfer && has_state_update {
                    if !func_body.contains("nonReentrant") && !func_body.contains("ReentrancyGuard")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find borrow with market state read
    fn find_borrow_market_manipulation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function borrow") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for exchange rate or price oracle reads
                let reads_market_data = func_body.contains("exchangeRate")
                    || func_body.contains("getUnderlyingPrice")
                    || func_body.contains("getAccountLiquidity")
                    || func_body.contains("borrowRate");

                // Check for external call after market read
                let has_external_after = func_body.contains("doTransferOut")
                    || func_body.contains("transfer(")
                    || func_body.contains(".call");

                if reads_market_data && has_external_after {
                    if !func_body.contains("nonReentrant") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find liquidation with callback opportunity
    fn find_liquidation_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function liquidate") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for seize pattern with transfer
                let has_seize = func_body.contains("seize")
                    || func_body.contains("liquidateBorrow")
                    || func_body.contains("repayBorrow");

                let has_transfer = func_body.contains("safeTransfer")
                    || func_body.contains("transfer(")
                    || func_body.contains("doTransfer");

                if has_seize && has_transfer {
                    if !func_body.contains("nonReentrant") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find cToken interaction chains
    fn find_ctoken_chain(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && !trimmed.contains("internal") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for multiple cToken operations
                let ctoken_ops = [
                    "mint(",
                    "redeem(",
                    "borrow(",
                    "repay(",
                    "liquidate(",
                    "seize(",
                ]
                .iter()
                .filter(|op| func_body.contains(*op))
                .count();

                if ctoken_ops >= 2 {
                    // Multiple cToken ops can create callback chains
                    if !func_body.contains("nonReentrant") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find comptroller interaction vulnerabilities
    fn find_comptroller_callback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for comptroller calls followed by transfers
                let has_comptroller = func_body.contains("comptroller.")
                    || func_body.contains("enterMarkets")
                    || func_body.contains("exitMarket")
                    || func_body.contains("claimComp");

                let has_external = func_body.contains("transfer(")
                    || func_body.contains("safeTransfer")
                    || func_body.contains(".call");

                if has_comptroller && has_external {
                    // State can change between comptroller check and action
                    if !func_body.contains("nonReentrant") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }

    /// Detect ERC-4626 vault contracts to skip compound callback analysis.
    ///
    /// ERC-4626 vaults have mint/redeem/deposit/withdraw as standard operations.
    /// These share names with Compound cToken operations but are fundamentally
    /// different -- vault mint/redeem are share management, not lending operations.
    /// Flagging these as compound callback chains is a false positive.
    fn is_erc4626_vault(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Explicit ERC-4626 markers
        if source.contains("ERC4626") || source.contains("IERC4626") || source.contains("ERC-4626")
        {
            return true;
        }

        // Compound-specific markers that indicate this IS a Compound protocol
        let has_compound_marker = lower.contains("ctoken")
            || lower.contains("comptroller")
            || lower.contains("dotransferin")
            || lower.contains("dotransferout")
            || lower.contains("accounttokens")
            || lower.contains("totalborrow")
            || lower.contains("borrowrate")
            || lower.contains("exchangeratestored");

        // If it has Compound markers, it is NOT an ERC-4626 vault
        if has_compound_marker {
            return false;
        }

        // ERC-4626 standard function signatures
        let has_deposit = source.contains("function deposit(");
        let has_redeem = source.contains("function redeem(");
        let has_total_assets = source.contains("function totalAssets(");
        let has_shares = lower.contains("shares");

        // ERC-4626 vault: has standard vault functions + shares + totalAssets
        let vault_function_count = [has_deposit, has_redeem, has_total_assets]
            .iter()
            .filter(|&&x| x)
            .count();

        if vault_function_count >= 2 && has_shares {
            return true;
        }

        // Vault-like: has deposit + totalAssets + share conversion patterns
        let has_convert = lower.contains("converttoshares") || lower.contains("converttoassets");
        let has_preview = lower.contains("previewdeposit") || lower.contains("previewredeem");

        if has_deposit && has_total_assets && (has_convert || has_preview) {
            return true;
        }

        false
    }
}

impl Detector for CompoundCallbackChainDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
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

        // FP Reduction: Skip ERC-4626 vault contracts.
        // ERC-4626 vaults have standard deposit/withdraw/mint/redeem functions
        // that share names with Compound cToken operations. These are by-design
        // vault callbacks, not compound callback chain vulnerabilities.
        if self.is_erc4626_vault(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_unprotected_mint_redeem(source) {
            let message = format!(
                "Function '{}' in contract '{}' has mint/redeem without reentrancy guard. \
                 Token transfers can trigger callbacks enabling reentrancy.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect cToken mint/redeem:\n\n\
                     1. Add reentrancy guard to all external functions\n\
                     2. Follow checks-effects-interactions:\n\
                        - Update accountTokens before transfer\n\
                        - Update totalSupply before transfer\n\
                     3. Use nonReentrant modifier"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_borrow_market_manipulation(source) {
            let message = format!(
                "Function '{}' in contract '{}' reads market data before external call. \
                 Market state can be manipulated via callback.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect borrow from market manipulation:\n\n\
                     1. Add reentrancy protection\n\
                     2. Re-check liquidity after transfer\n\
                     3. Use TWAP for price oracles\n\
                     4. Validate exchange rate bounds"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_liquidation_callback(source) {
            let message = format!(
                "Function '{}' in contract '{}' has liquidation with callback opportunity. \
                 Liquidator can manipulate state during seize.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Secure liquidation process:\n\n\
                     1. Add reentrancy guard\n\
                     2. Validate health factor after action\n\
                     3. Lock borrower position during liquidation\n\
                     4. Use pull pattern for seized assets"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_ctoken_chain(source) {
            let message = format!(
                "Function '{}' in contract '{}' chains multiple cToken operations. \
                 Callbacks between operations can corrupt state.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect cToken operation chains:\n\n\
                     1. Use single transaction batching\n\
                     2. Add reentrancy guard covering all ops\n\
                     3. Validate intermediate states\n\
                     4. Consider atomic flash loan patterns"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_comptroller_callback(source) {
            let message = format!(
                "Function '{}' in contract '{}' interacts with comptroller before transfer. \
                 Market state can change between check and action.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Secure comptroller interactions:\n\n\
                     1. Add reentrancy protection\n\
                     2. Re-validate liquidity after transfers\n\
                     3. Use snapshots for state validation\n\
                     4. Lock market entries during operations"
                        .to_string(),
                );

            findings.push(finding);
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

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_detector_properties() {
        let detector = CompoundCallbackChainDetector::new();
        assert_eq!(detector.name(), "Compound Callback Chain");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // -- ERC-4626 vault exclusion tests --

    #[test]
    fn test_erc4626_explicit_marker_detected() {
        let detector = CompoundCallbackChainDetector::new();
        let ctx = create_context(
            "contract MyVault is ERC4626 { \
             function deposit(uint256 assets) public {} \
             function mint(uint256 shares) public {} \
             function redeem(uint256 shares) public {} \
             }",
        );
        assert!(detector.is_erc4626_vault(&ctx));
    }

    #[test]
    fn test_erc4626_vault_like_detected() {
        let detector = CompoundCallbackChainDetector::new();
        let ctx = create_context(
            "contract SecureVault { \
             uint256 public totalSupply; \
             function deposit(uint256 assets, address receiver) public returns (uint256 shares) {} \
             function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {} \
             function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); } \
             function mint(uint256 shares) public returns (uint256 assets) {} \
             }",
        );
        assert!(detector.is_erc4626_vault(&ctx));
    }

    #[test]
    fn test_compound_protocol_not_excluded() {
        let detector = CompoundCallbackChainDetector::new();
        // Actual Compound-style contract should NOT be excluded
        let ctx = create_context(
            "contract CToken { \
             address public comptroller; \
             uint256 public totalBorrows; \
             function mint(uint256 amount) external { \
                 doTransferIn(msg.sender, amount); \
                 accountTokens[msg.sender] += tokens; \
                 totalSupply += tokens; \
             } \
             function redeem(uint256 tokens) external { \
                 doTransferOut(msg.sender, amount); \
                 accountTokens[msg.sender] -= tokens; \
                 totalSupply -= tokens; \
             } \
             function borrow(uint256 amount) external { \
                 uint256 rate = borrowRate; \
                 doTransferOut(msg.sender, amount); \
             } \
             }",
        );
        assert!(!detector.is_erc4626_vault(&ctx));
    }

    #[test]
    fn test_erc4626_vault_with_mint_redeem_excluded() {
        let detector = CompoundCallbackChainDetector::new();
        // ERC-4626 vault with mint/redeem (which overlap with Compound operations)
        let ctx = create_context(
            "contract VulnerableVault_HookReentrancy { \
             IERC20 public immutable asset; \
             uint256 public totalSupply; \
             mapping(address => uint256) public balanceOf; \
             function deposit(uint256 assets) public returns (uint256 shares) { \
                 shares = totalSupply == 0 ? assets : (assets * totalSupply) / asset.balanceOf(address(this)); \
                 asset.transferFrom(msg.sender, address(this), assets); \
                 balanceOf[msg.sender] += shares; \
                 totalSupply += shares; \
             } \
             function mint(uint256 shares) public returns (uint256 assets) { \
                 assets = totalSupply == 0 ? shares : (shares * asset.balanceOf(address(this))) / totalSupply; \
                 asset.transferFrom(msg.sender, address(this), assets); \
                 balanceOf[msg.sender] += shares; \
                 totalSupply += shares; \
             } \
             function redeem(uint256 shares) public returns (uint256 assets) { \
                 assets = (shares * asset.balanceOf(address(this))) / totalSupply; \
                 asset.transfer(msg.sender, assets); \
                 balanceOf[msg.sender] -= shares; \
                 totalSupply -= shares; \
             } \
             function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); } \
             }",
        );
        assert!(detector.is_erc4626_vault(&ctx));
    }

    #[test]
    fn test_erc4626_with_preview_functions_excluded() {
        let detector = CompoundCallbackChainDetector::new();
        let ctx = create_context(
            "contract MyVault { \
             function deposit(uint256 assets) public returns (uint256 shares) {} \
             function totalAssets() public view returns (uint256) {} \
             function previewDeposit(uint256 assets) public view returns (uint256) {} \
             function _convertToShares(uint256 assets) internal view returns (uint256) {} \
             }",
        );
        assert!(detector.is_erc4626_vault(&ctx));
    }
}
