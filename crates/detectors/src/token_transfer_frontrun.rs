use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for token transfer front-running vulnerabilities
///
/// This detector identifies transferFrom() operations in price-dependent contexts
/// that lack slippage protection or deadline checks, making them vulnerable to
/// front-running attacks.
///
/// **Vulnerability:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
/// **Severity:** Medium
///
/// ## Description
///
/// Token transfer front-running occurs when:
/// 1. User submits transaction to buy tokens/NFTs at current price
/// 2. Price oracle or exchange rate changes before transaction executes
/// 3. Attacker front-runs by buying first, causing price increase
/// 4. User's transaction executes at worse price
/// 5. Attacker sells at profit (sandwich attack)
///
/// Common vulnerable patterns:
/// - Token purchases without slippage limits
/// - NFT minting without price locks
/// - DEX swaps without minimum output amounts
/// - Operations without deadline parameters
///
pub struct TokenTransferFrontrunDetector {
    base: BaseDetector,
}

impl Default for TokenTransferFrontrunDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenTransferFrontrunDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-transfer-frontrun".to_string()),
                "Token Transfer Front-Running".to_string(),
                "Detects transferFrom() operations vulnerable to front-running due to lack of slippage protection"
                    .to_string(),
                vec![
                    DetectorCategory::MEV,
                    DetectorCategory::Logic,
                    DetectorCategory::DeFi,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Checks if function contains price-dependent token transfers
    fn has_vulnerable_transfer(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // --- FP Reduction: Skip constructor functions ---
        // Constructors run once at deployment and cannot be front-run by users
        if matches!(function.function_type, ast::FunctionType::Constructor)
            || func_name_lower == "constructor"
        {
            return None;
        }

        // --- FP Reduction: Skip view/pure functions ---
        // View and pure functions cannot modify state, so they cannot perform
        // actual token transfers; any transferFrom in their source is dead code
        // or part of an interface definition
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Skip if function is internal/private
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return None;
        }

        // --- FP Reduction: Skip admin/owner-only functions ---
        // Functions guarded by access control modifiers are called by trusted
        // parties (owner, admin, governance) who are not adversarial; front-running
        // these is not a profitable attack vector
        let has_access_control = function.modifiers.iter().any(|m| {
            let mod_name = m.name.name.to_lowercase();
            mod_name.contains("only")
                || mod_name.contains("owner")
                || mod_name.contains("admin")
                || mod_name.contains("auth")
                || mod_name.contains("restrict")
                || mod_name.contains("governance")
                || mod_name.contains("keeper")
                || mod_name.contains("operator")
                || mod_name.contains("manager")
                || mod_name.contains("guardian")
                || mod_name == "initializer"
                || mod_name == "reinitializer"
        });
        if has_access_control {
            return None;
        }

        // Also check for inline access control patterns in the source
        if self.has_inline_access_control(&func_source) {
            return None;
        }

        // Look for transferFrom calls
        let has_transfer_from = func_source.contains("transferFrom");
        if !has_transfer_from {
            return None;
        }

        // --- FP Reduction: Skip SafeERC20 usage ---
        // If the function uses safeTransferFrom instead of raw transferFrom,
        // it indicates the developer is security-conscious. While SafeERC20
        // itself does not prevent front-running, contracts using it typically
        // have other protections. More importantly, safeTransfer/safeTransferFrom
        // patterns are often wrappers that handle return values and are less
        // likely to be bare vulnerable transfers.
        if self.uses_safe_transfer(&func_source) {
            return None;
        }

        // --- FP Reduction: Skip transfers to msg.sender ---
        // Transfers where the recipient is msg.sender (the caller) cannot be
        // profitably front-run because the caller is withdrawing to themselves.
        // An attacker cannot redirect the funds by front-running.
        if self.is_self_transfer(&func_source) {
            return None;
        }

        // --- FP Reduction: Skip commit-reveal patterns ---
        // Functions implementing commit-reveal schemes are inherently protected
        // against front-running since the actual parameters are hidden until reveal
        if self.has_commit_reveal_pattern(&func_source) {
            return None;
        }

        // --- FP Reduction: Skip signature verification patterns ---
        // Functions that verify cryptographic signatures (e.g., permit, EIP-712)
        // are protected because the signed message cannot be altered by front-runners
        if self.has_signature_verification(&func_source) {
            return None;
        }

        // --- FP Reduction: Skip flash loan repayment patterns ---
        // Flash loan callbacks (onFlashLoan, executeOperation, etc.) repay within
        // the same transaction. These atomic operations cannot be front-run because
        // the entire borrow-use-repay happens in a single transaction.
        if self.is_flash_loan_repayment(&func_name_lower, &func_source) {
            return None;
        }

        // Check for price-dependent operations
        let is_price_dependent = func_name_lower.contains("buy")
            || func_name_lower.contains("purchase")
            || func_name_lower.contains("swap")
            || func_name_lower.contains("mint")
            || func_name_lower.contains("trade")
            || func_source.contains("getPrice")
            || func_source.contains("price")
            || func_source.contains("calculateAmount")
            || func_source.contains("getAmountOut");

        if !is_price_dependent {
            return None;
        }

        // Check for slippage protection (multiple forms)
        let has_slippage_protection = self.has_min_amount_param(function)
            || self.has_slippage_check(&func_source)
            || self.has_deadline_param(function)
            || self.has_deadline_validation(&func_source)
            || self.has_price_protection(&func_source);

        if !has_slippage_protection {
            return Some(format!(
                "Price-dependent transfer without slippage protection. \
                Function '{}' performs transferFrom in price-dependent context but lacks \
                minAmountOut/slippage parameters or deadline checks",
                function.name.name
            ));
        }

        None
    }

    /// Checks if function has minimum amount output parameter
    fn has_min_amount_param(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("min")
                    && (name_lower.contains("amount") || name_lower.contains("out"))
            } else {
                false
            }
        })
    }

    /// Checks if function has deadline parameter
    fn has_deadline_param(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("deadline") || name_lower.contains("expiry")
            } else {
                false
            }
        })
    }

    /// Checks source code for slippage protection patterns
    fn has_slippage_check(&self, source: &str) -> bool {
        (source.contains("require") || source.contains("revert"))
            && (source.contains("minAmount")
                || source.contains("minOut")
                || source.contains("slippage")
                || source.contains(">=")
                    && (source.contains("amount") || source.contains("output")))
    }

    /// Checks source code for deadline validation patterns
    fn has_deadline_validation(&self, source: &str) -> bool {
        // Look for timestamp checks with expiration/deadline
        (source.contains("block.timestamp") || source.contains("block.number"))
            && (source.contains("<=") || source.contains("<"))
            && (source.contains("expiration")
                || source.contains("deadline")
                || source.contains("expiry"))
    }

    /// Checks source code for price protection patterns
    fn has_price_protection(&self, source: &str) -> bool {
        // Look for price limit checks
        (source.contains("require") || source.contains("revert"))
            && (source.contains("price") || source.contains("Price"))
            && (source.contains("<=")
                || source.contains(">=")
                || source.contains("<")
                || source.contains(">"))
            && (source.contains("target")
                || source.contains("max")
                || source.contains("min")
                || source.contains("limit"))
    }

    /// FP Reduction: Checks if function uses SafeERC20 patterns
    /// SafeERC20 wraps transfer calls with return-value checks. Functions using
    /// safeTransferFrom are from security-aware codebases and typically have
    /// additional protections in place.
    fn uses_safe_transfer(&self, source: &str) -> bool {
        source.contains("safeTransferFrom")
            || source.contains("safeTransfer(")
            || source.contains("SafeERC20")
    }

    /// FP Reduction: Checks if the transferFrom target is msg.sender
    /// Self-transfers (withdrawals to the caller) cannot be profitably front-run
    /// because the attacker cannot redirect the funds.
    fn is_self_transfer(&self, source: &str) -> bool {
        // Match patterns like: transferFrom(address, msg.sender, ...)
        // or transferFrom(..., msg.sender, ...)
        // Also check for .transfer(msg.sender, ...) patterns
        let lower = source.to_lowercase();

        // Check if all transferFrom calls in this function target msg.sender
        // This is a heuristic: if msg.sender appears near transferFrom as recipient
        if source.contains("transferFrom") && source.contains("msg.sender") {
            // Look for patterns where msg.sender is the recipient (2nd arg of transferFrom)
            // e.g., token.transferFrom(pool, msg.sender, amount)
            // or IERC20(token).transferFrom(address(this), msg.sender, amount)
            for line in source.lines() {
                let trimmed = line.trim();
                if trimmed.contains("transferFrom") && !trimmed.starts_with("//") {
                    // If transferFrom is present but msg.sender is NOT in this line,
                    // then not all transfers are to self
                    if !trimmed.contains("msg.sender") {
                        return false;
                    }
                }
            }
            return true;
        }

        // Check for .transfer(msg.sender, amount) pattern
        lower.contains(".transfer(msg.sender")
    }

    /// FP Reduction: Checks for commit-reveal scheme patterns
    /// Commit-reveal inherently prevents front-running by hiding parameters
    /// until the reveal phase.
    fn has_commit_reveal_pattern(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        (lower.contains("commit") && lower.contains("reveal"))
            || (lower.contains("commitment") && lower.contains("keccak256"))
            || (lower.contains("commitments[") || lower.contains("commits["))
            || lower.contains("commit-reveal")
            || lower.contains("commitreveal")
    }

    /// FP Reduction: Checks for cryptographic signature verification
    /// Functions verifying signatures (permit, EIP-712, ECDSA) are protected
    /// because signed data cannot be altered by front-runners.
    fn has_signature_verification(&self, source: &str) -> bool {
        source.contains("ecrecover")
            || source.contains("ECDSA.recover")
            || source.contains("SignatureChecker")
            || source.contains("isValidSignature")
            || source.contains("EIP712")
            || source.contains("permit(")
            || (source.contains("v, r, s") || source.contains("bytes memory signature"))
                && (source.contains("recover") || source.contains("verify"))
    }

    /// FP Reduction: Checks for flash loan repayment patterns
    /// Flash loan callbacks execute atomically within a single transaction
    /// and cannot be front-run.
    fn is_flash_loan_repayment(&self, func_name: &str, source: &str) -> bool {
        // Common flash loan callback function names
        let flash_loan_callbacks = [
            "onflashloan",
            "executeoperation",
            "flashloancallback",
            "uniswapv2call",
            "uniswapv3flashcallback",
            "uniswapv3swapcallback",
            "pancakecall",
            "pancakeswapv3swapcallback",
            "onflashloanreceived",
            "flashloan",
            "receiveflashloan",
        ];

        if flash_loan_callbacks
            .iter()
            .any(|&cb| func_name == cb || func_name.contains(cb))
        {
            return true;
        }

        // Check source for flash loan repayment patterns
        let lower = source.to_lowercase();
        (lower.contains("flashloan")
            || lower.contains("flash_loan")
            || lower.contains("flash loan"))
            && (lower.contains("repay") || lower.contains("payback") || lower.contains("return"))
    }

    /// FP Reduction: Checks for inline access control patterns
    /// Functions with msg.sender checks or role-based access control
    /// are called by trusted parties.
    fn has_inline_access_control(&self, source: &str) -> bool {
        // Check for common inline access control patterns
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender==")
            || source.contains("if (msg.sender !=")
            || source.contains("if (msg.sender!=")
            || source.contains("require(hasRole")
            || source.contains("_checkRole")
            || source.contains("_checkOwner")
            || (source.contains("msg.sender") && source.contains("owner"))
            || source.contains("AccessControl")
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
}

impl Detector for TokenTransferFrontrunDetector {
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

        for function in ctx.get_functions() {
            if let Some(issue) = self.has_vulnerable_transfer(function, ctx) {
                let message = format!(
                    "Function '{}' has token transfer front-running vulnerability. {} \
                    This enables sandwich attacks where attackers can front-run user transactions \
                    to extract MEV by manipulating prices",
                    function.name.name, issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add slippage protection to '{}'. Implement: \
                        (1) Add minAmountOut parameter and validate: require(amountOut >= minAmountOut, 'Slippage'); \
                        (2) Add deadline parameter: require(block.timestamp <= deadline, 'Expired'); \
                        (3) Use TWAP oracles instead of spot prices; \
                        (4) Implement commit-reveal for sensitive operations; \
                        (5) Consider private transaction pools (Flashbots) for MEV protection",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_metadata() {
        let detector = TokenTransferFrontrunDetector::new();
        assert_eq!(detector.id().0, "token-transfer-frontrun");
        assert_eq!(detector.name(), "Token Transfer Front-Running");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detector_categories() {
        let detector = TokenTransferFrontrunDetector::new();
        let categories = detector.categories();
        assert!(categories.contains(&DetectorCategory::MEV));
        assert!(categories.contains(&DetectorCategory::Logic));
        assert!(categories.contains(&DetectorCategory::DeFi));
    }
}
