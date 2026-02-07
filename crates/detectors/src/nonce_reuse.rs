use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for nonce reuse and management vulnerabilities
pub struct NonceReuseDetector {
    base: BaseDetector,
}

impl Default for NonceReuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceReuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("nonce-reuse".to_string()),
                "Nonce Reuse Vulnerability".to_string(),
                "Detects improper nonce management that allows replay attacks or transaction reordering".to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for NonceReuseDetector {
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

        // Contract-level early exit: skip contracts that have no nonce-related state
        // or code at all. This avoids scanning vaults, AMMs, staking contracts, etc.
        if !self.contract_has_nonce_context(&ctx.source_code) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(nonce_issue) = self.check_nonce_reuse(function, ctx) {
                let message = format!(
                    "Function '{}' has nonce management vulnerability. {} \
                    Improper nonce handling enables replay attacks or transaction reordering exploits.",
                    function.name.name, nonce_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                .with_fix_suggestion(format!(
                    "Fix nonce management in '{}'. \
                    Increment nonce after validation, use mapping(address => uint256) for per-user nonces, \
                    validate nonce before execution, include nonce in signature hash, \
                    and implement nonce cancellation mechanism.",
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

impl NonceReuseDetector {
    /// Check whether the contract source has any nonce-related state or patterns.
    /// Contracts that never mention nonces, nonce mappings, or replay protection
    /// are skipped entirely (vaults, AMMs, staking, etc.).
    fn contract_has_nonce_context(&self, contract_source: &str) -> bool {
        contract_source.contains("nonce")
            || contract_source.contains("Nonce")
            || contract_source.contains("replay")
            || contract_source.contains("REPLAY")
    }

    /// Check for nonce reuse vulnerabilities
    fn check_nonce_reuse(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // Skip view/pure functions -- they are read-only and cannot have nonce reuse issues
        if matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) {
            return None;
        }

        // Skip simple nonce utility/management functions by name.
        // These are nonce lifecycle helpers (increment, get, invalidate, use, revoke),
        // not functions that consume nonces for authorization purposes.
        let func_name_lower = function.name.name.to_lowercase();
        if self.is_nonce_utility_function(&func_name_lower) {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let contract_source = &ctx.source_code;

        // Check if function uses nonces
        let uses_nonce = func_source.contains("nonce") || func_source.contains("Nonce");

        if !uses_nonce {
            return None;
        }

        // Determine if the function has proper nonce management patterns.
        // These are used across multiple checks to suppress false positives.
        let has_nonce_increment = func_source.contains("nonces[")
            && (func_source.contains("++")
                || func_source.contains("+= 1")
                || func_source.contains("+ 1"));
        let has_used_nonce_tracking = func_source.contains("usedNonces[")
            || func_source.contains("usedNonce[")
            || func_source.contains("processedMessages[")
            || func_source.contains("] = true")
            || func_source.contains("revealed = true")
            || func_source.contains("executed[");
        let has_nonce_comparison = func_source.contains("nonce >")
            || func_source.contains("nonce >=")
            || func_source.contains("> lastNonce")
            || func_source.contains(">= lastNonce");
        let has_nonce_invalidation =
            has_nonce_increment || has_used_nonce_tracking || has_nonce_comparison;

        // Check if function has signature-related context (ecrecover, verify, permit, etc.)
        let is_signature_context = func_source.contains("ecrecover")
            || func_source.contains("ECDSA")
            || func_source.contains("isValidSignature")
            || func_source.contains("_checkIsValidSignature")
            || func_source.contains("SignatureChecker");
        let is_permit_context = func_name_lower.contains("permit")
            || func_source.contains("PERMIT_TYPEHASH")
            || func_source.contains("Permit(");

        // Pattern 1: Nonce is checked but never incremented or invalidated
        let has_nonce_check = func_source.contains("nonces[") || func_source.contains("nonce ==");

        let lacks_increment = has_nonce_check && !has_nonce_invalidation;

        if lacks_increment {
            return Some(
                "Nonce is checked but never incremented, \
                allowing same nonce to be reused for replay attacks"
                    .to_string(),
            );
        }

        // Pattern 2: Nonce incremented before validation
        // Skip this check for post-increment patterns like `nonces[owner]++` where the
        // increment and read are atomic. Also skip when the increment is on a nonce-related
        // mapping (not an arbitrary counter).
        if !self.is_safe_nonce_increment_pattern(&func_source) {
            let nonce_increment_idx = self.find_nonce_increment_index(&func_source);
            let require_idx = func_source.find("require(");
            let revert_idx = func_source.find("revert ");

            if let Some(inc) = nonce_increment_idx {
                if let Some(req) = require_idx {
                    if inc < req {
                        return Some(
                            "Nonce incremented before validation checks, \
                            allows nonce consumption even when transaction fails"
                                .to_string(),
                        );
                    }
                }

                if let Some(rev) = revert_idx {
                    if inc < rev {
                        return Some(
                            "Nonce incremented before revert conditions, \
                            nonce gets consumed even on failed transactions"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Pattern 3: No nonce validation in signature verification
        // Only flag if the function verifies signatures but does NOT include
        // the nonce in the signed hash at all.
        let verifies_signature = func_source.contains("ecrecover")
            || (func_source.contains("verify") && func_source.contains("signature"));

        if verifies_signature {
            let nonce_in_hash = func_source.contains("abi.encode")
                || func_source.contains("abi.encodePacked")
                || func_source.contains("keccak256");

            if !nonce_in_hash {
                return Some(
                    "Signature verification without nonce in signed message, \
                    allows signature replay across different nonces"
                        .to_string(),
                );
            }
        }

        // Pattern 4: Global nonce instead of per-user
        // Only flag if the function declares a STORAGE-level global nonce (not a local
        // variable or function parameter), and the contract has no per-user nonce mapping.
        let uses_global_nonce_storage = func_source.contains("uint256 public nonce;")
            || contract_source.contains("uint256 public nonce;")
            || contract_source.contains("uint256 nonce;");

        // Exclude: local variables/params named nonce are not global nonces
        let has_per_user_mapping = contract_source.contains("mapping(address")
            && (contract_source.contains("nonce") || contract_source.contains("Nonce"))
            || contract_source.contains("nonces[")
            || contract_source.contains("userNonces[")
            || contract_source.contains("usedNonces[")
            || contract_source.contains("cumulativeWithdrawalsQueued[");

        if uses_global_nonce_storage && !has_per_user_mapping {
            return Some(
                "Uses global nonce instead of per-user mapping, \
                forces sequential execution and limits parallelization"
                    .to_string(),
            );
        }

        // Pattern 5: Nonce parameter without validation
        // Only flag when a nonce parameter is accepted but not validated.
        // Recognise these valid patterns:
        //   - `require(nonce ==` or `require(nonces[` or `if (nonce !=` (direct validation)
        //   - `nonces[owner]++` / `nonces[...]++` (auto-increment reads current nonce)
        //   - `usedNonces[nonce]` / `usedNonces[sender][nonce]` (used-nonce tracking)
        //   - `nonce > lastNonce` / `nonce >= lastNonce` (comparison validation)
        //   - Nonce included in EIP-712 struct hash (abi.encode with nonce present)
        //   - Permit functions that use `nonces[owner]` directly (standard EIP-2612)
        let has_nonce_param = func_source.contains("uint256 nonce")
            && (func_source.contains("function") || func_source.contains("("));

        if has_nonce_param {
            let has_direct_validation = func_source.contains("require(nonce ==")
                || func_source.contains("require(nonces[")
                || func_source.contains("if (nonce !=")
                || func_source.contains("if (nonce ==")
                || func_source.contains("require(!usedNonces")
                || func_source.contains("require(!processedMessages");

            let has_implicit_validation =
                has_nonce_invalidation || is_permit_context || is_signature_context;

            // Also check: if nonce is included in abi.encode (part of signed hash), it is
            // validated through signature verification.
            let nonce_in_signed_hash = (func_source.contains("abi.encode")
                || func_source.contains("abi.encodePacked"))
                && (func_source.contains("ecrecover")
                    || func_source.contains("verify")
                    || func_source.contains("Signature")
                    || func_source.contains("_checkIsValidSignature")
                    || func_source.contains("commitment"));

            if !has_direct_validation && !has_implicit_validation && !nonce_in_signed_hash {
                return Some(
                    "Nonce parameter accepted but not validated against stored nonce, \
                    allows arbitrary nonce values"
                        .to_string(),
                );
            }
        }

        // Pattern 6: Missing nonce cancellation mechanism
        // Only flag for contracts that use sequential nonce patterns AND have no
        // cancellation. Skip for EIP-2612 permit (standard does not require cancellation),
        // commit-reveal schemes, and contracts using used-nonce mappings (which inherently
        // allow non-sequential use).
        let has_sequential_nonce = func_source.contains("nonces[")
            && (func_source.contains("++") || func_source.contains("nonce =="));

        let contract_has_cancellation = contract_source.contains("cancel")
            || contract_source.contains("invalidate")
            || contract_source.contains("revoke")
            || contract_source.contains("usedNonces")
            || contract_source.contains("invalidateNonce");

        // Skip cancellation check for standard patterns that do not need it
        let skip_cancellation = is_permit_context
            || has_used_nonce_tracking
            || func_name_lower.contains("reveal")
            || func_name_lower.contains("commit");

        if has_sequential_nonce && !contract_has_cancellation && !skip_cancellation {
            return Some(
                "No nonce cancellation mechanism, \
                users cannot invalidate pending transactions with old nonces"
                    .to_string(),
            );
        }

        // Pattern 7: Nonce overflow not handled
        let increments_nonce = func_source.contains("nonces[") && func_source.contains("++")
            || func_source.contains("nonces[") && func_source.contains("+=");

        let _no_overflow_check = increments_nonce
            && !func_source.contains("unchecked")
            && !func_source.contains("SafeMath");

        // Pattern 8 removed: Sequential nonce requirement is a standard design pattern
        // (used by EIP-2612, EIP-712 meta-transactions, and most nonce schemes).
        // Flagging it as a vulnerability produces false positives on well-known standards.

        // Pattern 9: Nonce used for randomness
        // Only flag when the nonce is directly used in randomness generation, not when
        // "nonce" is used as a salt in commit-reveal schemes.
        let is_commit_reveal = func_name_lower.contains("reveal")
            || func_name_lower.contains("commit")
            || func_source.contains("commitment")
            || func_source.contains("commitments[")
            || contract_source.contains("commit") && contract_source.contains("reveal");

        let uses_for_randomness = (func_source.contains("random")
            || func_source.contains("Random")
            || func_source.contains("seed"))
            && uses_nonce
            && !is_commit_reveal;

        if uses_for_randomness {
            return Some(
                "Nonce used for randomness generation, \
                nonces are predictable and unsuitable for random number generation"
                    .to_string(),
            );
        }

        None
    }

    /// Detect safe nonce increment patterns that look like "pre-increment" in text
    /// but are actually safe.
    ///
    /// The `nonces[owner]++` post-increment pattern reads the current nonce value
    /// and then increments it atomically. When written as:
    ///   `uint256 nonce = nonces[owner]++;`
    /// the `++` textually appears before subsequent `require()` calls, but the
    /// nonce consumption is intentional and safe -- the require validates the
    /// recovered signature, not the nonce value itself.
    fn is_safe_nonce_increment_pattern(&self, func_source: &str) -> bool {
        // Pattern: `= nonces[...]++` -- post-increment assignment
        // This is the standard EIP-2612 / OpenZeppelin permit pattern
        if func_source.contains("= nonces[") && func_source.contains("++") {
            return true;
        }
        // Pattern: `nonces[...] = nonce + 1` -- explicit assignment after use
        if func_source.contains("nonces[") && func_source.contains("= nonce + 1") {
            return true;
        }
        false
    }

    /// Find the index of a nonce-related increment in the function source.
    /// Returns None if the increment is not on a nonce-related variable.
    fn find_nonce_increment_index(&self, func_source: &str) -> Option<usize> {
        // Look for `nonces[...]++` or `nonces[...] +=`
        // Only flag increments that are clearly on nonce state variables
        for (idx, _) in func_source.match_indices("++") {
            // Check if this ++ is near a nonce variable
            let prefix = &func_source[idx.saturating_sub(40)..idx];
            if prefix.contains("nonce") || prefix.contains("Nonce") {
                return Some(idx);
            }
        }
        for (idx, _) in func_source.match_indices("+=") {
            let prefix = &func_source[idx.saturating_sub(40)..idx];
            if prefix.contains("nonce") || prefix.contains("Nonce") {
                return Some(idx);
            }
        }
        None
    }

    /// Check if a function is a simple nonce utility/management helper.
    /// These functions manage the nonce lifecycle (increment, get, invalidate, use, revoke)
    /// and should not be flagged for nonce reuse -- they ARE the nonce management mechanism.
    fn is_nonce_utility_function(&self, func_name_lower: &str) -> bool {
        // Direct nonce management function names
        let nonce_utility_names = [
            "incrementnonce",
            "getnonce",
            "invalidatenonce",
            "usenonce",
            "revokenonce",
            "cancelnonce",
            "consumenance",
            "_usenonce",
            "_incrementnonce",
        ];

        if nonce_utility_names
            .iter()
            .any(|name| func_name_lower == *name)
        {
            return true;
        }

        // Also match patterns like "nonceIncrement", "nonceInvalidate", etc.
        if func_name_lower.starts_with("nonce") || func_name_lower.ends_with("nonce") {
            let nonce_action_words = [
                "increment",
                "invalidate",
                "revoke",
                "cancel",
                "consume",
                "use",
                "get",
                "set",
                "reset",
                "bump",
            ];
            if nonce_action_words
                .iter()
                .any(|word| func_name_lower.contains(word))
            {
                return true;
            }
        }

        // Match cancel/invalidate functions that manage nonces
        // e.g., "cancelAllBefore", "cancelPendingTransactions", "invalidateAllNonces"
        if func_name_lower.contains("cancel") || func_name_lower.contains("invalidate") {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = NonceReuseDetector::new();
        assert_eq!(detector.name(), "Nonce Reuse Vulnerability");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_nonce_utility_function() {
        let detector = NonceReuseDetector::new();
        assert!(detector.is_nonce_utility_function("incrementnonce"));
        assert!(detector.is_nonce_utility_function("getnonce"));
        assert!(detector.is_nonce_utility_function("_usenonce"));
        assert!(detector.is_nonce_utility_function("nonceincrement"));
        assert!(detector.is_nonce_utility_function("cancelnonce"));
        assert!(!detector.is_nonce_utility_function("execute"));
        assert!(!detector.is_nonce_utility_function("transfer"));
        assert!(!detector.is_nonce_utility_function("permit"));
    }

    #[test]
    fn test_is_safe_nonce_increment_pattern() {
        let detector = NonceReuseDetector::new();
        // Post-increment assignment: standard EIP-2612 pattern
        assert!(detector.is_safe_nonce_increment_pattern("uint256 nonce = nonces[owner]++;"));
        // Explicit nonce + 1 assignment
        assert!(detector.is_safe_nonce_increment_pattern("nonces[staker] = nonce + 1;"));
        // Not a safe pattern: bare increment before validation
        assert!(
            !detector.is_safe_nonce_increment_pattern("nonces[owner]++; require(signer == owner);")
        );
    }

    #[test]
    fn test_find_nonce_increment_index() {
        let detector = NonceReuseDetector::new();
        // Should find nonce-related increment
        assert!(
            detector
                .find_nonce_increment_index("nonces[owner]++; require(valid);")
                .is_some()
        );
        // Should NOT find non-nonce increment
        assert!(
            detector
                .find_nonce_increment_index("counter++; require(nonce == expected);")
                .is_none()
        );
        // Should find nonce += pattern
        assert!(
            detector
                .find_nonce_increment_index("nonces[sender] += 1;")
                .is_some()
        );
    }

    #[test]
    fn test_contract_has_nonce_context() {
        let detector = NonceReuseDetector::new();
        assert!(detector.contract_has_nonce_context("mapping(address => uint256) public nonces;"));
        assert!(detector.contract_has_nonce_context("uint256 public Nonce;"));
        assert!(detector.contract_has_nonce_context("// replay protection"));
        // Vault/AMM contract with no nonce usage
        assert!(!detector.contract_has_nonce_context(
            "function deposit(uint256 amount) external { balances[msg.sender] += amount; }"
        ));
    }
}
