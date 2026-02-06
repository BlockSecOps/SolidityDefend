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

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl NonceReuseDetector {
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

        // Pattern 1: Nonce not incremented after use
        let has_nonce_check = func_source.contains("nonces[") || func_source.contains("nonce ==");

        let lacks_increment = has_nonce_check
            && !func_source.contains("++")
            && !func_source.contains("+=")
            && !func_source.contains("nonces[")
            && !func_source.contains("] =");

        if lacks_increment {
            return Some(
                "Nonce is checked but never incremented, \
                allowing same nonce to be reused for replay attacks"
                    .to_string(),
            );
        }

        // Pattern 2: Nonce incremented before validation
        let nonce_increment_idx = func_source.find("++").or_else(|| func_source.find("+="));
        let require_idx = func_source.find("require(");
        let revert_idx = func_source.find("revert");

        if let (Some(inc), Some(req)) = (nonce_increment_idx, require_idx) {
            if inc < req {
                return Some(
                    "Nonce incremented before validation checks, \
                    allows nonce consumption even when transaction fails"
                        .to_string(),
                );
            }
        }

        if let (Some(inc), Some(rev)) = (nonce_increment_idx, revert_idx) {
            if inc < rev {
                return Some(
                    "Nonce incremented before revert conditions, \
                    nonce gets consumed even on failed transactions"
                        .to_string(),
                );
            }
        }

        // Pattern 3: No nonce validation in signature verification
        let verifies_signature = func_source.contains("ecrecover")
            || func_source.contains("verify")
            || func_source.contains("Signature");

        let missing_nonce_in_sig = verifies_signature
            && uses_nonce
            && !func_source.contains("abi.encode")
            && !func_source.contains("nonce")
            || !func_source.contains("keccak256") && !func_source.contains("nonce");

        if missing_nonce_in_sig {
            return Some(
                "Signature verification without nonce in signed message, \
                allows signature replay across different nonces"
                    .to_string(),
            );
        }

        // Pattern 4: Global nonce instead of per-user
        // Check both function source AND contract-level source for per-user mapping declarations,
        // since mapping declarations are typically at contract scope (state variables).
        let uses_global_nonce =
            func_source.contains("uint256 nonce") || func_source.contains("uint256 public nonce");

        let has_per_user_mapping = func_source.contains("mapping(address")
            || contract_source.contains("mapping(address => mapping")
            || contract_source.contains("mapping(address => uint256) public nonce")
            || contract_source.contains("mapping(address => uint256) nonce")
            || contract_source.contains("nonces[msg.sender]")
            || contract_source.contains("nonces[sender]")
            || contract_source.contains("usedNonces[");

        let not_per_user = uses_global_nonce && !has_per_user_mapping;

        if not_per_user {
            return Some(
                "Uses global nonce instead of per-user mapping, \
                forces sequential execution and limits parallelization"
                    .to_string(),
            );
        }

        // Pattern 5: Nonce parameter without validation
        let has_nonce_param = func_source.contains("uint256 nonce")
            && (func_source.contains("function") || func_source.contains("("));

        let no_validation = has_nonce_param
            && !func_source.contains("require(nonce ==")
            && !func_source.contains("require(nonces[")
            && !func_source.contains("if (nonce !=");

        if no_validation {
            return Some(
                "Nonce parameter accepted but not validated against stored nonce, \
                allows arbitrary nonce values"
                    .to_string(),
            );
        }

        // Pattern 6: Missing nonce cancellation mechanism
        // Check the entire contract source for cancellation functions, not just this function.
        // Cancellation is typically in a separate dedicated function within the same contract.
        let has_nonce_logic = func_source.contains("nonces[") || func_source.contains("nonce ==");

        let contract_has_cancellation = contract_source.contains("cancel")
            || contract_source.contains("invalidate")
            || contract_source.contains("revoke")
            || contract_source.contains("usedNonces");

        let no_cancellation = has_nonce_logic && !contract_has_cancellation;

        if no_cancellation {
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

        // Pattern 8: Sequential nonce requirement too strict
        let requires_sequential = func_source.contains("require(nonce == nonces[")
            || func_source.contains("if (nonce != nonces[");

        let no_gap_allowed =
            requires_sequential && !func_source.contains(">=") && !func_source.contains("bitmap");

        if no_gap_allowed {
            return Some(
                "Requires strictly sequential nonces without gaps, \
                single failed transaction blocks all subsequent transactions"
                    .to_string(),
            );
        }

        // Pattern 9: Nonce used for randomness
        let uses_for_randomness = (func_source.contains("random")
            || func_source.contains("Random")
            || func_source.contains("seed"))
            && uses_nonce;

        if uses_for_randomness {
            return Some(
                "Nonce used for randomness generation, \
                nonces are predictable and unsuitable for random number generation"
                    .to_string(),
            );
        }

        // Pattern 10 removed: Detecting "VULNERABILITY" in comments is unreliable.
        // It matches developer documentation and comments rather than actual code patterns,
        // producing false positives on contracts that document known issues in comments.

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
}
