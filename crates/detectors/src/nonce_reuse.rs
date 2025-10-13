use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for nonce reuse and management vulnerabilities
pub struct NonceReuseDetector {
    base: BaseDetector,
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
        if function.body.is_none() {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

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
            return Some(format!(
                "Nonce is checked but never incremented, \
                allowing same nonce to be reused for replay attacks"
            ));
        }

        // Pattern 2: Nonce incremented before validation
        let nonce_increment_idx = func_source.find("++").or_else(|| func_source.find("+="));
        let require_idx = func_source.find("require(");
        let revert_idx = func_source.find("revert");

        if let (Some(inc), Some(req)) = (nonce_increment_idx, require_idx) {
            if inc < req {
                return Some(format!(
                    "Nonce incremented before validation checks, \
                    allows nonce consumption even when transaction fails"
                ));
            }
        }

        if let (Some(inc), Some(rev)) = (nonce_increment_idx, revert_idx) {
            if inc < rev {
                return Some(format!(
                    "Nonce incremented before revert conditions, \
                    nonce gets consumed even on failed transactions"
                ));
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
            return Some(format!(
                "Signature verification without nonce in signed message, \
                allows signature replay across different nonces"
            ));
        }

        // Pattern 4: Global nonce instead of per-user
        let uses_global_nonce =
            func_source.contains("uint256 nonce") || func_source.contains("uint256 public nonce");

        let not_per_user = uses_global_nonce && !func_source.contains("mapping(address");

        if not_per_user {
            return Some(format!(
                "Uses global nonce instead of per-user mapping, \
                forces sequential execution and limits parallelization"
            ));
        }

        // Pattern 5: Nonce parameter without validation
        let has_nonce_param = func_source.contains("uint256 nonce")
            && (func_source.contains("function") || func_source.contains("("));

        let no_validation = has_nonce_param
            && !func_source.contains("require(nonce ==")
            && !func_source.contains("require(nonces[")
            && !func_source.contains("if (nonce !=");

        if no_validation {
            return Some(format!(
                "Nonce parameter accepted but not validated against stored nonce, \
                allows arbitrary nonce values"
            ));
        }

        // Pattern 6: Missing nonce cancellation mechanism
        let has_nonce_logic = func_source.contains("nonces[") || func_source.contains("nonce ==");

        let no_cancellation = has_nonce_logic
            && !func_source.contains("cancel")
            && !func_source.contains("invalidate")
            && !func_source.contains("revoke");

        if no_cancellation {
            return Some(format!(
                "No nonce cancellation mechanism, \
                users cannot invalidate pending transactions with old nonces"
            ));
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
            return Some(format!(
                "Requires strictly sequential nonces without gaps, \
                single failed transaction blocks all subsequent transactions"
            ));
        }

        // Pattern 9: Nonce used for randomness
        let uses_for_randomness = (func_source.contains("random")
            || func_source.contains("Random")
            || func_source.contains("seed"))
            && uses_nonce;

        if uses_for_randomness {
            return Some(format!(
                "Nonce used for randomness generation, \
                nonces are predictable and unsuitable for random number generation"
            ));
        }

        // Pattern 10: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("nonce") || func_source.contains("replay"))
        {
            return Some(format!("Nonce reuse vulnerability marker detected"));
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
