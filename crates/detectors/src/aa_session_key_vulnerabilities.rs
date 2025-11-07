//! Account Abstraction Session Key Vulnerabilities Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::access_control_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct SessionKeyVulnerabilitiesDetector {
    base: BaseDetector,
}

impl SessionKeyVulnerabilitiesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-session-key-vulnerabilities".to_string()),
                "Session Key Vulnerabilities".to_string(),
                "Detects overly permissive session keys, missing expiration, and scope limit issues".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    fn is_session_key_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("sessionkey") || source.contains("session"))
            && (source.contains("execute") || source.contains("validate"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check session key validation functions
        if name.contains("validate")
            && (name.contains("session") || source_lower.contains("sessionkey"))
        {
            // Check for missing expiration validation
            let has_expiration = (source_lower.contains("expir")
                || source_lower.contains("validuntil"))
                && (source_lower.contains("timestamp") || source_lower.contains("block.timestamp"));
            let has_deadline =
                source_lower.contains("deadline") && source_lower.contains("block.timestamp");

            if !has_expiration && !has_deadline {
                issues.push((
                    "Session key without expiration check (永久有效)".to_string(),
                    Severity::High,
                    "Add expiration: require(block.timestamp <= sessionKey.validUntil, \"Session expired\");".to_string()
                ));
            }

            // Check for overly permissive scope
            let has_target_restriction =
                source_lower.contains("allowedtarget") || source_lower.contains("whitelist");
            let has_function_restriction =
                source_lower.contains("selector") || source_lower.contains("allowedfunction");
            let has_value_limit = source_lower.contains("maxvalue")
                || (source_lower.contains("value") && source_lower.contains("<="));

            if !has_target_restriction {
                issues.push((
                    "Session key without target contract restrictions".to_string(),
                    Severity::Critical,
                    "Restrict targets: require(sessionKey.allowedTargets[target], \"Target not allowed\");".to_string()
                ));
            }

            if !has_function_restriction {
                issues.push((
                    "Session key without function selector restrictions".to_string(),
                    Severity::High,
                    "Restrict functions: require(sessionKey.allowedSelectors[selector], \"Function not allowed\");".to_string()
                ));
            }

            if !has_value_limit {
                issues.push((
                    "Session key without value transfer limits".to_string(),
                    Severity::High,
                    "Add value limits: require(msg.value <= sessionKey.maxValue, \"Value exceeds limit\");".to_string()
                ));
            }

            // Check for missing revocation mechanism
            let has_revocation =
                source_lower.contains("revoke") || source_lower.contains("disable");

            if !has_revocation {
                issues.push((
                    "No session key revocation mechanism".to_string(),
                    Severity::Medium,
                    "Add revocation: require(!revokedKeys[sessionKeyHash], \"Key revoked\");"
                        .to_string(),
                ));
            }

            // Check for missing nonce/replay protection
            let has_nonce = source_lower.contains("nonce")
                && (source_lower.contains("++") || source_lower.contains("increment"));

            if !has_nonce {
                issues.push((
                    "Session key without nonce (replay attack risk)".to_string(),
                    Severity::High,
                    "Add nonce: require(nonce == sessionKey.nonce++, \"Invalid nonce\");"
                        .to_string(),
                ));
            }
        }

        // Check session key registration/creation
        if name.contains("createsession")
            || name.contains("registersession")
            || name.contains("addsession")
        {
            // Check for missing permission validation
            let has_owner_check = source_lower.contains("owner")
                && (source_lower.contains("==") || source_lower.contains("require"));

            if !has_owner_check {
                issues.push((
                    "Anyone can create session keys (no owner validation)".to_string(),
                    Severity::Critical,
                    "Validate owner: require(msg.sender == owner, \"Only owner can create session keys\");".to_string()
                ));
            }

            // Check for overly long expiration periods
            let has_max_duration = source_lower.contains("maxduration")
                || (source_lower.contains("duration") && source_lower.contains("<="));

            if !has_max_duration {
                issues.push((
                    "No maximum duration limit for session keys".to_string(),
                    Severity::Medium,
                    "Add duration limit: require(duration <= MAX_SESSION_DURATION, \"Duration too long\");".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for SessionKeyVulnerabilitiesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SessionKeyVulnerabilitiesDetector {
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

        if !self.is_session_key_contract(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection for comprehensive session key implementations

        let source_lower = ctx.source_code.to_lowercase();

        // Check for comprehensive session key protection (all critical features)
        let has_expiration =
            source_lower.contains("expirationtime") || source_lower.contains("validuntil");
        let has_spending_limit =
            source_lower.contains("spendinglimit") || source_lower.contains("maxvalue");
        let has_target_whitelist =
            source_lower.contains("targetwhitelist") || source_lower.contains("allowedtargets");
        let has_operation_limit =
            source_lower.contains("operationlimit") || source_lower.contains("operationcount");
        let has_revocation = source_lower.contains("revoke") || source_lower.contains("isactive");

        // If contract has comprehensive session key protections, return early
        if has_expiration
            && has_spending_limit
            && has_target_whitelist
            && has_operation_limit
            && has_revocation
        {
            // Comprehensive session key implementation with all security features
            return Ok(findings);
        }

        // Also check for role-based access control patterns
        if access_control_patterns::has_role_hierarchy_pattern(ctx) {
            // Role-based access control provides structured permission management
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
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
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
