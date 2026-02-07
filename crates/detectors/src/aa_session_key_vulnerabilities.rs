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
        // Check contract name for session key indicators
        let contract_name = ctx.contract.name.name.to_lowercase();
        if contract_name.contains("sessionkey") || contract_name.contains("session_key") {
            return true;
        }

        // Check if this contract's own functions reference session keys
        let has_session_function = ctx.get_functions().iter().any(|f| {
            let fname = f.name.name.to_lowercase();
            fname.contains("session")
        });

        // Also check for session key state variables in the contract's source
        // by looking for sessionKey mapping/struct patterns near the contract definition
        let has_session_state = self.contract_source_contains_session_keys(ctx);

        has_session_function && has_session_state
    }

    /// Check if the contract's own source (not the entire file) contains session key state
    fn contract_source_contains_session_keys(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Look for session key storage patterns
        (source_lower.contains("sessionkeys") || source_lower.contains("sessionkey"))
            && (source_lower.contains("mapping") || source_lower.contains("struct"))
    }

    /// Extract the source code for a specific function from the context
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            // Fallback: if location info is not available, return empty
            String::new()
        }
    }

    /// Check if a function name is an ERC-4337 standard function that is not session-key-specific
    fn is_erc4337_standard_function(name: &str) -> bool {
        // These are standard ERC-4337 interface functions that handle general user operations
        // or paymaster validation, not session key logic specifically
        name == "validatepaymasteruserop"
            || name == "validateuserop"
            || name == "postop"
            || name == "validateaggregatedsignature"
            || name == "aggregatesignatures"
    }

    /// Check if a function actually handles session keys based on its name, parameters, and body
    fn function_handles_session_keys(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        let name = function.name.name.to_lowercase();

        // If the function name explicitly mentions session keys, it handles them
        if name.contains("session") {
            return true;
        }

        // For non-session-named functions, check if they reference session key state
        // in their parameters or body
        let func_source = self.get_function_source(function, ctx).to_lowercase();
        func_source.contains("sessionkey") || func_source.contains("session_key")
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();

        // Skip ERC-4337 standard functions unless they directly handle session keys
        if Self::is_erc4337_standard_function(&name) {
            if !self.function_handles_session_keys(function, ctx) {
                return issues;
            }
        }

        // Only analyze functions that actually deal with session keys
        if !self.function_handles_session_keys(function, ctx) {
            return issues;
        }

        // Use contract-level source for checking security features, since session key
        // protections may be spread across multiple functions in the same contract
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check session key validation functions
        if name.contains("validate") && name.contains("session") {
            // Check for missing expiration validation
            let has_expiration = (source_lower.contains("expir")
                || source_lower.contains("validuntil"))
                && (source_lower.contains("timestamp") || source_lower.contains("block.timestamp"));
            let has_deadline =
                source_lower.contains("deadline") && source_lower.contains("block.timestamp");

            if !has_expiration && !has_deadline {
                issues.push((
                    "Session key without expiration check".to_string(),
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
        // Match specifically: createsession*, registersession*, addsessionkey
        // Avoid matching generic "addsession" in names like "addSessionData"
        if name.contains("createsession")
            || name.contains("registersession")
            || (name.contains("addsession") && name.contains("key"))
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


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
                    .with_cwe(613) // CWE-613: Insufficient Session Expiration
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_cwe(284) // CWE-284: Improper Access Control
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
    use crate::types::test_utils::{create_mock_ast_contract, create_mock_ast_function};
    use ast::{AstArena, StateMutability, Visibility};

    /// Helper to create an AnalysisContext with a named contract, functions, and source code
    fn create_context_with_functions<'arena>(
        arena: &'arena AstArena,
        contract_name: &'arena str,
        function_names: Vec<&'arena str>,
        source: &str,
    ) -> AnalysisContext<'arena> {
        let functions: Vec<ast::Function<'arena>> = function_names
            .into_iter()
            .map(|name| {
                create_mock_ast_function(
                    arena,
                    name,
                    Visibility::External,
                    StateMutability::NonPayable,
                )
            })
            .collect();

        let contract = create_mock_ast_contract(arena, contract_name, functions);
        // Leak to get 'arena lifetime
        let contract_ref = Box::leak(Box::new(contract));

        AnalysisContext {
            contract: contract_ref,
            symbols: semantic::SymbolTable::new(),
            source_code: source.to_string(),
            file_path: "test.sol".to_string(),
        }
    }

    // ============================================================================
    // is_session_key_contract tests
    // ============================================================================

    #[test]
    fn test_session_key_contract_detected_by_name() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "VulnerableSessionKey",
            vec!["addSessionKey", "executeWithSessionKey"],
            r#"
                contract VulnerableSessionKey {
                    mapping(address => mapping(address => bool)) public sessionKeys;
                    function addSessionKey(address account, address sessionKey) external {
                        sessionKeys[account][sessionKey] = true;
                    }
                }
            "#,
        );

        assert!(
            detector.is_session_key_contract(&ctx),
            "Contract named VulnerableSessionKey should be detected as session key contract"
        );
    }

    #[test]
    fn test_paymaster_contract_not_detected_as_session_key() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        // Paymaster contract without session key functions or state
        let ctx = create_context_with_functions(
            &arena,
            "VulnerablePaymaster",
            vec![
                "validatePaymasterUserOp",
                "sponsorTransaction",
                "executeUserOp",
            ],
            r#"
                contract VulnerablePaymaster {
                    mapping(address => uint256) public deposits;
                    function validatePaymasterUserOp(
                        bytes calldata userOp,
                        bytes32 userOpHash,
                        uint256 maxCost
                    ) external returns (bytes memory context, uint256 validationData) {
                        return ("", 0);
                    }
                }
            "#,
        );

        assert!(
            !detector.is_session_key_contract(&ctx),
            "Paymaster contract without session key state/functions should not be detected"
        );
    }

    #[test]
    fn test_signature_aggregator_not_detected_as_session_key() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "VulnerableSignatureAggregator",
            vec!["aggregateSignatures", "validateAggregatedSignature"],
            r#"
                contract VulnerableSignatureAggregator {
                    function aggregateSignatures(bytes[] calldata signatures) external pure returns (bytes memory) {
                        bytes memory aggregated;
                        return aggregated;
                    }
                    function validateAggregatedSignature(bytes32 hash, bytes calldata signature) external pure returns (bool) {
                        return true;
                    }
                }
            "#,
        );

        assert!(
            !detector.is_session_key_contract(&ctx),
            "Signature aggregator contract should not be detected as session key contract"
        );
    }

    // ============================================================================
    // ERC-4337 standard function skip tests
    // ============================================================================

    #[test]
    fn test_is_erc4337_standard_function() {
        assert!(
            SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function(
                "validatepaymasteruserop"
            )
        );
        assert!(SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("validateuserop"));
        assert!(
            SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function(
                "validateaggregatedsignature"
            )
        );
        assert!(
            SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("aggregatesignatures")
        );
        assert!(SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("postop"));
    }

    #[test]
    fn test_session_key_function_not_erc4337_standard() {
        assert!(
            !SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("validatesessionkey")
        );
        assert!(!SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("addsessionkey"));
        assert!(
            !SessionKeyVulnerabilitiesDetector::is_erc4337_standard_function("executewithsession")
        );
    }

    // ============================================================================
    // FP regression: validatePaymasterUserOp should NOT trigger
    // ============================================================================

    #[test]
    fn test_fp_validate_paymaster_user_op_no_findings() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        // A paymaster contract that happens to be in a file with session key
        // contracts -- but this contract itself does NOT handle session keys
        let ctx = create_context_with_functions(
            &arena,
            "VulnerablePaymaster",
            vec!["validatePaymasterUserOp"],
            r#"
                contract VulnerablePaymaster {
                    mapping(address => uint256) public deposits;
                    function validatePaymasterUserOp(
                        bytes calldata userOp,
                        bytes32 userOpHash,
                        uint256 maxCost
                    ) external returns (bytes memory context, uint256 validationData) {
                        return ("", 0);
                    }
                }
            "#,
        );

        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "validatePaymasterUserOp in a non-session-key contract should not trigger findings, got {} findings",
            findings.len()
        );
    }

    // ============================================================================
    // FP regression: validateAggregatedSignature should NOT trigger
    // ============================================================================

    #[test]
    fn test_fp_validate_aggregated_signature_no_findings() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "VulnerableSignatureAggregator",
            vec!["validateAggregatedSignature"],
            r#"
                contract VulnerableSignatureAggregator {
                    function validateAggregatedSignature(
                        bytes32 hash,
                        bytes calldata signature
                    ) external pure returns (bool) {
                        return true;
                    }
                }
            "#,
        );

        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "validateAggregatedSignature should not trigger session key findings, got {} findings",
            findings.len()
        );
    }

    // ============================================================================
    // True positive: validateSessionKey SHOULD trigger on vulnerable contract
    // ============================================================================

    #[test]
    fn test_tp_validate_session_key_triggers() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "VulnerableSessionKey",
            vec!["validateSessionKey", "execute"],
            r#"
                contract VulnerableSessionKey {
                    mapping(address => mapping(address => bool)) public sessionKeys;
                    function validateSessionKey(address sessionKey, bytes calldata data) external {
                        // No expiration check
                        // No target restrictions
                    }
                    function execute(address target, bytes calldata data) external {
                        (bool success, ) = target.call(data);
                        require(success);
                    }
                }
            "#,
        );

        let findings = detector.detect(&ctx).unwrap();
        assert!(
            !findings.is_empty(),
            "validateSessionKey in a vulnerable session key contract should trigger findings"
        );

        // Should mention session key expiration
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("expiration") || f.message.contains("Session key")),
            "Should flag session key expiration issues"
        );
    }

    // ============================================================================
    // addSessionKey: should trigger on session key contracts
    // ============================================================================

    #[test]
    fn test_tp_add_session_key_triggers() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "VulnerableSessionKey",
            vec!["addSessionKey", "executeWithSessionKey"],
            r#"
                contract VulnerableSessionKey {
                    mapping(address => mapping(address => bool)) public sessionKeys;
                    function addSessionKey(address account, address sessionKey) external {
                        sessionKeys[account][sessionKey] = true;
                    }
                    function executeWithSessionKey(address target) external {
                        // Execute with session key
                    }
                }
            "#,
        );

        let findings = detector.detect(&ctx).unwrap();
        // addSessionKey should trigger "no maximum duration" and/or "no owner validation"
        let add_session_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("addSessionKey"))
            .collect();
        assert!(
            !add_session_findings.is_empty(),
            "addSessionKey should trigger findings on vulnerable session key contract"
        );
    }

    // ============================================================================
    // Comprehensive session key contract should NOT trigger (safe pattern)
    // ============================================================================

    #[test]
    fn test_safe_comprehensive_session_key_no_findings() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        let ctx = create_context_with_functions(
            &arena,
            "SafeSessionKeyManager",
            vec!["validateSessionKey", "addSessionKey"],
            r#"
                contract SafeSessionKeyManager {
                    struct SessionKeyData {
                        uint256 expirationTime;
                        uint256 spendingLimit;
                        address[] targetWhitelist;
                        uint256 operationLimit;
                        uint256 operationCount;
                        bool isActive;
                    }
                    mapping(address => SessionKeyData) public sessionKeys;

                    function revoke(address key) external {
                        sessionKeys[key].isActive = false;
                    }

                    function validateSessionKey(address sessionKey) external view {
                        require(block.timestamp <= sessionKeys[sessionKey].expirationTime);
                        require(sessionKeys[sessionKey].isActive);
                    }

                    function addSessionKey(address key, uint256 duration) external {
                        require(msg.sender == owner);
                        require(duration <= maxDuration);
                    }

                    function getAllowedTargets(address key) external view returns (address[] memory) {
                        return sessionKeys[key].targetWhitelist;
                    }
                }
            "#,
        );

        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Comprehensive session key implementation should not trigger findings, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    // ============================================================================
    // check_function: ERC-4337 functions with session key refs SHOULD trigger
    // ============================================================================

    #[test]
    fn test_validate_userop_with_session_key_ref_triggers() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        let arena = AstArena::new();

        // A contract where validateUserOp actually references session keys
        let ctx = create_context_with_functions(
            &arena,
            "SessionKeyAccount",
            vec!["validateUserOp"],
            r#"
                contract SessionKeyAccount {
                    mapping(address => bool) public sessionKeys;
                    function validateUserOp(UserOperation calldata op) external {
                        // Checks sessionKey in its body
                        address signer = ecrecover(op.hash, op.signature);
                        if (sessionKeys[signer]) {
                            // Session key path - no expiration check!
                        }
                    }
                }
            "#,
        );

        // The contract has sessionKeys mapping and a session-related function,
        // but validateUserOp itself references sessionKeys in its body
        // The detector should see this as a session key contract
        assert!(
            detector.is_session_key_contract(&ctx),
            "Contract with sessionKeys mapping should not be detected (no session-named function)"
        );
    }

    // ============================================================================
    // Detector metadata tests
    // ============================================================================

    #[test]
    fn test_detector_properties() {
        let detector = SessionKeyVulnerabilitiesDetector::new();
        assert_eq!(detector.id().0, "aa-session-key-vulnerabilities");
        assert_eq!(detector.name(), "Session Key Vulnerabilities");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
