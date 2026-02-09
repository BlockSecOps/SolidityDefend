use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for unprotected delegatecall in fallback functions
///
/// This detector identifies fallback or receive functions that perform delegatecall
/// without proper access control, allowing any caller to execute arbitrary code.
///
/// **Vulnerability:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
/// **Severity:** High
///
/// ## Description
///
/// Unprotected delegatecall in fallback functions is dangerous because:
/// 1. Fallback executes on any call to non-existent functions
/// 2. No explicit function signature required
/// 3. Can be triggered with simple ETH transfers
/// 4. Often used in proxy patterns without proper validation
///
/// ## False Positive Reduction (Phase 54)
///
/// Standard proxy contracts use fallback+delegatecall by design. This detector
/// now recognizes and skips:
/// - Transparent proxies with admin checks in fallback
/// - UUPS proxies (upgrade logic in implementation)
/// - Beacon proxies (implementation from immutable beacon)
/// - Diamond proxies (EIP-2535 facet routing)
/// - Proxies with protected upgrade functions and constructor-set implementation
/// - Contracts where the primary vulnerability is shadowing/storage collision
///   (covered by dedicated detectors)
///
pub struct FallbackDelegatecallUnprotectedDetector {
    base: BaseDetector,
}

impl Default for FallbackDelegatecallUnprotectedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FallbackDelegatecallUnprotectedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("fallback-delegatecall-unprotected".to_string()),
                "Unprotected Fallback Delegatecall".to_string(),
                "Detects delegatecall in fallback/receive functions without proper access control"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for FallbackDelegatecallUnprotectedDetector {
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

        // Phase 52 FP Reduction: Skip legitimate proxy contracts
        // Proxy contracts MUST use delegatecall in fallback to forward calls to implementation.
        // This is by design per EIP-1967 and other proxy standards (Safe, OpenZeppelin, etc.).
        if utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Extract contract-level source for contextual analysis
        let contract_source = self.get_contract_source(ctx.contract, ctx);

        // Phase 54 FP Reduction: Skip contracts that follow standard proxy patterns
        // These use fallback+delegatecall by design; the real vulnerability (if any)
        // is in upgrade access control or storage layout, not in the fallback itself.
        if self.is_standard_proxy_pattern(&contract_source, ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip Diamond proxy patterns (EIP-2535)
        // Diamond proxies route calls to facets via selector mapping - by design.
        if self.is_diamond_proxy(&contract_source, ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(risk_description) =
                self.has_unprotected_fallback_delegatecall(function, ctx)
            {
                let message = format!(
                    "Function '{}' performs delegatecall in fallback/receive without access control. {} \
                    This allows any caller to execute arbitrary code by calling non-existent functions \
                    or sending ETH to the contract.",
                    function.name.name, risk_description
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
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(format!(
                        "Add access control to fallback function '{}'. \
                    Validate implementation address before delegatecall. \
                    Use modifiers like 'onlyOwner' or check msg.sender explicitly. \
                    Consider using OpenZeppelin's transparent or UUPS proxy patterns.",
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

impl FallbackDelegatecallUnprotectedDetector {
    /// Check if fallback/receive function has unprotected delegatecall
    fn has_unprotected_fallback_delegatecall(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Must have function body
        function.body.as_ref()?;

        // Check if this is fallback or receive function
        if !self.is_fallback_or_receive(function) {
            return None;
        }

        // Get function source
        let func_source = self.get_function_source(function, ctx);

        // Check for delegatecall
        if !func_source.contains("delegatecall") {
            return None;
        }

        // Check for access control
        if self.has_access_control(&func_source, function) {
            return None;
        }

        Some(
            "Fallback/receive function performs delegatecall without validating the caller. \
            Any address can trigger this by calling a non-existent function or sending ETH."
                .to_string(),
        )
    }

    /// Check if function is fallback or receive
    fn is_fallback_or_receive(&self, function: &ast::Function<'_>) -> bool {
        // Check function type
        matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        ) || function.name.name.to_lowercase() == "fallback"
            || function.name.name.to_lowercase() == "receive"
            || function.name.name.is_empty() // Unnamed functions are fallback
    }

    /// Check if function has proper access control
    fn has_access_control(&self, source: &str, function: &ast::Function<'_>) -> bool {
        // Check for access control modifiers
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("access")
                || modifier_name.contains("role")
                || modifier_name.contains("nonreentrant")
                || modifier_name.contains("whennotpaused")
                || modifier_name.contains("guard")
            {
                return true;
            }
        }

        let lower = source.to_lowercase();

        // Check for inline access control patterns
        // Direct msg.sender equality checks
        source.contains("require(msg.sender ==")
            || source.contains("require(msg.sender == owner")
            || source.contains("require(msg.sender == admin")
            || source.contains("if (msg.sender != owner)")
            || source.contains("if (msg.sender != admin)")
            || source.contains("onlyOwner")
            || source.contains("onlyAdmin")
            || source.contains("hasRole")
            // Phase 54: Transparent proxy admin check (admin CANNOT call fallback)
            || source.contains("msg.sender != _getAdmin()")
            || source.contains("msg.sender != admin")
            || source.contains("msg.sender == _getAdmin()")
            // Phase 54: Mapping-based access control (e.g., isSigner[msg.sender])
            || lower.contains("issigner[msg.sender]")
            || lower.contains("isauthorized[msg.sender]")
            || lower.contains("isallowed[msg.sender]")
            // Phase 54: Any require/if with msg.sender check in fallback
            || (source.contains("require(") && source.contains("msg.sender"))
            || (source.contains("if (") && source.contains("msg.sender"))
            || (source.contains("if(") && source.contains("msg.sender"))
    }

    /// Phase 54 FP Reduction: Detect standard proxy patterns at the contract level.
    ///
    /// A standard proxy pattern has:
    /// - A fallback function with delegatecall (the forwarding mechanism)
    /// - An implementation address stored in constructor, immutable, or EIP-1967 slot
    /// - Either protected upgrade function OR immutable/constructor-only implementation
    ///
    /// When these conditions are met, the fallback+delegatecall IS the proxy working
    /// as intended. The real vulnerability (if any) is in upgrade access control
    /// or storage layout - covered by dedicated detectors.
    fn is_standard_proxy_pattern(&self, contract_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = contract_source.to_lowercase();
        let _contract_name = ctx.contract.name.name.to_lowercase();

        // Must have delegatecall in the contract to be a proxy
        if !lower.contains("delegatecall") {
            return false;
        }

        // Check for EIP-1967 compliant storage slots
        let has_eip1967 = contract_source
            .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || contract_source
                .contains("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
            || lower.contains("eip1967.proxy.implementation")
            || lower.contains("eip1967.proxy.admin");

        if has_eip1967 {
            return true;
        }

        // Check for implementation variable with protected upgrade
        let has_impl_var = lower.contains("implementation") || lower.contains("_implementation");

        let has_protected_upgrade = (lower.contains("function upgradeto")
            || lower.contains("function setimplementation")
            || lower.contains("function upgrade("))
            && (lower.contains("require(msg.sender ==")
                || lower.contains("require(msg.sender==")
                || lower.contains("onlyowner")
                || lower.contains("onlyadmin")
                || lower.contains("onlyproxyadmin")
                || lower.contains("_checkowner")
                || lower.contains("onlyrole"));

        // Check for immutable implementation (cannot be changed after deployment)
        let has_immutable_impl = lower.contains("immutable") && lower.contains("implementation");

        // Check for beacon proxy pattern (implementation from external beacon)
        let is_beacon_proxy = lower.contains("beacon") && lower.contains("implementation()");

        // Proxy with protected upgrade: the fallback delegatecall is by design
        if has_impl_var && has_protected_upgrade {
            return true;
        }

        // Immutable proxy: implementation cannot change, fallback is safe by design
        if has_immutable_impl {
            return true;
        }

        // Beacon proxy: implementation comes from immutable beacon contract
        if is_beacon_proxy {
            return true;
        }

        // Standard proxy assembly pattern: calldatacopy + delegatecall + returndatacopy
        let has_standard_assembly = lower.contains("calldatacopy")
            && lower.contains("delegatecall")
            && lower.contains("returndatacopy");

        // Constructor-set implementation (set once, not changeable via unprotected public function)
        let has_constructor_set_impl = lower.contains("constructor")
            && has_impl_var
            && !lower.contains("function setimplementation")
            && !lower.contains("function upgradetoimplementation");

        // Check if there is an unprotected upgrade function (a public setter with no access control)
        let has_unprotected_setter = (lower.contains("function setimplementation")
            || lower.contains("function upgradetoimplementation")
            || lower.contains("function upgrade("))
            && !lower.contains("onlyowner")
            && !lower.contains("onlyadmin")
            && !lower.contains("onlyproxyadmin")
            && !lower.contains("require(msg.sender ==")
            && !lower.contains("require(msg.sender==")
            && !lower.contains("_checkowner")
            && !lower.contains("onlyrole");

        // Standard proxy with constructor-set implementation and no unprotected setter:
        // The fallback+delegatecall IS the proxy pattern working as designed.
        // Access control belongs on the implementation's functions, not the proxy fallback.
        // Other proxy vulnerabilities (shadowing, storage collision, unprotected upgrade)
        // are covered by their dedicated detectors.
        if has_standard_assembly && has_constructor_set_impl && !has_unprotected_setter {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Detect Diamond proxy (EIP-2535) patterns.
    ///
    /// Diamond proxies use facet routing: the fallback looks up the facet address
    /// for the given selector in a mapping (selectorToFacet) and delegates to it.
    /// This is a legitimate architectural pattern, not a vulnerability.
    fn is_diamond_proxy(&self, contract_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = contract_source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Explicit diamond pattern indicators
        let has_diamond_storage = lower.contains("diamondstorage")
            || lower.contains("diamond.standard.diamond.storage")
            || lower.contains("selectortofacet")
            || lower.contains("facetaddress");

        let is_diamond_named = contract_name.contains("diamond");

        // Diamond cut function is the standard upgrade mechanism
        let has_diamond_cut = lower.contains("diamondcut") || lower.contains("diamond_cut");

        (has_diamond_storage && lower.contains("delegatecall"))
            || (is_diamond_named && lower.contains("delegatecall"))
            || (has_diamond_cut && lower.contains("delegatecall"))
    }

    /// Get source code for a specific contract (not the entire file).
    ///
    /// Uses the contract name to locate its definition in the file source,
    /// then extracts the full contract body using brace matching. This is more
    /// robust than relying on AST location which may not cover the full contract.
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let contract_name = &contract.name.name;
        let source = &ctx.source_code;

        // Find "contract <Name>" in the source
        let search_patterns = [
            format!("contract {} ", contract_name),
            format!("contract {}\n", contract_name),
            format!("contract {}{{", contract_name),
        ];

        let contract_start = search_patterns
            .iter()
            .filter_map(|pat| source.find(pat.as_str()))
            .min();

        if let Some(start_pos) = contract_start {
            // Find the opening brace
            if let Some(brace_offset) = source[start_pos..].find('{') {
                let brace_pos = start_pos + brace_offset;
                let mut depth = 0;
                let mut end_pos = brace_pos;

                for (i, ch) in source[brace_pos..].char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end_pos = brace_pos + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                return source[start_pos..end_pos].to_string();
            }
        }

        // Fallback: use AST location
        let start = contract.location.start().line();
        let end = contract.location.end().line();
        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
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
    use crate::types::test_utils::create_mock_ast_contract;

    #[test]
    fn test_detector_properties() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        assert_eq!(detector.name(), "Unprotected Fallback Delegatecall");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "fallback-delegatecall-unprotected");
    }

    #[test]
    fn test_is_standard_proxy_eip1967() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = r#"
            contract MyProxy {
                bytes32 private constant IMPLEMENTATION_SLOT =
                    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
                fallback() external payable {
                    assembly { delegatecall(gas(), impl, 0, calldatasize(), 0, 0) }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "MyProxy", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        assert!(detector.is_standard_proxy_pattern(source, &ctx));
    }

    #[test]
    fn test_is_standard_proxy_protected_upgrade() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = r#"
            contract AdminProxy {
                address public implementation;
                address public admin;
                constructor(address _impl) { implementation = _impl; admin = msg.sender; }
                function upgradeTo(address newImpl) external {
                    require(msg.sender == admin, "Only admin");
                    implementation = newImpl;
                }
                fallback() external payable {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "AdminProxy", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        assert!(detector.is_standard_proxy_pattern(source, &ctx));
    }

    #[test]
    fn test_not_proxy_no_protection() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = r#"
            contract DangerousContract {
                address public implementation;
                function setImplementation(address newImpl) external {
                    implementation = newImpl;
                }
                fallback() external payable {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "DangerousContract", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        // Should NOT be recognized as standard proxy (unprotected setter)
        assert!(!detector.is_standard_proxy_pattern(source, &ctx));
    }

    #[test]
    fn test_diamond_proxy_detection() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = r#"
            contract Diamond {
                mapping(bytes4 => address) public selectorToFacet;
                fallback() external payable {
                    address facet = selectorToFacet[msg.sig];
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "Diamond", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        assert!(detector.is_diamond_proxy(source, &ctx));
    }

    #[test]
    fn test_immutable_proxy_detection() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = r#"
            contract ImmutableProxy {
                address public immutable implementation;
                constructor(address _impl) { implementation = _impl; }
                fallback() external payable {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "ImmutableProxy", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        assert!(detector.is_standard_proxy_pattern(source, &ctx));
    }

    #[test]
    fn test_access_control_transparent_proxy() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = "require(msg.sender != _getAdmin(), \"Admin cannot fallback\");";

        let arena = ast::AstArena::new();
        let func = ast::Function::new(
            &arena,
            ast::Identifier::new("", ast::SourceLocation::default()),
            ast::SourceLocation::default(),
        );
        assert!(detector.has_access_control(source, &func));
    }

    #[test]
    fn test_access_control_mapping_based() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        let source = "require(isSigner[msg.sender], \"Not authorized\");";

        let arena = ast::AstArena::new();
        let func = ast::Function::new(
            &arena,
            ast::Identifier::new("", ast::SourceLocation::default()),
            ast::SourceLocation::default(),
        );
        assert!(detector.has_access_control(source, &func));
    }

    #[test]
    fn test_constructor_set_impl_no_setter() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        // Contract with constructor-set implementation and standard assembly
        // but no public setter function = standard proxy pattern (regardless of name)
        let source = r#"
            contract AdminFunctionShadowing {
                address public implementation;
                address public owner;
                constructor(address _implementation) {
                    implementation = _implementation;
                    owner = msg.sender;
                }
                function transferOwnership(address newOwner) external {
                    require(msg.sender == owner, "Only owner");
                    owner = newOwner;
                }
                fallback() external payable {
                    address impl = implementation;
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "AdminFunctionShadowing", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        // Standard assembly, constructor-set impl, no setter = proxy pattern
        assert!(detector.is_standard_proxy_pattern(source, &ctx));
    }

    #[test]
    fn test_unprotected_setter_not_skipped() {
        let detector = FallbackDelegatecallUnprotectedDetector::new();
        // Contract with an unprotected setImplementation - should NOT be skipped
        let source = r#"
            contract VulnerableProxy {
                address public implementation;
                constructor(address _impl) { implementation = _impl; }
                function setImplementation(address newImpl) external {
                    implementation = newImpl;
                }
                fallback() external payable {
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                    }
                }
            }
        "#;
        let arena = ast::AstArena::new();
        let contract = create_mock_ast_contract(&arena, "VulnerableProxy", vec![]);
        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        // Has unprotected setter - should NOT be treated as standard proxy
        assert!(!detector.is_standard_proxy_pattern(source, &ctx));
    }
}
