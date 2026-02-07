use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for fallback function shadowing vulnerabilities
///
/// This detector identifies cases where a proxy contract's fallback function
/// or explicit proxy functions shadow functions intended for the implementation contract.
///
/// **Vulnerability Pattern:**
/// - Proxy defines public/external functions with same names as implementation
/// - Fallback function has hardcoded selector checks that intercept calls
/// - Missing transparent proxy pattern (no ifAdmin modifier)
/// - Receive function shadows implementation's receive logic
/// - Function selectors conflict between proxy and implementation
///
/// **Risk:**
/// - Functions in implementation become unreachable
/// - State corruption due to misrouted calls
/// - Critical functions like upgrade/pause become ineffective
/// - Unexpected behavior when users call shadowed functions
///
/// **Real-world Impact:**
/// - Multiple proxy implementations with misrouted admin functions
/// - Upgrade functions that don't actually upgrade
/// - Pause mechanisms that don't pause implementation
///
/// **CWE Mapping:**
/// - CWE-670: Always-Incorrect Control Flow Implementation
///
/// **Severity:** Medium
///
/// **FP Reduction v2 (comprehensive):**
/// - Skip contracts that have no fallback or receive function
/// - Skip view/pure functions (read-only, cannot shadow state-changing logic)
/// - Skip internal/private functions
/// - Skip standard proxy patterns: Diamond (EIP-2535), UUPS (EIP-1822), Beacon
/// - Skip proxy admin functions with proper access control (onlyOwner, onlyAdmin, etc.)
/// - Skip receive functions with empty bodies (intentional ETH acceptance)
/// - Skip fallbacks that explicitly revert (not routing calls to implementation)
///
/// **FP Reduction v3:**
/// - Skip contracts inheriting from known proxy base contracts (OpenZeppelin, etc.)
/// - Skip Transparent Proxy pattern with admin-separation in inheritance chain
/// - Skip EIP-1967 storage slot patterns with _beforeFallback() / _delegate() helpers
/// - Skip minimal proxy (EIP-1167 clone) contracts
/// - Skip fallback-only proxy contracts (no public/external non-fallback functions)
pub struct FallbackFunctionShadowingDetector {
    base: BaseDetector,
}

impl FallbackFunctionShadowingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("fallback-function-shadowing".to_string()),
                "Fallback Function Shadowing".to_string(),
                "Detects when proxy functions shadow implementation functions".to_string(),
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::Upgradeable,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Get contract source code (scoped to just this contract, not the whole file)
    /// FP Reduction: Avoids flagging non-proxy contracts that share a file with a proxy
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start > 0 && end <= source_lines.len() {
            let start_idx = start.saturating_sub(1);
            source_lines[start_idx..end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if contract has any fallback or receive function.
    /// FP Reduction: If a proxy contract has no fallback/receive, it cannot
    /// perform delegation, so function shadowing is not applicable.
    fn has_fallback_or_receive(&self, ctx: &AnalysisContext) -> bool {
        ctx.get_functions().iter().any(|f| {
            matches!(
                f.function_type,
                ast::FunctionType::Fallback | ast::FunctionType::Receive
            )
        })
    }

    /// Check if contract looks like a proxy
    /// FP Reduction: Uses contract-scoped source instead of file-level source
    /// to avoid flagging non-proxy contracts that happen to share a file with a proxy
    fn is_proxy_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Check if contract name suggests it's a proxy
        if contract_name.contains("proxy") {
            return true;
        }

        // Check if THIS contract has fallback with delegatecall (not just any contract in the file)
        if source.contains("fallback") && source.contains("delegatecall") {
            return true;
        }

        // Check for EIP-1967 storage slots within this contract
        if source.contains("eip1967.proxy.implementation") {
            return true;
        }

        false
    }

    /// Check if contract is a Diamond proxy (EIP-2535).
    /// FP Reduction: Diamond proxies intentionally route selectors through a storage
    /// mapping (selectorToFacet). This is by-design and not function shadowing.
    fn is_diamond_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Detect Diamond proxy by name
        if contract_name.contains("diamond") {
            return true;
        }

        // Detect Diamond proxy by storage pattern
        if source.contains("diamond.standard.diamond.storage")
            || source.contains("selectorToFacet")
            || source.contains("selectorToFacetAndPosition")
            || source.contains("IDiamondCut")
            || source.contains("IDiamondLoupe")
            || source.contains("facetAddress")
        {
            return true;
        }

        false
    }

    /// Check if contract is a UUPS proxy (EIP-1822).
    /// FP Reduction: UUPS proxies have NO admin functions in the proxy itself;
    /// all upgrade logic lives in the implementation. A minimal UUPS proxy only has
    /// fallback + receive + constructor, so there is nothing to shadow.
    fn is_uups_proxy(&self, ctx: &AnalysisContext) -> bool {
        let contract_name = ctx.contract.name.name.to_lowercase();

        if contract_name.contains("uups") {
            return true;
        }

        // UUPS pattern: proxy has EIP-1967 slots but NO public/external admin functions
        // (only fallback, receive, constructor, and private helpers)
        let source = self.get_contract_source(ctx.contract, ctx);
        if source.contains("eip1967.proxy.implementation") {
            let has_admin_functions = ctx.get_functions().iter().any(|f| {
                matches!(
                    f.visibility,
                    ast::Visibility::Public | ast::Visibility::External
                ) && !matches!(
                    f.function_type,
                    ast::FunctionType::Fallback
                        | ast::FunctionType::Receive
                        | ast::FunctionType::Constructor
                )
            });
            if !has_admin_functions {
                return true;
            }
        }

        false
    }

    /// Check if contract is a Beacon proxy.
    /// FP Reduction: Beacon proxies get their implementation from a separate beacon
    /// contract. They have no admin functions in the proxy itself.
    fn is_beacon_proxy(&self, ctx: &AnalysisContext) -> bool {
        let contract_name = ctx.contract.name.name.to_lowercase();
        let source = self.get_contract_source(ctx.contract, ctx);

        if contract_name.contains("beacon") {
            return true;
        }

        // Beacon pattern: uses IBeacon interface to get implementation
        if source.contains("IBeacon") && source.contains("implementation") {
            return true;
        }

        false
    }

    /// Check if contract is an immutable proxy (implementation cannot change).
    /// FP Reduction: Immutable proxies have a fixed implementation set at construction
    /// time. They cannot be upgraded and have minimal proxy interface.
    fn is_immutable_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        if contract_name.contains("immutable") {
            return true;
        }

        // Immutable pattern: uses `immutable` keyword for implementation address
        if source.contains("immutable implementation")
            || source.contains("address public immutable")
        {
            return true;
        }

        false
    }

    /// Check if contract inherits from a known proxy base contract.
    /// FP Reduction v3: OpenZeppelin and other standard proxy base contracts
    /// have well-audited fallback routing. Contracts inheriting from them
    /// follow established patterns and should not be flagged.
    fn inherits_known_proxy_base(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);

        // OpenZeppelin proxy base contracts
        let known_bases = [
            "TransparentUpgradeableProxy",
            "ERC1967Proxy",
            "ERC1967Upgrade",
            "UUPSUpgradeable",
            "BeaconProxy",
            "UpgradeableBeacon",
            "ProxyAdmin",
            "Proxy", // OpenZeppelin abstract Proxy base
            "MinimalForwarder",
        ];

        // Check inheritance: `contract X is KnownBase` or `contract X is A, KnownBase`
        for base in &known_bases {
            // Check "is BaseContract" patterns in contract header
            if source.contains(&format!("is {}", base))
                || source.contains(&format!("is {}", base))
                || source.contains(&format!(", {}", base))
                || source.contains(&format!(", {} ", base))
            {
                return true;
            }
        }

        false
    }

    /// Check if contract is a minimal proxy (EIP-1167 clone).
    /// FP Reduction v3: Minimal proxies are created by clone factories and have
    /// a fixed bytecode pattern. They have no admin functions and cannot be
    /// upgraded. Flagging them is always a false positive.
    fn is_minimal_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Name-based detection
        if contract_name.contains("clone") || contract_name.contains("minimal") {
            return true;
        }

        // EIP-1167 bytecode pattern (hex prefix of minimal proxy bytecode)
        if source.contains("363d3d373d3d3d363d73") || source.contains("3d602d80600a3d3981f3") {
            return true;
        }

        // OpenZeppelin Clones library usage
        if source.contains("Clones.clone") || source.contains("Clones.cloneDeterministic") {
            return true;
        }

        false
    }

    /// Check if the proxy contract is a fallback-only proxy with no public/external
    /// non-fallback functions beyond constructor.
    /// FP Reduction v3: A proxy with only fallback+receive+constructor has nothing
    /// to shadow. All calls go through fallback to the implementation.
    fn is_fallback_only_proxy(&self, ctx: &AnalysisContext) -> bool {
        let has_non_fallback_public = ctx.get_functions().iter().any(|f| {
            matches!(
                f.visibility,
                ast::Visibility::Public | ast::Visibility::External
            ) && !matches!(
                f.function_type,
                ast::FunctionType::Fallback
                    | ast::FunctionType::Receive
                    | ast::FunctionType::Constructor
            )
        });

        !has_non_fallback_public
    }

    /// Check if a function is a standard proxy admin/infrastructure function
    /// that is DESIGNED to exist in the proxy contract itself.
    /// These are NOT shadowing -- they are core proxy functionality.
    fn is_standard_proxy_function(&self, func_name: &str, func_source: &str) -> bool {
        // Standard proxy admin functions that modify proxy state (with access control)
        let proxy_admin_functions = [
            "upgradeto",
            "upgradetoandcall",
            "changeadmin",
            "setimplementation",
            "changeimplementation",
        ];

        // Standard proxy getter/view functions (always safe in proxy)
        let proxy_view_functions = ["implementation", "admin", "getimplementation", "getadmin"];

        // View/getter functions in proxy are always safe -- they read proxy state
        for view_fn in &proxy_view_functions {
            if func_name == *view_fn {
                return true;
            }
        }

        // Admin functions with access control are standard proxy functionality
        for admin_fn in &proxy_admin_functions {
            if func_name.contains(admin_fn) && self.has_access_control(func_source) {
                return true;
            }
        }

        false
    }

    /// Check if function has any form of access control
    fn has_access_control(&self, func_source: &str) -> bool {
        // Modifier-based access control
        func_source.contains("onlyOwner")
            || func_source.contains("onlyAdmin")
            || func_source.contains("onlyProxyAdmin")
            || func_source.contains("ifAdmin")
            // Require-based access control
            || func_source.contains("require(msg.sender == admin")
            || func_source.contains("require(msg.sender == owner")
            || func_source.contains("require(msg.sender == _admin")
            || func_source.contains("msg.sender == _getAdmin")
            || func_source.contains("msg.sender == getAdmin")
            || func_source.contains("_checkAdmin")
            || func_source.contains("_checkOwner")
            || func_source.contains("require(msg.sender ==")
    }

    /// Check if function could shadow implementation functions
    fn has_shadowing_risk(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_name = function.name.name.to_lowercase();
        let source = self.get_function_source(function, ctx);

        // Skip if function is internal or private (can't shadow)
        match function.visibility {
            ast::Visibility::Internal | ast::Visibility::Private => return None,
            _ => {}
        }

        // FP Reduction: Skip view/pure functions entirely.
        // View/pure functions only read state -- they read the proxy's own state
        // (e.g., implementation(), admin()) and do not shadow state-changing
        // implementation functions.
        if matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) {
            return None;
        }

        // FP Reduction: Skip fallback/receive function types -- these are checked
        // separately by has_hardcoded_selectors and has_receive_shadowing
        if matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        ) {
            return None;
        }

        // FP Reduction: Skip constructors -- they execute once at deployment
        // and cannot shadow implementation functions
        if matches!(function.function_type, ast::FunctionType::Constructor) {
            return None;
        }

        // Check for common proxy admin functions that might shadow implementation
        let risky_function_names = [
            "upgrade",
            "upgradeto",
            "setimplementation",
            "changeimplementation",
            "transferownership",
            "changeowner",
            "setowner",
            "pause",
            "unpause",
            "initialize",
            "init",
            "getadmin",
            "getowner",
            "getimplementation",
            "getversion",
        ];

        for risky_name in &risky_function_names {
            if func_name.contains(risky_name) {
                // Check if this is in a proxy contract
                if self.is_proxy_contract(ctx) {
                    // FP Reduction: If the function is a standard proxy admin function
                    // with proper access control, it is intentional proxy infrastructure,
                    // not shadowing.
                    if self.is_standard_proxy_function(&func_name, &source) {
                        return None;
                    }

                    // FP Reduction: If the function has any form of access control
                    // (onlyOwner, onlyAdmin, require(msg.sender == ...)), the developer
                    // intentionally restricted it, reducing shadowing risk.
                    if self.has_access_control(&source) {
                        return None;
                    }

                    // FP Reduction: Check for broader transparent proxy admin-separation
                    // patterns (ifAdmin modifier, admin check in fallback, etc.)
                    if self.has_if_admin_pattern(&source, ctx) {
                        return None;
                    }

                    return Some(format!(
                        "Function '{}' may shadow implementation's function. In transparent proxies, use ifAdmin pattern to separate admin and user calls",
                        function.name.name
                    ));
                }
            }
        }

        None
    }

    /// Check if fallback function has hardcoded selector checks
    fn has_hardcoded_selectors(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let source = self.get_function_source(function, ctx);

        // Check if fallback/receive function
        if !matches!(
            function.function_type,
            ast::FunctionType::Fallback | ast::FunctionType::Receive
        ) {
            return None;
        }

        // FP Reduction: Diamond proxies use storage-based selector routing via
        // selectorToFacet mapping. This is the recommended approach and should
        // not be flagged even though msg.sig is referenced.
        if self.is_diamond_proxy(ctx) {
            return None;
        }

        // FP Reduction: If the fallback uses a selector whitelist check
        // (e.g., require(allowedSelectors[selector])), this is a security pattern,
        // not hardcoded selector interception.
        if source.contains("allowedSelectors") || source.contains("whitelistedSelectors") {
            return None;
        }

        // Look for hardcoded selector checks
        if source.contains("msg.sig ==")
            || source.contains("msg.sig!=")
            || source.contains("selector ==")
        {
            // Check if there are multiple selector checks (likely routing logic)
            let selector_checks =
                source.matches("msg.sig").count() + source.matches("selector ==").count();
            if selector_checks > 0 {
                return Some(
                    "Fallback function has hardcoded selector checks. This can shadow implementation functions. \
                    Consider using Diamond pattern with storage-based routing or transparent proxy pattern".to_string()
                );
            }
        }

        // Check for hardcoded bytes4 selectors in fallback
        if source.contains("bytes4 private constant") && source.contains("SELECTOR") {
            let selector_defs = source.matches("bytes4 private constant").count();
            if selector_defs > 0 {
                return Some(
                    "Fallback defines hardcoded function selectors. These selectors will be intercepted and never reach implementation. \
                    Use storage-based selector routing instead".to_string()
                );
            }
        }

        None
    }

    /// Check if contract uses ifAdmin/transparent proxy pattern
    /// FP Reduction: Uses contract-scoped source and recognizes common transparent
    /// proxy admin-separation patterns (not just generic access control)
    fn has_if_admin_pattern(&self, source: &str, ctx: &AnalysisContext) -> bool {
        let contract_source = self.get_contract_source(ctx.contract, ctx);

        // Check for ifAdmin modifier in THIS contract (standard transparent proxy pattern)
        if contract_source.contains("modifier ifAdmin") {
            return true;
        }

        // Check for transparent proxy admin check patterns in the function
        // These specifically separate admin vs user paths (not just generic access control)
        if source.contains("msg.sender == admin")
            || source.contains("msg.sender == _getAdmin")
            || source.contains("msg.sender == getAdmin")
            || source.contains("msg.sender == _admin")
            || source.contains("ifAdmin")
            || source.contains("onlyProxyAdmin")
            || source.contains("_checkAdmin")
        {
            return true;
        }

        // FP Reduction: Check for admin-separation in the fallback function itself.
        // If the fallback blocks admin calls (transparent proxy pattern), the contract
        // is properly separating admin/user interfaces.
        let fallback_has_admin_separation = ctx.get_functions().iter().any(|f| {
            if matches!(f.function_type, ast::FunctionType::Fallback) {
                let fallback_source = self.get_function_source(f, ctx);
                // Transparent proxy patterns in fallback:
                // - require(msg.sender != _getAdmin(), ...)
                // - if (msg.sender == _getAdmin()) { return; }
                fallback_source.contains("msg.sender != _getAdmin")
                    || fallback_source.contains("msg.sender == _getAdmin")
                    || fallback_source.contains("msg.sender != admin")
                    || fallback_source.contains("msg.sender == admin")
            } else {
                false
            }
        });

        if fallback_has_admin_separation {
            return true;
        }

        false
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let lines: Vec<&str> = ctx.source_code.lines().collect();
        if start > 0 && end <= lines.len() {
            let start_idx = start.saturating_sub(1);
            lines[start_idx..end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if a receive function body is empty or minimal (just accepts ETH).
    /// FP Reduction: An empty receive() function like `receive() external payable {}`
    /// is a common pattern to accept ETH. It does not shadow any implementation logic
    /// because it only triggers on plain ETH transfers with no calldata.
    fn is_empty_receive(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        let source = self.get_function_source(function, ctx);

        // Trim the source and check if body is effectively empty
        // Patterns: `receive() external payable {}` or with modifiers
        let trimmed = source
            .replace("receive", "")
            .replace("external", "")
            .replace("payable", "")
            .replace("nonReentrant", "")
            .replace("whenNotPaused", "")
            .replace("()", "");
        let trimmed = trimmed.trim();

        // Empty body: just braces
        trimmed == "{}" || trimmed == "{ }" || trimmed.is_empty()
    }

    /// Check if receive function exists alongside fallback
    /// FP Reduction: Skip receive functions that delegate to the implementation
    /// (this is proper transparent proxy behavior, not shadowing)
    fn has_receive_shadowing(&self, ctx: &AnalysisContext) -> Option<String> {
        let mut has_receive = false;
        let mut receive_delegates = false;
        let mut receive_is_empty = false;
        let mut receive_calls_fallback = false;
        let mut has_fallback_with_delegatecall = false;

        for function in ctx.get_functions() {
            match function.function_type {
                ast::FunctionType::Receive => {
                    has_receive = true;
                    let source = self.get_function_source(function, ctx);
                    // FP Reduction: If receive() delegates to implementation, it's not shadowing
                    if source.contains("_delegate") || source.contains("delegatecall") {
                        receive_delegates = true;
                    }
                    // FP Reduction: If receive() is empty, it just accepts ETH
                    if self.is_empty_receive(function, ctx) {
                        receive_is_empty = true;
                    }
                    // FP Reduction: If receive() calls _fallback(), it routes to implementation
                    if source.contains("_fallback") {
                        receive_calls_fallback = true;
                    }
                }
                ast::FunctionType::Fallback => {
                    let source = self.get_function_source(function, ctx);
                    if source.contains("delegatecall") {
                        has_fallback_with_delegatecall = true;
                    }
                }
                _ => {}
            }
        }

        // FP Reduction: If receive() delegates to implementation, it's not shadowing
        // This is the correct transparent proxy pattern
        if receive_delegates {
            return None;
        }

        // FP Reduction: If receive() calls _fallback() which delegates, it's not shadowing
        if receive_calls_fallback {
            return None;
        }

        // FP Reduction: If receive() has an empty body, it simply accepts ETH.
        // This is standard practice in proxies (UUPS, Beacon, etc.) and does not
        // shadow any implementation logic.
        if receive_is_empty {
            return None;
        }

        // Only flag if proxy has a receive function that does NOT delegate
        if has_receive && has_fallback_with_delegatecall && self.is_proxy_contract(ctx) {
            return Some(
                "Proxy defines receive() function which shadows implementation's receive logic. \
                Consider delegating receive to implementation or documenting why proxy handles ETH"
                    .to_string(),
            );
        }

        None
    }
}

impl Default for FallbackFunctionShadowingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FallbackFunctionShadowingDetector {
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


        // Skip if not a proxy contract
        if !self.is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip if contract has no fallback or receive function.
        // Without a fallback/receive, the contract cannot delegate calls to an
        // implementation, so function shadowing is not possible.
        if !self.has_fallback_or_receive(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Diamond proxies entirely.
        // Diamond proxies (EIP-2535) use a storage-based mapping of selectors to facets.
        // Functions like facets(), facetAddress(), diamondCut() are part of the Diamond
        // standard and are intentional, not shadowing.
        if self.is_diamond_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip UUPS proxies.
        // UUPS proxies (EIP-1822) have NO admin functions in the proxy itself.
        // All upgrade logic lives in the implementation contract.
        if self.is_uups_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Beacon proxies.
        // Beacon proxies get their implementation from a beacon contract.
        // They typically have no admin functions in the proxy.
        if self.is_beacon_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Immutable proxies.
        // Immutable proxies have a fixed implementation set at deployment.
        // They cannot be upgraded and have minimal proxy interface.
        if self.is_immutable_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction v3: Skip contracts inheriting from known proxy base contracts.
        // OpenZeppelin TransparentUpgradeableProxy, ERC1967Proxy, etc. have
        // well-audited fallback routing. Inherited patterns are safe by design.
        if self.inherits_known_proxy_base(ctx) {
            return Ok(findings);
        }

        // FP Reduction v3: Skip minimal proxies (EIP-1167 clones).
        // These have fixed bytecode with no admin functions.
        if self.is_minimal_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction v3: Skip fallback-only proxies.
        // If the proxy has no public/external functions besides fallback/receive/constructor,
        // there is nothing to shadow. All calls route through fallback to implementation.
        if self.is_fallback_only_proxy(ctx) {
            return Ok(findings);
        }

        // Check for receive function shadowing
        if let Some(issue) = self.has_receive_shadowing(ctx) {
            let message = format!(
                "Contract '{}' has receive function shadowing. {}",
                ctx.contract.name.name, issue
            );

            let finding = self
                .base
                .create_finding(
                    ctx,
                    message,
                    ctx.contract.name.location.start().line() as u32,
                    ctx.contract.name.location.start().column() as u32,
                    ctx.contract.name.name.len() as u32,
                )
                .with_cwe(670);

            findings.push(finding);
        }

        // Check each function for shadowing risks
        for function in ctx.get_functions() {
            // Check for shadowing risk in regular functions
            if let Some(risk_description) = self.has_shadowing_risk(function, ctx) {
                let message = format!(
                    "Function '{}' in proxy contract may shadow implementation. {} \
                    Real-world impact: Similar to issues in various proxy implementations where admin functions were shadowed.",
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
                    .with_cwe(670);

                findings.push(finding);
            }

            // Check for hardcoded selectors in fallback
            if let Some(selector_issue) = self.has_hardcoded_selectors(function, ctx) {
                let message = format!(
                    "Fallback function '{}' has hardcoded selector routing. {}",
                    function.name.name, selector_issue
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
                    .with_cwe(670);

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
    fn test_detector_properties() {
        let detector = FallbackFunctionShadowingDetector::new();
        assert_eq!(detector.id().0, "fallback-function-shadowing");
        assert_eq!(detector.name(), "Fallback Function Shadowing");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_default() {
        let detector = FallbackFunctionShadowingDetector::default();
        assert_eq!(detector.id().0, "fallback-function-shadowing");
    }
}
