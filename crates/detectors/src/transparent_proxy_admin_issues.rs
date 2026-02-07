use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for transparent proxy admin issues
///
/// In transparent proxies, the admin cannot call implementation functions
/// (they are routed to admin-only functions). This can cause issues if:
/// 1. Admin tries to interact with implementation (calls fail silently)
/// 2. Admin address is used for both admin and user operations
/// 3. Admin function selectors clash with implementation
///
/// ## Context-aware false positive reduction
///
/// This detector applies multiple layers of FP reduction:
/// - **Non-proxy gate**: Skips contracts that are not proxy contracts at all
/// - **OpenZeppelin skip**: Skips well-audited OZ TransparentUpgradeableProxy
/// - **ProxyAdmin skip**: Skips contracts using the ProxyAdmin pattern correctly
/// - **UUPS skip**: UUPS proxies have a different admin model (no ifAdmin routing)
/// - **Diamond/EIP-2535 skip**: Diamond proxies use facet routing, not admin routing
/// - **Beacon proxy skip**: Beacon proxies delegate to an external beacon, no admin routing
/// - **View/pure/internal/private skip**: Non-state-changing or non-public functions
///   cannot cause admin routing issues
/// - **Proper admin separation**: Contracts with proper ifAdmin/onlyAdmin patterns
///   that correctly separate admin and user call paths are not flagged
/// - **Library/Interface skip**: Libraries and interfaces are not proxy contracts
pub struct TransparentProxyAdminIssuesDetector {
    base: BaseDetector,
}

impl Default for TransparentProxyAdminIssuesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparentProxyAdminIssuesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("transparent-proxy-admin-issues"),
                "Transparent Proxy Admin Issues".to_string(),
                "Detects potential issues with transparent proxy admin patterns including \
                 selector conflicts and admin routing problems"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Contract-level false-positive guards
    // -----------------------------------------------------------------------

    /// Extract contract-scoped source code (avoids cross-contract FPs in same file)
    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            ctx.source_code.clone()
        }
    }

    /// FP Reduction: Skip library and interface contracts entirely.
    /// Libraries cannot be proxies and interfaces have no implementation.
    fn is_library_or_interface(&self, ctx: &AnalysisContext) -> bool {
        matches!(
            ctx.contract.contract_type,
            ast::ContractType::Library | ast::ContractType::Interface
        )
    }

    /// FP Reduction: Gate detection to actual proxy contracts.
    /// A contract must exhibit strong proxy signals to be analyzed.
    fn is_proxy_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Contract name contains "proxy"
        if contract_name.contains("proxy") {
            return true;
        }

        // EIP-1967 storage slots (implementation, admin, beacon)
        let has_eip1967_slots = source.contains("IMPLEMENTATION_SLOT")
            || source.contains("_IMPLEMENTATION_SLOT")
            || source.contains("EIP1967")
            || source.contains("ERC1967")
            || source
                .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source
                .contains("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103");

        // Explicit proxy inheritance
        let has_proxy_inheritance = source.contains("TransparentUpgradeableProxy")
            || source.contains("TransparentProxy")
            || source.contains("UUPSUpgradeable")
            || source.contains("BeaconProxy")
            || source.contains("ERC1967Proxy");

        // Fallback + delegatecall pattern
        let has_delegatecall_fallback = (source.contains("fallback")
            || source.contains("_fallback"))
            && source.contains("delegatecall");

        // ifAdmin routing pattern (transparent proxy specific)
        let has_if_admin = source.contains("ifAdmin") && source.contains("delegatecall");

        has_eip1967_slots || has_proxy_inheritance || has_delegatecall_fallback || has_if_admin
    }

    /// FP Reduction: Check if this is a transparent proxy specifically
    /// (as opposed to UUPS, Diamond, or Beacon).
    fn is_transparent_proxy(&self, source: &str) -> bool {
        source.contains("TransparentUpgradeableProxy")
            || source.contains("TransparentProxy")
            || (source.contains("_admin()") && source.contains("_fallback()"))
            || (source.contains("ifAdmin") && source.contains("delegatecall"))
    }

    /// FP Reduction: Skip well-audited OpenZeppelin TransparentUpgradeableProxy.
    /// OZ contracts are thoroughly audited and use proper admin separation via
    /// the ifAdmin modifier and EIP-1967 admin slots.
    fn is_openzeppelin_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let file_path = ctx.file_path.to_lowercase();

        // File path indicates OZ vendored dependency
        let is_oz_path = file_path.contains("@openzeppelin")
            || file_path.contains("/openzeppelin-contracts/")
            || file_path.contains("/dependencies/openzeppelin/")
            || file_path.contains("/vendor/openzeppelin/")
            || (file_path.contains("openzeppelin") && file_path.contains("/proxy/"));

        // Source contains OZ license/header or SPDX
        let has_oz_header =
            source.contains("OpenZeppelin Contracts") || source.contains("openzeppelin-contracts");

        // OZ TransparentUpgradeableProxy has ADMIN_SLOT + ifAdmin + AdminChanged event
        let has_oz_admin_pattern = source.contains("ADMIN_SLOT")
            && (source.contains("ifAdmin") || source.contains("onlyAdmin"))
            && source.contains("AdminChanged");

        // Standard OZ pattern: TransparentUpgradeableProxy with ERC1967 base
        let is_oz_transparent = source.contains("TransparentUpgradeableProxy")
            && (source.contains("ERC1967") || source.contains("_ADMIN_SLOT"));

        is_oz_path || (has_oz_header && has_oz_admin_pattern) || is_oz_transparent
    }

    /// FP Reduction: Skip contracts that correctly use the ProxyAdmin pattern.
    /// When a ProxyAdmin contract manages admin operations, the proxy itself
    /// is not vulnerable to admin routing issues.
    fn uses_proxy_admin_pattern(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);

        // ProxyAdmin contract or inheritance
        let has_proxy_admin =
            source.contains("ProxyAdmin") || source.contains("ITransparentUpgradeableProxy");

        // Admin set to a contract (not EOA) via constructor
        let admin_is_contract = source.contains("ProxyAdmin(")
            || source.contains("new ProxyAdmin")
            || source.contains("_changeAdmin(address(");

        // Proper admin separation: admin address stored and only used in ifAdmin
        let has_proper_separation = source.contains("ifAdmin")
            && source.contains("_fallback()")
            && (source.contains("_admin()") || source.contains("_getAdmin()"));

        has_proxy_admin || admin_is_contract || has_proper_separation
    }

    /// FP Reduction: Skip UUPS proxies (EIP-1822).
    /// UUPS proxies have upgrade logic in the implementation, not the proxy.
    /// They do not use the transparent proxy admin routing pattern.
    fn is_uups_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        if contract_name.contains("uups") {
            return true;
        }

        // UUPS pattern: implementation contains upgradeToAndCall + _authorizeUpgrade
        if source.contains("UUPSUpgradeable") || source.contains("_authorizeUpgrade") {
            return true;
        }

        // UUPS proxy: EIP-1967 slots but no admin routing (no ifAdmin)
        if source.contains("eip1967.proxy.implementation")
            && !source.contains("ifAdmin")
            && !source.contains("_admin()")
        {
            return true;
        }

        false
    }

    /// FP Reduction: Skip Diamond proxies (EIP-2535).
    /// Diamond proxies use facet routing via selectorToFacet mapping, not admin routing.
    fn is_diamond_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        if contract_name.contains("diamond") {
            return true;
        }

        // Diamond storage/routing patterns
        source.contains("diamond.standard.diamond.storage")
            || source.contains("selectorToFacet")
            || source.contains("selectorToFacetAndPosition")
            || source.contains("IDiamondCut")
            || source.contains("IDiamondLoupe")
            || source.contains("facetAddress")
            || source.contains("DiamondCut")
    }

    /// FP Reduction: Skip Beacon proxies.
    /// Beacon proxies get implementation from a beacon contract, no admin routing.
    fn is_beacon_proxy(&self, ctx: &AnalysisContext) -> bool {
        let source = self.get_contract_source(ctx.contract, ctx);
        let contract_name = ctx.contract.name.name.to_lowercase();

        if contract_name.contains("beacon") {
            return true;
        }

        source.contains("IBeacon") && source.contains("implementation")
    }

    // -----------------------------------------------------------------------
    // Function-level false-positive guards
    // -----------------------------------------------------------------------

    /// FP Reduction: Check if a line is inside a view/pure/internal/private function.
    /// These functions cannot cause transparent proxy admin routing issues because:
    /// - view/pure: no state changes, safe to call from any context
    /// - internal/private: not callable externally, cannot clash with proxy admin
    fn is_in_non_vulnerable_function(&self, lines: &[&str], line_idx: usize) -> bool {
        // Walk backwards to find the enclosing function declaration
        for i in (0..=line_idx).rev() {
            let trimmed = lines[i].trim();

            // Stop at contract boundary
            if trimmed.starts_with("contract ")
                || trimmed.starts_with("abstract contract ")
                || trimmed.starts_with("library ")
                || trimmed.starts_with("interface ")
            {
                return false;
            }

            if trimmed.contains("function ") || trimmed.starts_with("function ") {
                // Check for view/pure (no state changes - safe in proxy context)
                if trimmed.contains(" view ") || trimmed.contains(" pure ") {
                    return true;
                }
                // Check for internal/private (not externally callable - no selector clash)
                if trimmed.contains(" internal ") || trimmed.contains(" private ") {
                    return true;
                }
                // Found the function, it's public/external and state-changing
                return false;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Issue detection (with FP reduction integrated)
    // -----------------------------------------------------------------------

    /// Check for admin-related issues with FP-aware filtering
    fn find_admin_issues(&self, source: &str, ctx: &AnalysisContext) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let contract_source = self.get_contract_source(ctx.contract, ctx);

        for (i, line) in lines.iter().enumerate() {
            // FP Reduction: Skip lines inside view/pure/internal/private functions
            if self.is_in_non_vulnerable_function(&lines, i) {
                continue;
            }

            // Check for admin calling implementation functions
            if line.contains("admin.call(") || line.contains("admin.delegatecall(") {
                // FP Reduction: If contract has proper ifAdmin routing, this is likely
                // intentional admin-to-implementation forwarding
                if contract_source.contains("ifAdmin") && contract_source.contains("_delegate(") {
                    continue;
                }

                issues.push((
                    (i + 1) as u32,
                    "Admin address used for delegatecall - admin cannot call implementation \
                     functions in transparent proxy pattern"
                        .to_string(),
                ));
            }

            // Check for missing ifAdmin modifier on admin functions
            if (line.contains("function upgradeTo")
                || line.contains("function changeAdmin")
                || line.contains("function admin()"))
                && !line.contains("ifAdmin")
                && source.contains("TransparentUpgradeableProxy")
            {
                // FP Reduction: Skip if the function is internal/private (helper, not entry point)
                if line.contains(" internal ") || line.contains(" private ") {
                    continue;
                }

                // FP Reduction: Skip if the function is view/pure (read-only admin getter)
                if line.contains(" view ") || line.contains(" pure ") {
                    continue;
                }

                // FP Reduction: If contract has onlyAdmin or require(msg.sender == admin),
                // it uses a different but valid access control pattern
                if line.contains("onlyAdmin")
                    || line.contains("onlyOwner")
                    || line.contains("onlyProxyAdmin")
                {
                    continue;
                }

                // FP Reduction: Check if the function has access control on subsequent lines
                let func_end = lines
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, l)| l.trim() == "}" || l.contains("function "))
                    .map(|(idx, _)| idx)
                    .unwrap_or(lines.len());
                let func_body: String = lines[i..func_end].join("\n");
                if func_body.contains("require(msg.sender == admin")
                    || func_body.contains("require(msg.sender == _admin")
                    || func_body.contains("_checkAdmin()")
                {
                    continue;
                }

                issues.push((
                    (i + 1) as u32,
                    "Admin function may be missing ifAdmin modifier".to_string(),
                ));
            }

            // Check for potential admin address reuse
            if line.contains("admin = msg.sender") && source.contains("initialize") {
                // FP Reduction: If ProxyAdmin is used, msg.sender is the deployer setting
                // a separate ProxyAdmin contract, not reusing the admin address
                if source.contains("ProxyAdmin") || source.contains("_changeAdmin(") {
                    continue;
                }

                // FP Reduction: If there is proper admin separation logic nearby
                if contract_source.contains("require(admin != msg.sender")
                    || contract_source.contains("admin != _msgSender()")
                {
                    continue;
                }

                issues.push((
                    (i + 1) as u32,
                    "Setting admin to msg.sender in initializer - admin should be separate \
                     from users"
                        .to_string(),
                ));
            }
        }

        issues
    }

    /// Check for implementation contracts that might conflict, with FP reduction
    fn check_implementation_conflicts(
        &self,
        source: &str,
        ctx: &AnalysisContext,
    ) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // FP Reduction: Only check actual implementation contracts (Initializable or Upgradeable)
        // that will be used behind a transparent proxy
        let is_implementation = source.contains("Initializable") || source.contains("Upgradeable");
        if !is_implementation {
            return issues;
        }

        // FP Reduction: Skip if the contract IS the proxy itself (proxy redefines these
        // functions intentionally via ifAdmin routing)
        if self.is_transparent_proxy(source) {
            return issues;
        }

        // FP Reduction: Skip if this is a UUPS implementation (it is supposed to have
        // upgradeTo because UUPS puts upgrade logic in the implementation)
        if source.contains("UUPSUpgradeable") || source.contains("_authorizeUpgrade") {
            return issues;
        }

        // FP Reduction: Skip if this is a Diamond facet
        if source.contains("IDiamondCut")
            || source.contains("DiamondCut")
            || source.contains("facetAddress")
        {
            return issues;
        }

        for (i, line) in lines.iter().enumerate() {
            // FP Reduction: Skip lines inside view/pure/internal/private functions
            if self.is_in_non_vulnerable_function(&lines, i) {
                continue;
            }

            // Functions that could clash with transparent proxy admin
            let clash_patterns = [
                ("function admin(", "admin()"),
                ("function upgradeTo(", "upgradeTo(address)"),
                ("function implementation(", "implementation()"),
            ];

            for (pattern, name) in &clash_patterns {
                if line.contains(*pattern) {
                    // FP Reduction: view/pure implementations are read-only and typically
                    // safe even if they share the selector, because the admin routing
                    // will intercept them anyway
                    if line.contains(" view ") || line.contains(" pure ") {
                        continue;
                    }

                    // FP Reduction: internal/private functions do not generate external
                    // selectors, so they cannot clash with the proxy admin interface
                    if line.contains(" internal ") || line.contains(" private ") {
                        continue;
                    }

                    // FP Reduction: If function has override keyword and matches a standard
                    // interface, it is likely intentional (e.g., IGovernor.admin())
                    if line.contains(" override ") {
                        continue;
                    }

                    issues.push((
                        (i + 1) as u32,
                        format!(
                            "Function '{}' in implementation will be unreachable by admin \
                             in transparent proxy pattern",
                            name
                        ),
                    ));
                }
            }
        }

        issues
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for TransparentProxyAdminIssuesDetector {
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

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // ---------------------------------------------------------------
        // Contract-level early exits (FP reduction)
        // ---------------------------------------------------------------

        // FP Reduction: Skip libraries and interfaces entirely
        if self.is_library_or_interface(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip non-proxy contracts for transparent proxy checks.
        // Implementation conflict checks run separately below.
        let contract_is_proxy = self.is_proxy_contract(ctx);

        // FP Reduction: Skip well-audited OpenZeppelin proxy implementations
        if self.is_openzeppelin_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip UUPS proxies (different admin model)
        if self.is_uups_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Diamond/EIP-2535 proxies (facet routing, not admin routing)
        if self.is_diamond_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Beacon proxies (no admin routing)
        if self.is_beacon_proxy(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip contracts correctly using the ProxyAdmin pattern
        if self.uses_proxy_admin_pattern(ctx) {
            return Ok(findings);
        }

        // ---------------------------------------------------------------
        // Transparent proxy specific issue detection
        // ---------------------------------------------------------------
        if contract_is_proxy && self.is_transparent_proxy(source) {
            let issues = self.find_admin_issues(source, ctx);

            for (line, issue_desc) in issues {
                let message = format!("Transparent proxy '{}': {}", contract_name, issue_desc);

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 20)
                    .with_cwe(436) // CWE-436: Interpretation Conflict
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Ensure admin operations and user operations use separate addresses. \
                         The admin address can only call admin functions, not implementation \
                         functions."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // ---------------------------------------------------------------
        // Implementation contract conflict detection (with FP filtering)
        // ---------------------------------------------------------------
        let conflicts = self.check_implementation_conflicts(source, ctx);
        for (line, issue_desc) in conflicts {
            let message = format!(
                "Implementation contract '{}': {}",
                contract_name, issue_desc
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, 20)
                .with_cwe(436)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Rename functions that clash with transparent proxy admin functions. \
                     Consider using UUPS pattern if implementation needs these function names."
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

    #[test]
    fn test_detector_properties() {
        let detector = TransparentProxyAdminIssuesDetector::new();
        assert_eq!(detector.name(), "Transparent Proxy Admin Issues");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_is_transparent_proxy() {
        let detector = TransparentProxyAdminIssuesDetector::new();
        assert!(detector.is_transparent_proxy("contract MyProxy is TransparentUpgradeableProxy {"));
        assert!(!detector.is_transparent_proxy("contract MyToken {"));
    }
}
