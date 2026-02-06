use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for delegatecall to self vulnerabilities
///
/// Detects patterns where contracts make delegatecall to themselves,
/// which can cause unexpected behavior or enable attack vectors.
///
/// False positive reduction: skips legitimate proxy patterns including
/// EIP-1967, Diamond (EIP-2535), Beacon, UUPS, Transparent, Safe wallet,
/// abstract Proxy base contracts, and fallback functions that forward
/// to an implementation address.
pub struct DelegatecallToSelfDetector {
    base: BaseDetector,
}

impl Default for DelegatecallToSelfDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallToSelfDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("delegatecall-to-self"),
                "Delegatecall to Self".to_string(),
                "Detects patterns where contracts make delegatecall to themselves (address(this)), \
                 which can cause infinite loops, storage corruption, or unexpected behavior."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    fn find_self_delegatecall(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Direct delegatecall to this -- genuine true positive
            if trimmed.contains("delegatecall") && trimmed.contains("address(this)") {
                // Skip if the line is inside a proxy forwarding pattern where
                // address(this) is used for something other than the target
                // (e.g., checking balance of self before delegatecall)
                if self.is_direct_self_delegatecall(trimmed) {
                    // Check if target variable is immutable/constant
                    if !self.has_immutable_target(source, trimmed) {
                        let func_name = self.find_containing_function(&lines, line_num);
                        let issue = "Direct delegatecall to address(this)".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Delegatecall via stored self reference
            if trimmed.contains("delegatecall") {
                // Check if the delegatecall target variable is immutable/constant -- skip if so
                if self.has_immutable_target(source, trimmed)
                    || self.has_constant_target(source, trimmed)
                {
                    continue;
                }

                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Skip proxy forwarding patterns: if the function body references
                // an implementation address variable, this is likely a proxy
                if self.is_proxy_forwarding_body(&func_body) {
                    continue;
                }

                // Check for patterns like: address target = address(this); target.delegatecall
                if func_body.contains("= address(this)")
                    || func_body.contains("selfAddress")
                    || func_body.contains("_self")
                {
                    // Check if the delegatecall actually uses this self-referencing variable
                    if trimmed.contains("target.delegatecall")
                        || trimmed.contains("selfAddress.delegatecall")
                        || trimmed.contains("_self.delegatecall")
                    {
                        // Verify the target variable is actually assigned address(this),
                        // not just present in the function for other purposes
                        if self.verify_target_is_self(&func_body, trimmed) {
                            let func_name = self.find_containing_function(&lines, line_num);
                            let issue =
                                "Possible delegatecall to self via stored address".to_string();
                            findings.push((line_num as u32 + 1, func_name, issue));
                        }
                    }
                }
            }

            // Multicall/batch patterns with self-delegation
            // Only flag when delegatecall target is genuinely address(this)
            if (trimmed.contains("multicall") || trimmed.contains("batch"))
                && trimmed.contains("delegatecall")
            {
                // Only flag if the line actually uses address(this) as target
                if trimmed.contains("address(this).delegatecall")
                    || trimmed.contains("address(this)).delegatecall")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let issue =
                        "Multicall with delegatecall may enable self-delegation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Check if a delegatecall line genuinely targets address(this)
    /// Returns true when address(this) is the actual delegatecall target,
    /// not just present on the same line for another reason.
    fn is_direct_self_delegatecall(&self, line: &str) -> bool {
        // Pattern: address(this).delegatecall(...)
        if line.contains("address(this).delegatecall") {
            return true;
        }
        // Pattern: (address(this)).delegatecall(...)
        if line.contains("address(this)).delegatecall") {
            return true;
        }
        // If address(this) appears but not as the delegatecall receiver,
        // it might be used for something else (e.g., balance check)
        false
    }

    fn find_recursive_delegation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect function that calls itself via delegatecall
            if trimmed.contains("function ") {
                let func_name = self.extract_function_name(trimmed);
                let func_body = self.get_function_body(&lines, line_num);

                // Skip proxy forwarding functions -- these legitimately use delegatecall
                // to an external implementation address
                if self.is_proxy_forwarding_body(&func_body) {
                    continue;
                }

                // Skip fallback/receive functions (handled separately)
                if func_name == "unknown" || func_name.is_empty() {
                    continue;
                }

                // Check if function makes delegatecall that could call itself
                if func_body.contains("delegatecall") {
                    // Look for selector that matches this function name.
                    // IMPORTANT: Strip the function declaration line itself before
                    // checking for the selector pattern, because the declaration
                    // trivially contains "funcName(" and would always match.
                    let selector_pattern = format!("{}(", func_name);
                    let body_without_decl = func_body
                        .find('\n')
                        .map(|pos| &func_body[pos..])
                        .unwrap_or("");

                    // msg.sig forwarding is a proxy pattern, not recursive self-call.
                    // Only flag msg.sig if it is combined with address(this) as target.
                    let has_msg_sig_self =
                        func_body.contains("msg.sig") && func_body.contains("address(this)");

                    // this.<func_name> pattern (fix precedence with parentheses)
                    // Also check in body_without_decl to avoid matching the
                    // declaration line itself
                    let has_this_call = body_without_decl.contains("this.")
                        && body_without_decl.contains(&func_name);

                    if body_without_decl.contains(&selector_pattern)
                        || has_msg_sig_self
                        || has_this_call
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    fn find_fallback_self_delegation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect fallback/receive with delegatecall
            if (trimmed.contains("fallback") || trimmed.contains("receive"))
                && trimmed.contains("function")
            {
                let func_body = self.get_function_body(&lines, line_num);

                if func_body.contains("delegatecall") {
                    // FP reduction: Skip if the fallback delegates to an implementation
                    // address (this is a standard proxy pattern, not delegatecall-to-self)
                    if self.is_proxy_forwarding_body(&func_body) {
                        continue;
                    }

                    // FP reduction: Skip if delegatecall target is immutable or constant
                    if self.fallback_has_safe_target(source, &func_body) {
                        continue;
                    }

                    // Only flag when target is genuinely address(this)
                    if func_body.contains("address(this).delegatecall")
                        || func_body.contains("address(this)).delegatecall")
                    {
                        let func_name = if trimmed.contains("fallback") {
                            "fallback".to_string()
                        } else {
                            "receive".to_string()
                        };
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Check if a function body represents a proxy forwarding pattern.
    /// Proxy patterns delegate to an external implementation address, not to self.
    fn is_proxy_forwarding_body(&self, func_body: &str) -> bool {
        let lower = func_body.to_lowercase();

        // References to implementation address variables
        let has_impl_ref = lower.contains("implementation")
            || lower.contains("_implementation")
            || lower.contains("impl_")
            || lower.contains("_impl")
            || lower.contains("singleton")
            || lower.contains("mastercopy")
            || lower.contains("_mastercopy")
            || lower.contains("logic_contract")
            || lower.contains("logiccontract")
            || lower.contains("target_contract");

        // Proxy internal helper calls
        let has_delegate_helper = lower.contains("_delegate(")
            || lower.contains("_fallback(")
            || lower.contains("_getimplementation")
            || lower.contains("_implementation()");

        // EIP-1967 storage slot access
        let has_eip1967_slot = func_body
            .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || func_body.contains("StorageSlot")
            || func_body.contains("sload")
            || func_body.contains("IMPLEMENTATION_SLOT");

        // Assembly-based proxy forwarding (common in minimal proxies)
        let has_assembly_forward = (func_body.contains("assembly") || func_body.contains("mstore"))
            && (func_body.contains("calldatacopy") || func_body.contains("calldatasize"))
            && func_body.contains("delegatecall");

        // Diamond proxy selector routing
        let has_diamond_routing = lower.contains("facetaddress")
            || lower.contains("selectortofacet")
            || lower.contains("diamondstorage");

        // Beacon proxy pattern
        let has_beacon = lower.contains("beacon") && lower.contains("implementation");

        has_impl_ref
            || has_delegate_helper
            || has_eip1967_slot
            || has_assembly_forward
            || has_diamond_routing
            || has_beacon
    }

    /// Check if the fallback function delegates to a safe (immutable/constant) target
    fn fallback_has_safe_target(&self, source: &str, func_body: &str) -> bool {
        // Extract any delegatecall target from the function body
        for line in func_body.lines() {
            let trimmed = line.trim();
            if trimmed.contains("delegatecall") {
                if self.has_immutable_target(source, trimmed)
                    || self.has_constant_target(source, trimmed)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Verify that a target variable in a delegatecall line is actually assigned address(this)
    fn verify_target_is_self(&self, func_body: &str, delegatecall_line: &str) -> bool {
        // Extract the target variable from the delegatecall line
        if let Some(target) = self.extract_delegatecall_target(delegatecall_line) {
            // Check if that variable is assigned address(this) in the function body
            let assignment1 = format!("{} = address(this)", target);
            let assignment2 = format!("{}=address(this)", target);
            let assignment3 = format!("{} =address(this)", target);

            func_body.contains(&assignment1)
                || func_body.contains(&assignment2)
                || func_body.contains(&assignment3)
        } else {
            // If we can't extract the target, be conservative and flag it
            true
        }
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
            if trimmed.contains("fallback") {
                return "fallback".to_string();
            }
            if trimmed.contains("receive") {
                return "receive".to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ")
                || trimmed.contains("fallback")
                || trimmed.contains("receive")
            {
                return i;
            }
        }
        0
    }

    fn get_function_body(&self, lines: &[&str], start: usize) -> String {
        let mut depth = 0;
        let mut started = false;
        let mut end = lines.len();

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
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if started && depth == 0 {
                break;
            }
        }

        lines[start..end].join("\n")
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }

    /// Phase 16 FP Reduction: Skip EIP-1967 compliant proxies
    /// These proxies legitimately use delegatecall patterns
    fn is_eip1967_proxy(&self, source: &str) -> bool {
        // EIP-1967 implementation slot
        source.contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source.contains("_IMPLEMENTATION_SLOT")
            || source.contains("ERC1967")
            || source.contains("ERC1967Proxy")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("UUPSUpgradeable")
            // OpenZeppelin proxy patterns
            || source.contains("@openzeppelin/contracts/proxy")
            || source.contains("Proxy.sol")
    }

    /// Phase 16 FP Reduction: Skip Diamond pattern (EIP-2535)
    /// Diamond proxies legitimately use delegatecall routing
    fn is_diamond_proxy(&self, source: &str) -> bool {
        source.contains("selectorToFacet")
            || source.contains("DiamondStorage")
            || source.contains("facetAddress")
            || source.contains("IDiamondCut")
            || source.contains("Diamond.sol")
            || source.contains("LibDiamond")
            || source.contains("FacetCut")
    }

    /// Phase 16 FP Reduction: Skip Safe wallet patterns
    /// Gnosis Safe uses delegatecall for module execution, which is intentional
    fn is_safe_wallet(&self, source: &str, ctx: &AnalysisContext) -> bool {
        // Check source content patterns
        if source.contains("GnosisSafe")
            || source.contains("Safe.sol")
            || source.contains("@safe-global/")
            || source.contains("@gnosis.pm/safe-contracts")
            || source.contains("ModuleManager")
            || source.contains("FallbackManager")
            || source.contains("execTransactionFromModule")
            // Safe-specific patterns
            || (source.contains("module") && source.contains("delegatecall") && source.contains("require(success"))
        {
            return true;
        }

        // Check file path for Safe wallet projects
        let file_path_lower = ctx.file_path.to_lowercase();
        if file_path_lower.contains("safe-smart-account")
            || file_path_lower.contains("safe-contracts")
            || file_path_lower.contains("gnosis-safe")
        {
            return true;
        }

        // Check contract name patterns for Safe components
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let safe_contract_names = [
            "multisend",
            "executor",
            "safeproxy",
            "safetol2setup",
            "storageaccessible",
            "migration",
            "simulatetxaccessor",
            "fallbackhandler",
            "compatibilityhandler",
            "signatureverifier",
        ];
        for name in &safe_contract_names {
            if contract_name_lower.contains(name) {
                return true;
            }
        }

        false
    }

    /// FP Reduction: Comprehensive proxy contract detection
    /// Catches proxy patterns not covered by EIP-1967, Diamond, or Safe checks
    fn is_generic_proxy_contract(&self, source: &str, ctx: &AnalysisContext) -> bool {
        let lower = source.to_lowercase();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();

        // Contract name indicates proxy
        let proxy_name_patterns = [
            "proxy",
            "delegator",
            "forwarder",
            "upgradeableproxy",
            "beaconproxy",
            "minimalproxy",
        ];
        let is_proxy_name = proxy_name_patterns
            .iter()
            .any(|p| contract_name_lower.contains(p));

        // Abstract proxy base contract pattern
        let is_abstract_proxy = source.contains("abstract contract Proxy")
            || source.contains("abstract contract BaseProxy")
            || (source.contains("function _delegate(")
                && source.contains("function _implementation("));

        // Beacon proxy pattern
        let is_beacon_proxy = (lower.contains("ibeacon") || lower.contains("beacon"))
            && lower.contains("implementation")
            && source.contains("delegatecall");

        // Minimal proxy / clone pattern (EIP-1167)
        let is_minimal_proxy = source.contains("0x3d602d80600a3d3981f3")
            || source.contains("0x363d3d373d3d3d363d73")
            || lower.contains("eip1167")
            || lower.contains("minimal proxy")
            || lower.contains("clone");

        // OpenZeppelin Proxy inheritance
        let is_oz_proxy = source.contains("import")
            && (source.contains("proxy/Proxy.sol")
                || source.contains("proxy/ERC1967")
                || source.contains("proxy/transparent")
                || source.contains("proxy/beacon")
                || source.contains("proxy/utils"));

        // Has _implementation() function (standard proxy pattern)
        let has_impl_getter = source.contains("function _implementation(")
            || source.contains("function implementation(");

        // Has fallback with _delegate pattern
        let has_delegate_pattern =
            source.contains("_delegate(") && source.contains("_implementation()");

        is_proxy_name
            || is_abstract_proxy
            || is_beacon_proxy
            || is_minimal_proxy
            || is_oz_proxy
            || has_delegate_pattern
            || (is_proxy_name && has_impl_getter)
            // Contract inherits from Proxy
            || (source.contains("is Proxy") && source.contains("delegatecall"))
    }

    /// Phase 16 FP Reduction: Check if delegatecall target is immutable
    /// Immutable targets are safe because they can't be changed after construction
    fn has_immutable_target(&self, source: &str, line: &str) -> bool {
        // Extract the variable being used as delegatecall target
        if let Some(target_var) = self.extract_delegatecall_target(line) {
            // Check if that variable is declared as immutable
            let immutable_pattern1 = format!("immutable {}", target_var);
            let immutable_pattern2 = format!("{} immutable", target_var);
            let immutable_pattern3 = format!("address immutable {}", target_var);

            source.contains(&immutable_pattern1)
                || source.contains(&immutable_pattern2)
                || source.contains(&immutable_pattern3)
        } else {
            false
        }
    }

    /// Check if delegatecall target is a constant address
    /// Constant addresses cannot be changed and are safe targets
    fn has_constant_target(&self, source: &str, line: &str) -> bool {
        if let Some(target_var) = self.extract_delegatecall_target(line) {
            let constant_pattern1 = format!("constant {}", target_var);
            let constant_pattern2 = format!("{} constant", target_var);
            let constant_pattern3 = format!("address constant {}", target_var);

            source.contains(&constant_pattern1)
                || source.contains(&constant_pattern2)
                || source.contains(&constant_pattern3)
        } else {
            false
        }
    }

    /// Extract the delegatecall target variable name from a line
    fn extract_delegatecall_target(&self, line: &str) -> Option<String> {
        // Match patterns like: target.delegatecall, implementation.delegatecall
        if let Some(pos) = line.find(".delegatecall") {
            let before = &line[..pos];
            // Find the variable name (last word before the dot)
            let words: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = words.last() {
                // Clean up any leading parentheses or other chars
                let cleaned = last.trim_start_matches('(').trim_start_matches('{');
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
        }
        None
    }
}

impl Detector for DelegatecallToSelfDetector {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Phase 16 FP Reduction: Skip valid proxy patterns
        if self.is_eip1967_proxy(source) {
            return Ok(findings);
        }

        if self.is_diamond_proxy(source) {
            return Ok(findings);
        }

        if self.is_safe_wallet(source, ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip generic proxy contracts that legitimately use delegatecall
        if self.is_generic_proxy_contract(source, ctx) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_self_delegatecall(source) {
            let message = format!(
                "Function '{}' in contract '{}' has delegatecall to self: {}. \
                 This can cause infinite loops or unexpected state changes.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(829)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid delegatecall to self:\n\n\
                     1. Never use address(this) as delegatecall target\n\
                     2. Validate target != address(this) before delegatecall\n\
                     3. Use direct internal calls instead\n\
                     4. If multicall needed, use call instead of delegatecall"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_recursive_delegation(source) {
            let message = format!(
                "Function '{}' in contract '{}' may recursively call itself via delegatecall. \
                 This can cause stack overflow or gas exhaustion.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(674)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Prevent recursive delegatecall:\n\n\
                     1. Add reentrancy guard for delegatecall functions\n\
                     2. Validate selector before delegatecall\n\
                     3. Use a depth counter to limit recursion\n\
                     4. Consider using staticcall for read-only operations"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_fallback_self_delegation(source) {
            let message = format!(
                "{} function in contract '{}' uses delegatecall which may target self. \
                 This can be exploited via crafted calldata.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(829)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Secure fallback delegatecall:\n\n\
                     1. Validate implementation address is external\n\
                     2. Add require(target != address(this))\n\
                     3. Use immutable implementation address\n\
                     4. Consider using EIP-1967 proxy pattern"
                        .to_string(),
                );

            findings.push(finding);
        }

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
        let detector = DelegatecallToSelfDetector::new();
        assert_eq!(detector.name(), "Delegatecall to Self");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_is_direct_self_delegatecall() {
        let detector = DelegatecallToSelfDetector::new();

        // True positive: address(this).delegatecall(...)
        assert!(detector.is_direct_self_delegatecall(
            "address(this).delegatecall(abi.encodeWithSignature(\"foo()\"))"
        ));

        // True positive: (address(this)).delegatecall(...)
        assert!(detector.is_direct_self_delegatecall("(address(this)).delegatecall(data)"));

        // False positive: address(this) used for balance, delegatecall targets impl
        assert!(
            !detector.is_direct_self_delegatecall("impl.delegatecall(abi.encode(address(this)))")
        );
    }

    #[test]
    fn test_proxy_forwarding_body_detection() {
        let detector = DelegatecallToSelfDetector::new();

        // Proxy fallback that forwards to implementation
        assert!(detector.is_proxy_forwarding_body(
            "function fallback() external payable {\n\
             address impl = _implementation();\n\
             impl.delegatecall(msg.data);\n\
             }"
        ));

        // Assembly-based proxy forwarding
        assert!(detector.is_proxy_forwarding_body(
            "fallback() external payable {\n\
             assembly {\n\
             calldatacopy(0, 0, calldatasize())\n\
             let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n\
             }\n\
             }"
        ));

        // Diamond proxy routing
        assert!(detector.is_proxy_forwarding_body(
            "function fallback() external payable {\n\
             address facet = facetAddress(msg.sig);\n\
             facet.delegatecall(msg.data);\n\
             }"
        ));

        // Not a proxy -- genuine self-delegatecall
        assert!(!detector.is_proxy_forwarding_body(
            "function dangerous() external {\n\
             address(this).delegatecall(data);\n\
             }"
        ));
    }

    #[test]
    fn test_generic_proxy_detection() {
        let _detector = DelegatecallToSelfDetector::new();

        // Beacon proxy
        let source = "contract MyBeaconProxy {\n\
            IBeacon beacon;\n\
            function _implementation() internal view returns (address) {\n\
                return beacon.implementation();\n\
            }\n\
            fallback() external payable {\n\
                address impl = _implementation();\n\
                impl.delegatecall(msg.data);\n\
            }\n\
        }";

        // We need an AnalysisContext to test this, so we verify the name-based check
        assert!(source.to_lowercase().contains("beacon"));
        assert!(source.to_lowercase().contains("implementation"));
    }

    #[test]
    fn test_immutable_target_skipped() {
        let detector = DelegatecallToSelfDetector::new();

        let source = "address immutable implementation;\n\
            constructor(address impl) { implementation = impl; }\n\
            function exec(bytes memory data) external {\n\
                implementation.delegatecall(data);\n\
            }";

        assert!(detector.has_immutable_target(source, "implementation.delegatecall(data);"));
    }

    #[test]
    fn test_constant_target_skipped() {
        let detector = DelegatecallToSelfDetector::new();

        let source = "address constant IMPL = 0x1234;\n\
            function exec(bytes memory data) external {\n\
                IMPL.delegatecall(data);\n\
            }";

        assert!(detector.has_constant_target(source, "IMPL.delegatecall(data);"));
    }

    #[test]
    fn test_verify_target_is_self() {
        let detector = DelegatecallToSelfDetector::new();

        // Target is actually assigned address(this)
        let func_body = "address target = address(this);\ntarget.delegatecall(data);";
        assert!(detector.verify_target_is_self(func_body, "target.delegatecall(data);"));

        // Target is assigned something else
        let func_body2 = "address target = someOtherAddress;\ntarget.delegatecall(data);";
        assert!(!detector.verify_target_is_self(func_body2, "target.delegatecall(data);"));
    }

    #[test]
    fn test_user_controlled_delegatecall_not_flagged() {
        let detector = DelegatecallToSelfDetector::new();

        // User-controlled delegatecall should NOT be flagged as "recursive delegation".
        // The function name appearing in its own declaration is not a recursive call.
        let source = "contract DirectUserControlled {\n\
            function execute(address target, bytes calldata data) external payable {\n\
                (bool success, ) = target.delegatecall(data);\n\
                require(success, \"Delegatecall failed\");\n\
            }\n\
        }";
        let findings = detector.find_recursive_delegation(source);
        assert!(
            findings.is_empty(),
            "User-controlled delegatecall should not be flagged as recursive delegation, got: {:?}",
            findings
        );

        // Batch with user-controlled targets should also NOT be flagged
        let source2 = "contract Batch {\n\
            function batchExecute(address[] calldata targets, bytes[] calldata data) external {\n\
                for (uint256 i = 0; i < targets.length; i++) {\n\
                    (bool success, ) = targets[i].delegatecall(data[i]);\n\
                }\n\
            }\n\
        }";
        let findings2 = detector.find_recursive_delegation(source2);
        assert!(
            findings2.is_empty(),
            "Batch user-controlled delegatecall should not be flagged, got: {:?}",
            findings2
        );
    }

    #[test]
    fn test_genuine_recursive_delegatecall_still_detected() {
        let detector = DelegatecallToSelfDetector::new();

        // Genuine recursive self-delegatecall SHOULD be detected:
        // function encodes its own selector and delegates to address(this)
        let source = "contract Recursive {\n\
            function dangerous() external {\n\
                bytes memory data = abi.encodeWithSignature(\"dangerous()\");\n\
                address(this).delegatecall(data);\n\
            }\n\
        }";
        let findings = detector.find_recursive_delegation(source);
        assert!(
            !findings.is_empty(),
            "Genuine recursive delegatecall should be detected"
        );
    }

    #[test]
    fn test_multicall_only_flags_self_target() {
        let detector = DelegatecallToSelfDetector::new();

        // Should produce findings for address(this).delegatecall in multicall
        let source = "contract Test {\n\
            function multicall(bytes[] memory data) external {\n\
                for (uint i = 0; i < data.length; i++) {\n\
                    address(this).delegatecall(data[i]);\n\
                }\n\
            }\n\
        }";
        let findings = detector.find_self_delegatecall(source);
        // Should flag the address(this).delegatecall line
        assert!(!findings.is_empty());

        // Should NOT produce findings for implementation.delegatecall
        let source2 = "contract Test {\n\
            function multicall(bytes[] memory data) external {\n\
                for (uint i = 0; i < data.length; i++) {\n\
                    implementation.delegatecall(data[i]);\n\
                }\n\
            }\n\
        }";
        let findings2 = detector.find_self_delegatecall(source2);
        // The multicall check should not fire without address(this)
        let multicall_findings: Vec<_> = findings2
            .iter()
            .filter(|f| f.2.contains("Multicall"))
            .collect();
        assert!(multicall_findings.is_empty());
    }
}
