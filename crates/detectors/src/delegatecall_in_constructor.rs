use anyhow::Result;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detects delegatecall performed in contract constructors
///
/// # Vulnerability
/// Performing delegatecall during contract construction introduces several risks:
/// 1. **Storage Corruption**: Delegated contract can write to any storage slot during initialization
/// 2. **Reentrancy**: Constructor can be reentered before completion
/// 3. **User-Controlled Init**: If user provides the init address, malicious code can execute
/// 4. **Failed Initialization**: If delegatecall fails but check is missing, contract deploys broken
/// 5. **Unpredictable State**: Contract state is undefined if initialization fails partially
///
/// # Secure Pattern
/// Instead of delegatecall in constructor:
/// 1. Use direct initialization in constructor
/// 2. Implement two-step initialization (constructor + initialize function)
/// 3. Set immutable values in constructor, delegate initialization to post-deployment call
/// 4. Use initializer pattern for proxy contracts
/// 5. Validate all initialization parameters
///
/// # Example Vulnerable Code
/// ```solidity
/// contract VulnerableConstructor {
///     address public owner;
///
///     constructor(address initLogic, bytes memory initData) {
///         // VULNERABLE: Delegatecall in constructor
///         initLogic.delegatecall(initData);
///         owner = msg.sender;
///     }
/// }
/// ```
///
/// # Example Secure Code
/// ```solidity
/// contract SecureConstructor {
///     address public owner;
///     bool private initialized;
///
///     constructor(address _owner) {
///         // SECURE: Direct initialization
///         owner = _owner;
///     }
///
///     function initialize(address impl, bytes calldata data) external {
///         require(!initialized, "Already initialized");
///         require(msg.sender == owner, "Only owner");
///
///         // SECURE: Initialization happens post-deployment
///         (bool success, ) = impl.delegatecall(data);
///         require(success, "Init failed");
///         initialized = true;
///     }
/// }
/// ```
///
/// # CWE-665: Improper Initialization
/// This detector identifies improper initialization patterns where delegatecall
/// during construction can lead to unpredictable contract state.
pub struct DelegatecallInConstructorDetector {
    base: BaseDetector,
}

impl DelegatecallInConstructorDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegatecall-in-constructor".to_string()),
                "Delegatecall in Constructor".to_string(),
                "Detects delegatecall performed during contract construction, which can lead to storage corruption and initialization issues".to_string(),
                vec![DetectorCategory::BestPractices, DetectorCategory::Upgradeable],
                Severity::Medium,
            ),
        }
    }

    /// Gets the source code of a function
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

    /// Checks if a function is a constructor
    fn is_constructor(&self, function: &ast::Function<'_>) -> bool {
        function.name.name == "constructor"
    }

    /// Checks if constructor contains delegatecall
    fn has_delegatecall(&self, source: &str) -> bool {
        // Check for explicit delegatecall
        if source.contains("delegatecall") {
            return true;
        }

        // Check for assembly delegatecall
        if source.contains("assembly") && source.contains("delegatecall(") {
            return true;
        }

        false
    }

    /// Analyzes the delegatecall pattern to provide specific details
    fn analyze_delegatecall_pattern(&self, source: &str) -> String {
        let mut issues = Vec::new();

        // Check if return value is not captured
        if self.is_statement_delegatecall(source) {
            issues.push("delegatecall return value not captured");
        }

        // Check if return value is not validated
        if self.is_unchecked_delegatecall(source) {
            issues.push("delegatecall success not validated with require()");
        }

        // Check for user-controlled target
        if self.has_user_controlled_target(source) {
            issues.push("delegatecall target comes from constructor parameter");
        }

        // Check for loop delegatecall
        if source.contains("for (") && source.contains("delegatecall") {
            issues.push("multiple delegatecalls in loop");
        }

        // Check for value transfer
        if source.contains("delegatecall{value:") {
            issues.push("delegatecall with ETH transfer");
        }

        if issues.is_empty() {
            "Delegatecall in constructor can lead to storage corruption during initialization"
                .to_string()
        } else {
            format!("Constructor delegatecall issues: {}", issues.join(", "))
        }
    }

    /// Checks if delegatecall is used as statement (return not captured)
    fn is_statement_delegatecall(&self, source: &str) -> bool {
        // Look for patterns like:
        // target.delegatecall(data);
        // address.delegatecall(data);
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.contains(".delegatecall(") && trimmed.ends_with(';') {
                // Check it's not in an assignment
                if !trimmed.contains("=")
                    || trimmed.find("=").unwrap() > trimmed.find(".delegatecall(").unwrap()
                {
                    return true;
                }
            }
        }

        false
    }

    /// Checks if delegatecall is captured but not validated
    fn is_unchecked_delegatecall(&self, source: &str) -> bool {
        if !source.contains("delegatecall") {
            return false;
        }

        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("delegatecall") && line.contains("bool") {
                // Found delegatecall with bool capture
                // Check next few lines for require/if validation
                let check_lines = &lines[i..std::cmp::min(i + 3, lines.len())];
                let has_validation = check_lines
                    .iter()
                    .any(|l| l.contains("require(") || l.contains("if (") || l.contains("if("));

                if !has_validation {
                    return true;
                }
            }
        }

        false
    }

    /// Checks if delegatecall target comes from constructor parameter
    fn has_user_controlled_target(&self, source: &str) -> bool {
        // Look for constructor parameters that are used in delegatecall
        if !source.contains("constructor") || !source.contains("delegatecall") {
            return false;
        }

        // Extract constructor parameters
        if let Some(params_start) = source.find("constructor(") {
            if let Some(params_end) = source[params_start..].find(")") {
                let params_section = &source[params_start..params_start + params_end];

                // Look for address parameters
                let address_params = [
                    "address",
                    "initLogic",
                    "initContract",
                    "_init",
                    "logic",
                    "implementation",
                ];

                for param in &address_params {
                    if params_section.contains(param) {
                        // Check if this parameter is used in delegatecall
                        if source[params_start + params_end..]
                            .contains(&format!("{}.delegatecall", param))
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Checks if this is a known safe pattern (e.g., EIP-1167 minimal proxy)
    fn is_safe_pattern(&self, source: &str) -> bool {
        // EIP-1167 minimal proxy doesn't use delegatecall in constructor
        // Some known safe patterns:

        // Pattern 1: Only setting EIP-1967 storage slot (no actual delegatecall to user code)
        if source.contains("IMPLEMENTATION_SLOT")
            && source.contains("sstore(slot, _implementation)")
            && !source.contains(".delegatecall(")
        {
            return true;
        }

        // Pattern 2: Immutable-only constructor
        if source.contains("constructor")
            && source.contains("immutable")
            && !source.contains("delegatecall")
        {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Check if contract is a known proxy implementation
    fn is_proxy_implementation(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // EIP-1967 proxy patterns
        if source.contains("IMPLEMENTATION_SLOT")
            || source.contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source.contains("_IMPLEMENTATION_SLOT")
        {
            return true;
        }

        // OpenZeppelin proxy patterns
        if source.contains("ERC1967Proxy")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("BeaconProxy")
            || source.contains("UUPSUpgradeable")
        {
            return true;
        }

        // Diamond proxy patterns (EIP-2535)
        if source.contains("DiamondCutFacet")
            || source.contains("IDiamondCut")
            || source.contains("DiamondLoupeFacet")
            || source.contains("IDiamondLoupe")
            || source_lower.contains("diamond proxy")
        {
            return true;
        }

        // Minimal proxy / clone patterns
        if source.contains("Clones") || source.contains("LibClone") || source.contains("EIP1167") {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Check for OpenZeppelin Initializable pattern
    fn has_initializable_pattern(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // Initializable imports
        source.contains("Initializable")
            || source.contains("@openzeppelin/contracts-upgradeable")
            || source.contains("initializer")
            || source.contains("_disableInitializers")
    }

    /// Phase 54 FP Reduction: Check for immutable proxy pattern
    fn is_immutable_proxy(&self, source: &str) -> bool {
        // Check if constructor only sets immutable values and doesn't delegatecall
        let has_immutable = source.contains("immutable");
        let constructor_idx = source.find("constructor");

        if let Some(idx) = constructor_idx {
            let constructor_section = &source[idx..];
            // Find the end of the constructor body
            if let Some(body_start) = constructor_section.find('{') {
                let mut depth = 1;
                let mut body_end = body_start + 1;
                for (i, c) in constructor_section[body_start + 1..].chars().enumerate() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                body_end = body_start + 1 + i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let constructor_body = &constructor_section[body_start..=body_end];
                // If constructor only has immutable assignments and no delegatecall, it's safe
                if has_immutable && !constructor_body.contains("delegatecall") {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for DelegatecallInConstructorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DelegatecallInConstructorDetector {
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

        // Phase 54 FP Reduction: Skip known proxy implementations
        if self.is_proxy_implementation(ctx) {
            return Ok(findings);
        }

        // Phase 54 FP Reduction: Skip contracts using Initializable pattern
        if self.has_initializable_pattern(ctx) {
            return Ok(findings);
        }

        // Check all functions for constructor delegatecall
        for function in ctx.get_functions() {
            // Only check constructors
            if !self.is_constructor(function) {
                continue;
            }

            let source = self.get_function_source(function, ctx);

            // Skip if this is a known safe pattern
            if self.is_safe_pattern(&source) {
                continue;
            }

            // Phase 54 FP Reduction: Skip immutable proxy patterns
            if self.is_immutable_proxy(&source) {
                continue;
            }

            if self.has_delegatecall(&source) {
                let analysis = self.analyze_delegatecall_pattern(&source);

                let message = format!("Constructor performs delegatecall. {}", analysis);

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.location.start().line() as u32,
                        function.location.start().column() as u32,
                        11, // Length of "constructor"
                    )
                    .with_cwe(665);

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DelegatecallInConstructorDetector::new();
        assert_eq!(detector.id().0, "delegatecall-in-constructor");
        assert_eq!(detector.name(), "Delegatecall in Constructor");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_default() {
        let detector = DelegatecallInConstructorDetector::default();
        assert_eq!(detector.id().0, "delegatecall-in-constructor");
    }
}
