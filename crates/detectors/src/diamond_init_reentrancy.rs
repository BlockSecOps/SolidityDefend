use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Diamond initialization reentrancy vulnerabilities
pub struct DiamondInitReentrancyDetector {
    base: BaseDetector,
}

impl DiamondInitReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("diamond-init-reentrancy".to_string()),
                "Diamond Initialization Reentrancy".to_string(),
                "Detects reentrancy vulnerabilities during Diamond initialization caused by external calls in diamondCut without reentrancy guards".to_string(),
                vec![
                    DetectorCategory::Diamond,
                    DetectorCategory::Upgradeable,
                    DetectorCategory::Reentrancy,
                ],
                Severity::High,
            ),
        }
    }
}

impl Detector for DiamondInitReentrancyDetector {
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

        // Check if this looks like a Diamond proxy contract
        
        let is_diamond_contract = self.is_diamond_contract(&ctx.source_code);

        if !is_diamond_contract {
            return Ok(findings);
        }

        // Check for initialization reentrancy issues
        let contract = ctx.contract;
        let contract_source = self.get_contract_source(contract, ctx);

        // Check for diamondCut function
        if self.has_diamond_cut_function(&contract_source) {
                // Pattern 1: diamondCut with delegatecall but no reentrancy guard
                if self.has_init_delegatecall(&contract_source)
                    && !self.has_reentrancy_protection(&contract_source)
                {
                    let message = format!(
                        "Contract '{}' performs delegatecall during diamondCut initialization without reentrancy protection. \
                        The initialization delegatecall executes arbitrary code from the init contract, which can call back \
                        into diamondCut or other functions before initialization completes. This allows attackers to \
                        manipulate state during initialization, register malicious facets, or bypass access controls.",
                        contract.name.name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            contract.name.location.start().line() as u32,
                            contract.name.location.start().column() as u32,
                            contract.name.name.len() as u32,
                        )
                        .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                        .with_fix_suggestion(format!(
                            "Add reentrancy protection to '{}': \
                            (1) Add 'modifier nonReentrant' using OpenZeppelin's ReentrancyGuard or custom implementation \
                            (2) Apply nonReentrant to diamondCut function \
                            (3) Use '_locked' state variable: set to true before delegatecall, false after \
                            (4) Check '!_locked' at function entry with 'require(!_locked, \"Reentrant call\")' \
                            (5) Consider using Checks-Effects-Interactions pattern - update state before delegatecall",
                            contract.name.name
                        ));

                    findings.push(finding);
                }

                // Pattern 2: State changes after initialization delegatecall
                if self.has_state_changes_after_init(&contract_source) {
                    let message = format!(
                        "Contract '{}' modifies state after initialization delegatecall. \
                        State changes after delegatecall create reentrancy window where the init contract \
                        can observe intermediate states. Attacker-controlled init contract can reenter \
                        and exploit the inconsistent state before changes complete.",
                        contract.name.name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            contract.name.location.start().line() as u32,
                            contract.name.location.start().column() as u32,
                            contract.name.name.len() as u32,
                        )
                        .with_cwe(841)
                        .with_fix_suggestion(format!(
                            "Reorder operations in '{}': \
                            (1) Complete all state changes BEFORE initialization delegatecall \
                            (2) Follow Checks-Effects-Interactions: checks, state updates, external calls \
                            (3) If post-init updates needed, use reentrancy lock during the entire operation \
                            (4) Validate init contract address before delegatecall \
                            (5) Consider making initialization atomic with 'initializer' modifier",
                            contract.name.name
                        ));

                    findings.push(finding);
                }

                // Pattern 3: Missing reentrancy lock variable
                if self.needs_reentrancy_lock(&contract_source)
                    && !self.has_lock_variable(&contract_source)
                {
                    let message = format!(
                        "Contract '{}' performs external calls during diamondCut but lacks reentrancy lock variable. \
                        Without explicit lock tracking (_locked, _status, etc.), the contract cannot prevent \
                        reentrant calls during initialization. This is critical for Diamond proxies where \
                        initialization can add new facets with arbitrary code.",
                        contract.name.name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            contract.name.location.start().line() as u32,
                            contract.name.location.start().column() as u32,
                            contract.name.name.len() as u32,
                        )
                        .with_cwe(841)
                        .with_fix_suggestion(format!(
                            "Implement reentrancy lock in '{}': \
                            (1) Add state variable: 'uint256 private _status = 1' (NOT_ENTERED) \
                            (2) Define constants: 'uint256 private constant _NOT_ENTERED = 1; uint256 private constant _ENTERED = 2' \
                            (3) Create nonReentrant modifier checking '_status != _ENTERED' \
                            (4) Set '_status = _ENTERED' on entry, '_NOT_ENTERED' on exit \
                            (5) Use storage position like Diamond Storage pattern to avoid slot collision",
                            contract.name.name
                        ));

                    findings.push(finding);
                }

                // Pattern 4: External call during initialization without validation
                if self.has_unvalidated_init_call(&contract_source) {
                    let message = format!(
                        "Contract '{}' performs initialization delegatecall without validating init contract. \
                        Missing validation allows attacker to supply malicious init address that performs \
                        reentrancy attacks during diamondCut. The init contract has full delegatecall privileges \
                        and can execute arbitrary code in proxy context.",
                        contract.name.name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            contract.name.location.start().line() as u32,
                            contract.name.location.start().column() as u32,
                            contract.name.name.len() as u32,
                        )
                        .with_cwe(841)
                        .with_fix_suggestion(format!(
                            "Validate init contract in '{}': \
                            (1) Check 'require(_init != address(0), \"Invalid init\")' if initialization expected \
                            (2) Validate init contract code exists: 'require(_init.code.length > 0, \"Init not contract\")' \
                            (3) Consider whitelisting approved init contracts \
                            (4) Use 'if (_init == address(0) && _calldata.length > 0) revert' for consistency \
                            (5) Emit event with init address for monitoring",
                            contract.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Pattern 5: Missing initialization status tracking
            // Check both contract source AND full source (for library/file-level patterns)
            let tracks_in_contract = self.tracks_initialization_status(&contract_source);
            let tracks_in_file = self.tracks_initialization_status(&ctx.source_code);

            if self.is_diamond_proxy(&contract_source)
                && self.has_initialization(&contract_source)
                && !tracks_in_contract
                && !tracks_in_file
            {
                let message = format!(
                    "Contract '{}' supports initialization but doesn't track initialization status. \
                    Without 'initialized' flag, the contract can be reinitialized multiple times through \
                    reentrancy, allowing attackers to reset state, change ownership, or register malicious facets \
                    after initial setup.",
                    contract.name.name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        contract.name.location.start().line() as u32,
                        contract.name.location.start().column() as u32,
                        contract.name.name.len() as u32,
                    )
                    .with_cwe(841)
                    .with_fix_suggestion(format!(
                        "Implement initialization tracking in '{}': \
                        (1) Add 'bool private _initialized' storage variable \
                        (2) Create 'initializer' modifier: 'require(!_initialized, \"Already initialized\")' \
                        (3) Set '_initialized = true' at start of initialization \
                        (4) Use OpenZeppelin's Initializable pattern for upgradeable contracts \
                        (5) Consider version tracking for multiple initialization phases",
                        contract.name.name
                    ));

                findings.push(finding);
            }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DiamondInitReentrancyDetector {
    fn is_diamond_contract(&self, source: &str) -> bool {
        let diamond_indicators = [
            "diamondCut",
            "FacetCut",
            "IDiamondCut",
            "LibDiamond",
            "Diamond",
        ];

        diamond_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
    }

    fn has_diamond_cut_function(&self, source: &str) -> bool {
        source.contains("function diamondCut")
            || source.contains("function _diamondCut")
            || (source.contains("diamondCut") && source.contains("FacetCut"))
    }

    fn has_init_delegatecall(&self, source: &str) -> bool {
        // Check for initialization delegatecall pattern
        let has_delegatecall = source.contains("delegatecall");
        let has_init_params = source.contains("_init")
            || source.contains("init")
            || source.contains("_calldata")
            || source.contains("initCalldata");

        has_delegatecall && has_init_params
    }

    fn has_reentrancy_protection(&self, source: &str) -> bool {
        // Check for reentrancy guard patterns
        let protection_patterns = [
            "nonReentrant",
            "ReentrancyGuard",
            "_locked",
            "_status",
            "NOT_ENTERED",
            "_ENTERED",
            "require(!locked",
            "require(!_locked",
            "locked = true",
        ];

        protection_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn has_state_changes_after_init(&self, source: &str) -> bool {
        // Look for state changes after delegatecall
        if !source.contains("delegatecall") {
            return false;
        }

        // Heuristic: Check for assignment or state modification after delegatecall
        // This is a simplified check - real implementation would parse AST
        let delegatecall_pos = source.find("delegatecall");
        if let Some(pos) = delegatecall_pos {
            let after_delegatecall = &source[pos..];

            // Look for state changes in code after delegatecall
            let state_change_patterns = ["=", "++", "--", "push(", "pop()", "delete "];

            // Check if there are statements after delegatecall (indicated by semicolons)
            let remaining = after_delegatecall.split(';').skip(1).collect::<Vec<_>>().join(";");

            state_change_patterns
                .iter()
                .any(|pattern| remaining.contains(pattern))
        } else {
            false
        }
    }

    fn needs_reentrancy_lock(&self, source: &str) -> bool {
        // Contract needs lock if it has external calls
        source.contains("delegatecall") || source.contains("call(") || source.contains(".call")
    }

    fn has_lock_variable(&self, source: &str) -> bool {
        // Check for lock state variable
        let lock_patterns = [
            "bool private _locked",
            "bool internal _locked",
            "uint256 private _status",
            "uint256 internal _status",
            "bool private locked",
            "uint256 private locked",
        ];

        lock_patterns.iter().any(|pattern| source.contains(pattern))
    }

    fn has_unvalidated_init_call(&self, source: &str) -> bool {
        // Check for delegatecall without address validation
        if !self.has_init_delegatecall(source) {
            return false;
        }

        // Look for validation patterns
        let validation_patterns = [
            "require(_init",
            "require(init",
            "if (_init == address(0))",
            "if (init == address(0))",
            "_init != address(0)",
            "init.code.length",
        ];

        // Has delegatecall but no validation
        !validation_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
    }

    fn is_diamond_proxy(&self, source: &str) -> bool {
        // Check if this is a Diamond proxy implementation
        let proxy_indicators = ["fallback", "delegatecall", "selectorToFacet"];

        proxy_indicators
            .iter()
            .filter(|indicator| source.contains(*indicator))
            .count()
            >= 2
    }

    fn has_initialization(&self, source: &str) -> bool {
        // Check for initialization logic
        let init_indicators = [
            "initialize",
            "init",
            "diamondCut",
            "_init",
            "initCalldata",
        ];

        init_indicators
            .iter()
            .any(|indicator| source.contains(indicator))
    }

    fn tracks_initialization_status(&self, source: &str) -> bool {
        // Check for initialization status tracking
        let status_patterns = [
            "bool private initialized",
            "bool internal initialized",
            "bool private _initialized",
            "bool internal _initialized",
            "Initializable",
            "initializer modifier",
        ];

        // Check standalone variables
        if status_patterns.iter().any(|pattern| source.contains(pattern)) {
            return true;
        }

        // Check for struct-based initialization tracking (Diamond storage pattern)
        // Look for "bool initialized" within a struct
        if source.contains("struct") && source.contains("bool initialized") {
            return true;
        }

        // Check for initializer modifier pattern
        if source.contains("modifier initializer")
            && (source.contains("!initialized") || source.contains("!_initialized"))
            && (source.contains("initialized = true") || source.contains("_initialized = true"))
        {
            return true;
        }

        false
    }

    fn get_contract_source(&self, contract: &ast::Contract<'_>, ctx: &AnalysisContext) -> String {
        let start = contract.location.start().line();
        let end = contract.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

impl Default for DiamondInitReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DiamondInitReentrancyDetector::new();
        assert_eq!(detector.name(), "Diamond Initialization Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "diamond-init-reentrancy");
        assert!(detector.categories().contains(&DetectorCategory::Diamond));
        assert!(detector
            .categories()
            .contains(&DetectorCategory::Upgradeable));
        assert!(detector
            .categories()
            .contains(&DetectorCategory::Reentrancy));
    }

    #[test]
    fn test_is_diamond_contract() {
        let detector = DiamondInitReentrancyDetector::new();

        assert!(detector.is_diamond_contract("function diamondCut() {}"));
        assert!(detector.is_diamond_contract("struct FacetCut { }"));
        assert!(detector.is_diamond_contract("library LibDiamond { }"));
        assert!(!detector.is_diamond_contract("contract Token { }"));
    }

    #[test]
    fn test_has_init_delegatecall() {
        let detector = DiamondInitReentrancyDetector::new();

        let code_with_init = r#"
            function diamondCut(address _init, bytes memory _calldata) {
                (bool success,) = _init.delegatecall(_calldata);
            }
        "#;
        assert!(detector.has_init_delegatecall(code_with_init));

        let code_without_init = r#"
            function diamondCut() {
                updateFacets();
            }
        "#;
        assert!(!detector.has_init_delegatecall(code_without_init));
    }

    #[test]
    fn test_has_reentrancy_protection() {
        let detector = DiamondInitReentrancyDetector::new();

        let protected_code = r#"
            modifier nonReentrant() {
                require(!_locked, "Reentrant call");
                _locked = true;
                _;
                _locked = false;
            }
            function diamondCut() nonReentrant { }
        "#;
        assert!(detector.has_reentrancy_protection(protected_code));

        let unprotected_code = r#"
            function diamondCut() { }
        "#;
        assert!(!detector.has_reentrancy_protection(unprotected_code));
    }

    #[test]
    fn test_has_state_changes_after_init() {
        let detector = DiamondInitReentrancyDetector::new();

        let vulnerable_code = r#"
            function init(address _init) {
                _init.delegatecall(data);
                owner = msg.sender;
            }
        "#;
        assert!(detector.has_state_changes_after_init(vulnerable_code));

        let secure_code = r#"
            function init(address _init) {
                owner = msg.sender;
                _init.delegatecall(data);
            }
        "#;
        assert!(!detector.has_state_changes_after_init(secure_code));
    }

    #[test]
    fn test_has_lock_variable() {
        let detector = DiamondInitReentrancyDetector::new();

        let with_lock = "bool private _locked;";
        assert!(detector.has_lock_variable(with_lock));

        let with_status = "uint256 private _status;";
        assert!(detector.has_lock_variable(with_status));

        let without_lock = "uint256 public value;";
        assert!(!detector.has_lock_variable(without_lock));
    }

    #[test]
    fn test_has_unvalidated_init_call() {
        let detector = DiamondInitReentrancyDetector::new();

        let vulnerable_code = r#"
            function diamondCut(address _init, bytes memory data) {
                _init.delegatecall(data);
            }
        "#;
        assert!(detector.has_unvalidated_init_call(vulnerable_code));

        let secure_code = r#"
            function diamondCut(address _init, bytes memory data) {
                require(_init != address(0), "Invalid init");
                _init.delegatecall(data);
            }
        "#;
        assert!(!detector.has_unvalidated_init_call(secure_code));
    }

    #[test]
    fn test_tracks_initialization_status() {
        let detector = DiamondInitReentrancyDetector::new();

        let with_tracking = "bool private _initialized;";
        assert!(detector.tracks_initialization_status(with_tracking));

        let with_initializable = "contract Diamond is Initializable { }";
        assert!(detector.tracks_initialization_status(with_initializable));

        let without_tracking = "function initialize() { }";
        assert!(!detector.tracks_initialization_status(without_tracking));
    }
}
