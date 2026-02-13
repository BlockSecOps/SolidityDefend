use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for constructor reentrancy vulnerabilities
///
/// Detects patterns where reentrancy can occur during contract
/// construction, before security mechanisms are fully initialized.
pub struct ConstructorReentrancyDetector {
    base: BaseDetector,
}

impl Default for ConstructorReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstructorReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("constructor-reentrancy"),
                "Constructor Reentrancy".to_string(),
                "Detects external calls in constructors that can enable reentrancy \
                 before security mechanisms are fully initialized."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Deployment],
                Severity::High,
            ),
        }
    }

    /// Check if a line starts a real constructor (not an initialize() function)
    fn is_actual_constructor(trimmed: &str) -> bool {
        // Must be a Solidity constructor keyword, not an initialize() function
        // Match "constructor(" but not "// constructor" or inside a string
        let t = trimmed.trim_start_matches("//").trim();
        if t != trimmed {
            return false; // was a comment
        }
        trimmed.starts_with("constructor")
            || trimmed.starts_with("constructor(")
            || (trimmed.contains("constructor")
                && trimmed.contains("(")
                && !trimmed.contains("function"))
    }

    /// Find external calls in constructors
    fn find_constructor_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Only match actual constructors, not initialize() functions
            if Self::is_actual_constructor(trimmed) {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for external calls that can cause reentrancy
                // Note: .transfer and .send have 2300 gas stipend - cannot reenter
                if constructor_body.contains(".call(")
                    || constructor_body.contains(".call{")
                    || constructor_body.contains(".delegatecall(")
                {
                    let body_lower = constructor_body.to_lowercase();

                    // FP Reduction: Skip if the constructor checks the return value
                    let has_return_check = body_lower.contains("require(success")
                        || body_lower.contains("if (!success)")
                        || body_lower.contains("if(!success)");

                    // FP Reduction: Skip proxy constructors that delegatecall to
                    // a validated implementation address (standard proxy pattern)
                    let is_proxy_init = body_lower.contains("_implementation")
                        || body_lower.contains("implementation_slot")
                        || body_lower.contains("eip1967")
                        || (body_lower.contains("delegatecall")
                            && body_lower.contains("_data.length"));

                    if !has_return_check && !is_proxy_init {
                        findings.push((line_num as u32 + 1, "constructor".to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Find callback triggers in constructors
    ///
    /// Note: ERC20's _mint() does NOT trigger callbacks.
    /// Only ERC721/ERC1155 safe mint functions trigger receiver callbacks:
    /// - _safeMint() triggers onERC721Received()
    /// - safeTransferFrom() triggers onERC721Received()/onERC1155Received()
    fn find_constructor_callbacks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if Self::is_actual_constructor(trimmed) {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for operations that trigger callbacks
                // Note: ERC20's _mint() and SafeERC20._safeTransfer do NOT trigger callbacks
                // Only ERC721/ERC1155 safe functions trigger receiver callbacks:
                // - _safeMint() triggers onERC721Received()
                // - safeTransferFrom() triggers onERC721Received()/onERC1155Received()
                if constructor_body.contains("_safeMint")
                    || constructor_body.contains("safeMint(")
                    || constructor_body.contains("safeTransferFrom")
                    || constructor_body.contains("onERC721Received")
                    || constructor_body.contains("onERC1155Received")
                {
                    findings.push((line_num as u32 + 1, "constructor".to_string()));
                }
            }
        }

        findings
    }

    /// Find state modifications after external calls in constructor
    fn find_state_after_call(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if Self::is_actual_constructor(trimmed) {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_lines = &lines[line_num..func_end];

                // FP Reduction: Skip proxy constructors
                let body_text: String = constructor_lines.join("\n");
                let body_lower = body_text.to_lowercase();
                if body_lower.contains("_implementation")
                    || body_lower.contains("implementation_slot")
                    || body_lower.contains("eip1967")
                    || (body_lower.contains("delegatecall") && body_lower.contains("_data.length"))
                {
                    continue;
                }

                let mut found_call = false;
                let mut call_line = 0;

                for (i, cline) in constructor_lines.iter().enumerate() {
                    // Only flag calls that can cause reentrancy
                    // .transfer/.send have 2300 gas limit - cannot reenter
                    // Note: ERC20 SafeERC20.safeTransfer does NOT trigger callbacks
                    // Only ERC721/ERC1155 _safeMint triggers receiver callbacks
                    if cline.contains(".call(")
                        || cline.contains(".call{")
                        || cline.contains(".delegatecall(")
                        || cline.contains("_safeMint")
                    {
                        found_call = true;
                        call_line = i;
                    }

                    // FP Reduction: If the call result is checked with require(success)
                    // before any state changes, the reentrancy risk is mitigated
                    if found_call && i > call_line {
                        if cline.contains("require(success") || cline.contains("require(result") {
                            // Result is validated — state changes after this are safe
                            found_call = false;
                            continue;
                        }
                        if cline.contains(" = ") && !cline.contains("==") {
                            findings.push(((line_num + i) as u32 + 1, "constructor".to_string()));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find inherited constructor issues
    fn find_inherited_constructor_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Use proper constructor detection (avoids matching comments/strings)
            if Self::is_actual_constructor(trimmed) {
                let func_end = self.find_function_end(&lines, line_num);
                let constructor_body: String = lines[line_num..func_end].join("\n");

                // Check for inherited constructor with callback-triggering interaction
                // Note: _mint() does NOT trigger callbacks, only _safeMint() does
                if (constructor_body.contains("ERC721") || constructor_body.contains("ERC1155"))
                    && constructor_body.contains("_safeMint")
                {
                    findings.push((line_num as u32 + 1, "constructor".to_string()));
                }
            }
        }

        findings
    }

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

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
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ConstructorReentrancyDetector {
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

        // FP Reduction: Skip upgradeable/proxy contracts that use initialize()
        // instead of constructors — their constructors are typically empty or
        // only set immutable state (EIP-1967 slot, etc.)
        if crate::utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts that have a constructor or initialize function
        let has_constructor = ctx.contract.functions.iter().any(|f| {
            matches!(f.function_type, ast::FunctionType::Constructor)
                || f.name.name.to_lowercase().contains("initialize")
        });
        if !has_constructor {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // FP Reduction: Skip contracts that are purely initializable patterns
        // (e.g., OpenZeppelin Initializable) — these don't use constructors for logic
        if source_lower.contains("initializable")
            && source_lower.contains("initializer")
            && !source.contains("constructor")
        {
            return Ok(findings);
        }

        let contract_name = self.get_contract_name(ctx);

        for (line, _) in self.find_constructor_external_calls(source) {
            let message = format!(
                "Constructor in contract '{}' makes external calls. \
                 Reentrancy can occur before security mechanisms are initialized.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid external calls in constructor:\n\n\
                     1. Move external calls to an initialize() function\n\
                     2. Use two-step initialization pattern\n\
                     3. Ensure all state is set before external calls\n\
                     4. Use reentrancy guards even in constructor"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_constructor_callbacks(source) {
            let message = format!(
                "Constructor in contract '{}' uses ERC721/ERC1155 safe functions that trigger receiver callbacks. \
                 Callbacks via onERC721Received/onERC1155Received can reenter before initialization completes.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid callback-triggering operations in constructor:\n\n\
                     1. For ERC721: Use _mint() instead of _safeMint()\n\
                     2. For ERC1155: Complete state initialization before minting\n\
                     3. Move minting to post-construction initialize()\n\
                     4. Note: ERC20's _mint() is safe - no callbacks"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_state_after_call(source) {
            let message = format!(
                "Constructor in contract '{}' modifies state after external call. \
                 Classic checks-effects-interactions violation in constructor.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Follow checks-effects-interactions in constructor:\n\n\
                     constructor() {\n\
                         // 1. Set all state first\n\
                         owner = msg.sender;\n\
                         initialized = true;\n\n\
                         // 2. External calls last\n\
                         token.transfer(...);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, _) in self.find_inherited_constructor_calls(source) {
            let message = format!(
                "Constructor in contract '{}' inherits from contracts with callback mechanisms. \
                 Ensure parent constructors don't enable reentrancy.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Review inherited constructor behavior:\n\n\
                     1. Check if parent constructors make external calls\n\
                     2. Audit ERC721/ERC1155 _safeMint in constructors\n\
                     3. Consider delaying minting to after construction"
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
        let detector = ConstructorReentrancyDetector::new();
        assert_eq!(detector.name(), "Constructor Reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_erc20_mint_not_flagged_as_callback() {
        let detector = ConstructorReentrancyDetector::new();

        // ERC20's _mint() does NOT trigger callbacks - should NOT be flagged
        let source = r#"
            contract Token is ERC20 {
                constructor() ERC20("Test", "TST") {
                    _mint(msg.sender, 1000000 * 10 ** decimals());
                }
            }
        "#;

        let findings = detector.find_constructor_callbacks(source);
        assert!(
            findings.is_empty(),
            "ERC20 _mint() should not be flagged as callback-triggering"
        );
    }

    #[test]
    fn test_erc721_safemint_flagged_as_callback() {
        let detector = ConstructorReentrancyDetector::new();

        // ERC721's _safeMint() DOES trigger onERC721Received callback - should be flagged
        let source = r#"
            contract NFT is ERC721 {
                constructor() ERC721("Test", "TST") {
                    _safeMint(msg.sender, 1);
                }
            }
        "#;

        let findings = detector.find_constructor_callbacks(source);
        assert_eq!(
            findings.len(),
            1,
            "ERC721 _safeMint() should be flagged as callback-triggering"
        );
    }

    #[test]
    fn test_safe_transfer_from_flagged() {
        let detector = ConstructorReentrancyDetector::new();

        // safeTransferFrom triggers receiver callbacks
        let source = r#"
            contract NFTReceiver {
                constructor(IERC721 nft, uint256 tokenId) {
                    nft.safeTransferFrom(address(this), msg.sender, tokenId);
                }
            }
        "#;

        let findings = detector.find_constructor_callbacks(source);
        assert_eq!(
            findings.len(),
            1,
            "safeTransferFrom should be flagged as callback-triggering"
        );
    }

    #[test]
    fn test_erc20_safe_transfer_not_flagged_in_callbacks() {
        let detector = ConstructorReentrancyDetector::new();

        // SafeERC20.safeTransfer does NOT trigger callbacks (just wraps transfer with check)
        // It should NOT be in the callback findings
        let source = r#"
            contract Vault {
                constructor(IERC20 token) {
                    token.safeTransfer(msg.sender, 100);
                }
            }
        "#;

        let findings = detector.find_constructor_callbacks(source);
        // safeTransfer (ERC20 style) should not trigger callback warning
        // Note: Our detector now only looks for safeTransferFrom which is ERC721/1155
        assert!(
            findings.is_empty(),
            "ERC20 safeTransfer should not be flagged as callback-triggering"
        );
    }

    #[test]
    fn test_external_call_flagged() {
        let detector = ConstructorReentrancyDetector::new();

        // Low-level .call() without return check should be flagged
        let source = r#"
            contract Vulnerable {
                constructor(address target) {
                    target.call{value: 1 ether}("");
                }
            }
        "#;

        let findings = detector.find_constructor_external_calls(source);
        assert_eq!(
            findings.len(),
            1,
            "Low-level .call() without return check should be flagged"
        );
    }

    #[test]
    fn test_external_call_with_require_not_flagged() {
        let detector = ConstructorReentrancyDetector::new();

        // Low-level .call() with require(success) should NOT be flagged
        // The return check mitigates the reentrancy risk
        let source = r#"
            contract Secure {
                constructor(address target) {
                    (bool success,) = target.call{value: 1 ether}("");
                    require(success);
                }
            }
        "#;

        let findings = detector.find_constructor_external_calls(source);
        assert_eq!(
            findings.len(),
            0,
            "Low-level .call() with require(success) should not be flagged"
        );
    }
}
