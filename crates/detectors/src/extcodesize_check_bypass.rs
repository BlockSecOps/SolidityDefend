use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EXTCODESIZE check bypass vulnerabilities
///
/// Detects patterns where EXTCODESIZE checks can be bypassed during
/// contract construction when code size is 0.
///
/// False positive reduction strategies:
/// - Skip view/pure/internal/private functions (not externally callable entry points)
/// - Skip EIP-1167 minimal proxy clone detection patterns (legitimate use)
/// - Skip Diamond proxy facet existence checks (legitimate delegatecall guard)
/// - Skip contracts that also validate msg.sender == tx.origin (prevents constructor bypass)
/// - Skip cases where extcodesize is used for proxy/delegatecall code existence verification
/// - Skip isContract definitions that are view/pure helper functions
/// - Skip modifier bodies that also include tx.origin == msg.sender validation
pub struct ExtcodesizeCheckBypassDetector {
    base: BaseDetector,
}

impl Default for ExtcodesizeCheckBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtcodesizeCheckBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("extcodesize-check-bypass"),
                "EXTCODESIZE Check Bypass".to_string(),
                "Detects EXTCODESIZE checks that can be bypassed during contract \
                 construction when the code size is temporarily zero."
                    .to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Contract-level false-positive guards
    // -----------------------------------------------------------------------

    /// Check if the contract already has a tx.origin == msg.sender guard anywhere.
    /// This pattern prevents constructor-based bypass, making extcodesize checks safe.
    fn contract_has_txorigin_sender_guard(&self, source: &str) -> bool {
        let source_lower = source.to_lowercase();
        // Patterns: require(tx.origin == msg.sender) or if (tx.origin == msg.sender)
        // or the reverse order
        (source_lower.contains("tx.origin == msg.sender")
            || source_lower.contains("msg.sender == tx.origin")
            || source_lower.contains("tx.origin != msg.sender")
            || source_lower.contains("msg.sender != tx.origin"))
            && (source_lower.contains("require(")
                || source_lower.contains("if (")
                || source_lower.contains("if("))
    }

    /// Check if this is an EIP-1167 minimal proxy / clone detection pattern.
    /// Contracts that inspect code to detect clones use extcodesize legitimately.
    fn is_eip1167_clone_pattern(&self, source: &str) -> bool {
        let source_lower = source.to_lowercase();
        // EIP-1167 clone detection keywords
        source_lower.contains("eip-1167")
            || source_lower.contains("eip1167")
            || source_lower.contains("minimal proxy")
            || source_lower.contains("minimalproxy")
            || source_lower.contains("clone")
                && (source_lower.contains("proxy") || source_lower.contains("factory"))
            || source_lower.contains("clonefactory")
            || source_lower.contains("clones.sol")
            || source_lower.contains("libclone")
            || source_lower.contains("363d3d373d3d3d363d73") // EIP-1167 bytecode prefix
            || source_lower.contains("create_clone")
            || source_lower.contains("createclone")
    }

    /// Check if this is a Diamond proxy pattern (EIP-2535) that uses extcodesize
    /// to verify facet code existence before delegatecall -- a legitimate use.
    fn is_diamond_proxy_pattern(&self, source: &str) -> bool {
        let source_lower = source.to_lowercase();
        (source_lower.contains("diamond")
            || source_lower.contains("facet")
            || source_lower.contains("eip-2535")
            || source_lower.contains("eip2535"))
            && (source_lower.contains("delegatecall")
                || source_lower.contains("selectortoface")
                || source_lower.contains("facetaddress"))
    }

    /// Check if extcodesize is used for proxy/delegatecall code existence verification
    /// rather than EOA detection. This is a valid non-bypassable usage.
    fn is_proxy_code_existence_check(&self, lines: &[&str], line_num: usize) -> bool {
        // Look at surrounding context (10 lines before and after)
        let context_start = line_num.saturating_sub(10);
        let context_end = std::cmp::min(line_num + 10, lines.len());
        let context: String = lines[context_start..context_end].join("\n");
        let context_lower = context.to_lowercase();

        // If the context mentions delegatecall/proxy/implementation, this is a
        // code-existence check for a proxy, not an EOA detection check
        (context_lower.contains("delegatecall")
            || context_lower.contains("implementation")
            || context_lower.contains("proxy")
            || context_lower.contains("_fallback"))
            && (context_lower.contains("revert")
                || context_lower.contains("require")
                || context_lower.contains("> 0"))
    }

    // -----------------------------------------------------------------------
    // Function-level false-positive guards
    // -----------------------------------------------------------------------

    /// Extract the full function/modifier source from lines starting at the function
    /// declaration found by scanning backward from `line_num`.
    fn get_containing_function_source(&self, lines: &[&str], line_num: usize) -> String {
        // Find function start
        let mut func_start = 0;
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") || trimmed.contains("modifier ") {
                func_start = i;
                break;
            }
        }
        let func_end = self.find_function_end(lines, func_start);
        lines[func_start..func_end].join("\n")
    }

    /// Check if the containing function is view, pure, internal, or private.
    /// These are not externally callable entry points and thus the extcodesize
    /// bypass is not directly exploitable through them.
    fn is_non_exploitable_function(&self, lines: &[&str], line_num: usize) -> bool {
        // Find the function declaration line by scanning backward
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                // Gather the full signature (may span multiple lines until '{')
                let sig_end = std::cmp::min(i + 5, lines.len());
                let sig: String = lines[i..sig_end].join(" ");

                // Extract just the signature part before the body
                let sig_part = if let Some(brace_pos) = sig.find('{') {
                    &sig[..brace_pos]
                } else {
                    &sig
                };

                // Check visibility and mutability
                let has_view = sig_part.contains(" view ")
                    || sig_part.contains(" view\n")
                    || sig_part.ends_with(" view");
                let has_pure = sig_part.contains(" pure ")
                    || sig_part.contains(" pure\n")
                    || sig_part.ends_with(" pure");
                let has_internal = sig_part.contains(" internal ")
                    || sig_part.contains(" internal\n")
                    || sig_part.ends_with(" internal");
                let has_private = sig_part.contains(" private ")
                    || sig_part.contains(" private\n")
                    || sig_part.ends_with(" private");

                return has_view || has_pure || has_internal || has_private;
            }
            // Stop if we hit a modifier or contract declaration
            if trimmed.contains("modifier ") || trimmed.starts_with("contract ") {
                break;
            }
        }
        false
    }

    /// Check if the containing function/modifier already has a tx.origin == msg.sender
    /// guard, which prevents constructor-based bypass.
    fn function_has_txorigin_guard(&self, lines: &[&str], line_num: usize) -> bool {
        let func_source = self.get_containing_function_source(lines, line_num);
        let lower = func_source.to_lowercase();
        lower.contains("tx.origin == msg.sender")
            || lower.contains("msg.sender == tx.origin")
            || lower.contains("tx.origin != msg.sender")
            || lower.contains("msg.sender != tx.origin")
    }

    /// Check if the line is inside a comment (single-line // or within a doc comment block)
    fn is_in_comment(&self, line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*")
    }

    // -----------------------------------------------------------------------
    // Detection methods (with FP reduction integrated)
    // -----------------------------------------------------------------------

    /// Find EXTCODESIZE checks used for EOA detection
    fn find_extcodesize_checks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if self.is_in_comment(trimmed) {
                continue;
            }

            // Look for extcodesize checks
            if trimmed.contains("extcodesize")
                || trimmed.contains(".code.length")
                || trimmed.contains("codesize")
            {
                // Check if it's used for EOA detection (comparison to 0)
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                if context.contains("== 0") || context.contains("!= 0") {
                    // FP Reduction: skip view/pure/internal/private functions
                    if self.is_non_exploitable_function(&lines, line_num) {
                        continue;
                    }

                    // FP Reduction: skip proxy/delegatecall code existence checks
                    if self.is_proxy_code_existence_check(&lines, line_num) {
                        continue;
                    }

                    // FP Reduction: skip if containing function has tx.origin guard
                    if self.function_has_txorigin_guard(&lines, line_num) {
                        continue;
                    }

                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find isContract patterns
    fn find_is_contract_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if self.is_in_comment(trimmed) {
                continue;
            }

            if trimmed.contains("isContract") || trimmed.contains("_isContract") {
                // FP Reduction: skip if this is the function *definition* itself
                // (a view/pure helper). Only flag the *usage* in an external/public
                // security-critical context.
                if trimmed.contains("function ") {
                    // This is the definition line -- skip if view/pure
                    let sig_end = std::cmp::min(line_num + 4, lines.len());
                    let sig: String = lines[line_num..sig_end].join(" ");
                    let sig_part = if let Some(brace_pos) = sig.find('{') {
                        &sig[..brace_pos]
                    } else {
                        &sig
                    };
                    if sig_part.contains(" view ")
                        || sig_part.contains(" pure ")
                        || sig_part.contains(" internal ")
                        || sig_part.contains(" private ")
                    {
                        continue;
                    }
                }

                // FP Reduction: skip view/pure/internal/private callers
                if self.is_non_exploitable_function(&lines, line_num) {
                    continue;
                }

                // FP Reduction: skip if containing function has tx.origin guard
                if self.function_has_txorigin_guard(&lines, line_num) {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find contract-only modifiers that can be bypassed
    fn find_contract_only_modifier(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("modifier ")
                && (trimmed.contains("onlyEOA")
                    || trimmed.contains("noContract")
                    || trimmed.contains("notContract"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it relies on extcodesize
                if func_body.contains("extcodesize")
                    || func_body.contains(".code.length")
                    || func_body.contains("codesize")
                {
                    // FP Reduction: skip if modifier body also validates tx.origin
                    let body_lower = func_body.to_lowercase();
                    if body_lower.contains("tx.origin == msg.sender")
                        || body_lower.contains("msg.sender == tx.origin")
                    {
                        continue;
                    }

                    let modifier_name = self.extract_modifier_name(trimmed);
                    findings.push((line_num as u32 + 1, modifier_name));
                }
            }
        }

        findings
    }

    /// Find tx.origin != msg.sender as alternative check.
    /// With FP reduction: only flag if it is genuinely used alone for EOA gating,
    /// not when it is used as a *complement* to extcodesize (which is actually safer).
    fn find_txorigin_sender_check(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if self.is_in_comment(trimmed) {
                continue;
            }

            // tx.origin == msg.sender is also bypassable in some scenarios
            if trimmed.contains("tx.origin") && trimmed.contains("msg.sender") {
                // FP Reduction: skip view/pure/internal/private functions
                if self.is_non_exploitable_function(&lines, line_num) {
                    continue;
                }

                // FP Reduction: If the contract also uses extcodesize, the tx.origin
                // check is a *complement* to it (strengthens the guard), not a
                // standalone issue. Do not double-report.
                let func_source = self.get_containing_function_source(&lines, line_num);
                let func_lower = func_source.to_lowercase();
                if func_lower.contains("extcodesize")
                    || func_lower.contains(".code.length")
                    || func_lower.contains("codesize")
                    || func_lower.contains("iscontract")
                {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    // -----------------------------------------------------------------------
    // Utility helpers
    // -----------------------------------------------------------------------

    fn extract_modifier_name(&self, line: &str) -> String {
        if let Some(mod_start) = line.find("modifier ") {
            let after_mod = &line[mod_start + 9..];
            if let Some(paren_pos) = after_mod.find('(') {
                return after_mod[..paren_pos].trim().to_string();
            }
            if let Some(brace_pos) = after_mod.find('{') {
                return after_mod[..brace_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
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

impl Detector for ExtcodesizeCheckBypassDetector {
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
        // Contract-level FP short-circuits
        // ---------------------------------------------------------------

        // If the entire contract already validates tx.origin == msg.sender,
        // the constructor-bypass attack vector is neutralized.
        if self.contract_has_txorigin_sender_guard(source) {
            return Ok(findings);
        }

        // If this is an EIP-1167 clone factory or detection library,
        // extcodesize usage is legitimate.
        if self.is_eip1167_clone_pattern(source) {
            return Ok(findings);
        }

        // If this is a Diamond proxy (EIP-2535) that uses extcodesize to
        // verify facet code existence before delegatecall, skip entirely.
        if self.is_diamond_proxy_pattern(source) {
            return Ok(findings);
        }

        // ---------------------------------------------------------------
        // Per-pattern detection with function-level FP reduction
        // ---------------------------------------------------------------

        for (line, func_name) in self.find_extcodesize_checks(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses EXTCODESIZE to detect contracts. \
                 This check returns 0 during contract construction and can be bypassed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "EXTCODESIZE is unreliable for contract detection:\n\n\
                     // During constructor, extcodesize == 0\n\
                     // Alternatives:\n\
                     1. Use tx.origin == msg.sender (also has limitations)\n\
                     2. Use codehash check: account.codehash != keccak256(\"\")\n\
                     3. Accept that EOA-only is not enforceable\n\
                     4. Use reentrancy guards instead of contract checks"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_is_contract_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses isContract() check. \
                 This is bypassable during contract construction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "isContract() is unreliable:\n\n\
                     // Returns false during constructor execution\n\
                     // Consider alternative approaches:\n\
                     1. Re-evaluate if contract check is necessary\n\
                     2. Use callback mechanisms instead\n\
                     3. Implement proper access control"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, modifier_name) in self.find_contract_only_modifier(source) {
            let message = format!(
                "Modifier '{}' in contract '{}' attempts to restrict to EOA using code size. \
                 Contracts can bypass this during construction.",
                modifier_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "EOA-only modifiers are bypassable:\n\n\
                     // Attacker contract constructor can call your function\n\
                     // while extcodesize(attacker) == 0\n\n\
                     Consider:\n\
                     1. Removing the EOA restriction\n\
                     2. Using additional validation\n\
                     3. Implementing rate limiting instead"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_txorigin_sender_check(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses tx.origin for authentication. \
                 This has its own security implications and may be deprecated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "tx.origin has security implications:\n\n\
                     1. Vulnerable to phishing attacks\n\
                     2. Incompatible with smart wallets/AA\n\
                     3. May be deprecated in future EIPs\n\n\
                     Consider alternative security mechanisms."
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
        let detector = ExtcodesizeCheckBypassDetector::new();
        assert_eq!(detector.name(), "EXTCODESIZE Check Bypass");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
