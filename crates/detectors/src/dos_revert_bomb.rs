use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via revert bomb attacks
///
/// Detects patterns where external actors can force reverts through
/// fallback functions, receive functions, or callback manipulation.
pub struct DosRevertBombDetector {
    base: BaseDetector,
}

impl Default for DosRevertBombDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosRevertBombDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-revert-bomb"),
                "DoS Revert Bomb".to_string(),
                "Detects patterns vulnerable to revert bomb attacks where external \
                 contracts can force transaction failures through malicious reverts."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    /// Find vulnerable transfer patterns
    /// Note: .transfer() is NOT vulnerable to revert bombs - it has a 2300 gas stipend
    /// which prevents the recipient from doing anything complex (no storage writes, no external calls)
    /// The REAL revert bomb risk is with .call{} which forwards all gas
    fn find_vulnerable_transfers(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            let func_name = self.find_containing_function(&lines, line_num);

            // .transfer() is SAFE from revert bombs:
            // - Limited to 2300 gas stipend
            // - Recipient can only log an event, nothing else
            // - Cannot do storage writes or external calls
            // - Reverts on failure (which is predictable behavior)
            //
            // DO NOT flag .transfer() - it's the safe choice for simple ETH transfers

            // .call{} without try-catch is vulnerable - forwards all gas to recipient
            // Recipient can consume arbitrary gas or deliberately revert
            if (trimmed.contains(".call{value:") || trimmed.contains(".call{"))
                && !trimmed.contains("gas:")
            {
                // Check if this is in a try-catch block (safe)
                let in_try_catch = self.is_in_try_catch(&lines, line_num);
                if in_try_catch {
                    continue;
                }

                // Skip when the call target is msg.sender (user withdrawing their own funds).
                // A revert bomb from msg.sender only harms themselves, so it is not a
                // vulnerability -- the caller controls whether they revert.
                if self.is_call_to_msg_sender(trimmed, &lines, line_num) {
                    continue;
                }

                // Skip single-call functions (not in a loop) where the call is
                // the last meaningful operation. In this pattern only the caller
                // is affected by a revert, matching the safe pull/withdrawal pattern.
                if !self.is_in_loop(&lines, line_num)
                    && self.is_last_call_in_function(&lines, line_num)
                {
                    continue;
                }

                let issue =
                    ".call{} without gas limit forwards all gas - recipient can cause revert bomb"
                        .to_string();
                findings.push((line_num as u32 + 1, func_name.clone(), issue));
            }

            // Detect send() without return check - returns false on failure but doesn't revert
            // This is a different issue (unchecked return) not a revert bomb
            // Only flag if the return value is truly unchecked
            if trimmed.contains(".send(")
                && !trimmed.contains("require")
                && !trimmed.contains("if (")
                && !trimmed.contains("if(")
                && !trimmed.contains("bool ")
                && !trimmed.contains("success")
            {
                let issue =
                    "send() return value unchecked - failure will be silently ignored".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Check if line is inside a try-catch block
    fn is_in_try_catch(&self, lines: &[&str], line_num: usize) -> bool {
        // Look backwards for try keyword
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("try ") {
                return true;
            }
            // Stop at function boundary
            if trimmed.contains("function ") {
                return false;
            }
        }
        false
    }

    /// Check if a line is inside an interface declaration
    fn is_in_interface(&self, lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with("interface ") {
                return true;
            }
            if trimmed.starts_with("contract ") || trimmed.starts_with("abstract contract ") {
                return false;
            }
        }
        false
    }

    /// Find callback-dependent patterns
    fn find_callback_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Skip interface functions - they have no implementation
            if self.is_in_interface(&lines, line_num) {
                continue;
            }

            // Detect functions that call external contracts and depend on their behavior
            if trimmed.contains("function ") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for patterns where external contract behavior affects outcome
                // Only .call{} is vulnerable to revert bombs - .transfer() has 2300 gas limit (safe)
                let has_external_call = func_body.contains(".call{")
                    || func_body.contains(".send(")
                    || self.has_interface_call(&func_body);
                // Note: .transfer() is NOT included - it has 2300 gas stipend and is safe

                let has_state_change_after =
                    self.has_state_change_after_call(&lines, line_num, func_end);

                if has_external_call
                    && has_state_change_after
                    && !func_body.contains("try ")
                    && !func_body.contains("catch")
                {
                    // If the only external call in the function body is to
                    // msg.sender and the state changes happen BEFORE the
                    // call (checks-effects-interactions), this is the safe
                    // pull/withdrawal pattern -- skip it.
                    if self.is_safe_withdrawal_pattern(&func_body, &lines, line_num, func_end) {
                        continue;
                    }

                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find auction/bidding patterns vulnerable to revert bombs
    fn find_auction_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect auction-related functions
            if trimmed.contains("function ")
                && (trimmed.contains("bid")
                    || trimmed.contains("Bid")
                    || trimmed.contains("auction")
                    || trimmed.contains("offer"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for refund to previous bidder pattern
                if func_body.contains("transfer(")
                    && (func_body.contains("highestBidder")
                        || func_body.contains("previousBidder")
                        || func_body.contains("lastBidder"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find ERC721/ERC1155 callback vulnerabilities
    fn find_token_callback_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect safe transfer functions
            if trimmed.contains("safeTransferFrom") || trimmed.contains("_safeMint") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if there are state changes that depend on the transfer success
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_block_end(&lines, func_start);

                // Ensure valid slice bounds - func_end must be > line_num
                if func_end <= line_num {
                    continue;
                }

                // Check for critical state after safe transfer
                let lines_after_transfer: String = lines[line_num..func_end].join("\n");
                if lines_after_transfer.contains("=")
                    && !lines_after_transfer.contains("try ")
                    && (lines_after_transfer.contains("owner")
                        || lines_after_transfer.contains("balance")
                        || lines_after_transfer.contains("total"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find forced revert via gas griefing
    fn find_gas_griefing_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect calls without gas limits
            if trimmed.contains(".call{value:") && !trimmed.contains("gas:") {
                // Skip when the call target is msg.sender -- the caller
                // controls their own receive/fallback; griefing themselves
                // is not a vulnerability.
                if self.is_call_to_msg_sender(trimmed, &lines, line_num) {
                    continue;
                }

                // Skip single-call functions (not in loops) where the call
                // is the last meaningful operation -- only the caller is
                // affected by failure, matching the safe pull pattern.
                if !self.is_in_loop(&lines, line_num)
                    && self.is_last_call_in_function(&lines, line_num)
                {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Detect call forwarding all gas
            if trimmed.contains(".call{") && trimmed.contains("gasleft()") {
                // Same msg.sender exemption for explicit gasleft() forwarding
                if self.is_call_to_msg_sender(trimmed, &lines, line_num) {
                    continue;
                }

                if !self.is_in_loop(&lines, line_num)
                    && self.is_last_call_in_function(&lines, line_num)
                {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Check if this is an ERC20-style transfer with 2 arguments
    /// ERC20: token.transfer(address, uint256) - has comma between args
    /// ETH: address.transfer(uint256) - single argument
    fn is_two_arg_transfer(&self, line: &str) -> bool {
        if let Some(transfer_start) = line.find(".transfer(") {
            let after_transfer = &line[transfer_start + 10..];
            if let Some(paren_end) = after_transfer.find(')') {
                let args = &after_transfer[..paren_end];
                // ERC20 transfer has a comma (2 args), ETH transfer doesn't
                return args.contains(',');
            }
        }
        false
    }

    fn has_interface_call(&self, code: &str) -> bool {
        let patterns = [
            "IERC20(",
            "IERC721(",
            "IContract(",
            "IToken(",
            ".safeTransfer",
            ".safeTransferFrom",
        ];

        for pattern in patterns {
            if code.contains(pattern) {
                return true;
            }
        }
        false
    }

    fn has_state_change_after_call(&self, lines: &[&str], start: usize, end: usize) -> bool {
        let mut found_call = false;

        for i in start..end {
            let trimmed = lines[i].trim();

            // Match external calls specifically with dot prefix
            // Note: .transfer() is NOT vulnerable to revert bombs (2300 gas limit)
            // Only check .call{} which forwards all gas
            if trimmed.contains(".call{") || trimmed.contains(".send(") {
                found_call = true;
            }

            // Check for state changes after the call
            if found_call
                && trimmed.contains("=")
                && !trimmed.contains("==")
                && !trimmed.contains("memory")
                && !trimmed.contains("bool ")
            {
                return true;
            }
        }
        false
    }

    /// Determine if a function body follows the safe withdrawal / pull pattern:
    ///
    /// 1. The only `.call{}` in the body targets `msg.sender` (or a local
    ///    alias assigned from `msg.sender`).
    /// 2. All storage-mutating state changes happen BEFORE the external call
    ///    (checks-effects-interactions).
    /// 3. The call is NOT inside a loop.
    ///
    /// When all three conditions hold, only the caller themselves can cause
    /// a revert, so it is not a DoS revert bomb vulnerability.
    fn is_safe_withdrawal_pattern(
        &self,
        _func_body: &str,
        lines: &[&str],
        func_start: usize,
        func_end: usize,
    ) -> bool {
        // Find all .call{ lines in the function
        let mut call_lines: Vec<usize> = Vec::new();
        for i in func_start..func_end {
            let trimmed = lines[i].trim();
            if trimmed.contains(".call{") && !trimmed.starts_with("//") {
                call_lines.push(i);
            }
        }

        // Must have exactly one call and it must not be in a loop
        if call_lines.len() != 1 {
            return false;
        }
        let call_line = call_lines[0];

        if self.is_in_loop(lines, call_line) {
            return false;
        }

        // The call must target msg.sender
        let call_trimmed = lines[call_line].trim();
        if !self.is_call_to_msg_sender(call_trimmed, lines, call_line) {
            return false;
        }

        // Verify checks-effects-interactions: no state changes after the
        // call (the existing `has_state_change_after_call` scans from
        // func_start; we need to check only from the call line onward).
        // If there IS a state change after the call it is NOT safe CEI.
        if self.has_state_change_after_call(lines, call_line, func_end) {
            return false;
        }

        true
    }

    /// Check whether a `.call{...}` on the given line targets `msg.sender`.
    ///
    /// Covers common Solidity idioms:
    ///   - `msg.sender.call{value: ...}("")`
    ///   - `payable(msg.sender).call{value: ...}("")`
    ///   - `address(msg.sender).call{value: ...}("")`
    ///
    /// If the target is not on the current line (e.g. stored in a local
    /// variable), we look backwards in the same function for a preceding
    /// assignment such as `address recipient = msg.sender;` and resolve
    /// the alias.
    fn is_call_to_msg_sender(&self, trimmed: &str, lines: &[&str], line_num: usize) -> bool {
        // Direct patterns on the same line
        if trimmed.contains("msg.sender.call{")
            || trimmed.contains("payable(msg.sender).call{")
            || trimmed.contains("address(msg.sender).call{")
        {
            return true;
        }

        // Try to resolve an alias: extract the identifier before `.call{`
        if let Some(call_pos) = trimmed.find(".call{") {
            let before_call = trimmed[..call_pos].trim();
            // The identifier is the last whitespace-/paren-delimited token
            let target = before_call
                .rsplit(|c: char| c.is_whitespace() || c == '(' || c == '=' || c == ',')
                .next()
                .unwrap_or("")
                .trim_end_matches(')');

            if !target.is_empty() && target != "msg" {
                // Walk backwards in the function to see if this variable
                // was assigned from msg.sender.
                for i in (0..line_num).rev() {
                    let prev = lines[i].trim();
                    // Stop at function boundary
                    if prev.contains("function ") {
                        break;
                    }
                    // Match patterns like:
                    //   address target = msg.sender;
                    //   address payable target = payable(msg.sender);
                    //   target = msg.sender;
                    if prev.contains(target)
                        && prev.contains('=')
                        && !prev.contains("==")
                        && (prev.contains("msg.sender") || prev.contains("payable(msg.sender)"))
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Determine whether `line_num` is inside a `for`, `while`, or `do` loop.
    ///
    /// Walks backwards from the current line tracking brace depth. If we
    /// encounter a loop keyword at the correct nesting depth before we hit
    /// the enclosing function declaration, the line is considered to be
    /// inside a loop.
    fn is_in_loop(&self, lines: &[&str], line_num: usize) -> bool {
        let mut depth: i32 = 0;

        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();

            // Count braces to track nesting
            for c in trimmed.chars().rev() {
                match c {
                    '}' => depth += 1,
                    '{' => depth -= 1,
                    _ => {}
                }
            }

            // If we are at the same or enclosing scope (depth <= 0) and
            // this line opens a loop, then the target line is inside it.
            if depth <= 0
                && (trimmed.starts_with("for ")
                    || trimmed.starts_with("for(")
                    || trimmed.starts_with("while ")
                    || trimmed.starts_with("while(")
                    || trimmed.starts_with("do {")
                    || trimmed.starts_with("do{")
                    || trimmed == "do")
            {
                return true;
            }

            // Stop scanning at the enclosing function boundary
            if trimmed.contains("function ") {
                return false;
            }
        }

        false
    }

    /// Check whether the `.call{...}` at `line_num` is the last meaningful
    /// operation in its enclosing function.
    ///
    /// "Last meaningful operation" means there are no storage writes,
    /// additional external calls, or state-changing statements after the
    /// call line -- only the result check (`require(success)`, `if
    /// (!success)`, etc.), closing braces, return statements, or event
    /// emissions are allowed.
    fn is_last_call_in_function(&self, lines: &[&str], line_num: usize) -> bool {
        let func_start = self.find_function_start(lines, line_num);
        let func_end = self.find_block_end(lines, func_start);

        // Look at every line after the call up to the function end.
        for i in (line_num + 1)..func_end {
            let trimmed = lines[i].trim();

            // Skip blank lines, comments, and pure braces
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with("*")
                || trimmed == "}"
                || trimmed == "};"
                || trimmed == "{"
            {
                continue;
            }

            // Allow result checks (require/revert/assert on the success bool)
            if trimmed.starts_with("require(")
                || trimmed.starts_with("require (")
                || trimmed.starts_with("if (!")
                || trimmed.starts_with("if(!")
                || trimmed.starts_with("if (!success")
                || trimmed.starts_with("if(!success")
                || trimmed.starts_with("assert(")
                || trimmed.starts_with("revert")
            {
                continue;
            }

            // Allow return statements
            if trimmed.starts_with("return") {
                continue;
            }

            // Allow event emissions
            if trimmed.starts_with("emit ") {
                continue;
            }

            // Allow success-variable declarations produced by the call itself
            // e.g. `(bool success, ) = ...` sometimes spans multiple lines
            if trimmed.contains("success") && !trimmed.contains('=') {
                continue;
            }

            // Allow closing if/else blocks that handle the call result
            if trimmed.starts_with("} else") || trimmed.starts_with("else") {
                continue;
            }

            // Anything else (state writes, additional calls, etc.) means
            // this is NOT the last meaningful operation.
            return false;
        }

        true
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
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

    fn find_block_end(&self, lines: &[&str], start: usize) -> usize {
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

impl Detector for DosRevertBombDetector {
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

        for (line, func_name, issue) in self.find_vulnerable_transfers(source) {
            let message = format!(
                "Function '{}' in contract '{}' has revert bomb risk: {}. \
                 Malicious contracts can force reverts via receive/fallback.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use call with return value check:\n\n\
                     (bool success, ) = recipient.call{value: amount}(\"\");\n\
                     if (!success) {\n\
                         // Handle failure - store for later claim\n\
                         pendingWithdrawals[recipient] += amount;\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_callback_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' depends on external callback behavior. \
                 Malicious contracts can force reverts during callbacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use try-catch for external calls:\n\n\
                     try externalContract.callback() {\n\
                         // success path\n\
                     } catch {\n\
                         // failure path - handle gracefully\n\
                         emit CallbackFailed(target);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_auction_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' refunds to previous bidder inline. \
                 Malicious bidder can block all future bids by reverting refunds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use withdrawal pattern for auctions:\n\n\
                     mapping(address => uint256) pendingReturns;\n\n\
                     function bid() external payable {\n\
                         pendingReturns[highestBidder] += highestBid;\n\
                         highestBidder = msg.sender;\n\
                         highestBid = msg.value;\n\
                     }\n\n\
                     function withdraw() external {\n\
                         uint256 amount = pendingReturns[msg.sender];\n\
                         pendingReturns[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_token_callback_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses safe transfer with callbacks. \
                 Recipient can revert in onERC721Received/onERC1155Received.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Handle safe transfer callbacks carefully:\n\n\
                     1. Complete state changes before safe transfer\n\
                     2. Use try-catch if available\n\
                     3. Consider using regular transfer for trusted paths\n\
                     4. Add fallback mechanism for failed transfers"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_gas_griefing_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' forwards unlimited gas to external call. \
                 Recipient can consume all gas causing out-of-gas revert.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit gas for external calls:\n\n\
                     // Limit gas to prevent griefing\n\
                     (bool success, ) = recipient.call{value: amount, gas: 10000}(\"\");\n\n\
                     // Or use transfer() which limits gas to 2300"
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
        let detector = DosRevertBombDetector::new();
        assert_eq!(detector.name(), "DoS Revert Bomb");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
