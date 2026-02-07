use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via external calls in loops
///
/// Detects patterns where external calls are made within loops,
/// allowing a single malicious recipient to block the entire operation.
///
/// False-positive reduction (context-aware):
///   - Skips view/pure functions (read-only, no state-change DoS)
///   - Skips internal/private functions (not directly callable externally)
///   - Skips admin/owner-only functions (admin controls loop bounds)
///   - Skips signature-verified owner functions (require(signer == owner), require(isSigner[]))
///   - Skips fixed-size/bounded loops (small literal upper bound <= 20)
///   - Skips try/catch wrapped external calls (errors do not propagate)
///   - Skips pull-over-push patterns (contract already uses safe withdrawal)
///   - Skips constructor functions (one-time bounded execution)
///   - Skips loops over caller-controlled parameter arrays (caller only DoSes themselves)
///   - Skips loops that only send to msg.sender (caller only DoSes themselves)
///   - Skips low-level call with success check and continue (error handling without try/catch)
///   - Batch function detection checks actual loop body (not entire function body)
pub struct DosExternalCallLoopDetector {
    base: BaseDetector,
}

impl Default for DosExternalCallLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosExternalCallLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-external-call-loop"),
                "DoS External Call in Loop".to_string(),
                "Detects external calls within loops that can lead to denial of service \
                 if any recipient reverts or consumes excessive gas."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    // ---------------------------------------------------------------
    // Context-aware false-positive helpers
    // ---------------------------------------------------------------

    /// Check if the containing function is view or pure.
    /// View/pure functions are read-only and cannot cause state-change DoS.
    fn is_view_or_pure_function(&self, lines: &[&str], line_num: usize) -> bool {
        let func_start = self.find_function_start(lines, line_num);
        // Gather up to 6 lines to handle multi-line function signatures
        let header_end = std::cmp::min(func_start + 6, lines.len());
        let sig: String = lines[func_start..header_end].join(" ");
        // Only check before the opening brace to avoid matching keywords in the body
        if let Some(brace_pos) = sig.find('{') {
            let before_brace = &sig[..brace_pos];
            return before_brace.contains(" view") || before_brace.contains(" pure");
        }
        let lower = sig.to_lowercase();
        lower.contains(" view") || lower.contains(" pure")
    }

    /// Check if the containing function is internal or private (not externally callable).
    fn is_internal_or_private_function(&self, lines: &[&str], line_num: usize) -> bool {
        let func_start = self.find_function_start(lines, line_num);
        let header_end = std::cmp::min(func_start + 6, lines.len());
        let sig: String = lines[func_start..header_end].join(" ");
        if let Some(brace_pos) = sig.find('{') {
            let before_brace = &sig[..brace_pos];
            return before_brace.contains(" internal") || before_brace.contains(" private");
        }
        sig.contains(" internal") || sig.contains(" private")
    }

    /// Check if a function header/body contains admin-only access control modifiers or
    /// inline require-based owner checks.
    fn is_admin_only_function(&self, lines: &[&str], func_start: usize, func_end: usize) -> bool {
        let func_source: String =
            lines[func_start..std::cmp::min(func_end, lines.len())].join("\n");
        let lower = func_source.to_lowercase();

        // Modifier-based access control
        let admin_modifiers = [
            "onlyowner",
            "onlyadmin",
            "onlyrole",
            "onlygovernor",
            "onlygovernance",
            "onlyauthorized",
            "onlyoperator",
            "onlymanager",
            "onlyguardian",
            "onlyminter",
            "onlycontroller",
            "onlykeepers",
            "onlymultisig",
        ];
        for modifier in &admin_modifiers {
            if lower.contains(modifier) {
                return true;
            }
        }

        // Inline require-based access control
        let owner_checks = [
            "require(msg.sender == owner",
            "require(msg.sender == _owner",
            "require(msg.sender == admin",
            "require(msg.sender == governance",
            "require(msg.sender == guardian",
            "if (msg.sender != owner",
            "if (msg.sender != _owner",
            "if (msg.sender != admin",
        ];
        for check in &owner_checks {
            if lower.contains(check) {
                return true;
            }
        }

        // OpenZeppelin Ownable2Step / AccessControl patterns
        if lower.contains("_checkowner()") || lower.contains("_checkrole(") {
            return true;
        }

        // Signature-verified owner checks (e.g., multisig patterns)
        // require(signer == owner, ...) or require(isSigner[...], ...)
        if lower.contains("require(signer == owner")
            || lower.contains("require(signer == _owner")
            || lower.contains("require(issigner[")
        {
            return true;
        }

        false
    }

    /// Check if the line is inside a constructor (one-time bounded operation).
    fn is_inside_constructor(&self, lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("constructor(") || trimmed.starts_with("constructor(") {
                // Verify we haven't exited the constructor body
                let ctor_end = self.find_block_end(lines, i);
                return line_num < ctor_end;
            }
            // If we hit a function keyword first, we're not in a constructor
            if trimmed.contains("function ") {
                return false;
            }
        }
        false
    }

    /// Check if a for-loop has a small, fixed/literal upper bound (e.g., `i < 5`).
    /// Loops with small bounds are not DoS vectors because iteration count is known
    /// at compile time.
    fn is_bounded_small_loop(&self, loop_line: &str) -> bool {
        // Maximum iteration count we consider "small/bounded"
        const MAX_SAFE_ITERATIONS: u64 = 20;

        let trimmed = loop_line.trim();

        // Match patterns like: for (...; i < 10; ...) or for (...; i <= 10; ...)
        // Also handle: for (...; i < MAX_RECIPIENTS; ...) where MAX is a constant name
        // We focus on literal numeric bounds here.
        if !trimmed.starts_with("for") {
            return false;
        }

        // Extract the condition part (between first ; and second ;)
        if let Some(open_paren) = trimmed.find('(') {
            let after_paren = &trimmed[open_paren + 1..];
            let parts: Vec<&str> = after_paren.splitn(3, ';').collect();
            if parts.len() >= 2 {
                let condition = parts[1].trim();
                // Look for literal numeric upper bound: i < N, i <= N, i != N
                for op in &["<= ", "< ", "!= "] {
                    if let Some(pos) = condition.find(op) {
                        let bound_str = condition[pos + op.len()..].trim();
                        // Strip trailing ')' or ';' or whitespace
                        let bound_clean: String = bound_str
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect();
                        if let Ok(bound) = bound_clean.parse::<u64>() {
                            if bound <= MAX_SAFE_ITERATIONS {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if the loop body wraps all external calls in try/catch blocks.
    /// When external calls are inside try/catch, a revert in one call does not
    /// propagate and block subsequent iterations.
    fn has_try_catch_protection(&self, loop_body: &str) -> bool {
        // Check if the loop body contains try/catch wrapping the external call patterns
        if !loop_body.contains("try ") {
            return false;
        }

        // Count how many external call patterns exist vs how many are inside try blocks
        let external_call_patterns = ["transfer(", ".send(", ".call{", ".call("];

        let mut has_unprotected_call = false;
        for pattern in &external_call_patterns {
            if loop_body.contains(pattern) {
                // Check if this pattern appears only inside try blocks
                // Simple heuristic: if the body has "try " and has the pattern,
                // and doesn't have the pattern outside of a try block context.
                // We approximate by checking that every line with the pattern
                // is preceded by a "try " on the same or a nearby line.
                for (i, line) in loop_body.lines().enumerate() {
                    let line_trimmed = line.trim();
                    if line_trimmed.contains(pattern) && !line_trimmed.starts_with("//") {
                        // Look backwards up to 3 lines for a "try " keyword
                        let start = if i >= 3 { i - 3 } else { 0 };
                        let context: String = loop_body
                            .lines()
                            .skip(start)
                            .take(i - start + 1)
                            .collect::<Vec<&str>>()
                            .join("\n");
                        if !context.contains("try ") {
                            has_unprotected_call = true;
                        }
                    }
                }
            }
        }

        // Also check interface calls within try blocks
        if self.has_external_interface_call(loop_body) {
            // If the body has interface calls, check if they are all inside try blocks
            for line in loop_body.lines() {
                let line_trimmed = line.trim();
                if line_trimmed.starts_with("//") {
                    continue;
                }
                // Simple heuristic: interface calls on lines not starting with "try"
                // and not inside a try block
                if self.line_has_interface_call(line_trimmed) && !line_trimmed.starts_with("try ") {
                    // Check if this line is inside a try block by looking for nearby "try"
                    has_unprotected_call = true;
                }
            }
        }

        !has_unprotected_call
    }

    /// Check if the contract already implements a pull-over-push pattern.
    /// Contracts that store amounts in mappings for later withdrawal are safe.
    fn has_pull_pattern(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Look for pull-over-push indicators in the contract:
        // 1. A "withdraw" function combined with a mapping for pending amounts
        // 2. "pendingWithdrawals" or "pendingPayments" mappings
        // 3. "claimable" pattern
        let has_withdraw_function = lower.contains("function withdraw")
            || lower.contains("function claim")
            || lower.contains("function claimrefund")
            || lower.contains("function claimreward");

        let has_pending_mapping = lower.contains("pendingwithdrawals")
            || lower.contains("pendingpayments")
            || lower.contains("owed[")
            || lower.contains("claimable[")
            || lower.contains("credits[")
            || lower.contains("balances[");

        has_withdraw_function && has_pending_mapping
    }

    /// Check if a for-loop iterates over a caller-controlled parameter array
    /// (calldata or memory array passed as a function argument). The caller
    /// controls the length, so they only DoS themselves.
    fn is_loop_over_caller_param(&self, loop_line: &str, lines: &[&str], line_num: usize) -> bool {
        // Extract the array name from the loop condition (e.g., "recipients.length")
        let array_name = if let Some(name) = self.extract_loop_array(loop_line) {
            name
        } else {
            return false;
        };

        // Find the function header to check if this array is a calldata/memory parameter
        let func_start = self.find_function_start(lines, line_num);
        let header_end = std::cmp::min(func_start + 8, lines.len());
        let func_header: String = lines[func_start..header_end].join(" ");

        // Check if the array name appears as a calldata or memory parameter
        let calldata_pattern = format!("calldata {}", array_name);
        let memory_pattern = format!("memory {}", array_name);
        let calldata_underscore = format!("calldata _{}", array_name);
        let memory_underscore = format!("memory _{}", array_name);

        func_header.contains(&calldata_pattern)
            || func_header.contains(&memory_pattern)
            || func_header.contains(&calldata_underscore)
            || func_header.contains(&memory_underscore)
    }

    /// Extract the array name from a for-loop condition (e.g., "recipients" from
    /// "for (uint i = 0; i < recipients.length; i++)").
    fn extract_loop_array(&self, loop_line: &str) -> Option<String> {
        if let Some(length_pos) = loop_line.find(".length") {
            let before_length = &loop_line[..length_pos];
            // Walk backwards from ".length" to find the array name
            let name: String = before_length
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
        None
    }

    /// Check if all external calls in a loop body only send to msg.sender.
    /// When the only recipient is msg.sender, the caller can only DoS themselves.
    fn loop_only_sends_to_msg_sender(&self, loop_body: &str) -> bool {
        let has_transfer = loop_body.contains("transfer(")
            || loop_body.contains(".send(")
            || loop_body.contains(".call{")
            || loop_body.contains(".call(");

        if !has_transfer {
            return false;
        }

        // Check each line that has a transfer/call: is the recipient msg.sender?
        for line in loop_body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            // Check for transfer/send/call patterns
            let is_external_call = trimmed.contains("transfer(")
                || trimmed.contains(".send(")
                || trimmed.contains(".call{")
                || trimmed.contains(".call(");

            if is_external_call {
                // If the line sends to msg.sender or payable(msg.sender), it's safe
                let has_msg_sender =
                    trimmed.contains("msg.sender") || trimmed.contains("payable(msg.sender)");
                if !has_msg_sender {
                    return false;
                }
            }
        }

        true
    }

    /// Check if the loop body uses low-level call with success check and continue,
    /// effectively implementing error handling without try/catch.
    fn has_call_success_continue(&self, loop_body: &str) -> bool {
        // Pattern: (bool success, ) = addr.call{...}(...); if (!success) { continue; }
        // or: (bool ok, ) = addr.call{...}(...); if (!ok) continue;
        let has_success_var = loop_body.contains("(bool success")
            || loop_body.contains("(bool ok")
            || loop_body.contains("(bool sent");
        let has_continue_on_fail = loop_body.contains("if (!success")
            && loop_body.contains("continue")
            || loop_body.contains("if (!ok") && loop_body.contains("continue")
            || loop_body.contains("if (!sent") && loop_body.contains("continue");

        has_success_var && has_continue_on_fail
    }

    /// Check if a for-loop has a named constant upper bound (e.g., `i < MAX_RECIPIENTS`).
    /// FP Reduction v3: Loops bounded by named constants like MAX_RECIPIENTS, MAX_BATCH_SIZE,
    /// etc. are developer-bounded. The constant name signals intentional bounding.
    fn is_bounded_by_named_constant(&self, loop_line: &str) -> bool {
        let trimmed = loop_line.trim();
        if !trimmed.starts_with("for") {
            return false;
        }

        // Extract the condition part (between first ; and second ;)
        if let Some(open_paren) = trimmed.find('(') {
            let after_paren = &trimmed[open_paren + 1..];
            let parts: Vec<&str> = after_paren.splitn(3, ';').collect();
            if parts.len() >= 2 {
                let condition = parts[1].trim();
                // Look for comparison with an ALL_CAPS constant
                for op in &["< ", "<= ", "!= "] {
                    if let Some(pos) = condition.find(op) {
                        let bound_str = condition[pos + op.len()..].trim();
                        // Strip trailing ')' or whitespace
                        let bound_name: String = bound_str
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        // Named constants: ALL_CAPS with underscores, or MAX_/MIN_ prefix
                        if !bound_name.is_empty() {
                            let is_all_caps =
                                bound_name.chars().all(|c| c.is_ascii_uppercase() || c == '_');
                            let has_max_min_prefix = bound_name.starts_with("MAX_")
                                || bound_name.starts_with("MIN_")
                                || bound_name.starts_with("LIMIT_")
                                || bound_name.starts_with("CAP_");
                            if is_all_caps || has_max_min_prefix {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if the loop body contains gas-bounded iteration patterns.
    /// FP Reduction v3: Loops with gasleft() checks break early when gas is low,
    /// preventing unbounded iteration and DoS.
    fn has_gas_bounded_iteration(&self, loop_body: &str) -> bool {
        // Pattern: if (gasleft() < threshold) break;
        // Pattern: require(gasleft() > threshold);
        loop_body.contains("gasleft()") && (loop_body.contains("break") || loop_body.contains("return"))
    }

    /// Check if all external calls in the loop use SafeERC20 wrapper.
    /// FP Reduction v3: SafeERC20 operations (safeTransfer, safeTransferFrom)
    /// wrap the call in a way that handles return values and reverts.
    /// Combined with try/catch or success checks, they're safe patterns.
    fn uses_safe_transfer_only(&self, loop_body: &str) -> bool {
        // Check for SafeERC20 patterns
        let has_safe_transfer = loop_body.contains("safeTransfer(")
            || loop_body.contains("safeTransferFrom(")
            || loop_body.contains("safeApprove(");

        // Check for raw transfer patterns that would NOT be safe
        let has_raw_transfer = loop_body.contains(".transfer(")
            || loop_body.contains(".send(")
            || loop_body.contains(".call{")
            || loop_body.contains(".call(");

        // Only safe if using SafeERC20 and NOT raw transfers
        has_safe_transfer && !has_raw_transfer
    }

    /// Check if the loop body only emits events and reads state, without
    /// making actual external calls that could revert.
    /// FP Reduction v3: Loops that only emit events are not DoS vectors.
    fn loop_only_emits_events(&self, loop_body: &str) -> bool {
        // Check for external call patterns
        let external_patterns = [
            ".transfer(",
            ".send(",
            ".call{",
            ".call(",
            "IERC20(",
            "IToken(",
            "IContract(",
        ];

        for pattern in &external_patterns {
            for line in loop_body.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains(pattern) {
                    return false;
                }
            }
        }

        // Also check for generic interface calls
        if self.has_external_interface_call(loop_body) {
            return false;
        }

        true
    }

    // ---------------------------------------------------------------
    // Core detection methods (with FP filtering)
    // ---------------------------------------------------------------

    /// Find external calls in loops
    fn find_calls_in_loops(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for/while loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                // --- FP reduction: skip constructors ---
                if self.is_inside_constructor(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip view/pure functions ---
                if self.is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip internal/private functions ---
                if self.is_internal_or_private_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip admin/owner-only functions ---
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_block_end(&lines, func_start);
                if self.is_admin_only_function(&lines, func_start, func_end) {
                    continue;
                }

                // --- FP reduction: skip fixed-size/bounded small loops ---
                if self.is_bounded_small_loop(trimmed) {
                    continue;
                }

                // --- FP reduction v3: skip loops bounded by named constants ---
                if self.is_bounded_by_named_constant(trimmed) {
                    continue;
                }

                // --- FP reduction: skip loops over caller-controlled parameters ---
                if self.is_loop_over_caller_param(trimmed, &lines, line_num) {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // --- FP reduction: skip try/catch wrapped calls ---
                if self.has_try_catch_protection(&loop_body) {
                    continue;
                }

                // --- FP reduction: skip low-level call with success+continue ---
                if self.has_call_success_continue(&loop_body) {
                    continue;
                }

                // --- FP reduction: skip loops that only send to msg.sender ---
                if self.loop_only_sends_to_msg_sender(&loop_body) {
                    continue;
                }

                // --- FP reduction v3: skip gas-bounded iteration ---
                if self.has_gas_bounded_iteration(&loop_body) {
                    continue;
                }

                // --- FP reduction v3: skip loops using SafeERC20 only ---
                if self.uses_safe_transfer_only(&loop_body) {
                    continue;
                }

                // --- FP reduction v3: skip loops that only emit events ---
                if self.loop_only_emits_events(&loop_body) {
                    continue;
                }

                // Check for various external call patterns
                if loop_body.contains("transfer(") {
                    let issue = "transfer() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                if loop_body.contains(".send(") {
                    let issue = "send() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                if loop_body.contains(".call{") || loop_body.contains(".call(") {
                    let issue = "call() in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for interface/contract calls
                if self.has_external_interface_call(&loop_body) {
                    let issue = "external contract call in loop".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find push payment pattern violations
    fn find_push_payment_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // --- FP reduction: skip if contract already has pull pattern ---
        if self.has_pull_pattern(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect functions that distribute to multiple recipients
            if trimmed.contains("function ")
                && (trimmed.contains("distribute")
                    || trimmed.contains("Distribute")
                    || trimmed.contains("payout")
                    || trimmed.contains("Payout")
                    || trimmed.contains("reward")
                    || trimmed.contains("airdrop"))
            {
                // --- FP reduction: skip view/pure functions ---
                if self.is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip internal/private functions ---
                if self.is_internal_or_private_function(&lines, line_num) {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // --- FP reduction: skip admin-only distribution functions ---
                if self.is_admin_only_function(&lines, line_num, func_end) {
                    continue;
                }

                // --- FP reduction: skip if function uses try/catch ---
                if func_body.contains("try ") {
                    continue;
                }

                // Check if it loops and transfers
                if (func_body.contains("for") || func_body.contains("while"))
                    && (func_body.contains("transfer(")
                        || func_body.contains(".send(")
                        || func_body.contains(".call{"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find batch operations with external calls
    fn find_batch_external_calls(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect batch functions
            if trimmed.contains("function ")
                && (trimmed.contains("batch")
                    || trimmed.contains("Batch")
                    || trimmed.contains("multi")
                    || trimmed.contains("Multi")
                    || trimmed.contains("bulk"))
            {
                // --- FP reduction: skip view/pure functions ---
                if self.is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip internal/private functions ---
                if self.is_internal_or_private_function(&lines, line_num) {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);

                // --- FP reduction: skip admin-only batch functions ---
                if self.is_admin_only_function(&lines, line_num, func_end) {
                    continue;
                }

                // Find actual loops within the function and check if external calls
                // are inside the loop body (not just anywhere in the function).
                let mut found_vulnerable_loop = false;
                for loop_idx in (line_num + 1)..func_end {
                    if loop_idx >= lines.len() {
                        break;
                    }
                    let loop_trimmed = lines[loop_idx].trim();
                    if !loop_trimmed.starts_with("for") && !loop_trimmed.starts_with("while") {
                        continue;
                    }

                    // --- FP reduction: skip bounded small loops ---
                    if self.is_bounded_small_loop(loop_trimmed) {
                        continue;
                    }

                    // --- FP reduction v3: skip loops bounded by named constants ---
                    if self.is_bounded_by_named_constant(loop_trimmed) {
                        continue;
                    }

                    // --- FP reduction: skip loops over caller-controlled parameters ---
                    if self.is_loop_over_caller_param(loop_trimmed, &lines, loop_idx) {
                        continue;
                    }

                    let loop_end = self.find_block_end(&lines, loop_idx);
                    let loop_body: String = lines[loop_idx..loop_end].join("\n");

                    // --- FP reduction: skip try/catch wrapped calls ---
                    if self.has_try_catch_protection(&loop_body) {
                        continue;
                    }

                    // --- FP reduction: skip low-level call with success+continue ---
                    if self.has_call_success_continue(&loop_body) {
                        continue;
                    }

                    // --- FP reduction: skip loops that only send to msg.sender ---
                    if self.loop_only_sends_to_msg_sender(&loop_body) {
                        continue;
                    }

                    // --- FP reduction v3: skip gas-bounded iteration ---
                    if self.has_gas_bounded_iteration(&loop_body) {
                        continue;
                    }

                    // --- FP reduction v3: skip loops using SafeERC20 only ---
                    if self.uses_safe_transfer_only(&loop_body) {
                        continue;
                    }

                    // --- FP reduction v3: skip loops that only emit events ---
                    if self.loop_only_emits_events(&loop_body) {
                        continue;
                    }

                    // Check that external calls are actually inside THIS loop body
                    let has_call_in_loop = loop_body.contains(".call{")
                        || loop_body.contains(".call(")
                        || loop_body.contains("transfer(")
                        || loop_body.contains(".send(")
                        || self.has_external_interface_call(&loop_body);

                    if has_call_in_loop {
                        found_vulnerable_loop = true;
                        break;
                    }
                }

                if found_vulnerable_loop {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find refund loops
    fn find_refund_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // --- FP reduction: skip if contract already has pull pattern ---
        if self.has_pull_pattern(source) {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                // --- FP reduction: skip constructors ---
                if self.is_inside_constructor(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip view/pure functions ---
                if self.is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip internal/private functions ---
                if self.is_internal_or_private_function(&lines, line_num) {
                    continue;
                }

                // --- FP reduction: skip admin-only functions ---
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_block_end(&lines, func_start);
                if self.is_admin_only_function(&lines, func_start, func_end) {
                    continue;
                }

                // --- FP reduction: skip bounded small loops ---
                if self.is_bounded_small_loop(trimmed) {
                    continue;
                }

                // --- FP reduction v3: skip loops bounded by named constants ---
                if self.is_bounded_by_named_constant(trimmed) {
                    continue;
                }

                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // --- FP reduction: skip try/catch wrapped calls ---
                if self.has_try_catch_protection(&loop_body) {
                    continue;
                }

                // --- FP reduction: skip low-level call with success+continue ---
                if self.has_call_success_continue(&loop_body) {
                    continue;
                }

                // --- FP reduction v3: skip gas-bounded iteration ---
                if self.has_gas_bounded_iteration(&loop_body) {
                    continue;
                }

                // --- FP reduction v3: skip loops using SafeERC20 only ---
                if self.uses_safe_transfer_only(&loop_body) {
                    continue;
                }

                // Check for refund pattern
                if (loop_body.contains("refund")
                    || loop_body.contains("Refund")
                    || loop_body.contains("withdraw")
                    || loop_body.contains("return"))
                    && (loop_body.contains("transfer(")
                        || loop_body.contains(".send(")
                        || loop_body.contains(".call{"))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    // ---------------------------------------------------------------
    // Utility helpers
    // ---------------------------------------------------------------

    fn has_external_interface_call(&self, code: &str) -> bool {
        // Check for interface call patterns like IToken(addr).function()
        let interface_patterns = [
            "IERC20(",
            "IToken(",
            "IContract(",
            "IVault(",
            "IPool(",
            "oracle.",
            "router.",
            "factory.",
            "pool.",
            "vault.",
        ];

        for pattern in interface_patterns {
            if code.contains(pattern) && code.contains("(") {
                return true;
            }
        }

        // Generic pattern: ISomething(addr).method()
        for line in code.lines() {
            if self.line_has_interface_call(line.trim()) {
                return true;
            }
        }

        false
    }

    /// Check if a single line contains an interface-style external call.
    /// Matches patterns like `ISomething(addr).method(...)` where the interface
    /// name starts with a capital I followed by another capital letter.
    fn line_has_interface_call(&self, trimmed: &str) -> bool {
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            return false;
        }
        // Look for pattern: I<UpperCase><word>(<something>).<method>(
        // e.g., IERC20(token).transfer(...), IVault(addr).deposit(...)
        let bytes = trimmed.as_bytes();
        let len = bytes.len();
        let mut i = 0;
        while i + 3 < len {
            // Find 'I' followed by an uppercase letter (start of interface name)
            if bytes[i] == b'I'
                && bytes[i + 1].is_ascii_uppercase()
                // Make sure it's not in the middle of a word (check char before)
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                // Walk forward to find the opening paren of the cast
                let mut j = i + 2;
                while j < len && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                // j should now point to '(' if this is an interface cast
                if j < len && bytes[j] == b'(' {
                    // Find the matching close paren
                    let mut depth = 1;
                    let mut k = j + 1;
                    while k < len && depth > 0 {
                        if bytes[k] == b'(' {
                            depth += 1;
                        } else if bytes[k] == b')' {
                            depth -= 1;
                        }
                        k += 1;
                    }
                    // After ')' we expect '.' for a method call
                    if k < len && bytes[k] == b'.' {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") || trimmed.contains("constructor(") {
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
            if trimmed.contains("constructor(") {
                return "constructor".to_string();
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

impl Detector for DosExternalCallLoopDetector {
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

        for (line, func_name, issue) in self.find_calls_in_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' has DoS vulnerability: {}. \
                 A single malicious or failing recipient can block the entire operation.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use pull-over-push pattern:\n\n\
                     // Instead of:\n\
                     for (uint i = 0; i < recipients.length; i++) {\n\
                         recipients[i].transfer(amounts[i]); // DoS risk\n\
                     }\n\n\
                     // Use:\n\
                     mapping(address => uint256) pendingWithdrawals;\n\n\
                     function withdraw() external {\n\
                         uint256 amount = pendingWithdrawals[msg.sender];\n\
                         pendingWithdrawals[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_push_payment_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses push payment pattern for distribution. \
                 Single failing recipient will revert entire distribution.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Convert to pull payment pattern:\n\n\
                     1. Store amounts in mapping instead of sending\n\
                     2. Let recipients claim their share\n\
                     3. Or use try-catch with failure tracking:\n\n\
                     try recipient.call{value: amount}(\"\") {\n\
                         // success\n\
                     } catch {\n\
                         failedPayments[recipient] = amount;\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_external_calls(source) {
            let message = format!(
                "Function '{}' in contract '{}' makes batch external calls without error handling. \
                 Single failure will revert the entire batch.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add error handling for batch operations:\n\n\
                     for (uint i = 0; i < targets.length; i++) {\n\
                         try IContract(targets[i]).method() {\n\
                             // handle success\n\
                         } catch {\n\
                             // log failure, continue\n\
                             emit BatchCallFailed(targets[i]);\n\
                         }\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_refund_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' refunds in a loop. \
                 Contract rejecting refund will block all subsequent refunds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement claimable refund pattern:\n\n\
                     mapping(address => uint256) refunds;\n\n\
                     function markRefund(address user, uint256 amount) internal {\n\
                         refunds[user] += amount;\n\
                     }\n\n\
                     function claimRefund() external {\n\
                         uint256 amount = refunds[msg.sender];\n\
                         refunds[msg.sender] = 0;\n\
                         payable(msg.sender).transfer(amount);\n\
                     }"
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
        let detector = DosExternalCallLoopDetector::new();
        assert_eq!(detector.name(), "DoS External Call in Loop");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_is_bounded_small_loop() {
        let detector = DosExternalCallLoopDetector::new();
        // Small literal bound should be considered safe
        assert!(detector.is_bounded_small_loop("for (uint i = 0; i < 5; i++) {"));
        assert!(detector.is_bounded_small_loop("for (uint i = 0; i < 10; i++) {"));
        assert!(detector.is_bounded_small_loop("for (uint i = 0; i <= 3; i++) {"));
        // Large literal bound should NOT be considered safe
        assert!(!detector.is_bounded_small_loop("for (uint i = 0; i < 100; i++) {"));
        assert!(!detector.is_bounded_small_loop("for (uint i = 0; i < 1000; i++) {"));
        // Dynamic bound (array.length) should NOT be considered safe
        assert!(!detector.is_bounded_small_loop("for (uint i = 0; i < recipients.length; i++) {"));
        // While loops are not bounded
        assert!(!detector.is_bounded_small_loop("while (i < 5) {"));
    }

    #[test]
    fn test_has_try_catch_protection() {
        let detector = DosExternalCallLoopDetector::new();

        let protected = r#"
            for (uint i = 0; i < len; i++) {
                try IToken(addr).transfer(to, amt) {
                    // success
                } catch {
                    emit Failed(to);
                }
            }
        "#;
        assert!(detector.has_try_catch_protection(protected));

        let unprotected = r#"
            for (uint i = 0; i < len; i++) {
                IToken(addr).transfer(to, amt);
            }
        "#;
        assert!(!detector.has_try_catch_protection(unprotected));
    }

    #[test]
    fn test_has_call_success_continue() {
        let detector = DosExternalCallLoopDetector::new();

        let with_continue = r#"
            for (uint i = 0; i < len; i++) {
                (bool success, ) = recipients[i].call{value: amounts[i]}("");
                if (!success) { continue; }
            }
        "#;
        assert!(detector.has_call_success_continue(with_continue));

        let without_continue = r#"
            for (uint i = 0; i < len; i++) {
                recipients[i].call{value: amounts[i]}("");
            }
        "#;
        assert!(!detector.has_call_success_continue(without_continue));
    }

    #[test]
    fn test_extract_loop_array() {
        let detector = DosExternalCallLoopDetector::new();
        assert_eq!(
            detector.extract_loop_array("for (uint i = 0; i < recipients.length; i++) {"),
            Some("recipients".to_string())
        );
        assert_eq!(
            detector.extract_loop_array("for (uint i = 0; i < _users.length; i++) {"),
            Some("_users".to_string())
        );
        assert_eq!(
            detector.extract_loop_array("for (uint i = 0; i < 10; i++) {"),
            None
        );
    }

    #[test]
    fn test_is_bounded_by_named_constant() {
        let detector = DosExternalCallLoopDetector::new();
        // Named constants (ALL_CAPS) should be considered bounded
        assert!(detector.is_bounded_by_named_constant("for (uint i = 0; i < MAX_RECIPIENTS; i++) {"));
        assert!(detector.is_bounded_by_named_constant("for (uint i = 0; i < MAX_BATCH_SIZE; i++) {"));
        assert!(detector.is_bounded_by_named_constant("for (uint i = 0; i < LIMIT_COUNT; i++) {"));
        assert!(detector.is_bounded_by_named_constant("for (uint i = 0; i < CAP_SIZE; i++) {"));
        // Non-constant names should NOT be considered bounded
        assert!(!detector.is_bounded_by_named_constant("for (uint i = 0; i < recipients.length; i++) {"));
        assert!(!detector.is_bounded_by_named_constant("for (uint i = 0; i < count; i++) {"));
        assert!(!detector.is_bounded_by_named_constant("for (uint i = 0; i < maxCount; i++) {"));
        // While loops are not matched
        assert!(!detector.is_bounded_by_named_constant("while (i < MAX_SIZE) {"));
    }

    #[test]
    fn test_has_gas_bounded_iteration() {
        let detector = DosExternalCallLoopDetector::new();
        let gas_bounded = r#"
            for (uint i = 0; i < len; i++) {
                if (gasleft() < 50000) break;
                recipients[i].transfer(amounts[i]);
            }
        "#;
        assert!(detector.has_gas_bounded_iteration(gas_bounded));

        let not_gas_bounded = r#"
            for (uint i = 0; i < len; i++) {
                recipients[i].transfer(amounts[i]);
            }
        "#;
        assert!(!detector.has_gas_bounded_iteration(not_gas_bounded));
    }

    #[test]
    fn test_uses_safe_transfer_only() {
        let detector = DosExternalCallLoopDetector::new();
        let safe_only = r#"
            for (uint i = 0; i < len; i++) {
                IERC20(token).safeTransfer(recipients[i], amounts[i]);
            }
        "#;
        assert!(detector.uses_safe_transfer_only(safe_only));

        // Mixed: has both safe and raw transfers
        let mixed = r#"
            for (uint i = 0; i < len; i++) {
                IERC20(token).safeTransfer(recipients[i], amounts[i]);
                recipients[i].transfer(ethAmounts[i]);
            }
        "#;
        assert!(!detector.uses_safe_transfer_only(mixed));

        // Only raw transfers
        let raw_only = r#"
            for (uint i = 0; i < len; i++) {
                recipients[i].transfer(amounts[i]);
            }
        "#;
        assert!(!detector.uses_safe_transfer_only(raw_only));
    }

    #[test]
    fn test_loop_only_emits_events() {
        let detector = DosExternalCallLoopDetector::new();
        let events_only = r#"
            for (uint i = 0; i < len; i++) {
                balances[recipients[i]] += amounts[i];
                emit Transfer(address(this), recipients[i], amounts[i]);
            }
        "#;
        assert!(detector.loop_only_emits_events(events_only));

        let with_transfer = r#"
            for (uint i = 0; i < len; i++) {
                recipients[i].transfer(amounts[i]);
                emit Sent(recipients[i], amounts[i]);
            }
        "#;
        assert!(!detector.loop_only_emits_events(with_transfer));
    }
}
