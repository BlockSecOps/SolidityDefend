use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

// ---------------------------------------------------------------------------
// 1. L2MsgValueInLoopDetector
// ---------------------------------------------------------------------------

/// Detector for `msg.value` used inside loops on L2 chains.
///
/// On Arbitrum and other L2s, `msg.value` inside a loop is a common
/// vulnerability because the same `msg.value` is read on every iteration,
/// effectively allowing the caller to "spend" the same Ether multiple times.
pub struct L2MsgValueInLoopDetector {
    base: BaseDetector,
}

impl Default for L2MsgValueInLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2MsgValueInLoopDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-msg-value-in-loop"),
                "L2 msg.value in Loop".to_string(),
                "Detects msg.value used inside loop constructs (for/while), which is \
                 a common vulnerability on L2 chains like Arbitrum where msg.value \
                 persists across iterations, allowing double-spending of Ether."
                    .to_string(),
                vec![DetectorCategory::L2],
                Severity::High,
            ),
        }
    }

    /// Scan the source for loop constructs containing `msg.value`.
    ///
    /// Strategy: iterate lines, when a `for (` or `while (` is found, track
    /// brace depth to determine the loop body. If `msg.value` appears inside
    /// that body, emit a finding.
    fn find_msg_value_in_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                i += 1;
                continue;
            }

            // Detect loop start
            let is_for = trimmed.contains("for (") || trimmed.contains("for(");
            let is_while = trimmed.contains("while (") || trimmed.contains("while(");

            if is_for || is_while {
                let loop_line = i;
                let func_name = self.find_containing_function(&lines, i);

                // Find the opening brace of the loop body
                let mut depth: i32 = 0;
                let mut body_started = false;
                let mut loop_body = String::new();
                let mut j = i;

                // For `for` loops, skip the parenthesized init/condition/update first
                // by tracking parens if needed, but simpler: just track braces from here
                while j < lines.len() {
                    for c in lines[j].chars() {
                        if c == '{' {
                            depth += 1;
                            body_started = true;
                        } else if c == '}' {
                            depth -= 1;
                        }
                    }

                    if body_started {
                        loop_body.push_str(lines[j]);
                        loop_body.push('\n');
                    }

                    if body_started && depth == 0 {
                        break;
                    }
                    j += 1;
                }

                // Check if msg.value appears in the loop body
                if loop_body.contains("msg.value") {
                    findings.push((loop_line as u32 + 1, func_name));
                }

                // Advance past the loop body to avoid re-matching nested loops
                // from the same outer loop
                i = j + 1;
                continue;
            }

            i += 1;
        }

        findings
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for L2MsgValueInLoopDetector {
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
        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_msg_value_in_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses msg.value inside a loop. \
                 On L2 chains like Arbitrum, msg.value persists across loop iterations, \
                 allowing the same Ether to be credited multiple times.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Cache msg.value before the loop and decrement it on each iteration:\n\n\
                     1. Store msg.value in a local variable before the loop\n\
                     2. Subtract each allocation from the cached value\n\
                     3. Require the cached value is sufficient on each iteration\n\
                     4. Refund remaining Ether after the loop\n\n\
                     Example:\n\
                     uint256 remaining = msg.value;\n\
                     for (uint i = 0; i < n; i++) {\n\
                         require(remaining >= amount, \"Insufficient\");\n\
                         remaining -= amount;\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 2. L2BlockNumberAssumptionDetector
// ---------------------------------------------------------------------------

/// Detector for `block.number` timing assumptions on L2 chains.
///
/// On L2 rollups (Optimism, Arbitrum, zkSync, etc.), `block.number` does
/// not correspond to L1 block numbers and may increment at different rates.
/// Using it for timing logic produces unreliable results.
pub struct L2BlockNumberAssumptionDetector {
    base: BaseDetector,
}

impl Default for L2BlockNumberAssumptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2BlockNumberAssumptionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-block-number-assumption"),
                "L2 block.number Timing Assumption".to_string(),
                "Detects block.number used in arithmetic or comparisons for timing, \
                 which is unreliable on L2 chains where block production rates differ \
                 significantly from L1 Ethereum mainnet."
                    .to_string(),
                vec![DetectorCategory::L2],
                Severity::Medium,
            ),
        }
    }

    /// Find `block.number` used in timing-sensitive arithmetic or comparisons.
    ///
    /// Flags patterns like `block.number - ...`, `block.number > ...`,
    /// `block.number < ...`, `block.number >= ...`, `block.number <= ...`,
    /// but NOT `blockhash(block.number)` which is a different usage.
    fn find_block_number_timing(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Skip if the contract source explicitly mentions L1 or mainnet,
        // indicating it is intentionally an L1-only contract.
        let lower_source = source.to_lowercase();
        if lower_source.contains("// l1 only")
            || lower_source.contains("// mainnet only")
            || lower_source.contains("l1 contract")
            || lower_source.contains("mainnet contract")
        {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            if !trimmed.contains("block.number") {
                continue;
            }

            // Skip `blockhash(block.number...)` patterns -- this is not a timing usage
            if trimmed.contains("blockhash(block.number") {
                continue;
            }

            // Skip pure event emissions / logging
            if trimmed.starts_with("emit ") {
                continue;
            }

            // Check for arithmetic or comparison operators adjacent to block.number
            let timing_patterns = [
                "block.number -",
                "block.number +",
                "block.number >",
                "block.number <",
                "block.number >=",
                "block.number <=",
                "block.number ==",
                "block.number !=",
                "- block.number",
                "+ block.number",
                "> block.number",
                "< block.number",
                ">= block.number",
                "<= block.number",
                "== block.number",
                "!= block.number",
            ];

            let has_timing_pattern = timing_patterns.iter().any(|p| trimmed.contains(p));

            if has_timing_pattern {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for L2BlockNumberAssumptionDetector {
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

        // FP Reduction: Skip interface contracts
        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_block_number_timing(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses block.number for timing logic. \
                 On L2 chains, block.number may not correspond to L1 blocks and can \
                 increment at different rates, making timing assumptions unreliable.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Replace block.number timing with block.timestamp:\n\n\
                     1. Use block.timestamp instead of block.number for time delays\n\
                     2. If block granularity is needed, use L2-specific APIs\n\
                     3. On Arbitrum, use ArbSys.arbBlockNumber() for L2 blocks\n\
                     4. On Optimism, use L1Block.number() for L1 block references\n\
                     5. Document any chain-specific assumptions clearly"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 3. L2GasPriceDependencyDetector
// ---------------------------------------------------------------------------

/// Detector for `tx.gasprice` / `block.basefee` usage in contract logic on L2.
///
/// L2 chains have fundamentally different gas models from L1 Ethereum.
/// Using `tx.gasprice` or `block.basefee` in calculations or conditions
/// may produce unexpected results on L2 deployments.
pub struct L2GasPriceDependencyDetector {
    base: BaseDetector,
}

impl Default for L2GasPriceDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2GasPriceDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-gas-price-dependency"),
                "L2 Gas Price Dependency".to_string(),
                "Detects tx.gasprice or block.basefee used in calculations or conditions. \
                 L2 chains have different gas pricing models (e.g., Arbitrum's two-dimensional \
                 fees, Optimism's L1 data fee) making these values unreliable for logic."
                    .to_string(),
                vec![DetectorCategory::L2],
                Severity::Medium,
            ),
        }
    }

    /// Find uses of `tx.gasprice` or `block.basefee` in calculations or conditions.
    fn find_gas_price_dependencies(&self, source: &str) -> Vec<(u32, String, &'static str)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            let has_gasprice = trimmed.contains("tx.gasprice") || trimmed.contains("tx.gasPrice");
            let has_basefee = trimmed.contains("block.basefee") || trimmed.contains("block.baseFee");

            if !has_gasprice && !has_basefee {
                continue;
            }

            // Skip pure event emissions
            if trimmed.starts_with("emit ") {
                continue;
            }

            let keyword = if has_gasprice {
                "tx.gasprice"
            } else {
                "block.basefee"
            };

            // Check if it's used in a calculation or condition (not just stored/logged)
            let in_arithmetic = trimmed.contains('*')
                || trimmed.contains('/')
                || trimmed.contains('+')
                || trimmed.contains('-')
                || trimmed.contains('%');

            let in_condition = trimmed.contains("require")
                || trimmed.contains("if ")
                || trimmed.contains("if(")
                || trimmed.contains("assert")
                || trimmed.contains(">=")
                || trimmed.contains("<=")
                || trimmed.contains("==")
                || trimmed.contains("!=")
                || trimmed.contains("> ")
                || trimmed.contains("< ");

            let in_assignment = trimmed.contains('=');

            if in_arithmetic || in_condition || in_assignment {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name, keyword));
            }
        }

        findings
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for L2GasPriceDependencyDetector {
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

        // FP Reduction: Skip interface contracts
        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, keyword) in self.find_gas_price_dependencies(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses {} in logic. \
                 L2 gas pricing models differ significantly from L1: Arbitrum uses \
                 two-dimensional fees, Optimism adds L1 data fees, and zkSync uses \
                 a different EVM gas schedule. This value may not behave as expected.",
                func_name, contract_name, keyword
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_cwe(840) // CWE-840: Business Logic Errors
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(format!(
                    "Avoid relying on {} for business logic on L2:\n\n\
                     1. Use L2-native gas oracles instead (e.g., Arbitrum's ArbGasInfo)\n\
                     2. If used for MEV protection, use commit-reveal or private mempools\n\
                     3. If used for fee estimation, query the L2 sequencer directly\n\
                     4. Consider that L2 gas prices can be zero or near-zero\n\
                     5. Account for L1 data posting costs separately on optimistic rollups",
                    keyword
                ));

            findings.push(finding);
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 4. L2Push0CrossDeployDetector
// ---------------------------------------------------------------------------

/// Detector for PUSH0 opcode compatibility issues in cross-chain deployments.
///
/// Solidity >= 0.8.20 generates PUSH0 opcodes by default (EVM version Shanghai).
/// Several L2 chains (e.g., Arbitrum before Stylus, older zkSync versions, some
/// alt-L1s) do not support PUSH0, causing deployment failures.
pub struct L2Push0CrossDeployDetector {
    base: BaseDetector,
}

impl Default for L2Push0CrossDeployDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2Push0CrossDeployDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-push0-cross-deploy"),
                "L2 PUSH0 Cross-Chain Deploy".to_string(),
                "Detects contracts compiled with Solidity >= 0.8.20 (which uses the \
                 PUSH0 opcode) that mention cross-chain or multi-chain deployment. \
                 Chains that do not support PUSH0 will reject these contracts."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::Deployment],
                Severity::Medium,
            ),
        }
    }

    /// Check if the source pragma specifies Solidity >= 0.8.20.
    fn has_push0_pragma(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if !trimmed.starts_with("pragma solidity") {
                continue;
            }

            // Extract version constraints from the pragma
            // Common patterns:
            //   pragma solidity ^0.8.20;
            //   pragma solidity >=0.8.20;
            //   pragma solidity >=0.8.20 <0.9.0;
            //   pragma solidity 0.8.20;
            //   pragma solidity ^0.8.24;

            // Check for version numbers >= 0.8.20
            if self.pragma_implies_push0(trimmed) {
                return Some(line_num as u32 + 1);
            }
        }

        None
    }

    /// Determine if a pragma line implies PUSH0 usage (version >= 0.8.20).
    fn pragma_implies_push0(&self, pragma_line: &str) -> bool {
        // Extract all version-like patterns: 0.X.Y
        let mut i = 0;
        let bytes = pragma_line.as_bytes();

        while i < bytes.len() {
            // Look for "0." pattern that starts a version
            if bytes[i] == b'0' && i + 1 < bytes.len() && bytes[i + 1] == b'.' {
                // Try to parse 0.major.minor
                if let Some((major, minor, end)) = self.parse_version(&pragma_line[i..]) {
                    // We only care about 0.8.x where x >= 20, or 0.9+
                    if major > 8 || (major == 8 && minor >= 20) {
                        // Check this version isn't preceded by '<' (upper bound)
                        // by looking at context before this version number
                        let before = pragma_line[..i].trim_end();
                        if !before.ends_with('<') {
                            return true;
                        }
                    }
                    i += end;
                    continue;
                }
            }
            i += 1;
        }

        false
    }

    /// Parse a version number like "0.8.20" from the start of `s`.
    /// Returns (major, minor, chars_consumed) or None.
    fn parse_version(&self, s: &str) -> Option<(u32, u32, usize)> {
        // Expect "0."
        if !s.starts_with("0.") {
            return None;
        }
        let rest = &s[2..];

        // Parse major (single or multi digit)
        let major_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if major_end == 0 {
            return None;
        }
        let major: u32 = rest[..major_end].parse().ok()?;

        // Expect '.'
        let after_major = &rest[major_end..];
        if !after_major.starts_with('.') {
            return None;
        }
        let minor_start = &after_major[1..];

        // Parse minor
        let minor_end = minor_start
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(minor_start.len());
        if minor_end == 0 {
            return None;
        }
        let minor: u32 = minor_start[..minor_end].parse().ok()?;

        let total_consumed = 2 + major_end + 1 + minor_end;
        Some((major, minor, total_consumed))
    }

    /// Check if the source mentions cross-chain or multi-chain deployment.
    fn has_cross_chain_keywords(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        let keywords = [
            "cross-chain",
            "crosschain",
            "cross chain",
            "multi-chain",
            "multichain",
            "multi chain",
            "deploy to multiple",
            "deploy on multiple",
            "multi-network",
            "multinetwork",
            "chain agnostic",
            "chain-agnostic",
            "any chain",
            "all chains",
            "multiple chains",
            "multiple networks",
            "arbitrum",
            "optimism",
            "polygon",
            "zksync",
            "base chain",
            "scroll",
            "linea",
            "mantle",
            "blast",
        ];

        keywords.iter().any(|kw| lower.contains(kw))
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for L2Push0CrossDeployDetector {
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

        // FP Reduction: Skip interface contracts
        if utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Both conditions must be true: pragma >= 0.8.20 AND cross-chain keywords
        if let Some(pragma_line) = self.has_push0_pragma(source) {
            if self.has_cross_chain_keywords(source) {
                let message = format!(
                    "Contract '{}' uses Solidity >= 0.8.20 (which emits PUSH0 opcode) and \
                     mentions cross-chain deployment. Some L2 chains and alt-L1s do not \
                     support PUSH0, which will cause deployment failures or runtime reverts.",
                    contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, pragma_line, 1, 50)
                    .with_cwe(435) // CWE-435: Improper Interaction Between Multiple Entities
                    .with_cwe(664) // CWE-664: Improper Control of a Resource Through its Lifetime
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Ensure PUSH0 compatibility for cross-chain deployments:\n\n\
                         1. Set the EVM target version explicitly in compiler settings:\n\
                            solc --evm-version paris (avoids PUSH0)\n\
                         2. In Foundry: evm_version = \"paris\" in foundry.toml\n\
                         3. In Hardhat: evmVersion: \"paris\" in hardhat.config.js\n\
                         4. Verify target chain EVM version support before deploying\n\
                         5. Test deployments on all target chains in testnets first"
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        let findings = utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_msg_value_in_loop_properties() {
        let detector = L2MsgValueInLoopDetector::new();
        assert_eq!(detector.id().0, "l2-msg-value-in-loop");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_l2_block_number_assumption_properties() {
        let detector = L2BlockNumberAssumptionDetector::new();
        assert_eq!(detector.id().0, "l2-block-number-assumption");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_l2_gas_price_dependency_properties() {
        let detector = L2GasPriceDependencyDetector::new();
        assert_eq!(detector.id().0, "l2-gas-price-dependency");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_l2_push0_cross_deploy_properties() {
        let detector = L2Push0CrossDeployDetector::new();
        assert_eq!(detector.id().0, "l2-push0-cross-deploy");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    // -----------------------------------------------------------------------
    // Unit tests for detection helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_msg_value_in_for_loop_detected() {
        let detector = L2MsgValueInLoopDetector::new();
        let source = r#"
contract MultiSend {
    function distribute(address[] calldata recipients) external payable {
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(msg.value / recipients.length);
        }
    }
}
"#;
        let findings = detector.find_msg_value_in_loops(source);
        assert!(
            !findings.is_empty(),
            "msg.value inside a for loop should be flagged"
        );
    }

    #[test]
    fn test_msg_value_outside_loop_not_flagged() {
        let detector = L2MsgValueInLoopDetector::new();
        let source = r#"
contract Safe {
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#;
        let findings = detector.find_msg_value_in_loops(source);
        assert!(
            findings.is_empty(),
            "msg.value outside a loop should not be flagged"
        );
    }

    #[test]
    fn test_msg_value_in_while_loop_detected() {
        let detector = L2MsgValueInLoopDetector::new();
        let source = r#"
contract Auction {
    function batchBid(uint256 count) external payable {
        uint256 i = 0;
        while (i < count) {
            _placeBid(msg.value);
            i++;
        }
    }
}
"#;
        let findings = detector.find_msg_value_in_loops(source);
        assert!(
            !findings.is_empty(),
            "msg.value inside a while loop should be flagged"
        );
    }

    #[test]
    fn test_block_number_arithmetic_detected() {
        let detector = L2BlockNumberAssumptionDetector::new();
        let source = r#"
contract TimeLock {
    function isUnlocked(uint256 lockBlock) public view returns (bool) {
        return block.number - lockBlock > 100;
    }
}
"#;
        let findings = detector.find_block_number_timing(source);
        assert!(
            !findings.is_empty(),
            "block.number arithmetic should be flagged"
        );
    }

    #[test]
    fn test_blockhash_block_number_not_flagged() {
        let detector = L2BlockNumberAssumptionDetector::new();
        let source = r#"
contract Random {
    function getHash() public view returns (bytes32) {
        return blockhash(block.number - 1);
    }
}
"#;
        let findings = detector.find_block_number_timing(source);
        assert!(
            findings.is_empty(),
            "blockhash(block.number) should not be flagged as timing"
        );
    }

    #[test]
    fn test_block_number_l1_only_skipped() {
        let detector = L2BlockNumberAssumptionDetector::new();
        let source = r#"
// L1 only contract
contract MainnetGovernance {
    function isReady(uint256 startBlock) public view returns (bool) {
        return block.number - startBlock > 50;
    }
}
"#;
        let findings = detector.find_block_number_timing(source);
        assert!(
            findings.is_empty(),
            "L1-only contracts should be skipped"
        );
    }

    #[test]
    fn test_tx_gasprice_in_condition_detected() {
        let detector = L2GasPriceDependencyDetector::new();
        let source = r#"
contract GasGuard {
    function execute() external {
        require(tx.gasprice <= maxGasPrice, "gas too high");
        _doWork();
    }
}
"#;
        let findings = detector.find_gas_price_dependencies(source);
        assert!(
            !findings.is_empty(),
            "tx.gasprice in require should be flagged"
        );
    }

    #[test]
    fn test_block_basefee_in_calculation_detected() {
        let detector = L2GasPriceDependencyDetector::new();
        let source = r#"
contract FeeCalculator {
    function estimateFee(uint256 gasUnits) external view returns (uint256) {
        return gasUnits * block.basefee;
    }
}
"#;
        let findings = detector.find_gas_price_dependencies(source);
        assert!(
            !findings.is_empty(),
            "block.basefee in arithmetic should be flagged"
        );
    }

    #[test]
    fn test_push0_pragma_detected() {
        let detector = L2Push0CrossDeployDetector::new();
        assert!(detector.has_push0_pragma("pragma solidity ^0.8.20;").is_some());
        assert!(detector.has_push0_pragma("pragma solidity >=0.8.24;").is_some());
        assert!(detector.has_push0_pragma("pragma solidity 0.8.25;").is_some());
        assert!(detector.has_push0_pragma("pragma solidity ^0.8.19;").is_none());
        assert!(detector.has_push0_pragma("pragma solidity >=0.8.0 <0.8.20;").is_none());
    }

    #[test]
    fn test_cross_chain_keywords_detected() {
        let detector = L2Push0CrossDeployDetector::new();
        assert!(detector.has_cross_chain_keywords("// Deploy on multiple chains including Arbitrum"));
        assert!(detector.has_cross_chain_keywords("/// @notice Cross-chain bridge"));
        assert!(!detector.has_cross_chain_keywords("// Simple ERC20 token"));
    }

    #[test]
    fn test_push0_without_cross_chain_no_finding() {
        let detector = L2Push0CrossDeployDetector::new();
        let source = "pragma solidity ^0.8.24;\n\ncontract Simple { }";
        // Should have push0 pragma but no cross-chain keywords
        assert!(detector.has_push0_pragma(source).is_some());
        assert!(!detector.has_cross_chain_keywords(source));
    }

    #[test]
    fn test_all_detectors_enabled_by_default() {
        assert!(L2MsgValueInLoopDetector::new().is_enabled());
        assert!(L2BlockNumberAssumptionDetector::new().is_enabled());
        assert!(L2GasPriceDependencyDetector::new().is_enabled());
        assert!(L2Push0CrossDeployDetector::new().is_enabled());
    }

    #[test]
    fn test_all_detectors_have_l2_category() {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(L2MsgValueInLoopDetector::new()),
            Box::new(L2BlockNumberAssumptionDetector::new()),
            Box::new(L2GasPriceDependencyDetector::new()),
            Box::new(L2Push0CrossDeployDetector::new()),
        ];
        for d in &detectors {
            assert!(
                d.categories().contains(&DetectorCategory::L2),
                "Detector '{}' should have L2 category",
                d.name()
            );
        }
    }
}
