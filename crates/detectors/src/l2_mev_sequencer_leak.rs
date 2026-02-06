use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for L2 MEV extraction by sequencers
///
/// Detects patterns where L2 sequencers can extract MEV through transaction
/// ordering, sandwich attacks, or information asymmetry.
pub struct L2MevSequencerLeakDetector {
    base: BaseDetector,
}

impl Default for L2MevSequencerLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2MevSequencerLeakDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-mev-sequencer-leak"),
                "L2 MEV Sequencer Leak".to_string(),
                "Detects patterns vulnerable to MEV extraction by L2 sequencers \
                 through ordering manipulation or information advantages."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    /// Find sequencer-exploitable ordering patterns
    fn find_ordering_vulnerabilities(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect swap functions without slippage protection
            if trimmed.contains("function ")
                && (trimmed.contains("swap") || trimmed.contains("Swap"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for slippage protection
                if !func_body.contains("minAmount")
                    && !func_body.contains("amountOutMin")
                    && !func_body.contains("slippage")
                {
                    let issue = "Swap without slippage protection".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for deadline protection
                if !func_body.contains("deadline") && !func_body.contains("expiry") {
                    let issue = "Swap without deadline protection".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect liquidation functions
            if trimmed.contains("function ")
                && trimmed.contains("liquidate")
                && !trimmed.starts_with("//")
            {
                // Skip view/pure liquidation functions - they are read-only
                if self.is_view_or_pure_function(trimmed)
                    || self.is_view_or_pure_in_header(&lines, line_num)
                {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for fair liquidation mechanisms
                if !func_body.contains("auction")
                    && !func_body.contains("dutch")
                    && !func_body.contains("delay")
                {
                    let issue = "Liquidation without fair ordering mechanism".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find priority gas auction vulnerabilities
    fn find_pga_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect first-come-first-served patterns
            if (trimmed.contains("firstCaller")
                || trimmed.contains("winner")
                || (trimmed.contains("require") && trimmed.contains("!claimed")))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Detect gas price dependencies
            if trimmed.contains("tx.gasprice") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find batch transaction vulnerabilities
    fn find_batch_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect batch/multicall without atomic guarantees
            if trimmed.contains("function ")
                && (trimmed.contains("multicall")
                    || trimmed.contains("batch")
                    || trimmed.contains("aggregate"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for atomicity
                if func_body.contains("for") && !func_body.contains("revert") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find oracle update MEV opportunities
    fn find_oracle_mev(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_oracle = source.contains("oracle") || source.contains("Oracle");
        if !has_oracle {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect price-dependent functions
            if trimmed.contains("function ")
                && (trimmed.contains("getPrice")
                    || trimmed.contains("latestAnswer")
                    || trimmed.contains("updatePrice"))
                && !trimmed.starts_with("//")
            {
                // Skip view/pure functions - they cannot be exploited by sequencer MEV
                // since they don't modify state and are not transaction-orderable
                if self.is_view_or_pure_function(trimmed)
                    || self.is_view_or_pure_in_header(&lines, line_num)
                {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for TWAP or aggregation
                if !func_body.contains("twap")
                    && !func_body.contains("TWAP")
                    && !func_body.contains("average")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
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

    /// Check if a function signature indicates a view or pure function.
    /// View/pure functions cannot modify state and are not exploitable by sequencer MEV.
    fn is_view_or_pure_function(&self, func_line: &str) -> bool {
        let trimmed = func_line.trim();
        trimmed.contains(" view ") || trimmed.contains(" view\n")
            || trimmed.contains(" pure ") || trimmed.contains(" pure\n")
            || trimmed.ends_with(" view") || trimmed.ends_with(" pure")
            || trimmed.contains(" view{") || trimmed.contains(" pure{")
            // Also handle multiline: check if "view" or "pure" appears after function params
            || trimmed.contains(") view") || trimmed.contains(") pure")
            || trimmed.contains(")view") || trimmed.contains(")pure")
    }

    /// Check if the function is a view/pure by looking at the full function header
    /// (which may span multiple lines up to the opening brace).
    fn is_view_or_pure_in_header(&self, lines: &[&str], func_start: usize) -> bool {
        // Collect lines from function declaration to the opening brace
        let mut header = String::new();
        for line in lines.iter().skip(func_start) {
            header.push_str(line);
            header.push(' ');
            if line.contains('{') {
                break;
            }
        }
        let header_lower = header.to_lowercase();
        header_lower.contains(" view ")
            || header_lower.contains(" view{")
            || header_lower.contains(" pure ")
            || header_lower.contains(" pure{")
            || header_lower.contains(")view")
            || header_lower.contains(")pure")
    }

    /// Check if the contract is a flash loan contract (L1 pattern).
    /// Flash loan contracts are L1 DeFi primitives; L2 sequencer MEV is not relevant.
    fn is_flash_loan_contract(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        // Flash loan provider/borrower indicators
        (lower.contains("flashloan")
            || lower.contains("flash loan")
            || lower.contains("flashmint")
            || lower.contains("flash mint"))
            && (lower.contains("onflashloan")
                || lower.contains("ierc3156")
                || lower.contains("flashborrower")
                || lower.contains("flashlender")
                || lower.contains("balancebefore")
                || lower.contains("balanceafter"))
    }

    /// Check if the contract is a delegatecall proxy contract.
    /// Delegatecall proxy contracts are not L2-specific and should not be flagged.
    fn is_delegatecall_proxy_contract(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        // Strong delegatecall proxy indicators
        lower.contains("delegatecall")
            && (lower.contains("proxy")
                || lower.contains("implementation")
                || lower.contains("fallback")
                || lower.contains("delegate"))
    }

    /// Check if contract appears to be L2-specific.
    /// Returns true if there are strong indicators this is an L2 contract.
    /// Uses strict matching to avoid false positives from common English words.
    fn is_l2_context(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // L2-specific imports/interfaces - use word-boundary-aware matching
        // Note: "base" is excluded as a standalone check because it matches
        // common words like "based", "database", "basedon" etc. Instead we
        // look for "base chain", "base network", "base l2", or Base-specific
        // contract addresses/interfaces.
        let has_l2_imports = lower.contains("arbitrum")
            || lower.contains("optimism")
            || lower.contains("zksync")
            || lower.contains("base chain")
            || lower.contains("base network")
            || lower.contains("base l2")
            || lower.contains("base rollup")
            || lower.contains("linea")
            || lower.contains("polygon zkevm")
            || lower.contains("scroll")
            || lower.contains("starknet")
            || lower.contains("mantle")
            || lower.contains("blast network")
            || lower.contains("blast l2")
            || lower.contains("blast chain")
            || lower.contains("blast rollup");

        // L2-specific interfaces
        let has_l2_interfaces = lower.contains("iarbsys")
            || lower.contains("iovmgaspriceoracle")
            || lower.contains("il2crossdomainmessenger")
            || lower.contains("icrossdomainmessenger")
            || lower.contains("iarbitrumbridge")
            || lower.contains("isequencerinbox")
            || lower.contains("il2bridge")
            || lower.contains("il1bridge");

        // L2-specific addresses/contracts
        let has_l2_contracts = source.contains("0x000000000000000000000000000000000000006E") // Arbitrum ArbSys
            || source.contains("0x420000000000000000000000000000000000000F") // Optimism Gas Oracle
            || source.contains("0x4200000000000000000000000000000000000007") // Optimism L2CrossDomainMessenger
            || lower.contains("arbsys")
            || lower.contains("arbinfo");

        // L2-specific functionality - require more specific patterns
        let has_l2_functionality = lower.contains("l2 sequencer")
            || lower.contains("l2sequencer")
            || lower.contains("sequencerinbox")
            || lower.contains("l1 message")
            || lower.contains("l2 message")
            || lower.contains("l1message")
            || lower.contains("l2message")
            || lower.contains("crossdomainmessenger")
            || lower.contains("l2_bridge")
            || lower.contains("l2bridge");

        has_l2_imports || has_l2_interfaces || has_l2_contracts || has_l2_functionality
    }
}

impl Detector for L2MevSequencerLeakDetector {
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

        // Only check contracts that appear to be L2-specific
        // L2 MEV issues are not relevant for L1-only contracts
        if !self.is_l2_context(source) {
            return Ok(findings);
        }

        // Skip flash loan contracts - these are L1 DeFi patterns,
        // not subject to L2 sequencer MEV
        if self.is_flash_loan_contract(source) {
            return Ok(findings);
        }

        // Skip delegatecall proxy contracts - batch operations in these
        // contexts are proxy patterns, not L2 batch processing
        if self.is_delegatecall_proxy_contract(source) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_ordering_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' is vulnerable to sequencer MEV: {}. \
                 L2 sequencers can reorder transactions for profit extraction.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Mitigate sequencer MEV:\n\n\
                     1. Implement slippage protection (minAmountOut)\n\
                     2. Add transaction deadlines\n\
                     3. Use commit-reveal schemes for sensitive operations\n\
                     4. Consider private transaction pools\n\
                     5. Implement fair sequencing protocols"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_pga_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses patterns vulnerable to priority gas auctions. \
                 Sequencers can exploit ordering for first-mover advantage.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Avoid PGA-vulnerable patterns:\n\n\
                     1. Use batch auctions instead of first-come-first-served\n\
                     2. Implement commit-reveal for competitive operations\n\
                     3. Avoid gas price dependencies\n\
                     4. Consider time-weighted allocation"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs batch operations that sequencers \
                 could exploit through partial execution ordering.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Improve batch operation safety:\n\n\
                     1. Make batch operations atomic (all-or-nothing)\n\
                     2. Add revert on partial failure\n\
                     3. Implement batch ordering guarantees\n\
                     4. Consider splitting into individual transactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_oracle_mev(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses oracle prices without TWAP protection. \
                 Sequencers can exploit oracle update timing for MEV.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add oracle MEV protection:\n\n\
                     1. Use TWAP instead of spot prices\n\
                     2. Implement price deviation limits\n\
                     3. Add oracle update frequency checks\n\
                     4. Consider multi-source price aggregation"
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
        let detector = L2MevSequencerLeakDetector::new();
        assert_eq!(detector.name(), "L2 MEV Sequencer Leak");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // ========================================================================
    // L2 context detection tests
    // ========================================================================

    #[test]
    fn test_is_l2_context_with_arbitrum() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IArbSys } from "@arbitrum/nitro-contracts/src/precompiles/IArbSys.sol";
            contract ArbitrumSwap {
                function swap() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect Arbitrum context"
        );
    }

    #[test]
    fn test_is_l2_context_with_optimism() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IL2CrossDomainMessenger } from "@optimism/contracts/L2/messaging/IL2CrossDomainMessenger.sol";
            contract OptimismSwap {
                function swap() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect Optimism context"
        );
    }

    #[test]
    fn test_is_l2_context_with_sequencer_inbox() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            interface ISequencerInbox {
                function addSequencerL2Batch() external;
            }
            contract L2Handler {
                function process() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect sequencer inbox context"
        );
    }

    #[test]
    fn test_is_l2_context_with_arbsys_address() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract ArbitrumUtil {
                address constant ARBSYS = 0x000000000000000000000000000000000000006E;
                function getBlockNumber() external view returns (uint256) {
                    return IArbSys(ARBSYS).arbBlockNumber();
                }
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect ArbSys address"
        );
    }

    #[test]
    fn test_is_l2_context_rejects_generic_l1_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        // This contract has "based" (contains "base") but is NOT an L2 contract
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            // Token-based governance with flash loan protection
            contract VotingGovernance {
                mapping(address => uint256) public votingPower;
                // Voting power based on snapshot, not current balance
                function vote(uint256 proposalId) external {
                    // Use voting power at snapshot block
                }
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "Should NOT detect L2 context from 'based' in comments"
        );
    }

    #[test]
    fn test_is_l2_context_rejects_flash_loan_with_based_word() {
        let detector = L2MevSequencerLeakDetector::new();
        // Simulates VulnerableFlashLoan.sol pattern - has "based" in comments
        let source = r#"
            contract VulnerableFlashLoan {
                address public priceOracle;
                // Borrow decision based on manipulable price
                function borrow(uint256 amount) external {}
                function liquidate(address borrower, address token) external {}
                function getPrice(address token) external view returns (uint256) {
                    return IOracle(priceOracle).getPrice(token);
                }
            }
            interface IOracle {
                function getPrice(address token) external view returns (uint256);
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "Should NOT detect L2 context from 'based' in flash loan contract"
        );
    }

    #[test]
    fn test_is_l2_context_rejects_delegatecall_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        // Simulates UserControlledDelegatecall.sol pattern
        let source = r#"
            // Storage-based target selection
            contract StorageBasedSelection {
                address public owner;
                function batchExecute(address[] calldata targets, bytes[] calldata data) external {
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool success, ) = targets[i].delegatecall(data[i]);
                        require(success);
                    }
                }
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "Should NOT detect L2 context from 'Based' in contract name"
        );
    }

    #[test]
    fn test_is_l2_context_with_base_chain_explicit() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // Deployed on Base Chain
            contract BaseChainSwap {
                function swap(uint256 amountIn) external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect 'Base Chain' as L2 context"
        );
    }

    #[test]
    fn test_is_l2_context_with_crossdomainmessenger() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { ICrossDomainMessenger } from "./ICrossDomainMessenger.sol";
            contract L2Bridge {
                function relayMessage() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Should detect CrossDomainMessenger as L2 context"
        );
    }

    // ========================================================================
    // Flash loan contract exclusion tests
    // ========================================================================

    #[test]
    fn test_is_flash_loan_contract_with_erc3156() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract FlashLoanProvider {
                function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = address(this).balance;
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    uint256 balanceAfter = address(this).balance;
                }
            }
        "#;
        assert!(
            detector.is_flash_loan_contract(source),
            "Should detect flash loan contract"
        );
    }

    #[test]
    fn test_is_flash_loan_contract_with_flash_mint() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract FlashMintToken {
                function flashMint(address receiver, uint256 amount, bytes calldata data) external {
                    uint256 balanceBefore = totalSupply;
                    IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
                    uint256 balanceAfter = totalSupply;
                }
            }
        "#;
        assert!(
            detector.is_flash_loan_contract(source),
            "Should detect flash mint as flash loan"
        );
    }

    #[test]
    fn test_not_flash_loan_for_regular_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract ArbitrumDEX {
                function swap(uint256 amountIn) external {}
                function getPrice() external view returns (uint256) { return 0; }
            }
        "#;
        assert!(
            !detector.is_flash_loan_contract(source),
            "Regular contract should NOT be detected as flash loan"
        );
    }

    // ========================================================================
    // Delegatecall proxy contract exclusion tests
    // ========================================================================

    #[test]
    fn test_is_delegatecall_proxy_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract ProxyContract {
                address public implementation;
                fallback() external payable {
                    address impl = implementation;
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    }
                }
            }
        "#;
        assert!(
            detector.is_delegatecall_proxy_contract(source),
            "Should detect delegatecall proxy"
        );
    }

    #[test]
    fn test_is_delegatecall_batch_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract BatchDelegatecall {
                function batchExecute(address[] calldata targets, bytes[] calldata data) external {
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool success, ) = targets[i].delegatecall(data[i]);
                        require(success);
                    }
                }
            }
        "#;
        assert!(
            detector.is_delegatecall_proxy_contract(source),
            "Should detect delegatecall batch contract as proxy pattern"
        );
    }

    #[test]
    fn test_not_delegatecall_for_regular_contract() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract L2DEX {
                function swap(uint256 amount) external {}
            }
        "#;
        assert!(
            !detector.is_delegatecall_proxy_contract(source),
            "Regular contract should NOT be detected as delegatecall proxy"
        );
    }

    // ========================================================================
    // View/pure function exclusion tests
    // ========================================================================

    #[test]
    fn test_is_view_function_detected() {
        let detector = L2MevSequencerLeakDetector::new();
        assert!(detector.is_view_or_pure_function(
            "function getPrice(address token) external view returns (uint256) {"
        ));
    }

    #[test]
    fn test_is_pure_function_detected() {
        let detector = L2MevSequencerLeakDetector::new();
        assert!(detector.is_view_or_pure_function(
            "function calculate(uint256 a, uint256 b) internal pure returns (uint256) {"
        ));
    }

    #[test]
    fn test_non_view_function_not_matched() {
        let detector = L2MevSequencerLeakDetector::new();
        assert!(
            !detector.is_view_or_pure_function("function liquidate(address borrower) external {")
        );
    }

    #[test]
    fn test_view_in_multiline_header() {
        let detector = L2MevSequencerLeakDetector::new();
        let lines: Vec<&str> = vec![
            "    function getPrice(address token)",
            "        external",
            "        view",
            "        returns (uint256)",
            "    {",
        ];
        assert!(
            detector.is_view_or_pure_in_header(&lines, 0),
            "Should detect view in multiline function header"
        );
    }

    #[test]
    fn test_non_view_multiline_header() {
        let detector = L2MevSequencerLeakDetector::new();
        let lines: Vec<&str> = vec![
            "    function liquidate(address borrower)",
            "        external",
            "    {",
        ];
        assert!(
            !detector.is_view_or_pure_in_header(&lines, 0),
            "Should NOT detect view in non-view multiline header"
        );
    }

    // ========================================================================
    // Oracle MEV view/pure exclusion tests
    // ========================================================================

    #[test]
    fn test_oracle_mev_skips_view_getprice() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract PriceOracle {
                function getPrice(address token) external view returns (uint256) {
                    return prices[token];
                }
            }
        "#;
        let findings = detector.find_oracle_mev(source);
        assert!(
            findings.is_empty(),
            "Should skip view getPrice function, got {} findings",
            findings.len()
        );
    }

    #[test]
    fn test_oracle_mev_flags_non_view_updateprice() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract PriceOracle {
                function updatePrice(address token, uint256 newPrice) external {
                    prices[token] = newPrice;
                }
            }
        "#;
        let findings = detector.find_oracle_mev(source);
        assert!(
            !findings.is_empty(),
            "Should flag non-view updatePrice function"
        );
    }

    #[test]
    fn test_oracle_mev_skips_pure_function() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract PriceOracle {
                function getPrice(uint256 reserve0, uint256 reserve1) public pure returns (uint256) {
                    return (reserve1 * 1e18) / reserve0;
                }
            }
        "#;
        let findings = detector.find_oracle_mev(source);
        assert!(findings.is_empty(), "Should skip pure getPrice function");
    }

    // ========================================================================
    // Ordering vulnerabilities - liquidation exclusion tests
    // ========================================================================

    #[test]
    fn test_ordering_skips_view_liquidate() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract LendingPool {
                function liquidate(address borrower) external view returns (bool) {
                    return collateralValue < threshold;
                }
            }
        "#;
        let findings = detector.find_ordering_vulnerabilities(source);
        let liquidation_findings: Vec<_> = findings
            .iter()
            .filter(|(_, _, issue)| issue.contains("Liquidation"))
            .collect();
        assert!(
            liquidation_findings.is_empty(),
            "Should skip view liquidation function, got {} findings",
            liquidation_findings.len()
        );
    }

    #[test]
    fn test_ordering_flags_non_view_liquidate() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract LendingPool {
                function liquidate(address borrower, address collateralToken) external {
                    uint256 collateralValue = getCollateralValue(collateralToken, 1000 ether);
                    if (collateralValue < 1500 ether) {
                        // Liquidate
                    }
                }
            }
        "#;
        let findings = detector.find_ordering_vulnerabilities(source);
        let liquidation_findings: Vec<_> = findings
            .iter()
            .filter(|(_, _, issue)| issue.contains("Liquidation"))
            .collect();
        assert!(
            !liquidation_findings.is_empty(),
            "Should flag non-view liquidation function without fair ordering"
        );
    }

    // ========================================================================
    // Batch vulnerabilities - delegatecall exclusion tests
    // ========================================================================

    #[test]
    fn test_batch_flags_l2_multicall_without_revert() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            contract L2Router {
                function multicall(bytes[] calldata data) external returns (bytes[] memory) {
                    bytes[] memory results = new bytes[](data.length);
                    for (uint256 i = 0; i < data.length; i++) {
                        results[i] = Address.functionDelegateCall(address(this), data[i]);
                    }
                    return results;
                }
            }
        "#;
        let findings = detector.find_batch_vulnerabilities(source);
        assert!(
            !findings.is_empty(),
            "Should flag L2 multicall without revert"
        );
    }

    // ========================================================================
    // False positive regression tests for specific FP cases
    // ========================================================================

    #[test]
    fn test_fp_vulnerable_flash_loan_liquidate_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        // Simulates VulnerableFlashLoan.sol - an L1 flash loan contract
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            contract VulnerableOracleFlashLoan {
                address public priceOracle;
                function calculateCollateralValue(address token, uint256 amount) external view returns (uint256) {
                    uint256 price = IOracle(priceOracle).getPrice(token);
                    return amount * price;
                }
                // Borrow decision based on manipulable price
                function borrow(address collateralToken, uint256 collateralAmount, uint256 borrowAmount) external {
                    uint256 collateralValue = this.calculateCollateralValue(collateralToken, collateralAmount);
                    require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");
                }
                function liquidate(address borrower, address collateralToken) external {
                    uint256 collateralValue = this.calculateCollateralValue(collateralToken, 1000 ether);
                    if (collateralValue < 1500 ether) {
                        // Liquidate
                    }
                }
            }
            interface IOracle {
                function getPrice(address token) external view returns (uint256);
            }
        "#;
        // Should NOT be detected as L2 context
        assert!(
            !detector.is_l2_context(source),
            "VulnerableFlashLoan.sol should NOT be detected as L2 context"
        );
    }

    #[test]
    fn test_fp_user_controlled_delegatecall_batch_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        // Simulates UserControlledDelegatecall.sol
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            // Storage-based target selection
            contract BatchDelegatecall {
                address public owner;
                function batchExecute(address[] calldata targets, bytes[] calldata data) external {
                    require(targets.length == data.length, "Length mismatch");
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool success, ) = targets[i].delegatecall(data[i]);
                        require(success, "Batch call failed");
                    }
                }
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "UserControlledDelegatecall.sol should NOT be detected as L2 context"
        );
    }

    #[test]
    fn test_fp_secure_flash_loan_getprice_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        // Simulates SecureFlashLoan.sol
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            contract SecureOracleFlashLoan {
                address public twapOracle;
                address public chainlinkOracle;
                function getSecurePrice(address token) external view returns (uint256) {
                    uint256 twapPrice = ITWAPOracle(twapOracle).getTWAP(token, 30 minutes);
                    uint256 chainlinkPrice = IChainlinkOracle(chainlinkOracle).getPrice(token);
                    return (twapPrice + chainlinkPrice) / 2;
                }
            }
            interface IChainlinkOracle {
                function getPrice(address token) external view returns (uint256);
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "SecureFlashLoan.sol should NOT be detected as L2 context"
        );
    }

    // ========================================================================
    // True positive tests - L2 contracts that SHOULD be flagged
    // ========================================================================

    #[test]
    fn test_tp_arbitrum_swap_without_slippage() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IArbSys } from "@arbitrum/nitro-contracts/src/precompiles/IArbSys.sol";
            contract ArbitrumDEX {
                function swap(uint256 amountIn, address tokenIn, address tokenOut) external {
                    uint256 amountOut = pool.getAmountOut(amountIn, tokenIn, tokenOut);
                    pool.transfer(tokenOut, msg.sender, amountOut);
                }
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Arbitrum DEX should be L2 context"
        );
        let findings = detector.find_ordering_vulnerabilities(source);
        assert!(
            !findings.is_empty(),
            "Should flag Arbitrum swap without slippage"
        );
    }

    #[test]
    fn test_tp_optimism_liquidation_without_fair_ordering() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IL2CrossDomainMessenger } from "@optimism/contracts/L2/messaging/IL2CrossDomainMessenger.sol";
            contract OptimismLending {
                function liquidate(address borrower) external {
                    uint256 debt = getDebt(borrower);
                    uint256 collateral = getCollateral(borrower);
                    if (collateral * 100 < debt * 150) {
                        // Perform liquidation without fair ordering
                        seizeCollateral(borrower);
                    }
                }
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Optimism lending should be L2 context"
        );
        let findings = detector.find_ordering_vulnerabilities(source);
        let liquidation_findings: Vec<_> = findings
            .iter()
            .filter(|(_, _, issue)| issue.contains("Liquidation"))
            .collect();
        assert!(
            !liquidation_findings.is_empty(),
            "Should flag Optimism liquidation without fair ordering"
        );
    }

    #[test]
    fn test_tp_l2_oracle_non_view_updateprice() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IArbSys } from "@arbitrum/nitro-contracts/src/precompiles/IArbSys.sol";
            contract ArbitrumOracle {
                mapping(address => uint256) public prices;
                function updatePrice(address token) external {
                    uint256 spot = IPool(pool).getSpotPrice(token);
                    prices[token] = spot;
                }
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Arbitrum oracle should be L2 context"
        );
        let findings = detector.find_oracle_mev(source);
        assert!(
            !findings.is_empty(),
            "Should flag non-view updatePrice on L2"
        );
    }

    #[test]
    fn test_tp_l2_batch_without_atomicity() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            import { IArbSys } from "@arbitrum/nitro-contracts/src/precompiles/IArbSys.sol";
            contract ArbitrumBatchRouter {
                function multicall(bytes[] calldata data) external returns (bytes[] memory) {
                    bytes[] memory results = new bytes[](data.length);
                    for (uint256 i = 0; i < data.length; i++) {
                        (bool success, bytes memory result) = address(this).call(data[i]);
                        results[i] = result;
                    }
                    return results;
                }
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Arbitrum batch router should be L2 context"
        );
        let findings = detector.find_batch_vulnerabilities(source);
        assert!(
            !findings.is_empty(),
            "Should flag L2 multicall without revert"
        );
    }

    // ========================================================================
    // Edge case tests
    // ========================================================================

    #[test]
    fn test_blast_word_in_comment_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // This contract has blast protection against attacks
            contract SafeVault {
                function deposit() external {}
            }
        "#;
        assert!(
            !detector.is_l2_context(source),
            "The word 'blast' in a comment should NOT trigger L2 detection"
        );
    }

    #[test]
    fn test_blast_network_is_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // Deployed on Blast Network
            contract BlastDEX {
                function swap() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "'Blast Network' should trigger L2 detection"
        );
    }

    #[test]
    fn test_bridge_word_alone_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // This token bridge connects two chains
            contract TokenBridge {
                function deposit() external {}
            }
        "#;
        // "bridge" alone is no longer sufficient - must be L2-specific bridge pattern
        assert!(
            !detector.is_l2_context(source),
            "Generic 'bridge' should NOT trigger L2 detection without L2 indicators"
        );
    }

    #[test]
    fn test_cross_chain_alone_not_l2() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // Cross-chain messaging utility
            contract CrossChainMessenger {
                function sendMessage() external {}
            }
        "#;
        // Generic cross-chain is no longer sufficient without L2-specific patterns
        assert!(
            !detector.is_l2_context(source),
            "Generic 'cross-chain' should NOT trigger L2 detection without L2 indicators"
        );
    }

    #[test]
    fn test_mantle_l2_detected() {
        let detector = L2MevSequencerLeakDetector::new();
        let source = r#"
            // Deployed on Mantle L2
            import { IMantleToken } from "./IMantleToken.sol";
            contract MantleDEX {
                function swap() external {}
            }
        "#;
        assert!(
            detector.is_l2_context(source),
            "Mantle should be detected as L2"
        );
    }
}
