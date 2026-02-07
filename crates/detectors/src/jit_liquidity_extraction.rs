use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for Just-In-Time (JIT) liquidity extraction vulnerabilities
///
/// Detects patterns where attackers can add liquidity just before a large
/// swap and remove it immediately after, capturing swap fees without
/// providing sustained liquidity.
///
/// Vulnerable pattern:
/// ```solidity
/// // Pool allows single-block add/remove liquidity
/// function addLiquidity(uint256 amount) external {
///     // No time lock on liquidity
///     _mint(msg.sender, shares);
/// }
///
/// function removeLiquidity(uint256 shares) external {
///     // Can remove in same block as add
///     _burn(msg.sender, shares);
/// }
/// ```
pub struct JitLiquidityExtractionDetector {
    base: BaseDetector,
}

impl Default for JitLiquidityExtractionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl JitLiquidityExtractionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("jit-liquidity-extraction"),
                "JIT Liquidity Extraction".to_string(),
                "Detects AMM patterns vulnerable to Just-In-Time (JIT) liquidity attacks \
                 where attackers add liquidity before large swaps and remove immediately \
                 after to capture fees without sustained liquidity provision."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Phase 5 FP Reduction: Check if contract is actually an AMM pool
    /// JIT attacks only apply to AMM pools, not simple wallets/vaults
    fn is_amm_pool(&self, source: &str) -> bool {
        // Must have reserve tracking indicators
        let has_reserves = source.contains("reserve0")
            || source.contains("reserve1")
            || source.contains("getReserves")
            || source.contains("_reserve0")
            || source.contains("_reserve1");

        // Must have swap functionality or LP token mechanics
        let has_swap_or_lp = source.contains("swap(")
            || source.contains("function swap")
            || source.contains("IUniswapV2Pair")
            || source.contains("IPair")
            || source.contains("liquidity")
            || source.contains("kLast")
            || source.contains("priceCumulative")
            || source.contains("sqrtPrice")
            || source.contains("tickSpacing");

        // Both indicators required for AMM context
        has_reserves && has_swap_or_lp
    }

    /// Phase 5 FP Reduction: Check if this is a simple wallet/vault pattern
    fn is_simple_wallet_pattern(&self, source: &str) -> bool {
        let source_lower = source.to_lowercase();

        // Simple wallets have deposit/withdraw but no trading mechanics
        let has_simple_deposit_withdraw = (source_lower.contains("function deposit")
            || source_lower.contains("function withdraw"))
            && !source_lower.contains("swap")
            && !source_lower.contains("liquidity")
            && !source_lower.contains("reserve");

        // ERC4626 vaults are not JIT targets
        let is_erc4626 = source.contains("ERC4626")
            || source.contains("IERC4626")
            || (source.contains("totalAssets") && source.contains("totalSupply"));

        has_simple_deposit_withdraw || is_erc4626
    }

    /// Find liquidity functions without time locks
    fn find_instant_liquidity(&self, source: &str) -> Vec<(u32, String)> {
        // Phase 5 FP Reduction: Early exit for non-AMM contracts
        if !self.is_amm_pool(source) || self.is_simple_wallet_pattern(source) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut has_add_liquidity = false;
        let mut has_remove_liquidity = false;
        let mut has_timelock = false;
        let mut add_line = 0u32;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for add liquidity functions (more specific patterns)
            if trimmed.contains("function ")
                && (trimmed.contains("addLiquidity") || trimmed.contains("mint"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                has_add_liquidity = true;
                add_line = line_num as u32 + 1;

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for time lock
                if func_body.contains("lockTime")
                    || func_body.contains("timelock")
                    || func_body.contains("unlockTime")
                    || func_body.contains("lockUntil")
                {
                    has_timelock = true;
                }
            }

            // Check for remove liquidity functions (more specific patterns)
            if trimmed.contains("function ")
                && (trimmed.contains("removeLiquidity") || trimmed.contains("burn"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                has_remove_liquidity = true;

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for time lock in removal
                if func_body.contains("lockTime")
                    || func_body.contains("require(block")
                    || func_body.contains("unlockTime")
                {
                    has_timelock = true;
                }
            }
        }

        // FP Reduction: Skip pools with MINIMUM_LIQUIDITY dead shares (Uniswap V2 pattern).
        // Dead shares mitigate first-depositor inflation attacks and are a standard design choice.
        let has_dead_shares = source.contains("MINIMUM_LIQUIDITY")
            || source.contains("_mint(address(0)")
            || source.contains("mint(address(0)")
            || source.contains("dead shares");

        // If has both add and remove without timelock AND no dead shares protection
        if has_add_liquidity && has_remove_liquidity && !has_timelock && !has_dead_shares {
            findings.push((add_line, "liquidity_functions".to_string()));
        }

        findings
    }

    /// Find concentrated liquidity without JIT protection
    fn find_concentrated_liquidity_vuln(&self, source: &str) -> Vec<(u32, String)> {
        // Phase 5 FP Reduction: Only check actual AMM pools
        if !self.is_amm_pool(source) || self.is_simple_wallet_pattern(source) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for Uniswap V3 style concentrated liquidity
            if trimmed.contains("function ")
                && (trimmed.contains("mint") || trimmed.contains("increaseLiquidity"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for tick range parameters (concentrated liquidity)
                let is_concentrated = func_body.contains("tickLower")
                    || func_body.contains("tickUpper")
                    || func_body.contains("sqrtPrice");

                // Check for JIT protection
                let has_jit_protection = func_body.contains("jit")
                    || func_body.contains("JIT")
                    || func_body.contains("cooldown")
                    || func_body.contains("minDuration");

                if is_concentrated && !has_jit_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find same-block liquidity operations
    fn find_same_block_operations(&self, source: &str) -> Vec<(u32, String)> {
        // Phase 5 FP Reduction: Only check actual AMM pools
        if !self.is_amm_pool(source) || self.is_simple_wallet_pattern(source) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for liquidity removal functions (more specific to AMM context)
            if trimmed.contains("function ")
                && (trimmed.contains("removeLiquidity") || trimmed.contains("decreaseLiquidity"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if it allows same-block removal
                let blocks_same_block = func_body.contains("depositBlock")
                    || func_body.contains("lastDepositBlock")
                    || func_body.contains("block.number >")
                    || func_body.contains("block.number >=");

                if !blocks_same_block {
                    // No same-block protection found
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find flash loan compatible liquidity
    fn find_flash_liquidity(&self, source: &str) -> Vec<(u32, String)> {
        // Phase 5 FP Reduction: Only check actual AMM pools
        if !self.is_amm_pool(source) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract has both flash loan and liquidity features
        let has_flash = source.contains("flashLoan") || source.contains("flash(");
        let has_liquidity = source.contains("addLiquidity") || source.contains("removeLiquidity");

        if has_flash && has_liquidity {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ") && trimmed.contains("flash") {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
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
}

impl Detector for JitLiquidityExtractionDetector {
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

        // Find instant liquidity without time lock
        for (line, _) in self.find_instant_liquidity(source) {
            let message = format!(
                "Contract '{}' allows instant liquidity add/remove without time lock. \
                 Attackers can perform JIT liquidity attacks by adding liquidity just \
                 before large swaps and removing immediately after to capture fees.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add time lock for liquidity operations:\n\n\
                     mapping(address => uint256) public depositTime;\n\
                     uint256 public constant MIN_LOCK_TIME = 1 hours;\n\n\
                     function addLiquidity(uint256 amount) external {\n\
                         depositTime[msg.sender] = block.timestamp;\n\
                         // ... add liquidity\n\
                     }\n\n\
                     function removeLiquidity(uint256 shares) external {\n\
                         require(\n\
                             block.timestamp >= depositTime[msg.sender] + MIN_LOCK_TIME,\n\
                             \"Liquidity locked\"\n\
                         );\n\
                         // ... remove liquidity\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Find concentrated liquidity vulnerabilities
        for (line, func_name) in self.find_concentrated_liquidity_vuln(source) {
            let message = format!(
                "Function '{}' in contract '{}' provides concentrated liquidity without \
                 JIT protection. Attackers can provide narrow-range liquidity around \
                 pending large swaps to capture disproportionate fees.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Implement JIT protection for concentrated liquidity:\n\n\
                     1. Add minimum position duration\n\
                     2. Implement fee vesting over time\n\
                     3. Use time-weighted fee distribution\n\
                     4. Add cooldown between position changes\n\n\
                     Example:\n\
                     mapping(uint256 => uint256) public positionCreatedAt;\n\
                     uint256 public constant JIT_PROTECTION_PERIOD = 1 hours;\n\n\
                     function collectFees(uint256 tokenId) external {\n\
                         require(\n\
                             block.timestamp >= positionCreatedAt[tokenId] + JIT_PROTECTION_PERIOD,\n\
                             \"JIT protection active\"\n\
                         );\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find same-block operations
        for (line, func_name) in self.find_same_block_operations(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows liquidity removal in the same \
                 block as deposit. This enables atomic JIT attacks within a single transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Block same-block liquidity removal:\n\n\
                     mapping(address => uint256) public lastDepositBlock;\n\n\
                     function deposit() external {\n\
                         lastDepositBlock[msg.sender] = block.number;\n\
                         // ...\n\
                     }\n\n\
                     function withdraw() external {\n\
                         require(\n\
                             block.number > lastDepositBlock[msg.sender],\n\
                             \"Cannot withdraw same block\"\n\
                         );\n\
                         // ...\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Find flash liquidity
        for (line, func_name) in self.find_flash_liquidity(source) {
            let message = format!(
                "Function '{}' in contract '{}' combines flash loans with liquidity \
                 operations. This can enable sophisticated JIT attacks using borrowed capital.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Separate flash loan and liquidity operations:\n\n\
                     1. Prevent flash-borrowed funds from being used as liquidity\n\
                     2. Add reentrancy guards between flash and liquidity functions\n\
                     3. Implement cross-function locks\n\
                     4. Consider time delays between operations"
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
        let detector = JitLiquidityExtractionDetector::new();
        assert_eq!(detector.name(), "JIT Liquidity Extraction");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_instant_liquidity() {
        let detector = JitLiquidityExtractionDetector::new();

        // Test requires AMM context (reserves + liquidity functions) for JIT detection
        let vulnerable = r#"
            contract Pool {
                uint256 public reserve0;
                uint256 public reserve1;

                function swap(uint256 amountIn) external {
                    // swap logic using reserves
                }

                function addLiquidity(uint256 amount) external {
                    _mint(msg.sender, shares);
                }

                function removeLiquidity(uint256 shares) external {
                    _burn(msg.sender, shares);
                }
            }
        "#;
        let findings = detector.find_instant_liquidity(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_safe_liquidity() {
        let detector = JitLiquidityExtractionDetector::new();

        // Safe AMM pool with time lock - should not flag
        let safe = r#"
            contract Pool {
                uint256 public reserve0;
                uint256 public reserve1;
                mapping(address => uint256) public lockTime;

                function swap(uint256 amountIn) external {
                    // swap logic
                }

                function addLiquidity(uint256 amount) external {
                    lockTime[msg.sender] = block.timestamp + 1 hours;
                    _mint(msg.sender, shares);
                }

                function removeLiquidity(uint256 shares) external {
                    require(block.timestamp >= lockTime[msg.sender]);
                    _burn(msg.sender, shares);
                }
            }
        "#;
        let findings = detector.find_instant_liquidity(safe);
        assert!(findings.is_empty());
    }
}
