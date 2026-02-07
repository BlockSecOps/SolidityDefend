//! ERC-20 Transfer Return Bomb Detector
//!
//! Detects return data bombs that can cause DOS via excessive return data size.
//! Malicious ERC-20 tokens can return huge amounts of data to exhaust gas when
//! interacted with via low-level calls without return data size validation.
//!
//! This detector focuses on genuine risks:
//! - Low-level `.call()` used to invoke ERC-20 transfer/transferFrom without
//!   gas limits or return data size checks
//! - Assembly-level `returndatacopy` without bounded size validation
//!
//! The detector skips safe patterns that are NOT vulnerable:
//! - SafeERC20 / safeTransfer / safeTransferFrom (OpenZeppelin, Solmate)
//! - Solidity-level IERC20.transfer() calls (ABI decoder bounds return data)
//! - ETH transfers via `.call{value: x}("")` (not ERC-20 at all)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC20TransferReturnBombDetector {
    base: BaseDetector,
}

impl ERC20TransferReturnBombDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc20-transfer-return-bomb".to_string()),
                "ERC-20 Transfer Return Bomb".to_string(),
                "Detects return data bombs in ERC-20 token interactions".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Check if the contract uses SafeERC20 or equivalent safe transfer wrappers.
    /// These libraries handle return data safely and are not vulnerable to return bombs.
    fn uses_safe_transfer_patterns(source: &str) -> bool {
        // OpenZeppelin SafeERC20
        source.contains("SafeERC20")
            || source.contains("using SafeERC20")
            || source.contains("safeTransfer(")
            || source.contains("safeTransferFrom(")
            || source.contains("safeApprove(")
            || source.contains("safeIncreaseAllowance(")
            || source.contains("safeDecreaseAllowance(")
            // Solmate SafeTransferLib
            || source.contains("SafeTransferLib")
            || source.contains("using SafeTransferLib")
            || source.contains("safeTransferETH(")
            // OpenZeppelin import paths
            || source.contains("@openzeppelin/contracts/token/ERC20/utils/SafeERC20")
            || source.contains("openzeppelin-contracts/token/ERC20/utils/SafeERC20")
            // Solmate import paths
            || source.contains("solmate/utils/SafeTransferLib")
    }

    /// Check if a line is an ETH transfer (not an ERC-20 call).
    /// ETH transfers like `addr.call{value: x}("")` are not subject to ERC-20 return bombs.
    fn is_eth_transfer(line: &str) -> bool {
        let trimmed = line.trim();
        // .call{value: ...} is ETH transfer, not ERC-20
        trimmed.contains(".call{value:")
            || trimmed.contains(".call{ value:")
            || trimmed.contains(".call{value :")
            // payable(x).transfer() is ETH transfer, not ERC-20
            || (trimmed.contains("payable(") && trimmed.contains(".transfer("))
            // msg.sender.transfer, address.transfer with value context
            || trimmed.contains(".send(")
    }

    /// Check whether the contract uses ONLY Solidity-level ERC-20 calls
    /// (via interfaces like IERC20), as opposed to low-level `.call()` for token interaction.
    fn only_uses_interface_level_transfers(source: &str) -> bool {
        let has_interface_transfer = source.contains("IERC20")
            || source.contains("IERC20Metadata")
            || source.contains("ERC20")
            || source.contains("interface");

        if !has_interface_transfer {
            return false;
        }

        // Check if there are any low-level calls that encode transfer selectors
        // These would be the actual return bomb risk
        let lower = source.to_lowercase();
        let has_encoded_transfer = lower.contains("abi.encodewithselector")
            || lower.contains("abi.encodewithsignature")
            || lower.contains("abi.encodepacked")
            || lower.contains("0xa9059cbb") // transfer(address,uint256) selector
            || lower.contains("0x23b872dd"); // transferFrom(address,address,uint256) selector

        // If there are no encoded transfer calls, all transfers are interface-level
        !has_encoded_transfer
    }

    /// Check if low-level calls in the source are used specifically for ERC-20 token
    /// interactions (as opposed to ETH transfers or other purposes).
    fn has_low_level_token_call(source: &str) -> bool {
        let lower = source.to_lowercase();

        // Look for low-level .call() with encoded ERC-20 function selectors
        let has_call = lower.contains(".call(") || lower.contains(".call{");
        if !has_call {
            return false;
        }

        // Check if the call encodes an ERC-20 transfer/transferFrom
        let has_transfer_encoding = lower.contains("abi.encodewithselector")
            || lower.contains("abi.encodewithsignature")
            || lower.contains("\"transfer(")
            || lower.contains("\"transferfrom(")
            || lower.contains("0xa9059cbb") // transfer selector
            || lower.contains("0x23b872dd"); // transferFrom selector

        // Also check for assembly-based calls with transfer-related context
        let has_assembly_transfer = lower.contains("assembly")
            && (lower.contains("mstore") || lower.contains("returndatacopy"))
            && (lower.contains("transfer") || lower.contains("0xa9059cbb"));

        // Exclude pure ETH transfers: if all .call{ lines have value: and no selector encoding
        if has_call && !has_transfer_encoding && !has_assembly_transfer {
            // Check each line with .call to see if it's just ETH transfer
            let all_calls_are_eth = source.lines().all(|line| {
                let trimmed = line.trim().to_lowercase();
                if trimmed.contains(".call(") || trimmed.contains(".call{") {
                    Self::is_eth_transfer(line)
                } else {
                    true // non-call lines don't matter
                }
            });
            if all_calls_are_eth {
                return false;
            }
        }

        has_transfer_encoding || has_assembly_transfer
    }
}

impl Default for ERC20TransferReturnBombDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC20TransferReturnBombDetector {
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
        let lower = source.to_lowercase();

        // =====================================================================
        // Early exit: no ERC-20 transfer activity at all
        // =====================================================================
        let has_transfer = lower.contains("transfer(")
            || lower.contains("transferfrom(")
            || lower.contains("ierc20");

        if !has_transfer {
            return Ok(findings);
        }

        // =====================================================================
        // FP Reduction: Skip if the contract uses SafeERC20 or safe wrappers
        // SafeERC20 (OpenZeppelin) and SafeTransferLib (Solmate) handle return
        // data safely -- they check returndatasize and revert on anomalies.
        // =====================================================================
        if Self::uses_safe_transfer_patterns(source) {
            return Ok(findings);
        }

        // =====================================================================
        // FP Reduction: Skip if all transfers are Solidity-level interface calls
        // When calling IERC20(token).transfer(...) at the Solidity level, the
        // ABI decoder only reads the expected return type (bool). Excess return
        // data from a malicious token is ignored by the EVM -- there is no gas
        // bomb risk from Solidity-level calls.
        // =====================================================================
        if Self::only_uses_interface_level_transfers(source) {
            return Ok(findings);
        }

        // =====================================================================
        // From here, the contract uses low-level calls for token interaction.
        // These ARE potentially vulnerable to return data bombs.
        // =====================================================================

        // Pattern 1: Low-level call for ERC-20 transfers without return data size check
        if Self::has_low_level_token_call(source) {
            let uses_returndatasize =
                lower.contains("returndatasize") || lower.contains("returndata.length");

            let has_size_limit =
                lower.contains("require(returndatasize") || lower.contains("if (returndatasize");

            if !uses_returndatasize || !has_size_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "Low-level token transfer call lacks return data size validation - vulnerable to return bomb DOS".to_string(),
                    1,
                    1,
                    source.len() as u32,
                )
                .with_fix_suggestion(
                    "Check returndatasize() and reject if excessive (>64 bytes): require(returndatasize() <= 64). Alternatively, use OpenZeppelin SafeERC20 or Solmate SafeTransferLib.".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Low-level call for transfers without gas limit
        if Self::has_low_level_token_call(source) {
            let has_gas_limit = lower.contains(".call{gas:") || lower.contains("gasleft()");

            if !has_gas_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "Low-level call to token without gas limit - return bomb can exhaust all gas".to_string(),
                    1,
                    1,
                    source.len() as u32,
                )
                .with_fix_suggestion(
                    "Specify gas limit for calls: token.call{gas: 100000}(abi.encodeWithSelector(...)). Alternatively, use OpenZeppelin SafeERC20 or Solmate SafeTransferLib.".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Copying return data without size check (assembly-level)
        if Self::has_low_level_token_call(source) {
            let copies_returndata =
                lower.contains("returndatacopy") || lower.contains("abi.decode(returndata");

            if copies_returndata {
                let has_size_check = lower.contains("require(returndatasize")
                    || lower.contains("if (returndatasize");

                if !has_size_check {
                    let finding = self.base.create_finding(
                        ctx,
                        "Return data copied without size validation - DOS via excessive return data".to_string(),
                        1,
                        1,
                        source.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Validate returndatasize before copying: require(returndatasize() <= MAX_SIZE)".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
