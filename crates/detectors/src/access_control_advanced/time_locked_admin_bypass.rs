//! Time-Locked Admin Bypass Detector
//!
//! Detects timelock circumvention patterns and missing delay enforcement on critical
//! admin functions. Prevents instant rug pulls despite timelock promises.
//!
//! Only flags contracts that are actually implementing or inheriting timelock/governance
//! functionality. Contracts that merely mention "timelock" or "delay" in comments
//! (e.g., flash loan contracts, paymasters, social recovery wallets) are excluded.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TimeLockedAdminBypassDetector {
    base: BaseDetector,
}

impl TimeLockedAdminBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("time-locked-admin-bypass".to_string()),
                "Time-Locked Admin Bypass".to_string(),
                "Detects timelock circumvention and missing delay enforcement on critical admin functions".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Strip single-line (//) and multi-line (/* */) comments from source code.
    /// This prevents comment-only mentions of "timelock" or "delay" from triggering
    /// the detector on contracts that are not actually implementing timelocks.
    fn strip_comments(source: &str) -> String {
        let mut result = String::with_capacity(source.len());
        let chars: Vec<char> = source.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
                // Single-line comment: skip to end of line
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
            } else if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
                // Multi-line comment: skip to closing */
                i += 2;
                while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                if i + 1 < len {
                    i += 2; // skip */
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }

        result
    }

    /// Check if the contract is a non-timelock contract type that should be skipped.
    /// Flash loan contracts, ERC-4337 paymasters, social recovery wallets, and
    /// account abstraction contracts have their own security patterns and should
    /// not be flagged for missing timelock implementations.
    fn is_excluded_contract_type(lower: &str) -> bool {
        // Flash loan contracts
        let is_flash_loan = lower.contains("flashloan")
            || lower.contains("flash_loan")
            || lower.contains("flashmint")
            || lower.contains("onflashloan")
            || lower.contains("ierc3156flashlender")
            || lower.contains("ierc3156flashborrower");

        // ERC-4337 paymaster / account abstraction contracts
        let is_paymaster = lower.contains("paymaster")
            || lower.contains("validatepaymasteruserop")
            || lower.contains("entrypoint")
            || lower.contains("useroperation");

        // Social recovery wallet contracts
        let is_social_recovery = lower.contains("socialrecovery")
            || lower.contains("social_recovery")
            || (lower.contains("guardian") && lower.contains("recovery"))
            || (lower.contains("initiaterecovery") && lower.contains("completerecovery"));

        is_flash_loan || is_paymaster || is_social_recovery
    }

    /// Check if the contract has strong indicators of being a timelock or governance
    /// contract that is actually implementing timelock functionality. This requires
    /// actual Solidity declarations (state variables, inheritance, function signatures),
    /// not just keyword mentions in comments.
    fn has_timelock_indicators(code_lower: &str) -> bool {
        // Timelock inheritance or type usage
        let has_timelock_type = code_lower.contains("timelockcontroller")
            || code_lower.contains("is timelock")
            || code_lower.contains("is timelocked");

        // Timelock state variables (delay, eta, queuedTransactions, etc.)
        let has_timelock_state = code_lower.contains("uint256 public delay")
            || code_lower.contains("uint256 public constant delay")
            || code_lower.contains("uint256 private delay")
            || code_lower.contains("uint256 internal delay")
            || code_lower.contains("uint256 delay")
            || code_lower.contains("mapping") && code_lower.contains("queuedtransactions")
            || code_lower.contains("mapping") && code_lower.contains("queuedoperations")
            || code_lower.contains("uint256 public eta")
            || code_lower.contains("mindelay")
            || code_lower.contains("timelockdelay");

        // Governance patterns with timelock integration
        let has_governance_timelock = code_lower.contains("function settimelock")
            || code_lower.contains("function setdelay")
            || code_lower.contains("timelock public")
            || code_lower.contains("timelock private")
            || code_lower.contains("timelock internal")
            || code_lower.contains("itimelock");

        // Admin functions that indicate timelock governance intent
        let has_admin_with_timelock = (code_lower.contains("function upgradeto")
            || code_lower.contains("function setparameter")
            || code_lower.contains("function changeconfig")
            || code_lower.contains("onlyowner"))
            && (has_timelock_type || has_timelock_state || has_governance_timelock);

        has_timelock_type
            || has_timelock_state
            || has_governance_timelock
            || has_admin_with_timelock
    }
}

impl Default for TimeLockedAdminBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TimeLockedAdminBypassDetector {
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

        let lower = ctx.source_code.to_lowercase();

        // Early exit: skip non-timelock contract types entirely.
        // Flash loan, paymaster, social recovery, and AA contracts have their own
        // security patterns and should not be flagged for missing timelocks.
        if Self::is_excluded_contract_type(&lower) {
            return Ok(findings);
        }

        // Strip comments so that comment-only mentions of "timelock" or "delay"
        // do not trigger the detector on unrelated contracts.
        let code_no_comments = Self::strip_comments(&ctx.source_code);
        let code_lower = code_no_comments.to_lowercase();

        // Check if the actual code (not comments) mentions timelock concepts
        let mentions_timelock = code_lower.contains("timelock")
            || code_lower.contains("timelocked")
            || code_lower.contains("timedelay");

        if !mentions_timelock {
            return Ok(findings);
        }

        // Require strong timelock indicators before running any patterns.
        // The contract must actually be implementing timelock functionality
        // (state variables, inheritance, function signatures), not merely
        // referencing the concept.
        if !Self::has_timelock_indicators(&code_lower) {
            return Ok(findings);
        }

        // Pattern 1: Admin functions not going through timelock
        let has_admin_functions = code_lower.contains("function upgradeto")
            || code_lower.contains("function setparameter")
            || code_lower.contains("function changeconfig")
            || code_lower.contains("onlyowner");

        if has_admin_functions {
            let has_timelock_check = code_lower.contains("timelock.execute")
                || code_lower.contains("executeproposal")
                || code_lower.contains("require(block.timestamp >=");

            if !has_timelock_check {
                let finding = self.base.create_finding(
                    ctx,
                    "Admin functions exist but don't enforce timelock delay - timelock may be bypassable".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Route all admin functions through timelock contract with schedule→execute pattern".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Missing delay check in upgrade functions
        let has_upgrade =
            code_lower.contains("upgradeto") || code_lower.contains("upgradeimplementation");
        if has_upgrade {
            let has_delay = code_lower.contains("upgradedelay")
                || code_lower.contains("block.timestamp >=")
                || code_lower.contains("timelockcontroller");

            if !has_delay {
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        "Upgrade function lacks timelock delay - instant upgrades possible"
                            .to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Add minimum delay period before upgrade execution (e.g., 2-7 days)"
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 3: Direct state changes bypassing proposed->queued->executed flow.
        // Only check this if the contract has actual timelock state/type indicators,
        // ensuring we only flag contracts genuinely attempting a timelock implementation.
        let has_queue = code_lower.contains("queuetransaction")
            || code_lower.contains("queueoperation")
            || code_lower.contains("function queue")
            || code_lower.contains("function schedule");
        let has_execute = code_lower.contains("function execute")
            || code_lower.contains("executeproposal")
            || code_lower.contains("executetransaction");

        if !has_queue || !has_execute {
            let finding = self.base.create_finding(
                ctx,
                "Timelock implementation incomplete - missing queue/schedule or execute functions".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Implement complete timelock flow: propose→queue→wait(delay)→execute".to_string()
            );

            findings.push(finding);
        }

        // Pattern 4: Emergency functions bypassing timelock
        let has_emergency = code_lower.contains("emergency")
            || code_lower.contains("urgent")
            || code_lower.contains("immediate");

        if has_emergency {
            let has_multisig = code_lower.contains("multisig")
                || code_lower.contains("threshold")
                || code_lower.contains("requiresignatures");

            if !has_multisig {
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        "Emergency functions bypass timelock without multisig protection"
                            .to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Require multisig approval for emergency functions that bypass timelock"
                            .to_string(),
                    );

                findings.push(finding);
            }
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
    use crate::types::test_utils::create_test_context;

    /// Helper to run the detector and return findings
    fn run_detector(source: &str) -> Vec<Finding> {
        let detector = TimeLockedAdminBypassDetector::new();
        let ctx = create_test_context(source);
        detector.detect(&ctx).unwrap()
    }

    // =========================================================================
    // False positive regression tests
    // =========================================================================

    #[test]
    fn test_no_fp_flash_loan_contract() {
        // VulnerableFlashLoan.sol - flash loan contract that mentions "timelock"
        // only in comments should NOT be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract VulnerableGovernanceFlashLoan {
                mapping(address => uint256) public votingPower;

                // VULNERABLE: Instant execution without timelock
                function execute(uint256 proposalId) external {
                    // VULNERABLE: No timelock delay
                    require(!proposal.executed, "Already executed");
                }

                function onFlashLoan(
                    address initiator,
                    address token,
                    uint256 amount,
                    uint256 fee,
                    bytes calldata data
                ) external returns (bytes32) {
                    return keccak256("ERC3156FlashBorrower.onFlashLoan");
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Flash loan contract should not trigger timelock detector, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_paymaster_contract() {
        // VulnerablePaymaster.sol - ERC-4337 paymaster should NOT be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract VulnerablePaymaster {
                mapping(address => uint256) public deposits;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    return ("", 0);
                }

                // No timelock delay needed for paymaster
                function sponsorTransaction(address user, uint256 cost) external {
                    require(deposits[msg.sender] >= cost, "Insufficient deposit");
                    deposits[msg.sender] -= cost;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Paymaster contract should not trigger timelock detector, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_secure_paymaster_contract() {
        // SecurePaymaster.sol - secure ERC-4337 paymaster should NOT be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract SecurePaymaster {
                mapping(address => uint256) public deposits;
                mapping(address => mapping(uint256 => bool)) public usedNonces;
                uint256 public immutable chainId;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    require(!usedNonces[sender][nonce], "Nonce already used");
                    return ("", 0);
                }
            }

            contract SecureSocialRecovery {
                uint256 public constant RECOVERY_TIMELOCK = 7 days;
                mapping(address => address[]) public guardians;

                function initiateRecovery(address account, address newOwner) external {
                    require(isGuardian(account, msg.sender), "Not a guardian");
                }

                function completeRecovery(address account) external {
                    require(block.timestamp >= request.initiatedAt + RECOVERY_TIMELOCK);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Secure paymaster/social recovery contract should not trigger timelock detector, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_social_recovery_contract() {
        // test_social_recovery.sol - social recovery wallet should NOT be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract VulnerableSocialRecovery {
                mapping(address => address[]) public guardians;

                // This should trigger aa-social-recovery detector
                function initiateRecovery(address account, address newOwner) external {
                    // No timelock delay
                }

                function approveRecovery(address account) external {
                    // Missing guardian validation
                }

                function completeRecovery(address account) external {
                    // No replay protection
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Social recovery contract should not trigger timelock detector, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_contract_with_timelock_only_in_comments() {
        // A contract that mentions "timelock" and "delay" only in comments
        // should not be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            // TODO: Add timelock delay in future version
            contract SimpleAdmin {
                address public owner;

                modifier onlyOwner() {
                    require(msg.sender == owner, "Not owner");
                    _;
                }

                // Consider adding a timelock for this function
                function setConfig(uint256 value) external onlyOwner {
                    config = value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Contract with timelock only in comments should not be flagged, got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    // =========================================================================
    // True positive tests - these SHOULD trigger findings
    // =========================================================================

    #[test]
    fn test_tp_incomplete_timelock_missing_queue() {
        // A genuine timelock contract with missing queue function should be flagged.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract IncompleteTimelock {
                uint256 public delay = 2 days;
                mapping(bytes32 => uint256) public queuedTransactions;

                function execute(bytes32 txHash) external onlyOwner {
                    require(block.timestamp >= queuedTransactions[txHash], "Timelock not expired");
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Incomplete timelock with missing queue function should be flagged"
        );
        assert!(
            findings.iter().any(|f| f.message.contains("incomplete")),
            "Should report incomplete timelock implementation"
        );
    }

    #[test]
    fn test_tp_timelock_with_admin_bypass() {
        // A timelock contract where admin functions bypass the timelock.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            import "@openzeppelin/contracts/governance/TimelockController.sol";

            contract GovernanceWithBypass is TimelockController {
                uint256 public delay = 2 days;

                modifier onlyOwner() {
                    require(msg.sender == owner, "Not owner");
                    _;
                }

                function upgradeTo(address newImpl) external onlyOwner {
                    // Bypasses timelock entirely!
                    _upgrade(newImpl);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Timelock contract with admin bypass should be flagged"
        );
    }

    #[test]
    fn test_tp_emergency_bypass_no_multisig() {
        // A timelock with emergency bypass but no multisig protection.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract TimelockWithEmergency {
                uint256 public delay = 2 days;
                mapping(bytes32 => uint256) public queuedTransactions;

                function queueTransaction(bytes32 txHash) external {
                    queuedTransactions[txHash] = block.timestamp + delay;
                }

                function executeTransaction(bytes32 txHash) external {
                    require(block.timestamp >= queuedTransactions[txHash], "Timelock active");
                }

                function emergencyExecute(bytes32 txHash) external {
                    // No multisig, no delay
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.iter().any(|f| f.message.contains("Emergency")),
            "Emergency bypass without multisig should be flagged"
        );
    }

    #[test]
    fn test_no_findings_on_unrelated_contract() {
        // A contract that has nothing to do with timelocks should produce no findings.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract SimpleToken {
                mapping(address => uint256) public balanceOf;

                function transfer(address to, uint256 amount) external {
                    require(balanceOf[msg.sender] >= amount, "Insufficient");
                    balanceOf[msg.sender] -= amount;
                    balanceOf[to] += amount;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Unrelated token contract should produce no findings"
        );
    }

    #[test]
    fn test_no_findings_on_complete_timelock() {
        // A properly implemented timelock should not be flagged for incomplete flow.
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract ProperTimelock {
                uint256 public delay = 2 days;
                mapping(bytes32 => uint256) public queuedTransactions;

                function queueTransaction(bytes32 txHash, uint256 eta) external {
                    require(eta >= block.timestamp + delay, "ETA too soon");
                    queuedTransactions[txHash] = eta;
                }

                function executeTransaction(bytes32 txHash) external {
                    require(block.timestamp >= queuedTransactions[txHash], "Timelock active");
                    require(queuedTransactions[txHash] != 0, "Not queued");
                    delete queuedTransactions[txHash];
                }
            }
        "#;
        let findings = run_detector(source);
        // Should NOT have "incomplete" finding since both queue and execute exist
        let incomplete_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("incomplete"))
            .collect();
        assert!(
            incomplete_findings.is_empty(),
            "Complete timelock should not be flagged as incomplete, got: {:?}",
            incomplete_findings
                .iter()
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );
    }

    // =========================================================================
    // Helper function unit tests
    // =========================================================================

    #[test]
    fn test_strip_comments_single_line() {
        let source = "contract Foo {\n    // timelock delay\n    uint256 x;\n}";
        let stripped = TimeLockedAdminBypassDetector::strip_comments(source);
        assert!(!stripped.contains("timelock"));
        assert!(stripped.contains("uint256 x"));
    }

    #[test]
    fn test_strip_comments_multi_line() {
        let source = "contract Foo {\n    /* timelock delay */\n    uint256 x;\n}";
        let stripped = TimeLockedAdminBypassDetector::strip_comments(source);
        assert!(!stripped.contains("timelock"));
        assert!(stripped.contains("uint256 x"));
    }

    #[test]
    fn test_strip_comments_preserves_code() {
        let source = "uint256 public timelockDelay = 2 days;";
        let stripped = TimeLockedAdminBypassDetector::strip_comments(source);
        assert!(stripped.contains("timelockDelay"));
    }

    #[test]
    fn test_is_excluded_flash_loan() {
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "contract vulnerableflashloan {"
        ));
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "function onflashloan("
        ));
    }

    #[test]
    fn test_is_excluded_paymaster() {
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "contract vulnerablepaymaster {"
        ));
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "function validatepaymasteruserop("
        ));
    }

    #[test]
    fn test_is_excluded_social_recovery() {
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "contract vulnerablesocialrecovery { guardian recovery"
        ));
        assert!(TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "function initiaterecovery function completerecovery"
        ));
    }

    #[test]
    fn test_not_excluded_governance() {
        assert!(!TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "contract governance {"
        ));
        assert!(!TimeLockedAdminBypassDetector::is_excluded_contract_type(
            "contract timelockcontroller {"
        ));
    }

    #[test]
    fn test_has_timelock_indicators_state_variable() {
        assert!(TimeLockedAdminBypassDetector::has_timelock_indicators(
            "uint256 public delay = 2 days; mapping(bytes32 => uint256) public queuedtransactions;"
        ));
    }

    #[test]
    fn test_has_timelock_indicators_controller() {
        assert!(TimeLockedAdminBypassDetector::has_timelock_indicators(
            "contract governance is timelockcontroller {"
        ));
    }

    #[test]
    fn test_no_timelock_indicators_simple_contract() {
        assert!(!TimeLockedAdminBypassDetector::has_timelock_indicators(
            "contract simpletoken { function transfer() external {} }"
        ));
    }
}
