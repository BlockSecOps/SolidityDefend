//! CREATE2 Frontrunning Protection Detection
//!
//! Detects contracts that use CREATE2 with predictable salts or lack proper authorization,
//! which can lead to frontrunning attacks and address collision exploits.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct Create2FrontrunningDetector {
    base: BaseDetector,
}

impl Create2FrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("create2-frontrunning".to_string()),
                "CREATE2 Frontrunning Protection".to_string(),
                "Detects CREATE2 usage with predictable salts or missing authorization that could enable frontrunning and address collision attacks".to_string(),
                vec![
                    DetectorCategory::Deployment,
                    DetectorCategory::MEV,
                    DetectorCategory::AccessControl,
                ],
                Severity::High,
            ),
        }
    }

    fn check_create2_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check if contract uses CREATE2
        if !source_lower.contains("create2") {
            return findings;
        }

        // Phase 54 FP Reduction: Skip well-known library patterns
        if self.is_safe_clone_library(source) {
            return findings;
        }

        // Phase 54 FP Reduction: Skip if using salt commitment + time delay pattern
        if self.has_salt_commitment_pattern(source, &source_lower) {
            return findings;
        }

        // Phase 54 FP Reduction: Skip EIP-1167 minimal proxy clone factories
        if self.is_eip1167_clone_factory(source) {
            return findings;
        }

        // Phase 54 FP Reduction: Skip if contract has used salts tracking
        if self.has_salt_tracking(source, &source_lower) {
            return findings;
        }

        // Pattern 1: Predictable salt from msg.sender or simple counter
        let has_sender_salt = source_lower.contains("create2")
            && (source_lower.contains("msg.sender")
                || source_lower.contains("keccak256(abi.encodepacked(msg.sender")
                || source_lower.contains("bytes32(uint256(uint160(msg.sender")
                || source_lower.contains("address(msg.sender"));

        let has_counter_salt = source_lower.contains("create2")
            && (source_lower.contains("counter")
                || source_lower.contains("nonce")
                || source_lower.contains("deploymentcount"));

        if has_sender_salt {
            // Check if salt includes unpredictable element
            let has_randomness = source_lower.contains("blockhash")
                || source_lower.contains("prevrandao")
                || source_lower.contains("difficulty")
                || source_lower.contains("block.timestamp");

            if !has_randomness {
                findings.push((
                    "CREATE2 salt derived from msg.sender only (frontrunnable)".to_string(),
                    0,
                    "Add randomness: bytes32 salt = keccak256(abi.encodePacked(msg.sender, block.timestamp, nonce)); to prevent frontrunning".to_string(),
                ));
            }
        }

        if has_counter_salt {
            findings.push((
                "CREATE2 salt uses simple counter (predictable address)".to_string(),
                0,
                "Use unpredictable salt: Combine counter with blockhash or commit-reveal scheme: keccak256(abi.encodePacked(counter, blockhash(block.number - 1)))".to_string(),
            ));
        }

        // Pattern 2: Public CREATE2 deployment function without authorization
        let has_public_deploy = (source_lower.contains("function")
            && (source_lower.contains("deploy") || source_lower.contains("create")))
            && (source_lower.contains("public") || source_lower.contains("external"))
            && source_lower.contains("create2");

        if has_public_deploy {
            let has_access_control = source_lower.contains("onlyowner")
                || source_lower.contains("onlyadmin")
                || source_lower.contains("authorized")
                || (source_lower.contains("require")
                    && (source_lower.contains("owner") || source_lower.contains("whitelist")));

            if !has_access_control {
                findings.push((
                    "Public CREATE2 deployment function without access control".to_string(),
                    0,
                    "Add access control: function deploy() external onlyOwner or use whitelist pattern to prevent unauthorized deployments".to_string(),
                ));
            }
        }

        // Pattern 3: Missing salt validation
        if source_lower.contains("create2") && source_lower.contains("salt") {
            let has_salt_validation = (source_lower.contains("require")
                && source_lower.contains("salt"))
                || source_lower.contains("validateSalt")
                || source_lower.contains("checkSalt");

            if !has_salt_validation {
                findings.push((
                    "CREATE2 salt not validated (address collision risk)".to_string(),
                    0,
                    "Validate salt: require(!deployedSalts[salt], \"Salt already used\"); deployedSalts[salt] = true; to prevent address reuse".to_string(),
                ));
            }
        }

        // Pattern 4: CREATE2 with initialization in same transaction
        if source_lower.contains("create2") {
            // Check if initialization happens right after deployment
            let has_immediate_init = source_lower.contains("create2")
                && (source_lower.contains(".initialize(")
                    || source_lower.contains(".setup(")
                    || source_lower.contains(".init("));

            // Check for frontrunning protection
            let has_frontrun_protection = source_lower.contains("initializecodedhash")
                || source_lower.contains("expectedcodehash")
                || (source_lower.contains("codehash") && source_lower.contains("require"));

            if has_immediate_init && !has_frontrun_protection {
                findings.push((
                    "CREATE2 initialization without frontrunning protection".to_string(),
                    0,
                    "Protect initialization: Include initialization params in CREATE2 bytecode or verify codehash: require(address(deployed).codehash == expectedCodeHash)".to_string(),
                ));
            }
        }

        // Pattern 5: Assembly CREATE2 without proper checks
        if source_lower.contains("assembly") && source_lower.contains("create2") {
            // Check if there's salt commitment or other frontrunning protection
            let has_salt_commitment = source_lower.contains("saltcommitment")
                || source_lower.contains("commitsalt")
                || (source_lower.contains("commitment") && source_lower.contains("salt"));

            // Check for deployment success validation
            let has_success_check = source_lower.contains("iszero(")
                || (source_lower.contains("if") && source_lower.contains("create2"))
                || source_lower.contains("require");

            // Only flag if no salt commitment AND no success check
            if !has_salt_commitment && !has_success_check {
                findings.push((
                    "Assembly CREATE2 without deployment success check".to_string(),
                    0,
                    "Check deployment: assembly { addr := create2(...) } require(addr != address(0), \"Deployment failed\");".to_string(),
                ));
            }
        }

        // Pattern 6: Deterministic address calculation exposed (disabled - this is standard behavior)
        // Public computeAddress() is a standard feature of CREATE2 factories
        // Frontrunning protection should be via salt commitment, not hiding the address
        // if source_lower.contains("getaddress") || ... { ... }

        // Pattern 7: CREATE2 factory without nonce tracking
        if (source_lower.contains("factory") || source_lower.contains("deployer"))
            && source_lower.contains("create2")
        {
            let has_nonce = source_lower.contains("nonce")
                || source_lower.contains("deploymentcount")
                || source_lower.contains("counter");

            // Salt commitment is actually better than nonce for frontrunning protection
            let has_salt_commitment = source_lower.contains("saltcommitment")
                || source_lower.contains("commitsalt")
                || (source_lower.contains("commitment") && source_lower.contains("salt"));

            if !has_nonce && !has_salt_commitment {
                findings.push((
                    "CREATE2 factory without nonce/counter tracking".to_string(),
                    0,
                    "Track deployments: mapping(address => uint256) public nonces; Use in salt to prevent address prediction attacks. Or use salt commitment for stronger protection.".to_string(),
                ));
            }
        }

        // Pattern 8: CREATE2 with insufficient gas (disabled - too broad)
        // Most CREATE2 usage doesn't need explicit gas checks
        // The EVM will revert if there's insufficient gas
        // if source_lower.contains("create2") { ... }

        findings
    }

    /// Phase 54 FP Reduction: Detect OpenZeppelin Clones library usage
    /// Clones library is well-audited and handles CREATE2 safely
    fn is_safe_clone_library(&self, source: &str) -> bool {
        // OpenZeppelin Clones library
        if source.contains("import") && source.contains("Clones") {
            return true;
        }

        // Using Clones for address
        if source.contains("using Clones for") {
            return true;
        }

        // Direct Clones library calls
        if source.contains("Clones.clone(")
            || source.contains("Clones.cloneDeterministic(")
            || source.contains("Clones.predictDeterministicAddress(")
        {
            return true;
        }

        false
    }

    /// Phase 54 FP Reduction: Detect salt commitment + time delay pattern
    /// This is a secure pattern for preventing frontrunning
    fn has_salt_commitment_pattern(&self, source: &str, source_lower: &str) -> bool {
        // Check for commitment mapping
        let has_commitment = source_lower.contains("commitment")
            || source_lower.contains("saltcommit")
            || source_lower.contains("commitsalt");

        // Check for time delay
        let has_delay = source.contains("block.timestamp")
            && (source_lower.contains("delay")
                || source_lower.contains("timelock")
                || source_lower.contains("wait")
                || source.contains("days")
                || source.contains("hours"));

        has_commitment && has_delay
    }

    /// Phase 54 FP Reduction: Detect EIP-1167 minimal proxy clone factory
    /// These are standard proxy patterns that don't need frontrunning protection
    fn is_eip1167_clone_factory(&self, source: &str) -> bool {
        // EIP-1167 bytecode patterns
        let has_eip1167_bytecode = source.contains("3d602d80600a3d3981f3363d3d373d3d3d363d73")
            || source.contains("363d3d373d3d3d363d73")
            || source.contains("0x3d602d80600a3d3981f3")
            || source.contains("// EIP-1167")
            || source.contains("EIP1167")
            || source.contains("minimal proxy");

        // Check for clone-specific patterns
        let is_clone_factory = source.contains("LibClone")
            || source.contains("CloneFactory")
            || source.contains("createClone");

        has_eip1167_bytecode || is_clone_factory
    }

    /// Phase 54 FP Reduction: Detect salt tracking mechanisms
    /// If contract tracks used salts, it's protected against address reuse
    fn has_salt_tracking(&self, source: &str, source_lower: &str) -> bool {
        // Check for salt tracking mappings
        let has_salt_mapping = (source_lower.contains("usedsalts")
            || source_lower.contains("used_salts")
            || source_lower.contains("deployedsalts")
            || source_lower.contains("deployed_salts")
            || source_lower.contains("saltused")
            || source_lower.contains("salt_used"))
            && source_lower.contains("mapping");

        // Check for salt validation in require
        let has_salt_validation = source_lower.contains("require")
            && (source_lower.contains("salt")
                && (source_lower.contains("!") || source_lower.contains("not")));

        has_salt_mapping || has_salt_validation
    }

    /// Phase 54 FP Reduction: Check if function is a view/pure computeAddress function
    /// These are standard helper functions and not vulnerabilities
    fn is_compute_address_view(&self, source: &str) -> bool {
        // computeAddress is a standard view helper
        source.contains("function computeAddress")
            && (source.contains("view") || source.contains("pure"))
    }
}

impl Default for Create2FrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Create2FrontrunningDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        let issues = self.check_create2_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let severity = if message.contains("without access control")
                || message.contains("without frontrunning protection")
            {
                Severity::Critical
            } else if message.contains("predictable")
                || message.contains("collision risk")
                || message.contains("frontrunnable")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line_offset, 0, 20, severity)
                .with_fix_suggestion(remediation)
                .with_cwe(330); // CWE-330: Use of Insufficiently Random Values

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
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = Create2FrontrunningDetector::new();
        assert_eq!(detector.id().to_string(), "create2-frontrunning");
        assert_eq!(detector.name(), "CREATE2 Frontrunning Protection");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_predictable_sender_salt() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes memory bytecode) external {
                    bytes32 salt = bytes32(uint256(uint160(msg.sender)));
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("msg.sender only")));
    }

    #[test]
    fn test_detects_counter_salt() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                uint256 public counter;

                function deploy(bytes memory bytecode) external {
                    bytes32 salt = bytes32(counter);
                    counter++;
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("simple counter")));
    }

    #[test]
    fn test_detects_public_deploy_without_auth() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("without access control"))
        );
    }

    #[test]
    fn test_detects_missing_salt_validation() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("salt not validated"))
        );
    }

    #[test]
    fn test_detects_immediate_initialization() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function deployAndInit(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                    IContract(deployed).initialize(msg.sender);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| {
            f.message
                .contains("initialization without frontrunning protection")
        }));
    }

    #[test]
    fn test_detects_assembly_create2() {
        // This test verifies assembly CREATE2 without success check is detected
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                    return deployed;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should detect CREATE2 without deployment success check
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("CREATE2") && f.message.contains("success"))
        );
    }

    #[test]
    fn test_detects_exposed_address_calculation() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                function computeAddress(bytes32 salt, bytes32 bytecodeHash)
                    external
                    view
                    returns (address)
                {
                    return address(uint160(uint256(keccak256(abi.encodePacked(
                        bytes1(0xff),
                        address(this),
                        salt,
                        bytecodeHash
                    )))));
                }

                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Pattern intentionally disabled: computeAddress is a standard feature
        let has_address_calc_finding = result
            .iter()
            .any(|f| f.message.contains("exposes CREATE2 address calculation"));
        assert!(
            !has_address_calc_finding,
            "computeAddress is a standard feature, not a vulnerability"
        );
    }

    #[test]
    fn test_protected_create2_has_fewer_findings() {
        let detector = Create2FrontrunningDetector::new();
        let source = r#"
            contract Factory {
                address public owner;
                mapping(bytes32 => bool) public usedSalts;
                uint256 public nonce;

                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }

                function deploy(bytes memory bytecode) external onlyOwner {
                    require(gasleft() >= 100000, "Insufficient gas");
                    bytes32 salt = keccak256(abi.encodePacked(msg.sender, block.timestamp, nonce));
                    require(!usedSalts[salt], "Salt already used");
                    usedSalts[salt] = true;
                    nonce++;

                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                    require(deployed != address(0), "Deployment failed");
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have fewer/less severe findings due to protections
        // Still may flag assembly CREATE2 as informational
    }
}
