//! Regression tests for must-detect vulnerabilities
//!
//! This module ensures that critical vulnerabilities are always detected
//! by the analysis engine. Any changes to detectors that cause these tests
//! to fail should be carefully reviewed before merging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single must-detect test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MustDetectTest {
    /// Relative path to the test contract
    pub file_path: String,
    /// Detector ID that must report a finding
    pub detector_id: String,
    /// Line range where the vulnerability exists
    pub line_range: [u32; 2],
    /// Description of the vulnerability
    pub description: String,
    /// Severity level (for documentation)
    pub severity: String,
    /// Why this is a critical test case
    pub reason: String,
}

/// Result of running a must-detect test
#[derive(Debug, Clone)]
pub struct MustDetectResult {
    /// The test case
    pub test: MustDetectTest,
    /// Whether the vulnerability was detected
    pub detected: bool,
    /// Actual findings that matched (if any)
    pub matching_findings: Vec<ActualFinding>,
    /// Error message if test failed
    pub error: Option<String>,
}

/// A finding from the detector (simplified for testing)
#[derive(Debug, Clone)]
pub struct ActualFinding {
    pub detector_id: String,
    pub line: u32,
    pub severity: String,
    pub message: String,
}

/// Regression test suite containing all must-detect tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTestSuite {
    /// Version of the test suite
    pub version: String,
    /// All must-detect test cases
    pub tests: Vec<MustDetectTest>,
    /// Categories for organization
    pub categories: HashMap<String, Vec<String>>,
}

impl RegressionTestSuite {
    /// Create a new regression test suite with critical vulnerabilities
    pub fn new() -> Self {
        let tests = vec![
            // ============ REENTRANCY ============
            MustDetectTest {
                file_path: "tests/contracts/basic_vulnerabilities/reentrancy_issues.sol".to_string(),
                detector_id: "reentrancy".to_string(),
                line_range: [13, 21],
                description: "Classic reentrancy - external call before state update".to_string(),
                severity: "critical".to_string(),
                reason: "This is the most fundamental reentrancy pattern that must always be detected".to_string(),
            },

            // ============ ACCESS CONTROL ============
            MustDetectTest {
                file_path: "tests/contracts/basic_vulnerabilities/access_control_issues.sol".to_string(),
                detector_id: "access-control".to_string(),
                line_range: [18, 20],
                description: "Missing access control on setOwner()".to_string(),
                severity: "critical".to_string(),
                reason: "Anyone can take over the contract by calling setOwner()".to_string(),
            },
            MustDetectTest {
                file_path: "tests/contracts/basic_vulnerabilities/access_control_issues.sol".to_string(),
                detector_id: "access-control".to_string(),
                line_range: [23, 27],
                description: "Unauthorized withdrawal - anyone can withdraw funds".to_string(),
                severity: "critical".to_string(),
                reason: "Direct loss of funds - must always be detected".to_string(),
            },

            // ============ ORACLE MANIPULATION ============
            MustDetectTest {
                file_path: "tests/contracts/flash_loans/vulnerable/VulnerableFlashLoan.sol".to_string(),
                detector_id: "oracle-manipulation".to_string(),
                line_range: [16, 20],
                description: "Spot price oracle without TWAP protection".to_string(),
                severity: "critical".to_string(),
                reason: "Flash loan oracle manipulation led to $197M Euler Finance exploit".to_string(),
            },
            MustDetectTest {
                file_path: "tests/contracts/flash_loans/vulnerable/VulnerableFlashLoan.sol".to_string(),
                detector_id: "oracle-manipulation".to_string(),
                line_range: [41, 45],
                description: "AMM reserves used as oracle".to_string(),
                severity: "critical".to_string(),
                reason: "Mango Markets $110M exploit pattern".to_string(),
            },

            // ============ VAULT SECURITY ============
            MustDetectTest {
                file_path: "tests/contracts/erc4626_vaults/VulnerableVault_Inflation.sol".to_string(),
                detector_id: "vault-share-inflation".to_string(),
                line_range: [51, 72],
                description: "Share inflation attack - first depositor manipulation".to_string(),
                severity: "critical".to_string(),
                reason: "Cetus DEX $223M exploit pattern".to_string(),
            },

            // ============ CROSS-CHAIN ============
            MustDetectTest {
                file_path: "tests/contracts/cross_chain/phase13_legacy/bridge_chain_id/vulnerable_simple.sol".to_string(),
                detector_id: "bridge-chain-id-validation".to_string(),
                line_range: [13, 22],
                description: "Missing chain ID validation in bridge".to_string(),
                severity: "critical".to_string(),
                reason: "Cross-chain replay attacks can drain bridges".to_string(),
            },

            // ============ DELEGATECALL ============
            MustDetectTest {
                file_path: "tests/contracts/delegatecall/vulnerable/UserControlledDelegatecall.sol".to_string(),
                detector_id: "dangerous-delegatecall".to_string(),
                line_range: [1, 50],
                description: "User-controlled delegatecall target".to_string(),
                severity: "critical".to_string(),
                reason: "Allows arbitrary code execution in contract context".to_string(),
            },

            // ============ GOVERNANCE ============
            MustDetectTest {
                file_path: "tests/contracts/complex_scenarios/2025_vulnerabilities/governance/DAOGovernance.sol".to_string(),
                detector_id: "flashloan-governance-attack".to_string(),
                line_range: [160, 165],
                description: "Flash loan governance attack".to_string(),
                severity: "critical".to_string(),
                reason: "Beanstalk $182M exploit pattern".to_string(),
            },
            MustDetectTest {
                file_path: "tests/contracts/complex_scenarios/2025_vulnerabilities/governance/DAOGovernance.sol".to_string(),
                detector_id: "delegation-loop".to_string(),
                line_range: [338, 359],
                description: "Circular delegation vulnerability".to_string(),
                severity: "critical".to_string(),
                reason: "Can amplify voting power through delegation loops".to_string(),
            },

            // ============ ACCOUNT ABSTRACTION ============
            MustDetectTest {
                file_path: "tests/contracts/account_abstraction/vulnerable/VulnerablePaymaster.sol".to_string(),
                detector_id: "erc4337-paymaster-abuse".to_string(),
                line_range: [9, 23],
                description: "Missing nonce validation in paymaster".to_string(),
                severity: "critical".to_string(),
                reason: "Biconomy 2024 exploit pattern - nonce replay".to_string(),
            },

            // ============ MEV / SLIPPAGE ============
            MustDetectTest {
                file_path: "tests/contracts/complex_scenarios/2025_vulnerabilities/defi/FlashLoanArbitrage.sol".to_string(),
                detector_id: "slippage-protection".to_string(),
                line_range: [171, 177],
                description: "Zero slippage protection in swap".to_string(),
                severity: "critical".to_string(),
                reason: "Sandwich attacks can extract all value from trades".to_string(),
            },

            // ============ SIGNATURE SECURITY ============
            MustDetectTest {
                file_path: "tests/contracts/complex_scenarios/2025_vulnerabilities/governance/DAOGovernance.sol".to_string(),
                detector_id: "signature-replay".to_string(),
                line_range: [196, 222],
                description: "Signature replay vulnerability in voting".to_string(),
                severity: "critical".to_string(),
                reason: "Same signature can be used across proposals".to_string(),
            },
        ];

        let mut categories = HashMap::new();
        categories.insert(
            "reentrancy".to_string(),
            vec!["tests/contracts/basic_vulnerabilities/reentrancy_issues.sol".to_string()],
        );
        categories.insert(
            "access-control".to_string(),
            vec!["tests/contracts/basic_vulnerabilities/access_control_issues.sol".to_string()],
        );
        categories.insert(
            "oracle".to_string(),
            vec!["tests/contracts/flash_loans/vulnerable/VulnerableFlashLoan.sol".to_string()],
        );
        categories.insert(
            "vault".to_string(),
            vec!["tests/contracts/erc4626_vaults/VulnerableVault_Inflation.sol".to_string()],
        );
        categories.insert(
            "cross-chain".to_string(),
            vec![
                "tests/contracts/cross_chain/phase13_legacy/bridge_chain_id/vulnerable_simple.sol"
                    .to_string(),
            ],
        );
        categories.insert(
            "delegatecall".to_string(),
            vec![
                "tests/contracts/delegatecall/vulnerable/UserControlledDelegatecall.sol"
                    .to_string(),
            ],
        );
        categories.insert(
            "governance".to_string(),
            vec!["tests/contracts/complex_scenarios/2025_vulnerabilities/governance/DAOGovernance.sol".to_string()],
        );
        categories.insert(
            "account-abstraction".to_string(),
            vec![
                "tests/contracts/account_abstraction/vulnerable/VulnerablePaymaster.sol"
                    .to_string(),
            ],
        );

        Self {
            version: "1.0.0".to_string(),
            tests,
            categories,
        }
    }

    /// Load test suite from JSON file
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let suite: RegressionTestSuite = serde_json::from_str(&content)?;
        Ok(suite)
    }

    /// Save test suite to JSON file
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get total number of tests
    pub fn test_count(&self) -> usize {
        self.tests.len()
    }

    /// Get tests for a specific detector
    pub fn tests_for_detector(&self, detector_id: &str) -> Vec<&MustDetectTest> {
        self.tests
            .iter()
            .filter(|t| t.detector_id == detector_id)
            .collect()
    }

    /// Get tests for a specific file
    pub fn tests_for_file(&self, file_path: &str) -> Vec<&MustDetectTest> {
        self.tests
            .iter()
            .filter(|t| t.file_path == file_path)
            .collect()
    }

    /// Check if a finding satisfies a must-detect test
    pub fn check_finding(
        &self,
        test: &MustDetectTest,
        finding: &ActualFinding,
        line_tolerance: u32,
    ) -> bool {
        if test.detector_id != finding.detector_id {
            return false;
        }

        let start = test.line_range[0].saturating_sub(line_tolerance);
        let end = test.line_range[1] + line_tolerance;

        finding.line >= start && finding.line <= end
    }

    /// Run all tests against a set of findings
    pub fn run(&self, findings: &[ActualFinding], line_tolerance: u32) -> RegressionTestResults {
        let mut results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;

        for test in &self.tests {
            let matching: Vec<ActualFinding> = findings
                .iter()
                .filter(|f| self.check_finding(test, f, line_tolerance))
                .cloned()
                .collect();

            let detected = !matching.is_empty();

            if detected {
                passed += 1;
            } else {
                failed += 1;
            }

            results.push(MustDetectResult {
                test: test.clone(),
                detected,
                matching_findings: matching,
                error: if detected {
                    None
                } else {
                    Some(format!(
                        "REGRESSION: {} not detected in {}",
                        test.detector_id, test.file_path
                    ))
                },
            });
        }

        RegressionTestResults {
            total: self.tests.len(),
            passed,
            failed,
            results,
        }
    }
}

impl Default for RegressionTestSuite {
    fn default() -> Self {
        Self::new()
    }
}

/// Results from running regression tests
#[derive(Debug)]
pub struct RegressionTestResults {
    /// Total number of tests
    pub total: usize,
    /// Number of tests that passed
    pub passed: usize,
    /// Number of tests that failed
    pub failed: usize,
    /// Individual test results
    pub results: Vec<MustDetectResult>,
}

impl RegressionTestResults {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Get failed tests
    pub fn failed_tests(&self) -> Vec<&MustDetectResult> {
        self.results.iter().filter(|r| !r.detected).collect()
    }

    /// Generate a report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        report.push_str("║            MUST-DETECT REGRESSION TEST RESULTS               ║\n");
        report.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

        report.push_str(&format!(
            "SUMMARY: {} / {} tests passed ({:.1}%)\n\n",
            self.passed,
            self.total,
            if self.total > 0 {
                self.passed as f64 / self.total as f64 * 100.0
            } else {
                100.0
            }
        ));

        if self.failed > 0 {
            report.push_str("FAILED TESTS (REGRESSIONS)\n");
            report.push_str("══════════════════════════\n");

            for result in self.failed_tests() {
                report.push_str(&format!(
                    "\n  [FAIL] {} @ {}\n",
                    result.test.detector_id, result.test.file_path
                ));
                report.push_str(&format!(
                    "         Lines {}-{}: {}\n",
                    result.test.line_range[0], result.test.line_range[1], result.test.description
                ));
                report.push_str(&format!(
                    "         Severity: {}\n",
                    result.test.severity.to_uppercase()
                ));
                report.push_str(&format!("         Reason: {}\n", result.test.reason));
            }

            report.push_str("\n");
        }

        if self.passed > 0 && self.failed == 0 {
            report.push_str("All must-detect tests passed!\n");
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regression_suite_creation() {
        let suite = RegressionTestSuite::new();
        assert!(suite.test_count() > 0);
        assert!(suite.test_count() >= 13); // We defined 13 tests
    }

    #[test]
    fn test_check_finding_match() {
        let suite = RegressionTestSuite::new();
        let test = &suite.tests[0]; // Reentrancy test

        let matching_finding = ActualFinding {
            detector_id: test.detector_id.clone(),
            line: 15, // Within line range [13, 21]
            severity: "critical".to_string(),
            message: "Reentrancy found".to_string(),
        };

        let non_matching_finding = ActualFinding {
            detector_id: "access-control".to_string(),
            line: 15,
            severity: "critical".to_string(),
            message: "Access control".to_string(),
        };

        assert!(suite.check_finding(test, &matching_finding, 3));
        assert!(!suite.check_finding(test, &non_matching_finding, 3));
    }

    #[test]
    fn test_run_regression_suite() {
        let suite = RegressionTestSuite::new();

        // Simulate some findings
        let findings = vec![
            ActualFinding {
                detector_id: "reentrancy".to_string(),
                line: 15,
                severity: "critical".to_string(),
                message: "Reentrancy".to_string(),
            },
            ActualFinding {
                detector_id: "access-control".to_string(),
                line: 19,
                severity: "critical".to_string(),
                message: "Access control".to_string(),
            },
        ];

        let results = suite.run(&findings, 3);

        // Should have some passes (reentrancy, access control) and some failures
        assert!(results.passed >= 2);
        assert!(results.total == suite.test_count());
    }

    #[test]
    fn test_tests_for_detector() {
        let suite = RegressionTestSuite::new();

        let reentrancy_tests = suite.tests_for_detector("reentrancy");
        assert!(!reentrancy_tests.is_empty());

        let access_control_tests = suite.tests_for_detector("access-control");
        assert!(!access_control_tests.is_empty());
    }
}
