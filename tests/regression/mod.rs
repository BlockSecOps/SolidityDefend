// tests/regression/mod.rs
// Golden file regression test framework for SolidityDefend
// Ensures that analysis output remains consistent across changes

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use sha2::{Sha256, Digest};

// Re-export test utilities
use crate::common::test_utils::*;

/// Configuration for golden file regression tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionConfig {
    pub test_cases_dir: PathBuf,
    pub golden_files_dir: PathBuf,
    pub output_format: OutputFormat,
    pub update_mode: bool,
    pub tolerance_config: ToleranceConfig,
    pub excluded_detectors: Vec<String>,
    pub timeout: Duration,
}

/// Output format for golden files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Sarif,
    Text,
    All,
}

/// Tolerance configuration for comparing outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToleranceConfig {
    pub ignore_timestamps: bool,
    pub ignore_execution_time: bool,
    pub ignore_line_numbers: bool,
    pub ignore_column_numbers: bool,
    pub ignore_file_paths: bool,
    pub severity_tolerance: f64,
    pub confidence_tolerance: f64,
}

impl Default for ToleranceConfig {
    fn default() -> Self {
        Self {
            ignore_timestamps: true,
            ignore_execution_time: true,
            ignore_line_numbers: false,
            ignore_column_numbers: false,
            ignore_file_paths: true,
            severity_tolerance: 0.0,
            confidence_tolerance: 0.1,
        }
    }
}

/// A single golden file test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenTestCase {
    pub name: String,
    pub description: String,
    pub source_file: PathBuf,
    pub expected_detectors: Vec<String>,
    pub config_overrides: HashMap<String, serde_json::Value>,
    pub expected_exit_code: i32,
    pub tags: Vec<String>,
}

/// Result of a golden file test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenTestResult {
    pub test_case: GoldenTestCase,
    pub status: TestStatus,
    pub differences: Vec<OutputDifference>,
    pub execution_time: Duration,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Status of a golden file test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Failed,
    Updated,
    Skipped,
    Error(String),
}

/// Difference found in output comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDifference {
    pub diff_type: DifferenceType,
    pub location: String,
    pub expected: String,
    pub actual: String,
    pub severity: DifferenceSeverity,
}

/// Type of difference found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifferenceType {
    MissingDetection,
    ExtraDetection,
    DifferentSeverity,
    DifferentConfidence,
    DifferentMessage,
    DifferentLocation,
    StructuralChange,
}

/// Severity of a difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifferenceSeverity {
    Critical,   // Test should fail
    Major,      // Test should fail unless tolerance allows
    Minor,      // Test can pass with warning
    Cosmetic,   // Can be ignored based on tolerance
}

/// Golden file regression test runner
pub struct GoldenFileRunner {
    config: RegressionConfig,
    test_cases: Vec<GoldenTestCase>,
    temp_dir: Option<TempDir>,
}

impl GoldenFileRunner {
    /// Create a new golden file regression test runner
    pub fn new(config: RegressionConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let test_cases = Self::load_test_cases(&config)?;

        Ok(Self {
            config,
            test_cases,
            temp_dir: None,
        })
    }

    /// Create a default regression test setup
    pub fn with_defaults(base_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let test_cases_dir = temp_dir.path().join("test_cases");
        let golden_files_dir = temp_dir.path().join("golden");

        // Create directories
        fs::create_dir_all(&test_cases_dir)?;
        fs::create_dir_all(&golden_files_dir)?;

        // Create sample test cases
        Self::create_sample_test_cases(&test_cases_dir)?;

        let config = RegressionConfig {
            test_cases_dir,
            golden_files_dir,
            output_format: OutputFormat::All,
            update_mode: false,
            tolerance_config: ToleranceConfig::default(),
            excluded_detectors: Vec::new(),
            timeout: Duration::from_secs(30),
        };

        let test_cases = Self::load_test_cases(&config)?;

        Ok(Self {
            config,
            test_cases,
            temp_dir: Some(temp_dir),
        })
    }

    /// Create sample test cases for regression testing
    fn create_sample_test_cases(test_cases_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Reentrancy test case
        let reentrancy_content = r#"
pragma solidity ^0.8.0;

contract ReentrancyExample {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#;

        fs::write(test_cases_dir.join("reentrancy.sol"), reentrancy_content)?;

        // Access control test case
        let access_control_content = r#"
pragma solidity ^0.8.0;

contract AccessControlExample {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    // Missing access control modifier
    function withdraw(uint256 amount) external {
        require(amount <= balance, "Insufficient balance");
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Proper access control
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }
}
"#;

        fs::write(test_cases_dir.join("access_control.sol"), access_control_content)?;

        // Integer overflow test case (for older Solidity versions)
        let overflow_content = r#"
pragma solidity ^0.4.24;

contract OverflowExample {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // Vulnerable to underflow
        require(balances[msg.sender] - amount >= 0, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        // Vulnerable to overflow
        balances[to] += amount;
    }
}
"#;

        fs::write(test_cases_dir.join("overflow.sol"), overflow_content)?;

        // Complex multi-vulnerability test case
        let complex_content = r#"
pragma solidity ^0.8.0;

contract ComplexExample {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrancy() {
        require(!locked, "Reentrancy guard");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 ether;
        balances[owner] = totalSupply;
    }

    // Multiple potential issues
    function complexTransfer(address to, uint256 amount) external noReentrancy {
        require(to != address(0), "Invalid address");
        require(amount > 0, "Invalid amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        // Potential issue: external call after state changes
        if (to.code.length > 0) {
            (bool success, ) = to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, amount));
            // Not checking success - potential issue
        }
    }

    // Delegation issue
    function delegateCall(address target, bytes calldata data) external onlyOwner {
        // Dangerous: delegatecall with user-controlled target
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // Timestamp dependence
    function timeBasedFunction() external view returns (bool) {
        // Vulnerable to miner manipulation
        return block.timestamp % 2 == 0;
    }

    // tx.origin usage
    function authenticate() external view returns (bool) {
        // Vulnerable to phishing attacks
        return tx.origin == owner;
    }
}
"#;

        fs::write(test_cases_dir.join("complex.sol"), complex_content)?;

        // Create test case metadata files
        let reentrancy_meta = GoldenTestCase {
            name: "reentrancy".to_string(),
            description: "Classic reentrancy vulnerability test".to_string(),
            source_file: test_cases_dir.join("reentrancy.sol"),
            expected_detectors: vec!["reentrancy".to_string()],
            config_overrides: HashMap::new(),
            expected_exit_code: 1,
            tags: vec!["reentrancy".to_string(), "high-severity".to_string()],
        };

        let access_control_meta = GoldenTestCase {
            name: "access_control".to_string(),
            description: "Missing access control test".to_string(),
            source_file: test_cases_dir.join("access_control.sol"),
            expected_detectors: vec!["missing-access-control".to_string()],
            config_overrides: HashMap::new(),
            expected_exit_code: 1,
            tags: vec!["access-control".to_string(), "high-severity".to_string()],
        };

        let overflow_meta = GoldenTestCase {
            name: "overflow".to_string(),
            description: "Integer overflow/underflow test".to_string(),
            source_file: test_cases_dir.join("overflow.sol"),
            expected_detectors: vec!["unchecked-math".to_string(), "integer-underflow".to_string()],
            config_overrides: HashMap::new(),
            expected_exit_code: 1,
            tags: vec!["arithmetic".to_string(), "medium-severity".to_string()],
        };

        let complex_meta = GoldenTestCase {
            name: "complex".to_string(),
            description: "Complex contract with multiple vulnerabilities".to_string(),
            source_file: test_cases_dir.join("complex.sol"),
            expected_detectors: vec![
                "unchecked-external-call".to_string(),
                "dangerous-delegatecall".to_string(),
                "timestamp-dependence".to_string(),
                "tx-origin".to_string(),
            ],
            config_overrides: HashMap::new(),
            expected_exit_code: 1,
            tags: vec!["complex".to_string(), "multiple-issues".to_string()],
        };

        // Save metadata files
        fs::write(
            test_cases_dir.join("reentrancy.json"),
            serde_json::to_string_pretty(&reentrancy_meta)?,
        )?;
        fs::write(
            test_cases_dir.join("access_control.json"),
            serde_json::to_string_pretty(&access_control_meta)?,
        )?;
        fs::write(
            test_cases_dir.join("overflow.json"),
            serde_json::to_string_pretty(&overflow_meta)?,
        )?;
        fs::write(
            test_cases_dir.join("complex.json"),
            serde_json::to_string_pretty(&complex_meta)?,
        )?;

        Ok(())
    }

    /// Load test cases from the test cases directory
    fn load_test_cases(config: &RegressionConfig) -> Result<Vec<GoldenTestCase>, Box<dyn std::error::Error>> {
        let mut test_cases = Vec::new();

        if !config.test_cases_dir.exists() {
            return Ok(test_cases);
        }

        for entry in fs::read_dir(&config.test_cases_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                let test_case: GoldenTestCase = serde_json::from_str(&content)?;
                test_cases.push(test_case);
            }
        }

        test_cases.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(test_cases)
    }

    /// Run all golden file regression tests
    pub async fn run_all_tests(&mut self) -> Result<Vec<GoldenTestResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();

        println!("Running {} regression tests", self.test_cases.len());

        for (i, test_case) in self.test_cases.iter().enumerate() {
            println!("Running test {}/{}: {}", i + 1, self.test_cases.len(), test_case.name);

            let result = self.run_single_test(test_case).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Run a single golden file test
    async fn run_single_test(&self, test_case: &GoldenTestCase) -> Result<GoldenTestResult, Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();

        // Execute SolidityDefend
        let (exit_code, stdout, stderr) = self.execute_soliditydefend(test_case).await?;
        let execution_time = start_time.elapsed();

        // Compare with golden files
        let differences = if self.config.update_mode {
            // Update mode: save current output as golden
            self.update_golden_files(test_case, &stdout)?;
            Vec::new()
        } else {
            // Test mode: compare with existing golden files
            self.compare_with_golden(test_case, &stdout)?
        };

        // Determine test status
        let status = if self.config.update_mode {
            TestStatus::Updated
        } else if differences.iter().any(|d| matches!(d.severity, DifferenceSeverity::Critical | DifferenceSeverity::Major)) {
            TestStatus::Failed
        } else {
            TestStatus::Passed
        };

        Ok(GoldenTestResult {
            test_case: test_case.clone(),
            status,
            differences,
            execution_time,
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Execute SolidityDefend on a test case
    async fn execute_soliditydefend(&self, test_case: &GoldenTestCase) -> Result<(i32, String, String), Box<dyn std::error::Error>> {
        // This would execute the actual SolidityDefend binary
        // For now, simulate output based on the test case

        let source_content = fs::read_to_string(&test_case.source_file)?;
        let mut output = serde_json::json!({
            "version": "0.1.0",
            "analysis_time": "2024-01-01T00:00:00Z",
            "source_file": test_case.source_file.to_string_lossy(),
            "findings": []
        });

        let mut findings = Vec::new();
        let mut exit_code = 0;

        // Simulate reentrancy detection
        if source_content.contains("call{value:") && source_content.contains("balances[msg.sender] = 0") {
            findings.push(serde_json::json!({
                "detector": "reentrancy",
                "severity": "high",
                "confidence": "high",
                "message": "Potential reentrancy vulnerability detected",
                "line": 10,
                "column": 8,
                "function": "withdraw",
                "description": "External call is made before state variable is updated"
            }));
            exit_code = 1;
        }

        // Simulate access control detection
        if source_content.contains("function withdraw") && !source_content.contains("onlyOwner") &&
           !source_content.contains("require(msg.sender == owner") {
            findings.push(serde_json::json!({
                "detector": "missing-access-control",
                "severity": "high",
                "confidence": "high",
                "message": "Function lacks proper access control",
                "line": 13,
                "column": 4,
                "function": "withdraw",
                "description": "Sensitive function can be called by anyone"
            }));
            exit_code = 1;
        }

        // Simulate arithmetic detection for old Solidity
        if source_content.contains("pragma solidity ^0.4") {
            if source_content.contains("balances[msg.sender] - amount") {
                findings.push(serde_json::json!({
                    "detector": "integer-underflow",
                    "severity": "medium",
                    "confidence": "medium",
                    "message": "Potential integer underflow in arithmetic operation",
                    "line": 7,
                    "column": 16,
                    "function": "transfer",
                    "description": "Subtraction operation may underflow"
                }));
                exit_code = 1;
            }

            if source_content.contains("balances[to] += amount") {
                findings.push(serde_json::json!({
                    "detector": "unchecked-math",
                    "severity": "medium",
                    "confidence": "medium",
                    "message": "Potential integer overflow in arithmetic operation",
                    "line": 12,
                    "column": 8,
                    "function": "mint",
                    "description": "Addition operation may overflow"
                }));
                exit_code = 1;
            }
        }

        // Simulate complex contract detections
        if source_content.contains("ComplexExample") {
            if source_content.contains("to.call(abi.encodeWithSignature") {
                findings.push(serde_json::json!({
                    "detector": "unchecked-external-call",
                    "severity": "medium",
                    "confidence": "high",
                    "message": "External call return value not properly checked",
                    "line": 35,
                    "column": 12,
                    "function": "complexTransfer",
                    "description": "External call success is not verified"
                }));
                exit_code = 1;
            }

            if source_content.contains("target.delegatecall(data)") {
                findings.push(serde_json::json!({
                    "detector": "dangerous-delegatecall",
                    "severity": "high",
                    "confidence": "high",
                    "message": "Dangerous delegatecall with user-controlled target",
                    "line": 42,
                    "column": 8,
                    "function": "delegateCall",
                    "description": "Delegatecall allows arbitrary code execution"
                }));
                exit_code = 1;
            }

            if source_content.contains("block.timestamp % 2") {
                findings.push(serde_json::json!({
                    "detector": "timestamp-dependence",
                    "severity": "low",
                    "confidence": "medium",
                    "message": "Function depends on block timestamp",
                    "line": 48,
                    "column": 16,
                    "function": "timeBasedFunction",
                    "description": "Block timestamp can be manipulated by miners"
                }));
                exit_code = 1;
            }

            if source_content.contains("tx.origin == owner") {
                findings.push(serde_json::json!({
                    "detector": "tx-origin",
                    "severity": "medium",
                    "confidence": "high",
                    "message": "Use of tx.origin for authentication",
                    "line": 53,
                    "column": 16,
                    "function": "authenticate",
                    "description": "tx.origin is vulnerable to phishing attacks"
                }));
                exit_code = 1;
            }
        }

        output["findings"] = serde_json::Value::Array(findings);

        let stdout = serde_json::to_string_pretty(&output)?;
        let stderr = if exit_code == 0 {
            "Analysis completed successfully".to_string()
        } else {
            format!("Found {} issues", output["findings"].as_array().unwrap().len())
        };

        Ok((exit_code, stdout, stderr))
    }

    /// Update golden files with current output
    fn update_golden_files(&self, test_case: &GoldenTestCase, output: &str) -> Result<(), Box<dyn std::error::Error>> {
        let golden_file = self.config.golden_files_dir.join(format!("{}.json", test_case.name));

        // Ensure golden directory exists
        if let Some(parent) = golden_file.parent() {
            fs::create_dir_all(parent)?;
        }

        // Normalize output before saving
        let normalized_output = self.normalize_output(output)?;
        fs::write(golden_file, normalized_output)?;

        println!("Updated golden file for test: {}", test_case.name);
        Ok(())
    }

    /// Compare current output with golden file
    fn compare_with_golden(&self, test_case: &GoldenTestCase, output: &str) -> Result<Vec<OutputDifference>, Box<dyn std::error::Error>> {
        let golden_file = self.config.golden_files_dir.join(format!("{}.json", test_case.name));

        if !golden_file.exists() {
            return Ok(vec![OutputDifference {
                diff_type: DifferenceType::StructuralChange,
                location: "file".to_string(),
                expected: "Golden file exists".to_string(),
                actual: "Golden file missing".to_string(),
                severity: DifferenceSeverity::Critical,
            }]);
        }

        let golden_content = fs::read_to_string(golden_file)?;
        let normalized_output = self.normalize_output(output)?;
        let normalized_golden = self.normalize_output(&golden_content)?;

        // Parse JSON for detailed comparison
        let output_json: serde_json::Value = serde_json::from_str(&normalized_output)?;
        let golden_json: serde_json::Value = serde_json::from_str(&normalized_golden)?;

        self.compare_json_outputs(&golden_json, &output_json)
    }

    /// Normalize output for consistent comparison
    fn normalize_output(&self, output: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut json: serde_json::Value = serde_json::from_str(output)?;

        // Apply tolerance configurations
        if self.config.tolerance_config.ignore_timestamps {
            if let Some(obj) = json.as_object_mut() {
                obj.remove("analysis_time");
                obj.remove("timestamp");
            }
        }

        if self.config.tolerance_config.ignore_execution_time {
            if let Some(obj) = json.as_object_mut() {
                obj.remove("execution_time");
                obj.remove("duration");
            }
        }

        if self.config.tolerance_config.ignore_file_paths {
            if let Some(obj) = json.as_object_mut() {
                if let Some(source_file) = obj.get_mut("source_file") {
                    if let Some(path_str) = source_file.as_str() {
                        let path = Path::new(path_str);
                        if let Some(filename) = path.file_name() {
                            *source_file = serde_json::Value::String(filename.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        // Sort findings for consistent ordering
        if let Some(obj) = json.as_object_mut() {
            if let Some(findings) = obj.get_mut("findings") {
                if let Some(findings_array) = findings.as_array_mut() {
                    findings_array.sort_by(|a, b| {
                        let detector_a = a.get("detector").and_then(|v| v.as_str()).unwrap_or("");
                        let detector_b = b.get("detector").and_then(|v| v.as_str()).unwrap_or("");
                        detector_a.cmp(detector_b)
                    });
                }
            }
        }

        Ok(serde_json::to_string_pretty(&json)?)
    }

    /// Compare two JSON outputs and find differences
    fn compare_json_outputs(&self, expected: &serde_json::Value, actual: &serde_json::Value) -> Result<Vec<OutputDifference>, Box<dyn std::error::Error>> {
        let mut differences = Vec::new();

        // Compare findings arrays
        if let (Some(expected_findings), Some(actual_findings)) = (
            expected.get("findings").and_then(|v| v.as_array()),
            actual.get("findings").and_then(|v| v.as_array()),
        ) {
            // Check for missing detections
            for expected_finding in expected_findings {
                let detector = expected_finding.get("detector").and_then(|v| v.as_str()).unwrap_or("");
                let found = actual_findings.iter().any(|actual_finding| {
                    actual_finding.get("detector").and_then(|v| v.as_str()) == Some(detector)
                });

                if !found {
                    differences.push(OutputDifference {
                        diff_type: DifferenceType::MissingDetection,
                        location: format!("detector: {}", detector),
                        expected: format!("Detection: {}", detector),
                        actual: "Not detected".to_string(),
                        severity: DifferenceSeverity::Critical,
                    });
                }
            }

            // Check for extra detections
            for actual_finding in actual_findings {
                let detector = actual_finding.get("detector").and_then(|v| v.as_str()).unwrap_or("");
                let found = expected_findings.iter().any(|expected_finding| {
                    expected_finding.get("detector").and_then(|v| v.as_str()) == Some(detector)
                });

                if !found {
                    differences.push(OutputDifference {
                        diff_type: DifferenceType::ExtraDetection,
                        location: format!("detector: {}", detector),
                        expected: "Not detected".to_string(),
                        actual: format!("Detection: {}", detector),
                        severity: DifferenceSeverity::Major,
                    });
                }
            }

            // Compare matching detections for differences in details
            for expected_finding in expected_findings {
                let detector = expected_finding.get("detector").and_then(|v| v.as_str()).unwrap_or("");

                if let Some(actual_finding) = actual_findings.iter().find(|f| {
                    f.get("detector").and_then(|v| v.as_str()) == Some(detector)
                }) {
                    // Compare severity
                    if let (Some(expected_severity), Some(actual_severity)) = (
                        expected_finding.get("severity").and_then(|v| v.as_str()),
                        actual_finding.get("severity").and_then(|v| v.as_str()),
                    ) {
                        if expected_severity != actual_severity {
                            differences.push(OutputDifference {
                                diff_type: DifferenceType::DifferentSeverity,
                                location: format!("detector: {} severity", detector),
                                expected: expected_severity.to_string(),
                                actual: actual_severity.to_string(),
                                severity: DifferenceSeverity::Major,
                            });
                        }
                    }

                    // Compare confidence (with tolerance)
                    if let (Some(expected_confidence), Some(actual_confidence)) = (
                        expected_finding.get("confidence").and_then(|v| v.as_str()),
                        actual_finding.get("confidence").and_then(|v| v.as_str()),
                    ) {
                        if expected_confidence != actual_confidence {
                            differences.push(OutputDifference {
                                diff_type: DifferenceType::DifferentConfidence,
                                location: format!("detector: {} confidence", detector),
                                expected: expected_confidence.to_string(),
                                actual: actual_confidence.to_string(),
                                severity: DifferenceSeverity::Minor,
                            });
                        }
                    }

                    // Compare line numbers (if not ignored)
                    if !self.config.tolerance_config.ignore_line_numbers {
                        if let (Some(expected_line), Some(actual_line)) = (
                            expected_finding.get("line").and_then(|v| v.as_u64()),
                            actual_finding.get("line").and_then(|v| v.as_u64()),
                        ) {
                            if expected_line != actual_line {
                                differences.push(OutputDifference {
                                    diff_type: DifferenceType::DifferentLocation,
                                    location: format!("detector: {} line", detector),
                                    expected: expected_line.to_string(),
                                    actual: actual_line.to_string(),
                                    severity: DifferenceSeverity::Minor,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(differences)
    }

    /// Get test cases by tag
    pub fn get_test_cases_by_tag(&self, tag: &str) -> Vec<&GoldenTestCase> {
        self.test_cases.iter().filter(|tc| tc.tags.contains(&tag.to_string())).collect()
    }

    /// Get all available tags
    pub fn get_available_tags(&self) -> Vec<String> {
        let mut tags: Vec<_> = self.test_cases.iter()
            .flat_map(|tc| tc.tags.iter())
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        tags.sort();
        tags
    }

    /// Generate a hash of all golden files for integrity checking
    pub fn generate_golden_hash(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        let mut golden_files: Vec<_> = fs::read_dir(&self.config.golden_files_dir)?
            .collect::<Result<Vec<_>, _>>()?;

        golden_files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        for entry in golden_files {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                hasher.update(content.as_bytes());
            }
        }

        Ok(format!("{:x}", hasher.finalize()))
    }
}

// Test cases that will fail until SolidityDefend is fully implemented

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[should_panic(expected = "Golden file tests failed")]
    async fn test_golden_file_regression_should_fail_initially() {
        // This test should fail until SolidityDefend is fully implemented
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut runner = GoldenFileRunner::with_defaults(temp_dir.path())
            .expect("Failed to create runner");

        let results = runner.run_all_tests().await.expect("Failed to run tests");

        let failed_tests: Vec<_> = results.iter()
            .filter(|r| matches!(r.status, TestStatus::Failed))
            .collect();

        assert!(failed_tests.is_empty(), "Golden file tests failed: {}", failed_tests.len());
    }

    #[tokio::test]
    #[should_panic(expected = "Reentrancy detection failed")]
    async fn test_reentrancy_golden_should_fail() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut runner = GoldenFileRunner::with_defaults(temp_dir.path())
            .expect("Failed to create runner");

        let reentrancy_cases = runner.get_test_cases_by_tag("reentrancy");
        assert!(!reentrancy_cases.is_empty(), "Should have reentrancy test cases");

        for test_case in reentrancy_cases {
            let result = runner.run_single_test(test_case).await.expect("Test execution failed");
            assert!(
                matches!(result.status, TestStatus::Passed),
                "Reentrancy detection failed"
            );
        }
    }

    #[tokio::test]
    #[should_panic(expected = "Access control detection failed")]
    async fn test_access_control_golden_should_fail() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut runner = GoldenFileRunner::with_defaults(temp_dir.path())
            .expect("Failed to create runner");

        let access_cases = runner.get_test_cases_by_tag("access-control");
        assert!(!access_cases.is_empty(), "Should have access control test cases");

        for test_case in access_cases {
            let result = runner.run_single_test(test_case).await.expect("Test execution failed");
            assert!(
                matches!(result.status, TestStatus::Passed),
                "Access control detection failed"
            );
        }
    }

    #[tokio::test]
    async fn test_sample_test_case_creation() {
        // This should pass - basic test case creation
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let test_cases_dir = temp_dir.path().join("test_cases");

        GoldenFileRunner::create_sample_test_cases(&test_cases_dir)
            .expect("Failed to create sample test cases");

        // Verify files were created
        assert!(test_cases_dir.join("reentrancy.sol").exists());
        assert!(test_cases_dir.join("access_control.sol").exists());
        assert!(test_cases_dir.join("overflow.sol").exists());
        assert!(test_cases_dir.join("complex.sol").exists());

        // Verify metadata files
        assert!(test_cases_dir.join("reentrancy.json").exists());
        assert!(test_cases_dir.join("access_control.json").exists());
        assert!(test_cases_dir.join("overflow.json").exists());
        assert!(test_cases_dir.join("complex.json").exists());
    }

    #[tokio::test]
    async fn test_golden_runner_setup() {
        // This should pass - basic runner setup
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let runner = GoldenFileRunner::with_defaults(temp_dir.path())
            .expect("Failed to create runner");

        assert!(!runner.test_cases.is_empty(), "Should load test cases");
        assert!(!runner.get_available_tags().is_empty(), "Should have tags");

        // Check for expected test cases
        let test_names: Vec<_> = runner.test_cases.iter().map(|tc| &tc.name).collect();
        assert!(test_names.contains(&&"reentrancy".to_string()));
        assert!(test_names.contains(&&"access_control".to_string()));
        assert!(test_names.contains(&&"complex".to_string()));
    }

    #[tokio::test]
    async fn test_output_normalization() {
        // This should pass - output normalization
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let runner = GoldenFileRunner::with_defaults(temp_dir.path())
            .expect("Failed to create runner");

        let sample_output = r#"{
            "version": "0.1.0",
            "analysis_time": "2024-01-01T12:34:56Z",
            "execution_time": "1.234s",
            "source_file": "/long/path/to/file.sol",
            "findings": [
                {
                    "detector": "reentrancy",
                    "severity": "high",
                    "line": 10
                },
                {
                    "detector": "access-control",
                    "severity": "medium",
                    "line": 5
                }
            ]
        }"#;

        let normalized = runner.normalize_output(sample_output)
            .expect("Failed to normalize output");

        let normalized_json: serde_json::Value = serde_json::from_str(&normalized)
            .expect("Failed to parse normalized JSON");

        // Check that timestamps and execution time are removed
        assert!(normalized_json.get("analysis_time").is_none());
        assert!(normalized_json.get("execution_time").is_none());

        // Check that file paths are normalized
        let source_file = normalized_json.get("source_file").unwrap().as_str().unwrap();
        assert_eq!(source_file, "file.sol");

        // Check that findings are sorted
        let findings = normalized_json.get("findings").unwrap().as_array().unwrap();
        let first_detector = findings[0].get("detector").unwrap().as_str().unwrap();
        let second_detector = findings[1].get("detector").unwrap().as_str().unwrap();
        assert_eq!(first_detector, "access-control"); // Sorted alphabetically
        assert_eq!(second_detector, "reentrancy");
    }

    #[test]
    fn test_tolerance_config() {
        // This should pass - tolerance configuration
        let config = ToleranceConfig::default();

        assert!(config.ignore_timestamps);
        assert!(config.ignore_execution_time);
        assert!(!config.ignore_line_numbers);
        assert!(!config.ignore_column_numbers);
        assert!(config.ignore_file_paths);
        assert_eq!(config.severity_tolerance, 0.0);
        assert_eq!(config.confidence_tolerance, 0.1);
    }
}

/// Utilities for golden file regression testing
pub mod utils {
    use super::*;

    /// Generate a comprehensive regression test report
    pub async fn generate_regression_report(
        config: RegressionConfig
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut runner = GoldenFileRunner::new(config)?;
        let results = runner.run_all_tests().await?;

        let mut report = String::new();
        report.push_str("# Golden File Regression Test Report\n\n");

        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| matches!(r.status, TestStatus::Passed)).count();
        let failed_tests = results.iter().filter(|r| matches!(r.status, TestStatus::Failed)).count();
        let updated_tests = results.iter().filter(|r| matches!(r.status, TestStatus::Updated)).count();

        report.push_str(&format!("**Total Tests:** {}\n", total_tests));
        report.push_str(&format!("**Passed:** {}\n", passed_tests));
        report.push_str(&format!("**Failed:** {}\n", failed_tests));
        report.push_str(&format!("**Updated:** {}\n", updated_tests));
        report.push_str(&format!("**Success Rate:** {:.1}%\n\n",
            if total_tests > 0 { passed_tests as f64 / total_tests as f64 * 100.0 } else { 0.0 }));

        if failed_tests > 0 {
            report.push_str("## Failed Tests\n\n");
            for result in results.iter().filter(|r| matches!(r.status, TestStatus::Failed)) {
                report.push_str(&format!("### {}\n", result.test_case.name));
                report.push_str(&format!("**Description:** {}\n", result.test_case.description));

                if !result.differences.is_empty() {
                    report.push_str("**Differences:**\n");
                    for diff in &result.differences {
                        report.push_str(&format!("- {} at {}: Expected '{}', Got '{}'\n",
                            format!("{:?}", diff.diff_type), diff.location, diff.expected, diff.actual));
                    }
                }
                report.push_str("\n");
            }
        }

        // Generate hash for integrity checking
        let golden_hash = runner.generate_golden_hash()?;
        report.push_str(&format!("**Golden Files Hash:** {}\n", golden_hash));

        Ok(report)
    }

    /// Update all golden files in batch mode
    pub async fn update_all_golden_files(
        mut config: RegressionConfig
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.update_mode = true;
        let mut runner = GoldenFileRunner::new(config)?;
        let results = runner.run_all_tests().await?;

        let updated_count = results.iter().filter(|r| matches!(r.status, TestStatus::Updated)).count();
        println!("Updated {} golden files", updated_count);

        Ok(())
    }

    /// Run regression tests for specific tags only
    pub async fn run_tagged_tests(
        config: RegressionConfig,
        tags: Vec<String>
    ) -> Result<Vec<GoldenTestResult>, Box<dyn std::error::Error>> {
        let mut runner = GoldenFileRunner::new(config)?;
        let mut results = Vec::new();

        for tag in tags {
            let tagged_cases = runner.get_test_cases_by_tag(&tag);
            for test_case in tagged_cases {
                let result = runner.run_single_test(test_case).await?;
                results.push(result);
            }
        }

        Ok(results)
    }
}