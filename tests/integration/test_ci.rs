use std::process::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Test CI/CD integration features
/// These tests are designed to FAIL initially until the CI features are implemented

#[cfg(test)]
mod test_ci_integration {
    use super::*;

    fn create_test_solidity_file(dir: &Path, filename: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
        let file_path = dir.join(filename);
        fs::write(file_path, content)?;
        Ok(())
    }

    fn run_soliditydefend(args: &[&str], working_dir: &Path) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        let output = Command::new("./target/debug/soliditydefend")
            .args(args)
            .current_dir(working_dir)
            .output()?;
        Ok(output)
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_exit_codes_for_vulnerabilities() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Create a contract with vulnerabilities
        create_test_solidity_file(dir_path, "vulnerable.sol", r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;

    function setOwner(address newOwner) external {
        // Missing access control - should cause non-zero exit code
        owner = newOwner;
    }

    function dangerousFunction() external {
        // High severity vulnerability - should cause exit code 1
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        // This should fail because CLI binary doesn't exist yet
        let output = run_soliditydefend(&["--format", "json", "vulnerable.sol"], dir_path).unwrap();

        // Should exit with code 1 for high severity vulnerabilities
        assert_eq!(output.status.code(), Some(1));

        // Should output findings in JSON format
        let json_output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(json_output["findings"].is_array());
        assert!(!json_output["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_exit_codes_for_clean_code() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Create a clean contract
        create_test_solidity_file(dir_path, "clean.sol", r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CleanContract {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address not allowed");
        owner = newOwner;
    }
}"#).unwrap();

        // This should fail because CLI binary doesn't exist yet
        let output = run_soliditydefend(&["--format", "json", "clean.sol"], dir_path).unwrap();

        // Should exit with code 0 for clean code
        assert_eq!(output.status.code(), Some(0));

        // Should output empty findings or success message
        let json_output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if json_output["findings"].is_array() {
            assert!(json_output["findings"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_json_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        create_test_solidity_file(dir_path, "test.sol", r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    function unsafeFunction() external {
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        // This should fail because CLI binary doesn't exist yet
        let output = run_soliditydefend(&["--format", "json", "test.sol"], dir_path).unwrap();

        // Should produce valid JSON output
        let json_output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

        // Validate JSON structure
        assert!(json_output["findings"].is_array());
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_severity_based_exit_codes() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Test different severity levels
        create_test_solidity_file(dir_path, "high_severity.sol", r#"
pragma solidity ^0.8.0;
contract HighSeverity {
    function dangerous() external {
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        create_test_solidity_file(dir_path, "medium_severity.sol", r#"
pragma solidity ^0.8.0;
contract MediumSeverity {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Missing access control
    }
}"#).unwrap();

        // This should fail because CLI doesn't exist yet
        let high_output = run_soliditydefend(&["--exit-code-severity", "high", "high_severity.sol"], dir_path).unwrap();
        assert_eq!(high_output.status.code(), Some(1)); // Exit 1 for high severity

        let medium_output = run_soliditydefend(&["--exit-code-severity", "medium", "medium_severity.sol"], dir_path).unwrap();
        assert_eq!(medium_output.status.code(), Some(1)); // Exit 1 for medium+ severity

        // Should exit 0 if only low severity issues when threshold is high
        let low_threshold_output = run_soliditydefend(&["--exit-code-severity", "high", "medium_severity.sol"], dir_path).unwrap();
        assert_eq!(low_threshold_output.status.code(), Some(0));
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_baseline_comparison() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        create_test_solidity_file(dir_path, "evolving.sol", r#"
pragma solidity ^0.8.0;
contract EvolvingContract {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // This will be a baseline issue
    }
}"#).unwrap();

        // This should fail because CLI doesn't exist yet

        // Generate baseline
        let baseline_output = run_soliditydefend(&["--format", "json", "--baseline-output", "baseline.json", "evolving.sol"], dir_path).unwrap();
        assert_eq!(baseline_output.status.code(), Some(0)); // Baseline generation should succeed

        // Check against baseline (same code)
        let same_output = run_soliditydefend(&["--format", "json", "--baseline", "baseline.json", "evolving.sol"], dir_path).unwrap();
        assert_eq!(same_output.status.code(), Some(0)); // No new issues

        // Add new vulnerability
        create_test_solidity_file(dir_path, "evolving.sol", r#"
pragma solidity ^0.8.0;
contract EvolvingContract {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Baseline issue
    }
    function newDangerousFunction() external {
        selfdestruct(payable(msg.sender)); // New high severity issue
    }
}"#).unwrap();

        // Check against baseline (new vulnerability)
        let new_vuln_output = run_soliditydefend(&["--format", "json", "--baseline", "baseline.json", "evolving.sol"], dir_path).unwrap();
        assert_eq!(new_vuln_output.status.code(), Some(1)); // New high severity issue found

        let json_output: serde_json::Value = serde_json::from_slice(&new_vuln_output.stdout).unwrap();
        let new_findings: Vec<_> = json_output["findings"].as_array().unwrap()
            .iter()
            .filter(|f| f["baseline_state"] == "new")
            .collect();
        assert!(!new_findings.is_empty());
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_configuration_file() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Create configuration file
        let config_content = r#"
[analysis]
severity_threshold = "medium"
output_format = "json"
exit_on_findings = true

[detectors]
enabled = [
    "reentrancy",
    "missing-access-control",
    "dangerous-selfdestruct"
]
disabled = [
    "unused-variable"
]

[output]
include_fix_suggestions = true
show_code_snippets = true
color_output = false

[ci]
exit_code_severity = "high"
fail_on_new_findings = true
"#;

        fs::write(dir_path.join("soliditydefend.toml"), config_content).unwrap();

        create_test_solidity_file(dir_path, "configured.sol", r#"
pragma solidity ^0.8.0;
contract ConfiguredTest {
    function dangerous() external {
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        // This should fail because CLI doesn't exist yet
        let output = run_soliditydefend(&["--config", "soliditydefend.toml", "configured.sol"], dir_path).unwrap();

        // Should use configuration settings
        assert_eq!(output.status.code(), Some(1)); // Should fail due to high severity

        // Should output JSON format as configured
        let json_output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(json_output["findings"].is_array());
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_directory_scanning() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Create multiple files in different directories
        fs::create_dir_all(dir_path.join("contracts")).unwrap();
        fs::create_dir_all(dir_path.join("test")).unwrap();

        create_test_solidity_file(&dir_path.join("contracts"), "Contract1.sol", r#"
pragma solidity ^0.8.0;
contract Contract1 {
    function vulnerable() external {
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        create_test_solidity_file(&dir_path.join("contracts"), "Contract2.sol", r#"
pragma solidity ^0.8.0;
contract Contract2 {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Missing access control
    }
}"#).unwrap();

        create_test_solidity_file(&dir_path.join("test"), "Test.sol", r#"
pragma solidity ^0.8.0;
contract Test {
    // Test file - might want to exclude
}"#).unwrap();

        // This should fail because CLI doesn't exist yet
        let output = run_soliditydefend(&[
            "--format", "json",
            "--recursive",
            "--exclude", "test/**",
            "."
        ], dir_path).unwrap();

        let json_output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let findings = json_output["findings"].as_array().unwrap();

        // Should find issues in contracts directory but not test directory
        assert!(!findings.is_empty());

        // Should not include findings from test directory
        for finding in findings {
            let file_path = finding["file"].as_str().unwrap();
            assert!(!file_path.contains("test/"));
        }
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_parallel_execution() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Create multiple files for parallel processing
        for i in 1..=10 {
            create_test_solidity_file(dir_path, &format!("contract_{}.sol", i), &format!(r#"
pragma solidity ^0.8.0;
contract Contract{} {{
    function vulnerable() external {{
        selfdestruct(payable(msg.sender));
    }}
}}"#, i)).unwrap();
        }

        // This should fail because CLI doesn't exist yet
        let sequential_start = std::time::Instant::now();
        let seq_output = run_soliditydefend(&["--jobs", "1", "--format", "json", "."], dir_path).unwrap();
        let sequential_time = sequential_start.elapsed();

        let parallel_start = std::time::Instant::now();
        let par_output = run_soliditydefend(&["--jobs", "4", "--format", "json", "."], dir_path).unwrap();
        let parallel_time = parallel_start.elapsed();

        // Both should succeed and find the same number of issues
        assert_eq!(seq_output.status.code(), Some(1));
        assert_eq!(par_output.status.code(), Some(1));

        let seq_json: serde_json::Value = serde_json::from_slice(&seq_output.stdout).unwrap();
        let par_json: serde_json::Value = serde_json::from_slice(&par_output.stdout).unwrap();

        assert_eq!(
            seq_json["findings"].as_array().unwrap().len(),
            par_json["findings"].as_array().unwrap().len()
        );

        // Parallel execution should be faster (with sufficient files)
        assert!(parallel_time < sequential_time);
    }

    #[test]
    #[should_panic(expected = "CLI binary not found")]
    fn test_ci_quiet_and_verbose_modes() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        create_test_solidity_file(dir_path, "test.sol", r#"
pragma solidity ^0.8.0;
contract Test {
    function vulnerable() external {
        selfdestruct(payable(msg.sender));
    }
}"#).unwrap();

        // This should fail because CLI doesn't exist yet

        // Test quiet mode
        let quiet_output = run_soliditydefend(&["--quiet", "--format", "json", "test.sol"], dir_path).unwrap();
        assert!(quiet_output.stderr.is_empty()); // No progress or debug output

        // Test verbose mode
        let verbose_output = run_soliditydefend(&["--verbose", "--format", "json", "test.sol"], dir_path).unwrap();
        assert!(!verbose_output.stderr.is_empty()); // Should have debug/progress output

        // Both should find the same vulnerabilities
        let quiet_json: serde_json::Value = serde_json::from_slice(&quiet_output.stdout).unwrap();
        let verbose_json: serde_json::Value = serde_json::from_slice(&verbose_output.stdout).unwrap();

        assert_eq!(
            quiet_json["findings"].as_array().unwrap().len(),
            verbose_json["findings"].as_array().unwrap().len()
        );
    }
}