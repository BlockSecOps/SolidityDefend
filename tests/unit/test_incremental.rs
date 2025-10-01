use std::fs;
use std::path::Path;
use tempfile::TempDir;
use std::process::Command;

/// Test incremental scanning functionality
/// These tests are designed to FAIL initially until incremental scanning is implemented

#[cfg(test)]
mod test_incremental_scanning {
    use super::*;

    fn setup_git_repo(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        Command::new("git")
            .args(&["init"])
            .current_dir(dir)
            .output()?;

        Command::new("git")
            .args(&["config", "user.name", "Test User"])
            .current_dir(dir)
            .output()?;

        Command::new("git")
            .args(&["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()?;

        Ok(())
    }

    fn create_and_commit_file(dir: &Path, filename: &str, content: &str, commit_msg: &str) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(dir.join(filename), content)?;

        Command::new("git")
            .args(&["add", filename])
            .current_dir(dir)
            .output()?;

        Command::new("git")
            .args(&["commit", "-m", commit_msg])
            .current_dir(dir)
            .output()?;

        Ok(())
    }

    #[test]
    #[should_panic(expected = "IncrementalScanner not found")]
    fn test_git_diff_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create initial clean contract
        create_and_commit_file(dir_path, "Contract.sol", r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CleanContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
"#, "Initial clean contract").unwrap();

        // This should fail because IncrementalScanner is not implemented yet
        use incremental::IncrementalScanner;
        let scanner = IncrementalScanner::new(dir_path).unwrap();
        let changed_files = scanner.get_changed_files_since_commit("HEAD~1").unwrap();

        assert!(changed_files.is_empty()); // No changes since last commit

        // Add vulnerability
        fs::write(dir_path.join("Contract.sol"), r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Removed access control - vulnerability introduced
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // Added dangerous function
    function dangerousFunction() external {
        selfdestruct(payable(msg.sender));
    }
}
"#).unwrap();

        let changed_files_after = scanner.get_changed_files_since_commit("HEAD~1").unwrap();
        assert_eq!(changed_files_after.len(), 1);
        assert!(changed_files_after[0].ends_with("Contract.sol"));
    }

    #[test]
    #[should_panic(expected = "IncrementalScanner not found")]
    fn test_incremental_analysis_only_changed_files() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create multiple contracts
        create_and_commit_file(dir_path, "Contract1.sol", r#"
pragma solidity ^0.8.0;
contract Contract1 {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Vulnerability
    }
}
"#, "Add Contract1").unwrap();

        create_and_commit_file(dir_path, "Contract2.sol", r#"
pragma solidity ^0.8.0;
contract Contract2 {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Same vulnerability
    }
}
"#, "Add Contract2").unwrap();

        // Only modify Contract1
        fs::write(dir_path.join("Contract1.sol"), r#"
pragma solidity ^0.8.0;
contract Contract1 {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner; // Keep vulnerability
    }
    function dangerousFunction() external {
        selfdestruct(payable(msg.sender)); // Add new vulnerability
    }
}
"#).unwrap();

        // This should fail because incremental scanning is not implemented
        use incremental::IncrementalScanner;
        let scanner = IncrementalScanner::new(dir_path).unwrap();
        let analysis_result = scanner.analyze_incremental("HEAD~1").unwrap();

        // Should only analyze Contract1, not Contract2
        assert_eq!(analysis_result.analyzed_files.len(), 1);
        assert!(analysis_result.analyzed_files[0].ends_with("Contract1.sol"));

        // Should find vulnerabilities only in the changed file
        assert!(!analysis_result.findings.is_empty());
        for finding in &analysis_result.findings {
            assert!(finding.file_path.ends_with("Contract1.sol"));
        }
    }

    #[test]
    #[should_panic(expected = "IncrementalScanner not found")]
    fn test_dependency_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create base contract
        create_and_commit_file(dir_path, "Base.sol", r#"
pragma solidity ^0.8.0;
contract Base {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}
"#, "Add base contract").unwrap();

        // Create derived contract
        create_and_commit_file(dir_path, "Derived.sol", r#"
pragma solidity ^0.8.0;
import "./Base.sol";

contract Derived is Base {
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"#, "Add derived contract").unwrap();

        // Modify base contract (introduce vulnerability)
        fs::write(dir_path.join("Base.sol"), r#"
pragma solidity ^0.8.0;
contract Base {
    address public owner;

    // Removed modifier - breaks security in derived contracts
}
"#).unwrap();

        // This should fail because dependency tracking is not implemented
        use incremental::IncrementalScanner;
        let scanner = IncrementalScanner::new(dir_path).unwrap();
        let analysis_result = scanner.analyze_incremental_with_dependencies("HEAD~1").unwrap();

        // Should analyze both files due to dependency
        assert_eq!(analysis_result.analyzed_files.len(), 2);
        assert!(analysis_result.analyzed_files.iter().any(|f| f.ends_with("Base.sol")));
        assert!(analysis_result.analyzed_files.iter().any(|f| f.ends_with("Derived.sol")));

        // Should find issues in derived contract due to base contract changes
        let derived_findings: Vec<_> = analysis_result.findings.iter()
            .filter(|f| f.file_path.ends_with("Derived.sol"))
            .collect();
        assert!(!derived_findings.is_empty());
    }

    #[test]
    #[should_panic(expected = "CacheManager not found")]
    fn test_analysis_result_caching() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        create_and_commit_file(dir_path, "TestContract.sol", r#"
pragma solidity ^0.8.0;
contract TestContract {
    function test() external pure returns (uint256) {
        return 42;
    }
}
"#, "Add test contract").unwrap();

        // This should fail because CacheManager is not implemented
        use cache::CacheManager;
        let cache = CacheManager::new(dir_path.join(".soliditydefend_cache")).unwrap();

        // First analysis - should be uncached
        let start_time = std::time::Instant::now();
        let result1 = cache.get_or_analyze("TestContract.sol", "commit_hash_123").unwrap();
        let first_duration = start_time.elapsed();

        // Second analysis - should be cached
        let start_time = std::time::Instant::now();
        let result2 = cache.get_or_analyze("TestContract.sol", "commit_hash_123").unwrap();
        let second_duration = start_time.elapsed();

        // Results should be identical
        assert_eq!(result1.findings.len(), result2.findings.len());

        // Second analysis should be much faster (cached)
        assert!(second_duration < first_duration / 2);

        // Cache should invalidate when file changes
        fs::write(dir_path.join("TestContract.sol"), r#"
pragma solidity ^0.8.0;
contract TestContract {
    function dangerous() external {
        selfdestruct(payable(msg.sender)); // Add vulnerability
    }
}
"#).unwrap();

        let result3 = cache.get_or_analyze("TestContract.sol", "commit_hash_456").unwrap();
        assert!(result3.findings.len() > result1.findings.len());
    }

    #[test]
    #[should_panic(expected = "IncrementalScanner not found")]
    fn test_branch_comparison() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create main branch content
        create_and_commit_file(dir_path, "Main.sol", r#"
pragma solidity ^0.8.0;
contract MainContract {
    address owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"#, "Main branch contract").unwrap();

        // Create feature branch
        Command::new("git")
            .args(&["checkout", "-b", "feature-branch"])
            .current_dir(dir_path)
            .output().unwrap();

        // Add vulnerability in feature branch
        fs::write(dir_path.join("Main.sol"), r#"
pragma solidity ^0.8.0;
contract MainContract {
    address owner;

    // Removed modifier and access control
    function setOwner(address newOwner) external {
        owner = newOwner; // Vulnerability introduced
    }

    function dangerousFeature() external {
        selfdestruct(payable(msg.sender)); // New vulnerability
    }
}
"#).unwrap();

        Command::new("git")
            .args(&["add", "Main.sol"])
            .current_dir(dir_path)
            .output().unwrap();

        Command::new("git")
            .args(&["commit", "-m", "Add dangerous feature"])
            .current_dir(dir_path)
            .output().unwrap();

        // This should fail because branch comparison is not implemented
        use incremental::IncrementalScanner;
        let scanner = IncrementalScanner::new(dir_path).unwrap();
        let comparison = scanner.compare_branches("main", "feature-branch").unwrap();

        // Should detect new vulnerabilities in feature branch
        assert!(!comparison.new_findings.is_empty());
        assert!(comparison.new_findings.iter().any(|f| f.detector_id.contains("dangerous-selfdestruct")));
        assert!(comparison.new_findings.iter().any(|f| f.detector_id.contains("missing-access-control")));

        // Should have no resolved findings (since main was clean)
        assert!(comparison.resolved_findings.is_empty());
    }

    #[test]
    #[should_panic(expected = "IncrementalScanner not found")]
    fn test_incremental_with_exclusions() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create directory structure
        fs::create_dir_all(dir_path.join("contracts")).unwrap();
        fs::create_dir_all(dir_path.join("test")).unwrap();
        fs::create_dir_all(dir_path.join("scripts")).unwrap();

        // Add files in different directories
        create_and_commit_file(&dir_path.join("contracts"), "Main.sol", r#"
pragma solidity ^0.8.0;
contract Main { }
"#, "Add main contract").unwrap();

        create_and_commit_file(&dir_path.join("test"), "Test.sol", r#"
pragma solidity ^0.8.0;
contract Test { }
"#, "Add test").unwrap();

        create_and_commit_file(&dir_path.join("scripts"), "Deploy.sol", r#"
pragma solidity ^0.8.0;
contract Deploy { }
"#, "Add deploy script").unwrap();

        // Modify files
        fs::write(dir_path.join("contracts").join("Main.sol"), r#"
pragma solidity ^0.8.0;
contract Main {
    function vulnerable() external {
        selfdestruct(payable(msg.sender));
    }
}
"#).unwrap();

        fs::write(dir_path.join("test").join("Test.sol"), r#"
pragma solidity ^0.8.0;
contract Test {
    function testVulnerable() external {
        selfdestruct(payable(msg.sender));
    }
}
"#).unwrap();

        // This should fail because incremental scanning with exclusions is not implemented
        use incremental::IncrementalScanner;
        let scanner = IncrementalScanner::new(dir_path).unwrap();

        let config = incremental::IncrementalConfig {
            exclude_patterns: vec!["test/**".to_string(), "scripts/**".to_string()],
            include_patterns: vec!["contracts/**".to_string()],
        };

        let result = scanner.analyze_incremental_with_config("HEAD~1", &config).unwrap();

        // Should only analyze files in contracts directory
        assert_eq!(result.analyzed_files.len(), 1);
        assert!(result.analyzed_files[0].contains("contracts/Main.sol"));

        // Should not analyze test or scripts
        assert!(!result.analyzed_files.iter().any(|f| f.contains("test/")));
        assert!(!result.analyzed_files.iter().any(|f| f.contains("scripts/")));
    }

    #[test]
    #[should_panic(expected = "PerformanceTracker not found")]
    fn test_incremental_performance_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        setup_git_repo(dir_path).unwrap();

        // Create multiple files for performance testing
        for i in 1..=20 {
            create_and_commit_file(dir_path, &format!("Contract{}.sol", i), &format!(r#"
pragma solidity ^0.8.0;
contract Contract{} {{
    address owner;
    function setOwner(address newOwner) external {{
        owner = newOwner;
    }}
}}
"#, i), &format!("Add contract {}", i)).unwrap();
        }

        // Modify only one file
        fs::write(dir_path.join("Contract1.sol"), r#"
pragma solidity ^0.8.0;
contract Contract1 {
    address owner;
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
    function newFunction() external {
        selfdestruct(payable(msg.sender));
    }
}
"#).unwrap();

        // This should fail because performance tracking is not implemented
        use incremental::{IncrementalScanner, PerformanceTracker};
        let scanner = IncrementalScanner::new(dir_path).unwrap();
        let tracker = PerformanceTracker::new();

        // Run full analysis
        let full_start = std::time::Instant::now();
        let full_result = scanner.analyze_all().unwrap();
        let full_duration = full_start.elapsed();

        // Run incremental analysis
        let incremental_start = std::time::Instant::now();
        let incremental_result = scanner.analyze_incremental("HEAD~1").unwrap();
        let incremental_duration = incremental_start.elapsed();

        // Track performance metrics
        tracker.record_analysis("full", full_duration, full_result.analyzed_files.len());
        tracker.record_analysis("incremental", incremental_duration, incremental_result.analyzed_files.len());

        // Incremental should be significantly faster
        assert!(incremental_duration < full_duration / 5);

        // Incremental should analyze fewer files
        assert!(incremental_result.analyzed_files.len() < full_result.analyzed_files.len());

        // Performance metrics should be available
        let metrics = tracker.get_metrics().unwrap();
        assert!(metrics.contains_key("full"));
        assert!(metrics.contains_key("incremental"));
    }
}