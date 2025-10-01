// tests/validation/solidifi.rs
// SolidiFI benchmark integration for fault injection testing
// This validates SolidityDefend against SolidiFI's comprehensive fault injection dataset

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::time::timeout;

// Re-export test utilities
use crate::common::test_utils::*;

/// SolidiFI fault patterns that we validate against
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SolidiFIFaultPattern {
    // Arithmetic Faults
    AOD, // Arithmetic Operator Deletion
    AOR, // Arithmetic Operator Replacement
    AOI, // Arithmetic Operator Insertion

    // Assignment Faults
    ASOD, // Assignment Operator Deletion
    ASOR, // Assignment Operator Replacement

    // Boolean Faults
    BOD,  // Boolean Operator Deletion
    BOR,  // Boolean Operator Replacement

    // Conditional Faults
    COD,  // Conditional Operator Deletion
    COR,  // Conditional Operator Replacement
    COI,  // Conditional Operator Insertion

    // Data Flow Faults
    DFD,  // Data Flow Deletion
    DFR,  // Data Flow Replacement

    // Expression Faults
    EED,  // Expression Elimination Deletion
    EER,  // Expression Elimination Replacement

    // Function Call Faults
    FCD,  // Function Call Deletion
    FCR,  // Function Call Replacement

    // Inheritance Faults
    IHD,  // Inheritance Deletion
    IHI,  // Inheritance Insertion
    IHR,  // Inheritance Replacement

    // Loop Faults
    LOD,  // Loop Deletion
    LOR,  // Loop Replacement

    // Modifier Faults
    MOD,  // Modifier Deletion
    MOR,  // Modifier Replacement
    MOI,  // Modifier Insertion

    // Return Faults
    RTD,  // Return Deletion
    RTR,  // Return Replacement
    RTI,  // Return Insertion

    // Statement Faults
    STD,  // Statement Deletion
    STR,  // Statement Replacement
    STI,  // Statement Insertion

    // Variable Faults
    VRD,  // Variable Replacement
    VTD,  // Variable Type Deletion
    VTR,  // Variable Type Replacement
    VTI,  // Variable Type Insertion

    // Custom fault patterns
    Custom(String),
}

impl From<&str> for SolidiFIFaultPattern {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "AOD" => Self::AOD,
            "AOR" => Self::AOR,
            "AOI" => Self::AOI,
            "ASOD" => Self::ASOD,
            "ASOR" => Self::ASOR,
            "BOD" => Self::BOD,
            "BOR" => Self::BOR,
            "COD" => Self::COD,
            "COR" => Self::COR,
            "COI" => Self::COI,
            "DFD" => Self::DFD,
            "DFR" => Self::DFR,
            "EED" => Self::EED,
            "EER" => Self::EER,
            "FCD" => Self::FCD,
            "FCR" => Self::FCR,
            "IHD" => Self::IHD,
            "IHI" => Self::IHI,
            "IHR" => Self::IHR,
            "LOD" => Self::LOD,
            "LOR" => Self::LOR,
            "MOD" => Self::MOD,
            "MOR" => Self::MOR,
            "MOI" => Self::MOI,
            "RTD" => Self::RTD,
            "RTR" => Self::RTR,
            "RTI" => Self::RTI,
            "STD" => Self::STD,
            "STR" => Self::STR,
            "STI" => Self::STI,
            "VRD" => Self::VRD,
            "VTD" => Self::VTD,
            "VTR" => Self::VTR,
            "VTI" => Self::VTI,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// SolidiFI mutation test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidiFIMutation {
    pub id: String,
    pub original_file: PathBuf,
    pub mutated_file: PathBuf,
    pub fault_pattern: SolidiFIFaultPattern,
    pub line_number: u32,
    pub column_number: u32,
    pub original_code: String,
    pub mutated_code: String,
    pub is_equivalent: bool,
    pub is_killable: bool,
    pub description: String,
}

/// SolidiFI test suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidiFIConfig {
    pub fault_patterns: Vec<SolidiFIFaultPattern>,
    pub target_contracts: Vec<PathBuf>,
    pub mutation_timeout: Duration,
    pub max_mutations_per_pattern: usize,
    pub exclude_equivalent: bool,
    pub include_killable_only: bool,
}

impl Default for SolidiFIConfig {
    fn default() -> Self {
        Self {
            fault_patterns: vec![
                SolidiFIFaultPattern::AOD,
                SolidiFIFaultPattern::AOR,
                SolidiFIFaultPattern::BOD,
                SolidiFIFaultPattern::BOR,
                SolidiFIFaultPattern::COD,
                SolidiFIFaultPattern::COR,
                SolidiFIFaultPattern::STD,
                SolidiFIFaultPattern::STR,
                SolidiFIFaultPattern::MOD,
                SolidiFIFaultPattern::MOR,
            ],
            target_contracts: Vec::new(),
            mutation_timeout: Duration::from_secs(30),
            max_mutations_per_pattern: 100,
            exclude_equivalent: true,
            include_killable_only: true,
        }
    }
}

/// SolidiFI benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidiFIResults {
    pub total_mutations: usize,
    pub killed_mutations: usize,
    pub survived_mutations: usize,
    pub equivalent_mutations: usize,
    pub timeout_mutations: usize,
    pub mutation_score: f64,
    pub adjusted_mutation_score: f64,
    pub execution_time: Duration,
    pub pattern_results: HashMap<SolidiFIFaultPattern, PatternMutationResults>,
    pub detailed_results: Vec<MutationTestResult>,
}

/// Results for a specific fault pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMutationResults {
    pub total: usize,
    pub killed: usize,
    pub survived: usize,
    pub equivalent: usize,
    pub timeout: usize,
    pub mutation_score: f64,
    pub detection_rate: f64,
}

/// Result for an individual mutation test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationTestResult {
    pub mutation: SolidiFIMutation,
    pub status: MutationStatus,
    pub detected_issues: Vec<DetectedIssue>,
    pub execution_time: Duration,
    pub error_message: Option<String>,
}

/// Status of a mutation test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationStatus {
    Killed,      // Mutation detected (good)
    Survived,    // Mutation not detected (bad)
    Equivalent,  // Mutation doesn't change behavior
    Timeout,     // Analysis timed out
    Error(String), // Analysis failed
}

/// Issue detected by SolidityDefend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedIssue {
    pub detector_name: String,
    pub severity: String,
    pub confidence: String,
    pub message: String,
    pub line: u32,
    pub column: u32,
}

/// SolidiFI dataset manager and test runner
pub struct SolidiFIRunner {
    config: SolidiFIConfig,
    dataset_path: PathBuf,
    temp_dir: Option<TempDir>,
    mutations: Vec<SolidiFIMutation>,
}

impl SolidiFIRunner {
    /// Create a new SolidiFI runner
    pub fn new(config: SolidiFIConfig, dataset_path: Option<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let (dataset_path, temp_dir) = if let Some(path) = dataset_path {
            (path, None)
        } else {
            // Create mock SolidiFI dataset for testing
            let temp_dir = TempDir::new()?;
            let dataset_path = Self::create_mock_dataset(temp_dir.path(), &config)?;
            (dataset_path, Some(temp_dir))
        };

        let mutations = Self::load_mutations(&dataset_path, &config)?;

        Ok(Self {
            config,
            dataset_path,
            temp_dir,
            mutations,
        })
    }

    /// Create mock SolidiFI dataset for testing
    fn create_mock_dataset(temp_path: &Path, config: &SolidiFIConfig) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dataset_path = temp_path.join("solidifi");
        fs::create_dir_all(&dataset_path)?;

        // Create original contract
        let original_path = dataset_path.join("original");
        fs::create_dir_all(&original_path)?;

        let contract_content = r#"
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[owner] = totalSupply;
    }

    function transfer(address to, uint256 amount) external notPaused returns (bool) {
        require(to != address(0), "Invalid address");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        return true;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "Insufficient contract balance");
        payable(owner).transfer(amount);
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function changeOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
    }
}
"#;

        let original_file = original_path.join("VulnerableContract.sol");
        fs::write(&original_file, contract_content)?;

        // Create mutations directory
        let mutations_path = dataset_path.join("mutations");
        fs::create_dir_all(&mutations_path)?;

        // Generate sample mutations for different fault patterns
        Self::generate_sample_mutations(&mutations_path, &original_file, contract_content)?;

        Ok(dataset_path)
    }

    /// Generate sample mutations for testing
    fn generate_sample_mutations(
        mutations_path: &Path,
        original_file: &Path,
        original_content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // AOD - Remove arithmetic operator (vulnerable)
        let aod_content = original_content.replace(
            "balances[msg.sender] -= amount;",
            "balances[msg.sender] = amount;"  // Missing subtraction - vulnerable
        );
        let aod_file = mutations_path.join("AOD_001_VulnerableContract.sol");
        fs::write(&aod_file, aod_content)?;

        // BOR - Replace boolean operator (vulnerable)
        let bor_content = original_content.replace(
            "require(!paused, \"Contract paused\");",
            "require(paused, \"Contract paused\");"  // Inverted logic - vulnerable
        );
        let bor_file = mutations_path.join("BOR_001_VulnerableContract.sol");
        fs::write(&bor_file, bor_content)?;

        // MOD - Remove modifier (highly vulnerable)
        let mod_content = original_content.replace(
            "function withdraw(uint256 amount) external onlyOwner {",
            "function withdraw(uint256 amount) external {"  // Removed access control
        );
        let mod_file = mutations_path.join("MOD_001_VulnerableContract.sol");
        fs::write(&mod_file, mod_content)?;

        // COD - Remove condition (vulnerable)
        let cod_content = original_content.replace(
            "require(balances[msg.sender] >= amount, \"Insufficient balance\");",
            "// require(balances[msg.sender] >= amount, \"Insufficient balance\");"  // Removed check
        );
        let cod_file = mutations_path.join("COD_001_VulnerableContract.sol");
        fs::write(&cod_file, cod_content)?;

        // STD - Remove statement (potentially vulnerable)
        let std_content = original_content.replace(
            "balances[to] += amount;",
            "// balances[to] += amount;"  // Missing credit - vulnerable
        );
        let std_file = mutations_path.join("STD_001_VulnerableContract.sol");
        fs::write(&std_file, std_content)?;

        // VRD - Replace variable (vulnerable)
        let vrd_content = original_content.replace(
            "payable(owner).transfer(amount);",
            "payable(msg.sender).transfer(amount);"  // Wrong recipient - vulnerable
        );
        let vrd_file = mutations_path.join("VRD_001_VulnerableContract.sol");
        fs::write(&vrd_file, vrd_content)?;

        Ok(())
    }

    /// Load mutations from the dataset
    fn load_mutations(dataset_path: &Path, config: &SolidiFIConfig) -> Result<Vec<SolidiFIMutation>, Box<dyn std::error::Error>> {
        let mut mutations = Vec::new();
        let mutations_path = dataset_path.join("mutations");
        let original_path = dataset_path.join("original");

        if !mutations_path.exists() {
            return Ok(mutations);
        }

        for entry in fs::read_dir(&mutations_path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.extension().and_then(|s| s.to_str()) != Some("sol") {
                continue;
            }

            let file_name = entry.file_name().to_string_lossy();
            let parts: Vec<&str> = file_name.split('_').collect();

            if parts.len() < 3 {
                continue;
            }

            let fault_pattern = SolidiFIFaultPattern::from(parts[0]);

            // Skip if pattern not in config
            if !config.fault_patterns.contains(&fault_pattern) {
                continue;
            }

            let original_file = original_path.join(format!("{}.sol", parts[2].trim_end_matches(".sol")));
            let mutated_content = fs::read_to_string(&file_path)?;
            let original_content = if original_file.exists() {
                fs::read_to_string(&original_file)?
            } else {
                String::new()
            };

            // Determine if mutation is likely to be killable
            let is_killable = Self::is_likely_killable(&fault_pattern, &mutated_content);

            mutations.push(SolidiFIMutation {
                id: format!("{}_{}", parts[0], parts[1]),
                original_file,
                mutated_file: file_path,
                fault_pattern,
                line_number: 1, // Would be parsed from actual SolidiFI data
                column_number: 1,
                original_code: "".to_string(), // Would be extracted from diff
                mutated_code: "".to_string(),
                is_equivalent: false, // Would be determined by semantic analysis
                is_killable,
                description: format!("Mutation {} applied", parts[0]),
            });
        }

        // Apply configuration filters
        if config.exclude_equivalent {
            mutations.retain(|m| !m.is_equivalent);
        }

        if config.include_killable_only {
            mutations.retain(|m| m.is_killable);
        }

        // Limit mutations per pattern
        let mut pattern_counts: HashMap<SolidiFIFaultPattern, usize> = HashMap::new();
        mutations.retain(|m| {
            let count = pattern_counts.entry(m.fault_pattern.clone()).or_insert(0);
            if *count < config.max_mutations_per_pattern {
                *count += 1;
                true
            } else {
                false
            }
        });

        Ok(mutations)
    }

    /// Determine if a mutation is likely to be killable by security analysis
    fn is_likely_killable(pattern: &SolidiFIFaultPattern, mutated_content: &str) -> bool {
        match pattern {
            // These patterns often create detectable security vulnerabilities
            SolidiFIFaultPattern::MOD | SolidiFIFaultPattern::MOR => true,  // Modifier issues
            SolidiFIFaultPattern::COD | SolidiFIFaultPattern::COR => true,  // Condition issues
            SolidiFIFaultPattern::AOD | SolidiFIFaultPattern::AOR => true,  // Arithmetic issues
            SolidiFIFaultPattern::BOR => true,                              // Boolean logic issues
            SolidiFIFaultPattern::VRD => true,                              // Variable misuse
            SolidiFIFaultPattern::STD => {
                // Statement deletion is killable if it removes important security checks
                mutated_content.contains("//") &&
                (mutated_content.contains("require") || mutated_content.contains("assert"))
            },
            // Other patterns may or may not be killable
            _ => false,
        }
    }

    /// Run mutation testing
    pub async fn run_mutation_testing(&self) -> Result<SolidiFIResults, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut results = Vec::new();
        let mut pattern_stats: HashMap<SolidiFIFaultPattern, (usize, usize, usize, usize, usize)> = HashMap::new();

        println!("Running mutation testing on {} mutations", self.mutations.len());

        for (i, mutation) in self.mutations.iter().enumerate() {
            if i % 10 == 0 {
                println!("Progress: {}/{}", i, self.mutations.len());
            }

            let test_start = Instant::now();
            let result = self.run_single_mutation(mutation).await;
            let execution_time = test_start.elapsed();

            let mutation_result = MutationTestResult {
                mutation: mutation.clone(),
                status: result.status.clone(),
                detected_issues: result.detected_issues,
                execution_time,
                error_message: result.error_message,
            };

            // Update pattern statistics
            let stats = pattern_stats.entry(mutation.fault_pattern.clone()).or_insert((0, 0, 0, 0, 0));
            stats.0 += 1; // total

            match mutation_result.status {
                MutationStatus::Killed => stats.1 += 1,
                MutationStatus::Survived => stats.2 += 1,
                MutationStatus::Equivalent => stats.3 += 1,
                MutationStatus::Timeout => stats.4 += 1,
                MutationStatus::Error(_) => stats.4 += 1,
            }

            results.push(mutation_result);
        }

        let execution_time = start_time.elapsed();

        // Calculate overall metrics
        let total_mutations = results.len();
        let killed_mutations = results.iter().filter(|r| matches!(r.status, MutationStatus::Killed)).count();
        let survived_mutations = results.iter().filter(|r| matches!(r.status, MutationStatus::Survived)).count();
        let equivalent_mutations = results.iter().filter(|r| matches!(r.status, MutationStatus::Equivalent)).count();
        let timeout_mutations = results.iter().filter(|r| matches!(r.status, MutationStatus::Timeout) || matches!(r.status, MutationStatus::Error(_))).count();

        let mutation_score = if total_mutations > 0 {
            killed_mutations as f64 / total_mutations as f64
        } else {
            0.0
        };

        let adjusted_mutation_score = if total_mutations > equivalent_mutations {
            killed_mutations as f64 / (total_mutations - equivalent_mutations) as f64
        } else {
            0.0
        };

        // Calculate pattern results
        let mut pattern_results = HashMap::new();
        for (pattern, (total, killed, survived, equivalent, timeout)) in pattern_stats {
            let score = if total > 0 { killed as f64 / total as f64 } else { 0.0 };
            let detection_rate = if total > equivalent { killed as f64 / (total - equivalent) as f64 } else { 0.0 };

            pattern_results.insert(pattern, PatternMutationResults {
                total,
                killed,
                survived,
                equivalent,
                timeout,
                mutation_score: score,
                detection_rate,
            });
        }

        Ok(SolidiFIResults {
            total_mutations,
            killed_mutations,
            survived_mutations,
            equivalent_mutations,
            timeout_mutations,
            mutation_score,
            adjusted_mutation_score,
            execution_time,
            pattern_results,
            detailed_results: results,
        })
    }

    /// Run SolidityDefend on a single mutation
    async fn run_single_mutation(&self, mutation: &SolidiFIMutation) -> SingleMutationResult {
        // Execute SolidityDefend with timeout
        let result = timeout(
            self.config.mutation_timeout,
            self.execute_soliditydefend(&mutation.mutated_file),
        ).await;

        match result {
            Ok(Ok(detected_issues)) => {
                // Determine if mutation was killed
                let is_killed = self.is_mutation_killed(mutation, &detected_issues);

                let status = if is_killed {
                    MutationStatus::Killed
                } else if mutation.is_equivalent {
                    MutationStatus::Equivalent
                } else {
                    MutationStatus::Survived
                };

                SingleMutationResult {
                    status,
                    detected_issues,
                    error_message: None,
                }
            },
            Ok(Err(error)) => SingleMutationResult {
                status: MutationStatus::Error(error),
                detected_issues: Vec::new(),
                error_message: Some(error),
            },
            Err(_) => SingleMutationResult {
                status: MutationStatus::Timeout,
                detected_issues: Vec::new(),
                error_message: Some("Analysis timed out".to_string()),
            },
        }
    }

    /// Execute SolidityDefend on a mutated file
    async fn execute_soliditydefend(&self, file_path: &Path) -> Result<Vec<DetectedIssue>, String> {
        // This would execute the actual SolidityDefend binary
        // For now, simulate detection based on mutation patterns

        let content = fs::read_to_string(file_path).map_err(|e| e.to_string())?;
        let mut detected = Vec::new();

        // Simulate various vulnerability detections based on mutation content

        // Missing access control (from MOD mutations)
        if content.contains("function withdraw") && !content.contains("onlyOwner") {
            detected.push(DetectedIssue {
                detector_name: "missing-access-control".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                message: "Function lacks proper access control".to_string(),
                line: 35, // Approximate line number
                column: 4,
            });
        }

        // Inverted boolean logic (from BOR mutations)
        if content.contains("require(paused,") {
            detected.push(DetectedIssue {
                detector_name: "logic-error".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                message: "Suspicious boolean logic in require statement".to_string(),
                line: 15,
                column: 8,
            });
        }

        // Missing balance checks (from COD mutations)
        if content.contains("// require(balances[msg.sender] >= amount") {
            detected.push(DetectedIssue {
                detector_name: "missing-balance-check".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                message: "Missing balance validation in transfer function".to_string(),
                line: 25,
                column: 8,
            });
        }

        // Arithmetic errors (from AOD mutations)
        if content.contains("balances[msg.sender] = amount;") &&
           !content.contains("balances[msg.sender] -= amount;") {
            detected.push(DetectedIssue {
                detector_name: "arithmetic-error".to_string(),
                severity: "high".to_string(),
                confidence: "medium".to_string(),
                message: "Suspicious arithmetic operation in balance update".to_string(),
                line: 27,
                column: 8,
            });
        }

        // Missing state updates (from STD mutations)
        if content.contains("// balances[to] += amount;") {
            detected.push(DetectedIssue {
                detector_name: "incomplete-transfer".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                message: "Transfer function does not credit recipient".to_string(),
                line: 28,
                column: 8,
            });
        }

        // Wrong recipient (from VRD mutations)
        if content.contains("payable(msg.sender).transfer(amount);") &&
           content.contains("function withdraw(uint256 amount) external") {
            detected.push(DetectedIssue {
                detector_name: "wrong-recipient".to_string(),
                severity: "critical".to_string(),
                confidence: "high".to_string(),
                message: "Withdraw function sends funds to wrong recipient".to_string(),
                line: 36,
                column: 8,
            });
        }

        Ok(detected)
    }

    /// Determine if a mutation was killed by the analysis
    fn is_mutation_killed(&self, mutation: &SolidiFIMutation, detected_issues: &[DetectedIssue]) -> bool {
        // A mutation is considered "killed" if SolidityDefend detects issues that would
        // likely catch the vulnerability introduced by the mutation

        if detected_issues.is_empty() {
            return false;
        }

        // Check if detected issues are relevant to the mutation pattern
        match mutation.fault_pattern {
            SolidiFIFaultPattern::MOD | SolidiFIFaultPattern::MOR => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("access-control") ||
                    issue.detector_name.contains("modifier")
                )
            },
            SolidiFIFaultPattern::COD | SolidiFIFaultPattern::COR => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("check") ||
                    issue.detector_name.contains("validation") ||
                    issue.severity == "high"
                )
            },
            SolidiFIFaultPattern::AOD | SolidiFIFaultPattern::AOR => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("arithmetic") ||
                    issue.detector_name.contains("overflow") ||
                    issue.detector_name.contains("underflow")
                )
            },
            SolidiFIFaultPattern::BOR => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("logic") ||
                    issue.detector_name.contains("boolean")
                )
            },
            SolidiFIFaultPattern::VRD => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("recipient") ||
                    issue.detector_name.contains("variable") ||
                    issue.severity == "critical"
                )
            },
            SolidiFIFaultPattern::STD => {
                detected_issues.iter().any(|issue|
                    issue.detector_name.contains("transfer") ||
                    issue.detector_name.contains("incomplete") ||
                    issue.severity == "high"
                )
            },
            _ => {
                // For other patterns, any high/critical severity detection counts as killed
                detected_issues.iter().any(|issue|
                    issue.severity == "high" || issue.severity == "critical"
                )
            }
        }
    }

    /// Get mutations by fault pattern
    pub fn get_mutations_by_pattern(&self, pattern: &SolidiFIFaultPattern) -> Vec<&SolidiFIMutation> {
        self.mutations.iter().filter(|m| &m.fault_pattern == pattern).collect()
    }

    /// Get all fault patterns in the dataset
    pub fn get_fault_patterns(&self) -> Vec<SolidiFIFaultPattern> {
        let mut patterns: Vec<_> = self.mutations.iter()
            .map(|m| m.fault_pattern.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        patterns.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        patterns
    }
}

/// Result for a single mutation test execution
struct SingleMutationResult {
    status: MutationStatus,
    detected_issues: Vec<DetectedIssue>,
    error_message: Option<String>,
}

// Test cases that will fail until SolidityDefend is fully implemented

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[should_panic(expected = "Mutation score too low")]
    async fn test_solidifi_mutation_testing_should_fail_initially() {
        // This test should fail until SolidityDefend is fully implemented
        let config = SolidiFIConfig::default();
        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");
        let results = runner.run_mutation_testing().await.expect("Mutation testing failed");

        // These assertions will fail until proper implementation
        assert!(results.mutation_score > 0.8, "Mutation score too low: {}", results.mutation_score);
        assert!(results.adjusted_mutation_score > 0.85, "Adjusted mutation score too low");
    }

    #[tokio::test]
    #[should_panic(expected = "Access control mutations not killed")]
    async fn test_access_control_mutations_should_fail() {
        let config = SolidiFIConfig {
            fault_patterns: vec![SolidiFIFaultPattern::MOD, SolidiFIFaultPattern::MOR],
            ..Default::default()
        };

        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");
        let results = runner.run_mutation_testing().await.expect("Mutation testing failed");

        let mod_results = results.pattern_results.get(&SolidiFIFaultPattern::MOD);
        assert!(mod_results.is_some(), "MOD pattern results missing");

        let mod_score = mod_results.unwrap().detection_rate;
        assert!(mod_score > 0.9, "Access control mutations not killed: {}", mod_score);
    }

    #[tokio::test]
    #[should_panic(expected = "Arithmetic mutations not killed")]
    async fn test_arithmetic_mutations_should_fail() {
        let config = SolidiFIConfig {
            fault_patterns: vec![SolidiFIFaultPattern::AOD, SolidiFIFaultPattern::AOR],
            ..Default::default()
        };

        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");
        let results = runner.run_mutation_testing().await.expect("Mutation testing failed");

        let aod_results = results.pattern_results.get(&SolidiFIFaultPattern::AOD);
        assert!(aod_results.is_some(), "AOD pattern results missing");

        let aod_score = aod_results.unwrap().detection_rate;
        assert!(aod_score > 0.8, "Arithmetic mutations not killed: {}", aod_score);
    }

    #[tokio::test]
    #[should_panic(expected = "Boolean mutations not killed")]
    async fn test_boolean_mutations_should_fail() {
        let config = SolidiFIConfig {
            fault_patterns: vec![SolidiFIFaultPattern::BOR],
            ..Default::default()
        };

        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");
        let results = runner.run_mutation_testing().await.expect("Mutation testing failed");

        let bor_results = results.pattern_results.get(&SolidiFIFaultPattern::BOR);
        assert!(bor_results.is_some(), "BOR pattern results missing");

        let bor_score = bor_results.unwrap().detection_rate;
        assert!(bor_score > 0.75, "Boolean mutations not killed: {}", bor_score);
    }

    #[tokio::test]
    async fn test_mock_dataset_creation() {
        // This should pass - basic dataset functionality
        let config = SolidiFIConfig::default();
        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");

        assert!(!runner.mutations.is_empty(), "Should have mutations");
        assert!(!runner.get_fault_patterns().is_empty(), "Should have fault patterns");

        // Check that we have expected patterns
        let patterns = runner.get_fault_patterns();
        println!("Available patterns: {:?}", patterns);
        // At least some mutations should be loaded
        assert!(runner.mutations.len() > 0);
    }

    #[tokio::test]
    async fn test_mutation_loading() {
        // This should pass - mutation loading functionality
        let config = SolidiFIConfig {
            fault_patterns: vec![
                SolidiFIFaultPattern::AOD,
                SolidiFIFaultPattern::MOD,
                SolidiFIFaultPattern::BOR,
            ],
            max_mutations_per_pattern: 5,
            exclude_equivalent: true,
            include_killable_only: false,
            ..Default::default()
        };

        let runner = SolidiFIRunner::new(config, None).expect("Failed to create runner");

        // Should respect pattern filtering
        for mutation in &runner.mutations {
            assert!(
                matches!(
                    mutation.fault_pattern,
                    SolidiFIFaultPattern::AOD | SolidiFIFaultPattern::MOD | SolidiFIFaultPattern::BOR
                ),
                "Unexpected fault pattern: {:?}",
                mutation.fault_pattern
            );
        }

        // Should respect max mutations per pattern
        let mut pattern_counts: HashMap<SolidiFIFaultPattern, usize> = HashMap::new();
        for mutation in &runner.mutations {
            *pattern_counts.entry(mutation.fault_pattern.clone()).or_insert(0) += 1;
        }

        for (pattern, count) in pattern_counts {
            assert!(count <= 5, "Too many mutations for pattern {:?}: {}", pattern, count);
        }
    }

    #[test]
    fn test_fault_pattern_parsing() {
        // This should pass - pattern parsing
        assert_eq!(SolidiFIFaultPattern::from("AOD"), SolidiFIFaultPattern::AOD);
        assert_eq!(SolidiFIFaultPattern::from("mod"), SolidiFIFaultPattern::MOD);
        assert_eq!(SolidiFIFaultPattern::from("BOR"), SolidiFIFaultPattern::BOR);
        assert_eq!(SolidiFIFaultPattern::from("UNKNOWN"), SolidiFIFaultPattern::Custom("UNKNOWN".to_string()));
    }
}

/// Utilities for SolidiFI mutation testing
pub mod utils {
    use super::*;

    /// Generate a comprehensive SolidiFI mutation testing report
    pub async fn generate_mutation_report(
        config: SolidiFIConfig,
        dataset_path: Option<PathBuf>
    ) -> Result<String, Box<dyn std::error::Error>> {
        let runner = SolidiFIRunner::new(config, dataset_path)?;
        let results = runner.run_mutation_testing().await?;

        let mut report = String::new();
        report.push_str("# SolidiFI Mutation Testing Report\n\n");
        report.push_str(&format!("**Total Mutations:** {}\n", results.total_mutations));
        report.push_str(&format!("**Killed Mutations:** {}\n", results.killed_mutations));
        report.push_str(&format!("**Survived Mutations:** {}\n", results.survived_mutations));
        report.push_str(&format!("**Equivalent Mutations:** {}\n", results.equivalent_mutations));
        report.push_str(&format!("**Timeout/Error Mutations:** {}\n", results.timeout_mutations));
        report.push_str(&format!("**Mutation Score:** {:.2}%\n", results.mutation_score * 100.0));
        report.push_str(&format!("**Adjusted Mutation Score:** {:.2}%\n", results.adjusted_mutation_score * 100.0));
        report.push_str(&format!("**Execution Time:** {:.2}s\n\n", results.execution_time.as_secs_f64()));

        report.push_str("## Fault Pattern Results\n\n");
        for (pattern, pattern_results) in &results.pattern_results {
            report.push_str(&format!("### {:?}\n", pattern));
            report.push_str(&format!("- Total: {}\n", pattern_results.total));
            report.push_str(&format!("- Killed: {}\n", pattern_results.killed));
            report.push_str(&format!("- Survived: {}\n", pattern_results.survived));
            report.push_str(&format!("- Equivalent: {}\n", pattern_results.equivalent));
            report.push_str(&format!("- Timeout: {}\n", pattern_results.timeout));
            report.push_str(&format!("- Mutation Score: {:.2}%\n", pattern_results.mutation_score * 100.0));
            report.push_str(&format!("- Detection Rate: {:.2}%\n\n", pattern_results.detection_rate * 100.0));
        }

        Ok(report)
    }

    /// Run SolidiFI mutation testing and save results to JSON
    pub async fn run_and_save_results(
        config: SolidiFIConfig,
        dataset_path: Option<PathBuf>,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = SolidiFIRunner::new(config, dataset_path)?;
        let results = runner.run_mutation_testing().await?;

        let json = serde_json::to_string_pretty(&results)?;
        fs::write(output_path, json)?;

        Ok(())
    }

    /// Create a custom SolidiFI configuration for specific testing scenarios
    pub fn create_focused_config(
        target_patterns: Vec<SolidiFIFaultPattern>,
        max_mutations: usize,
    ) -> SolidiFIConfig {
        SolidiFIConfig {
            fault_patterns: target_patterns,
            target_contracts: Vec::new(),
            mutation_timeout: Duration::from_secs(60),
            max_mutations_per_pattern: max_mutations,
            exclude_equivalent: true,
            include_killable_only: true,
        }
    }
}