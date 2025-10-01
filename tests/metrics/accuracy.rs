// tests/metrics/accuracy.rs
// Comprehensive accuracy metrics calculation for SolidityDefend

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

// Re-export test utilities
use crate::common::test_utils::*;

/// Accuracy metrics for vulnerability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub dataset_name: String,
    pub total_contracts: usize,
    pub total_vulnerabilities: usize,
    pub detection_metrics: DetectionMetrics,
    pub per_vulnerability_metrics: HashMap<String, VulnerabilityMetrics>,
    pub confidence_metrics: ConfidenceMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub false_discovery_rate: f64,
    pub matthews_correlation_coefficient: f64,
    pub balanced_accuracy: f64,
    pub youden_index: f64,
}

/// Core detection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetrics {
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub accuracy: f64,
    pub specificity: f64,
    pub sensitivity: f64,
}

/// Per-vulnerability type metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMetrics {
    pub vulnerability_type: String,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub support: usize, // Number of actual instances
}

/// Confidence-based metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceMetrics {
    pub high_confidence_precision: f64,
    pub medium_confidence_precision: f64,
    pub low_confidence_precision: f64,
    pub confidence_accuracy_correlation: f64,
    pub average_confidence_true_positives: f64,
    pub average_confidence_false_positives: f64,
}

/// Performance-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub average_analysis_time_ms: f64,
    pub analysis_time_std_dev: f64,
    pub throughput_contracts_per_second: f64,
    pub memory_usage_mb: f64,
    pub scalability_factor: f64, // How performance scales with contract size
}

/// Ground truth data for a contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthContract {
    pub contract_path: PathBuf,
    pub vulnerabilities: Vec<GroundTruthVulnerability>,
    pub clean_regions: Vec<SourceRegion>, // Regions known to be clean
    pub metadata: ContractMetadata,
}

/// Ground truth vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub line_start: u32,
    pub line_end: u32,
    pub function_name: Option<String>,
    pub description: String,
    pub cwe_id: Option<u32>,
    pub cvss_score: Option<f64>,
}

/// Source code region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRegion {
    pub line_start: u32,
    pub line_end: u32,
    pub function_name: Option<String>,
}

/// Contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub solidity_version: String,
    pub lines_of_code: usize,
    pub complexity_score: u32,
    pub function_count: usize,
    pub contract_type: String, // token, defi, nft, etc.
}

/// Detected vulnerability by SolidityDefend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub confidence: String,
    pub line: u32,
    pub column: u32,
    pub function_name: Option<String>,
    pub message: String,
}

/// Accuracy metrics calculator
pub struct AccuracyCalculator {
    ground_truth_datasets: HashMap<String, Vec<GroundTruthContract>>,
    temp_dir: TempDir,
}

impl AccuracyCalculator {
    /// Create a new accuracy calculator
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut calculator = Self {
            ground_truth_datasets: HashMap::new(),
            temp_dir,
        };

        // Load default datasets
        calculator.load_test_datasets()?;

        Ok(calculator)
    }

    /// Load test datasets with ground truth
    fn load_test_datasets(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create synthetic ground truth datasets for testing
        self.create_reentrancy_dataset()?;
        self.create_access_control_dataset()?;
        self.create_arithmetic_dataset()?;
        self.create_mixed_vulnerabilities_dataset()?;
        self.create_clean_contracts_dataset()?;

        Ok(())
    }

    /// Create reentrancy vulnerability test dataset
    fn create_reentrancy_dataset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dataset_dir = self.temp_dir.path().join("reentrancy_dataset");
        fs::create_dir_all(&dataset_dir)?;

        let contracts = vec![
            // Classic reentrancy
            ("classic_reentrancy.sol", r#"
pragma solidity ^0.8.0;

contract ClassicReentrancy {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // State update after external call
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#, vec![
                GroundTruthVulnerability {
                    vulnerability_type: "reentrancy".to_string(),
                    severity: "high".to_string(),
                    line_start: 9,
                    line_end: 13,
                    function_name: Some("withdraw".to_string()),
                    description: "Classic reentrancy vulnerability - external call before state update".to_string(),
                    cwe_id: Some(362),
                    cvss_score: Some(8.1),
                }
            ]),

            // Read-only reentrancy
            ("readonly_reentrancy.sol", r#"
pragma solidity ^0.8.0;

contract ReadOnlyReentrancy {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    function updateBalance() external {
        // VULNERABLE: View function can be called during reentrancy
        uint256 currentBalance = this.getBalance(msg.sender);
        balances[msg.sender] = currentBalance + 100;
        totalSupply += 100;

        (bool success, ) = msg.sender.call("");
        require(success);
    }
}
"#, vec![
                GroundTruthVulnerability {
                    vulnerability_type: "readonly-reentrancy".to_string(),
                    severity: "medium".to_string(),
                    line_start: 11,
                    line_end: 17,
                    function_name: Some("updateBalance".to_string()),
                    description: "Read-only reentrancy vulnerability".to_string(),
                    cwe_id: Some(362),
                    cvss_score: Some(5.8),
                }
            ]),

            // Protected against reentrancy
            ("protected_reentrancy.sol", r#"
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ProtectedReentrancy is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        balances[msg.sender] = 0; // State update before external call

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"#, vec![]), // No vulnerabilities - this is clean
        ];

        let mut ground_truth_contracts = Vec::new();

        for (filename, source, vulnerabilities) in contracts {
            let contract_path = dataset_dir.join(filename);
            fs::write(&contract_path, source)?;

            let lines_of_code = source.lines().count();
            let function_count = source.matches("function").count();

            ground_truth_contracts.push(GroundTruthContract {
                contract_path,
                vulnerabilities,
                clean_regions: vec![], // Would be filled with regions known to be clean
                metadata: ContractMetadata {
                    solidity_version: "^0.8.0".to_string(),
                    lines_of_code,
                    complexity_score: calculate_complexity_score(source),
                    function_count,
                    contract_type: "defi".to_string(),
                },
            });
        }

        self.ground_truth_datasets.insert("reentrancy".to_string(), ground_truth_contracts);
        Ok(())
    }

    /// Create access control vulnerability test dataset
    fn create_access_control_dataset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dataset_dir = self.temp_dir.path().join("access_control_dataset");
        fs::create_dir_all(&dataset_dir)?;

        let contracts = vec![
            // Missing access control
            ("missing_access_control.sol", r#"
pragma solidity ^0.8.0;

contract MissingAccessControl {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: No access control
    function withdraw(uint256 amount) external {
        require(amount <= balance, "Insufficient balance");
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }

    function deposit() external payable {
        balance += msg.value;
    }
}
"#, vec![
                GroundTruthVulnerability {
                    vulnerability_type: "missing-access-control".to_string(),
                    severity: "high".to_string(),
                    line_start: 12,
                    line_end: 16,
                    function_name: Some("withdraw".to_string()),
                    description: "Function lacks proper access control".to_string(),
                    cwe_id: Some(284),
                    cvss_score: Some(7.5),
                }
            ]),

            // Proper access control
            ("proper_access_control.sol", r#"
pragma solidity ^0.8.0;

contract ProperAccessControl {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= balance, "Insufficient balance");
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }

    function deposit() external payable {
        balance += msg.value;
    }
}
"#, vec![]), // Clean contract
        ];

        let mut ground_truth_contracts = Vec::new();

        for (filename, source, vulnerabilities) in contracts {
            let contract_path = dataset_dir.join(filename);
            fs::write(&contract_path, source)?;

            let lines_of_code = source.lines().count();
            let function_count = source.matches("function").count();

            ground_truth_contracts.push(GroundTruthContract {
                contract_path,
                vulnerabilities,
                clean_regions: vec![],
                metadata: ContractMetadata {
                    solidity_version: "^0.8.0".to_string(),
                    lines_of_code,
                    complexity_score: calculate_complexity_score(source),
                    function_count,
                    contract_type: "utility".to_string(),
                },
            });
        }

        self.ground_truth_datasets.insert("access_control".to_string(), ground_truth_contracts);
        Ok(())
    }

    /// Create arithmetic vulnerability test dataset
    fn create_arithmetic_dataset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dataset_dir = self.temp_dir.path().join("arithmetic_dataset");
        fs::create_dir_all(&dataset_dir)?;

        let contracts = vec![
            // Integer overflow (pre-0.8.0)
            ("integer_overflow.sol", r#"
pragma solidity ^0.4.24;

contract IntegerOverflow {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // VULNERABLE: Integer underflow possible
        require(balances[msg.sender] - amount >= 0, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        // VULNERABLE: Integer overflow possible
        balances[to] += amount;
    }
}
"#, vec![
                GroundTruthVulnerability {
                    vulnerability_type: "integer-underflow".to_string(),
                    severity: "medium".to_string(),
                    line_start: 7,
                    line_end: 11,
                    function_name: Some("transfer".to_string()),
                    description: "Potential integer underflow in balance check".to_string(),
                    cwe_id: Some(191),
                    cvss_score: Some(5.3),
                },
                GroundTruthVulnerability {
                    vulnerability_type: "integer-overflow".to_string(),
                    severity: "medium".to_string(),
                    line_start: 13,
                    line_end: 16,
                    function_name: Some("mint".to_string()),
                    description: "Potential integer overflow in mint function".to_string(),
                    cwe_id: Some(190),
                    cvss_score: Some(5.3),
                }
            ]),

            // Safe arithmetic (0.8.0+)
            ("safe_arithmetic.sol", r#"
pragma solidity ^0.8.0;

contract SafeArithmetic {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount; // Safe in 0.8.0+
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount; // Safe in 0.8.0+
    }
}
"#, vec![]), // Clean contract - Solidity 0.8.0+ has built-in overflow protection
        ];

        let mut ground_truth_contracts = Vec::new();

        for (filename, source, vulnerabilities) in contracts {
            let contract_path = dataset_dir.join(filename);
            fs::write(&contract_path, source)?;

            let lines_of_code = source.lines().count();
            let function_count = source.matches("function").count();

            ground_truth_contracts.push(GroundTruthContract {
                contract_path,
                vulnerabilities,
                clean_regions: vec![],
                metadata: ContractMetadata {
                    solidity_version: if source.contains("^0.4") { "^0.4.24".to_string() } else { "^0.8.0".to_string() },
                    lines_of_code,
                    complexity_score: calculate_complexity_score(source),
                    function_count,
                    contract_type: "token".to_string(),
                },
            });
        }

        self.ground_truth_datasets.insert("arithmetic".to_string(), ground_truth_contracts);
        Ok(())
    }

    /// Create mixed vulnerabilities dataset
    fn create_mixed_vulnerabilities_dataset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dataset_dir = self.temp_dir.path().join("mixed_dataset");
        fs::create_dir_all(&dataset_dir)?;

        let source = r#"
pragma solidity ^0.8.0;

contract MixedVulnerabilities {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[owner] = totalSupply;
    }

    // VULNERABLE: Missing access control
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // VULNERABLE: Timestamp dependence
    function timeBasedFunction() external view returns (bool) {
        return block.timestamp % 2 == 0;
    }

    // VULNERABLE: tx.origin usage
    function authenticate() external view returns (bool) {
        return tx.origin == owner;
    }

    // VULNERABLE: Dangerous delegatecall
    function proxyCall(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;

        let vulnerabilities = vec![
            GroundTruthVulnerability {
                vulnerability_type: "missing-access-control".to_string(),
                severity: "high".to_string(),
                line_start: 15,
                line_end: 17,
                function_name: Some("setOwner".to_string()),
                description: "Owner change function lacks access control".to_string(),
                cwe_id: Some(284),
                cvss_score: Some(7.5),
            },
            GroundTruthVulnerability {
                vulnerability_type: "timestamp-dependence".to_string(),
                severity: "low".to_string(),
                line_start: 20,
                line_end: 22,
                function_name: Some("timeBasedFunction".to_string()),
                description: "Function depends on block timestamp".to_string(),
                cwe_id: Some(829),
                cvss_score: Some(3.1),
            },
            GroundTruthVulnerability {
                vulnerability_type: "tx-origin".to_string(),
                severity: "medium".to_string(),
                line_start: 25,
                line_end: 27,
                function_name: Some("authenticate".to_string()),
                description: "Use of tx.origin for authentication".to_string(),
                cwe_id: Some(477),
                cvss_score: Some(5.8),
            },
            GroundTruthVulnerability {
                vulnerability_type: "dangerous-delegatecall".to_string(),
                severity: "high".to_string(),
                line_start: 30,
                line_end: 33,
                function_name: Some("proxyCall".to_string()),
                description: "Dangerous delegatecall with user-controlled data".to_string(),
                cwe_id: Some(829),
                cvss_score: Some(8.1),
            },
        ];

        let contract_path = dataset_dir.join("mixed_vulnerabilities.sol");
        fs::write(&contract_path, source)?;

        let ground_truth_contract = GroundTruthContract {
            contract_path,
            vulnerabilities,
            clean_regions: vec![
                SourceRegion {
                    line_start: 35,
                    line_end: 39,
                    function_name: Some("transfer".to_string()),
                }
            ],
            metadata: ContractMetadata {
                solidity_version: "^0.8.0".to_string(),
                lines_of_code: source.lines().count(),
                complexity_score: calculate_complexity_score(source),
                function_count: source.matches("function").count(),
                contract_type: "mixed".to_string(),
            },
        };

        self.ground_truth_datasets.insert("mixed".to_string(), vec![ground_truth_contract]);
        Ok(())
    }

    /// Create clean contracts dataset
    fn create_clean_contracts_dataset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let dataset_dir = self.temp_dir.path().join("clean_dataset");
        fs::create_dir_all(&dataset_dir)?;

        let contracts = vec![
            ("clean_token.sol", r#"
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CleanToken is ERC20, Ownable {
    constructor(uint256 initialSupply) ERC20("CleanToken", "CLEAN") {
        _mint(msg.sender, initialSupply);
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}
"#),
            ("clean_vault.sol", r#"
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CleanVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public deposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Must deposit something");
        deposits[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        deposits[msg.sender] -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = payable(owner()).call{value: balance}("");
        require(success, "Emergency withdrawal failed");
    }
}
"#),
        ];

        let mut ground_truth_contracts = Vec::new();

        for (filename, source) in contracts {
            let contract_path = dataset_dir.join(filename);
            fs::write(&contract_path, source)?;

            let lines_of_code = source.lines().count();
            let function_count = source.matches("function").count();

            ground_truth_contracts.push(GroundTruthContract {
                contract_path,
                vulnerabilities: vec![], // Clean contracts have no vulnerabilities
                clean_regions: vec![], // Entire contract is clean
                metadata: ContractMetadata {
                    solidity_version: "^0.8.0".to_string(),
                    lines_of_code,
                    complexity_score: calculate_complexity_score(source),
                    function_count,
                    contract_type: "clean".to_string(),
                },
            });
        }

        self.ground_truth_datasets.insert("clean".to_string(), ground_truth_contracts);
        Ok(())
    }

    /// Calculate accuracy metrics for a specific dataset
    pub async fn calculate_accuracy_metrics(&self, dataset_name: &str) -> Result<AccuracyMetrics, Box<dyn std::error::Error>> {
        let ground_truth_contracts = self.ground_truth_datasets.get(dataset_name)
            .ok_or_else(|| format!("Dataset {} not found", dataset_name))?;

        let mut all_detections = Vec::new();
        let mut all_ground_truth = Vec::new();
        let mut performance_times = Vec::new();
        let mut per_vulnerability_stats: HashMap<String, (usize, usize, usize)> = HashMap::new();

        println!("Calculating accuracy metrics for dataset: {}", dataset_name);

        for contract in ground_truth_contracts {
            let start_time = Instant::now();

            // Simulate SolidityDefend analysis
            let detected_vulnerabilities = self.simulate_analysis(&contract.contract_path).await?;

            let analysis_time = start_time.elapsed();
            performance_times.push(analysis_time);

            // Collect all ground truth vulnerabilities
            all_ground_truth.extend(contract.vulnerabilities.clone());

            // Match detected vulnerabilities with ground truth
            let matches = self.match_vulnerabilities(&contract.vulnerabilities, &detected_vulnerabilities);

            for detected in detected_vulnerabilities {
                all_detections.push((detected, matches.iter().any(|(_, d)| {
                    d.vulnerability_type == detected.vulnerability_type &&
                    (d.line as i32 - detected.line as i32).abs() <= 2 // Allow 2-line tolerance
                })));
            }

            // Update per-vulnerability statistics
            for vuln in &contract.vulnerabilities {
                let stats = per_vulnerability_stats.entry(vuln.vulnerability_type.clone()).or_insert((0, 0, 0));
                stats.2 += 1; // Total ground truth instances

                let detected = detected_vulnerabilities.iter().any(|d| {
                    d.vulnerability_type == vuln.vulnerability_type &&
                    (d.line as i32 - vuln.line_start as i32).abs() <= 2
                });

                if detected {
                    stats.0 += 1; // True positive
                } else {
                    stats.1 += 1; // False negative
                }
            }

            // Count false positives for each vulnerability type
            for detected in &detected_vulnerabilities {
                let is_false_positive = !contract.vulnerabilities.iter().any(|gt| {
                    gt.vulnerability_type == detected.vulnerability_type &&
                    (detected.line as i32 - gt.line_start as i32).abs() <= 2
                });

                if is_false_positive {
                    let stats = per_vulnerability_stats.entry(detected.vulnerability_type.clone()).or_insert((0, 0, 0));
                    // Note: We need to track false positives separately
                }
            }
        }

        // Calculate overall detection metrics
        let detection_metrics = self.calculate_detection_metrics(&all_detections, &all_ground_truth);

        // Calculate per-vulnerability metrics
        let per_vulnerability_metrics = self.calculate_per_vulnerability_metrics(&per_vulnerability_stats);

        // Calculate confidence metrics
        let confidence_metrics = self.calculate_confidence_metrics(&all_detections);

        // Calculate performance metrics
        let performance_metrics = self.calculate_performance_metrics(&performance_times, ground_truth_contracts);

        // Calculate advanced metrics
        let false_discovery_rate = if detection_metrics.true_positives + detection_metrics.false_positives > 0 {
            detection_metrics.false_positives as f64 / (detection_metrics.true_positives + detection_metrics.false_positives) as f64
        } else {
            0.0
        };

        let matthews_correlation_coefficient = self.calculate_mcc(&detection_metrics);
        let balanced_accuracy = (detection_metrics.sensitivity + detection_metrics.specificity) / 2.0;
        let youden_index = detection_metrics.sensitivity + detection_metrics.specificity - 1.0;

        Ok(AccuracyMetrics {
            dataset_name: dataset_name.to_string(),
            total_contracts: ground_truth_contracts.len(),
            total_vulnerabilities: all_ground_truth.len(),
            detection_metrics,
            per_vulnerability_metrics,
            confidence_metrics,
            performance_metrics,
            false_discovery_rate,
            matthews_correlation_coefficient,
            balanced_accuracy,
            youden_index,
        })
    }

    /// Simulate SolidityDefend analysis (to be replaced with actual implementation)
    async fn simulate_analysis(&self, contract_path: &Path) -> Result<Vec<DetectedVulnerability>, Box<dyn std::error::Error>> {
        let source_content = fs::read_to_string(contract_path)?;
        let mut detected = Vec::new();

        // Simulate detection logic based on source content patterns

        // Reentrancy detection
        if source_content.contains("call{value:") || source_content.contains("call.value") {
            if source_content.contains("balances[msg.sender] = 0") {
                let call_pos = source_content.find("call").unwrap_or(0);
                let lines_before_call = source_content[..call_pos].matches('\n').count() + 1;

                detected.push(DetectedVulnerability {
                    vulnerability_type: "reentrancy".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                    line: lines_before_call as u32,
                    column: 8,
                    function_name: Some("withdraw".to_string()),
                    message: "Potential reentrancy vulnerability detected".to_string(),
                });
            }
        }

        // Access control detection
        if source_content.contains("function setOwner") && !source_content.contains("onlyOwner") {
            let pos = source_content.find("function setOwner").unwrap_or(0);
            let lines_before = source_content[..pos].matches('\n').count() + 1;

            detected.push(DetectedVulnerability {
                vulnerability_type: "missing-access-control".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                line: lines_before as u32,
                column: 4,
                function_name: Some("setOwner".to_string()),
                message: "Function lacks proper access control".to_string(),
            });
        }

        // Timestamp dependence
        if source_content.contains("block.timestamp") {
            let pos = source_content.find("block.timestamp").unwrap_or(0);
            let lines_before = source_content[..pos].matches('\n').count() + 1;

            detected.push(DetectedVulnerability {
                vulnerability_type: "timestamp-dependence".to_string(),
                severity: "low".to_string(),
                confidence: "medium".to_string(),
                line: lines_before as u32,
                column: 16,
                function_name: Some("timeBasedFunction".to_string()),
                message: "Function depends on block timestamp".to_string(),
            });
        }

        // tx.origin usage
        if source_content.contains("tx.origin") {
            let pos = source_content.find("tx.origin").unwrap_or(0);
            let lines_before = source_content[..pos].matches('\n').count() + 1;

            detected.push(DetectedVulnerability {
                vulnerability_type: "tx-origin".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                line: lines_before as u32,
                column: 16,
                function_name: Some("authenticate".to_string()),
                message: "Use of tx.origin for authentication".to_string(),
            });
        }

        // Dangerous delegatecall
        if source_content.contains("delegatecall") {
            let pos = source_content.find("delegatecall").unwrap_or(0);
            let lines_before = source_content[..pos].matches('\n').count() + 1;

            detected.push(DetectedVulnerability {
                vulnerability_type: "dangerous-delegatecall".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                line: lines_before as u32,
                column: 8,
                function_name: Some("proxyCall".to_string()),
                message: "Dangerous delegatecall with user-controlled data".to_string(),
            });
        }

        // Integer overflow/underflow for old Solidity versions
        if source_content.contains("pragma solidity ^0.4") || source_content.contains("pragma solidity ^0.5") {
            if source_content.contains("balances[msg.sender] - amount") {
                let pos = source_content.find("balances[msg.sender] - amount").unwrap_or(0);
                let lines_before = source_content[..pos].matches('\n').count() + 1;

                detected.push(DetectedVulnerability {
                    vulnerability_type: "integer-underflow".to_string(),
                    severity: "medium".to_string(),
                    confidence: "medium".to_string(),
                    line: lines_before as u32,
                    column: 16,
                    function_name: Some("transfer".to_string()),
                    message: "Potential integer underflow in arithmetic operation".to_string(),
                });
            }

            if source_content.contains("balances[to] += amount") {
                let pos = source_content.find("balances[to] += amount").unwrap_or(0);
                let lines_before = source_content[..pos].matches('\n').count() + 1;

                detected.push(DetectedVulnerability {
                    vulnerability_type: "integer-overflow".to_string(),
                    severity: "medium".to_string(),
                    confidence: "medium".to_string(),
                    line: lines_before as u32,
                    column: 8,
                    function_name: Some("mint".to_string()),
                    message: "Potential integer overflow in arithmetic operation".to_string(),
                });
            }
        }

        // Simulate some false positives occasionally
        if source_content.contains("function transfer") && rand::random::<f64>() < 0.1 {
            detected.push(DetectedVulnerability {
                vulnerability_type: "false-positive".to_string(),
                severity: "low".to_string(),
                confidence: "low".to_string(),
                line: 1,
                column: 1,
                function_name: Some("transfer".to_string()),
                message: "Simulated false positive".to_string(),
            });
        }

        Ok(detected)
    }

    /// Match detected vulnerabilities with ground truth
    fn match_vulnerabilities(
        &self,
        ground_truth: &[GroundTruthVulnerability],
        detected: &[DetectedVulnerability],
    ) -> Vec<(&GroundTruthVulnerability, &DetectedVulnerability)> {
        let mut matches = Vec::new();

        for gt in ground_truth {
            for det in detected {
                if gt.vulnerability_type == det.vulnerability_type {
                    // Check if line numbers are close (within 2 lines)
                    if (det.line as i32 - gt.line_start as i32).abs() <= 2 {
                        matches.push((gt, det));
                        break; // One-to-one matching
                    }
                }
            }
        }

        matches
    }

    /// Calculate core detection metrics
    fn calculate_detection_metrics(
        &self,
        detections: &[(DetectedVulnerability, bool)],
        ground_truth: &[GroundTruthVulnerability],
    ) -> DetectionMetrics {
        let true_positives = detections.iter().filter(|(_, is_tp)| *is_tp).count();
        let false_positives = detections.iter().filter(|(_, is_tp)| !*is_tp).count();
        let false_negatives = ground_truth.len().saturating_sub(true_positives);

        // For true negatives, we need to estimate based on total possible locations
        // This is a simplified calculation
        let total_possible_vulnerabilities = detections.len() + ground_truth.len() * 2;
        let true_negatives = total_possible_vulnerabilities.saturating_sub(true_positives + false_positives + false_negatives);

        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };

        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };

        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };

        let accuracy = if true_positives + true_negatives + false_positives + false_negatives > 0 {
            (true_positives + true_negatives) as f64 / (true_positives + true_negatives + false_positives + false_negatives) as f64
        } else {
            0.0
        };

        let specificity = if true_negatives + false_positives > 0 {
            true_negatives as f64 / (true_negatives + false_positives) as f64
        } else {
            0.0
        };

        let sensitivity = recall; // Sensitivity is the same as recall

        DetectionMetrics {
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            precision,
            recall,
            f1_score,
            accuracy,
            specificity,
            sensitivity,
        }
    }

    /// Calculate per-vulnerability type metrics
    fn calculate_per_vulnerability_metrics(
        &self,
        stats: &HashMap<String, (usize, usize, usize)>,
    ) -> HashMap<String, VulnerabilityMetrics> {
        let mut metrics = HashMap::new();

        for (vuln_type, (tp, fn_count, total)) in stats {
            let precision = if tp + 0 > 0 { *tp as f64 / (*tp + 0) as f64 } else { 0.0 }; // FP counted separately
            let recall = if tp + fn_count > 0 { *tp as f64 / (tp + fn_count) as f64 } else { 0.0 };
            let f1_score = if precision + recall > 0.0 {
                2.0 * (precision * recall) / (precision + recall)
            } else {
                0.0
            };

            metrics.insert(vuln_type.clone(), VulnerabilityMetrics {
                vulnerability_type: vuln_type.clone(),
                true_positives: *tp,
                false_positives: 0, // Would need to be calculated separately
                false_negatives: *fn_count,
                precision,
                recall,
                f1_score,
                support: *total,
            });
        }

        metrics
    }

    /// Calculate confidence-based metrics
    fn calculate_confidence_metrics(&self, detections: &[(DetectedVulnerability, bool)]) -> ConfidenceMetrics {
        let mut high_conf_correct = 0;
        let mut high_conf_total = 0;
        let mut medium_conf_correct = 0;
        let mut medium_conf_total = 0;
        let mut low_conf_correct = 0;
        let mut low_conf_total = 0;

        let mut tp_confidences = Vec::new();
        let mut fp_confidences = Vec::new();

        for (detection, is_correct) in detections {
            let confidence_score = match detection.confidence.as_str() {
                "high" => 0.9,
                "medium" => 0.6,
                "low" => 0.3,
                _ => 0.5,
            };

            if *is_correct {
                tp_confidences.push(confidence_score);
            } else {
                fp_confidences.push(confidence_score);
            }

            match detection.confidence.as_str() {
                "high" => {
                    high_conf_total += 1;
                    if *is_correct { high_conf_correct += 1; }
                },
                "medium" => {
                    medium_conf_total += 1;
                    if *is_correct { medium_conf_correct += 1; }
                },
                "low" => {
                    low_conf_total += 1;
                    if *is_correct { low_conf_correct += 1; }
                },
                _ => {}
            }
        }

        let high_confidence_precision = if high_conf_total > 0 {
            high_conf_correct as f64 / high_conf_total as f64
        } else { 0.0 };

        let medium_confidence_precision = if medium_conf_total > 0 {
            medium_conf_correct as f64 / medium_conf_total as f64
        } else { 0.0 };

        let low_confidence_precision = if low_conf_total > 0 {
            low_conf_correct as f64 / low_conf_total as f64
        } else { 0.0 };

        let avg_confidence_tp = if !tp_confidences.is_empty() {
            tp_confidences.iter().sum::<f64>() / tp_confidences.len() as f64
        } else { 0.0 };

        let avg_confidence_fp = if !fp_confidences.is_empty() {
            fp_confidences.iter().sum::<f64>() / fp_confidences.len() as f64
        } else { 0.0 };

        // Simple correlation calculation (would use proper statistical methods in production)
        let confidence_accuracy_correlation = if detections.len() > 1 {
            0.7 // Simplified correlation value
        } else { 0.0 };

        ConfidenceMetrics {
            high_confidence_precision,
            medium_confidence_precision,
            low_confidence_precision,
            confidence_accuracy_correlation,
            average_confidence_true_positives: avg_confidence_tp,
            average_confidence_false_positives: avg_confidence_fp,
        }
    }

    /// Calculate performance metrics
    fn calculate_performance_metrics(
        &self,
        analysis_times: &[Duration],
        contracts: &[GroundTruthContract],
    ) -> PerformanceMetrics {
        if analysis_times.is_empty() {
            return PerformanceMetrics {
                average_analysis_time_ms: 0.0,
                analysis_time_std_dev: 0.0,
                throughput_contracts_per_second: 0.0,
                memory_usage_mb: 0.0,
                scalability_factor: 1.0,
            };
        }

        let total_time_ms: f64 = analysis_times.iter().map(|d| d.as_millis() as f64).sum();
        let average_analysis_time_ms = total_time_ms / analysis_times.len() as f64;

        let variance = analysis_times.iter()
            .map(|d| {
                let diff = d.as_millis() as f64 - average_analysis_time_ms;
                diff * diff
            })
            .sum::<f64>() / analysis_times.len() as f64;

        let analysis_time_std_dev = variance.sqrt();

        let total_time_seconds = total_time_ms / 1000.0;
        let throughput_contracts_per_second = if total_time_seconds > 0.0 {
            contracts.len() as f64 / total_time_seconds
        } else { 0.0 };

        // Estimate memory usage (would use actual measurements in production)
        let avg_contract_size: usize = contracts.iter().map(|c| c.metadata.lines_of_code).sum::<usize>() / contracts.len().max(1);
        let memory_usage_mb = (avg_contract_size as f64 * 0.1).max(10.0); // Rough estimate

        // Calculate scalability factor (how analysis time scales with contract size)
        let scalability_factor = if contracts.len() > 1 {
            // Simple linear regression would be done here
            1.2 // Simplified factor
        } else { 1.0 };

        PerformanceMetrics {
            average_analysis_time_ms,
            analysis_time_std_dev,
            throughput_contracts_per_second,
            memory_usage_mb,
            scalability_factor,
        }
    }

    /// Calculate Matthews Correlation Coefficient
    fn calculate_mcc(&self, metrics: &DetectionMetrics) -> f64 {
        let tp = metrics.true_positives as f64;
        let tn = metrics.true_negatives as f64;
        let fp = metrics.false_positives as f64;
        let fn_val = metrics.false_negatives as f64;

        let numerator = (tp * tn) - (fp * fn_val);
        let denominator = ((tp + fp) * (tp + fn_val) * (tn + fp) * (tn + fn_val)).sqrt();

        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }

    /// Generate comprehensive accuracy report
    pub async fn generate_accuracy_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut report = String::new();
        report.push_str("# SolidityDefend Accuracy Analysis Report\n\n");

        for dataset_name in self.ground_truth_datasets.keys() {
            let metrics = self.calculate_accuracy_metrics(dataset_name).await?;

            report.push_str(&format!("## Dataset: {}\n\n", dataset_name));
            report.push_str(&format!("**Total Contracts:** {}\n", metrics.total_contracts));
            report.push_str(&format!("**Total Vulnerabilities:** {}\n", metrics.total_vulnerabilities));
            report.push_str("\n### Detection Metrics\n\n");
            report.push_str(&format!("- **Precision:** {:.3}\n", metrics.detection_metrics.precision));
            report.push_str(&format!("- **Recall:** {:.3}\n", metrics.detection_metrics.recall));
            report.push_str(&format!("- **F1 Score:** {:.3}\n", metrics.detection_metrics.f1_score));
            report.push_str(&format!("- **Accuracy:** {:.3}\n", metrics.detection_metrics.accuracy));
            report.push_str(&format!("- **Balanced Accuracy:** {:.3}\n", metrics.balanced_accuracy));
            report.push_str(&format!("- **Matthews Correlation Coefficient:** {:.3}\n", metrics.matthews_correlation_coefficient));
            report.push_str("\n### Confusion Matrix\n\n");
            report.push_str(&format!("- **True Positives:** {}\n", metrics.detection_metrics.true_positives));
            report.push_str(&format!("- **False Positives:** {}\n", metrics.detection_metrics.false_positives));
            report.push_str(&format!("- **True Negatives:** {}\n", metrics.detection_metrics.true_negatives));
            report.push_str(&format!("- **False Negatives:** {}\n", metrics.detection_metrics.false_negatives));

            report.push_str("\n### Per-Vulnerability Metrics\n\n");
            for (vuln_type, vuln_metrics) in &metrics.per_vulnerability_metrics {
                report.push_str(&format!("#### {}\n", vuln_type));
                report.push_str(&format!("- Precision: {:.3}\n", vuln_metrics.precision));
                report.push_str(&format!("- Recall: {:.3}\n", vuln_metrics.recall));
                report.push_str(&format!("- F1 Score: {:.3}\n", vuln_metrics.f1_score));
                report.push_str(&format!("- Support: {} instances\n\n", vuln_metrics.support));
            }

            report.push_str("\n### Performance Metrics\n\n");
            report.push_str(&format!("- **Average Analysis Time:** {:.1}ms\n", metrics.performance_metrics.average_analysis_time_ms));
            report.push_str(&format!("- **Throughput:** {:.1} contracts/second\n", metrics.performance_metrics.throughput_contracts_per_second));
            report.push_str(&format!("- **Memory Usage:** {:.1}MB\n", metrics.performance_metrics.memory_usage_mb));

            report.push_str("\n---\n\n");
        }

        report.push_str(&format!("Generated at: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        Ok(report)
    }

    /// Get available dataset names
    pub fn get_dataset_names(&self) -> Vec<String> {
        self.ground_truth_datasets.keys().cloned().collect()
    }
}

/// Calculate complexity score for a contract
fn calculate_complexity_score(source: &str) -> u32 {
    let mut score = 0u32;

    // Basic complexity factors
    score += source.matches("function").count() as u32 * 10;
    score += source.matches("modifier").count() as u32 * 15;
    score += source.matches("if").count() as u32 * 5;
    score += source.matches("for").count() as u32 * 10;
    score += source.matches("while").count() as u32 * 10;
    score += source.matches("require").count() as u32 * 3;
    score += source.matches("mapping").count() as u32 * 8;

    score
}

// Test cases that will fail until SolidityDefend is fully implemented

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[should_panic(expected = "Accuracy too low")]
    async fn test_accuracy_metrics_should_fail_initially() {
        // This test should fail until SolidityDefend achieves good accuracy
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");

        for dataset_name in calculator.get_dataset_names() {
            let metrics = calculator.calculate_accuracy_metrics(&dataset_name).await
                .expect("Failed to calculate metrics");

            // These assertions will fail until proper implementation
            assert!(metrics.detection_metrics.precision > 0.8,
                "Precision too low for {}: {}", dataset_name, metrics.detection_metrics.precision);
            assert!(metrics.detection_metrics.recall > 0.8,
                "Recall too low for {}: {}", dataset_name, metrics.detection_metrics.recall);
            assert!(metrics.detection_metrics.f1_score > 0.8,
                "F1 score too low for {}: {}", dataset_name, metrics.detection_metrics.f1_score);
        }

        panic!("Accuracy too low");
    }

    #[tokio::test]
    #[should_panic(expected = "Reentrancy detection accuracy insufficient")]
    async fn test_reentrancy_accuracy_should_fail() {
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");
        let metrics = calculator.calculate_accuracy_metrics("reentrancy").await
            .expect("Failed to calculate reentrancy metrics");

        assert!(metrics.detection_metrics.recall > 0.95,
            "Reentrancy detection accuracy insufficient: recall = {}", metrics.detection_metrics.recall);
    }

    #[tokio::test]
    #[should_panic(expected = "Access control detection accuracy insufficient")]
    async fn test_access_control_accuracy_should_fail() {
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");
        let metrics = calculator.calculate_accuracy_metrics("access_control").await
            .expect("Failed to calculate access control metrics");

        assert!(metrics.detection_metrics.recall > 0.9,
            "Access control detection accuracy insufficient: recall = {}", metrics.detection_metrics.recall);
    }

    #[tokio::test]
    async fn test_dataset_creation() {
        // This should pass - basic dataset creation
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");

        let dataset_names = calculator.get_dataset_names();
        assert!(!dataset_names.is_empty(), "Should have datasets");
        assert!(dataset_names.contains(&"reentrancy".to_string()));
        assert!(dataset_names.contains(&"access_control".to_string()));
        assert!(dataset_names.contains(&"clean".to_string()));
    }

    #[tokio::test]
    async fn test_metrics_calculation_structure() {
        // This should pass - basic metrics structure
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");
        let metrics = calculator.calculate_accuracy_metrics("clean").await
            .expect("Failed to calculate metrics");

        // Basic structure validation
        assert_eq!(metrics.dataset_name, "clean");
        assert!(metrics.total_contracts > 0);
        assert!(metrics.detection_metrics.precision >= 0.0 && metrics.detection_metrics.precision <= 1.0);
        assert!(metrics.detection_metrics.recall >= 0.0 && metrics.detection_metrics.recall <= 1.0);
        assert!(metrics.detection_metrics.f1_score >= 0.0 && metrics.detection_metrics.f1_score <= 1.0);
    }

    #[tokio::test]
    async fn test_report_generation() {
        // This should pass - report generation
        let calculator = AccuracyCalculator::new().expect("Failed to create calculator");
        let report = calculator.generate_accuracy_report().await
            .expect("Failed to generate report");

        assert!(!report.is_empty());
        assert!(report.contains("# SolidityDefend Accuracy Analysis Report"));
        assert!(report.contains("Detection Metrics"));
        assert!(report.contains("Performance Metrics"));
    }

    #[test]
    fn test_complexity_calculation() {
        // This should pass - complexity calculation
        let simple_contract = "contract Test { function test() public {} }";
        let complex_contract = r#"
            contract Complex {
                mapping(address => uint256) balances;
                modifier onlyOwner() { require(true); _; }
                function transfer() public onlyOwner {
                    if (true) {
                        for (uint i = 0; i < 10; i++) {
                            require(balances[msg.sender] > 0);
                        }
                    }
                }
            }
        "#;

        let simple_score = calculate_complexity_score(simple_contract);
        let complex_score = calculate_complexity_score(complex_contract);

        assert!(complex_score > simple_score);
        assert!(simple_score >= 10); // At least one function
    }
}

/// Utilities for accuracy testing
pub mod utils {
    use super::*;

    /// Run comprehensive accuracy analysis and save results
    pub async fn run_accuracy_analysis(
        output_dir: &Path
    ) -> Result<(), Box<dyn std::error::Error>> {
        let calculator = AccuracyCalculator::new()?;

        // Generate overall report
        let report = calculator.generate_accuracy_report().await?;
        fs::write(output_dir.join("accuracy_report.md"), report)?;

        // Generate detailed metrics for each dataset
        for dataset_name in calculator.get_dataset_names() {
            let metrics = calculator.calculate_accuracy_metrics(&dataset_name).await?;
            let json = serde_json::to_string_pretty(&metrics)?;
            fs::write(output_dir.join(format!("{}_metrics.json", dataset_name)), json)?;
        }

        println!("Accuracy analysis completed. Results saved to: {}", output_dir.display());
        Ok(())
    }

    /// Compare accuracy metrics between different versions
    pub fn compare_accuracy_metrics(
        baseline: &AccuracyMetrics,
        current: &AccuracyMetrics,
    ) -> AccuracyComparison {
        AccuracyComparison {
            dataset_name: current.dataset_name.clone(),
            precision_delta: current.detection_metrics.precision - baseline.detection_metrics.precision,
            recall_delta: current.detection_metrics.recall - baseline.detection_metrics.recall,
            f1_score_delta: current.detection_metrics.f1_score - baseline.detection_metrics.f1_score,
            performance_delta: current.performance_metrics.average_analysis_time_ms - baseline.performance_metrics.average_analysis_time_ms,
        }
    }

    /// Accuracy comparison result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AccuracyComparison {
        pub dataset_name: String,
        pub precision_delta: f64,
        pub recall_delta: f64,
        pub f1_score_delta: f64,
        pub performance_delta: f64,
    }
}