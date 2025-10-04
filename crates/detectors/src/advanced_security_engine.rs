use crate::defi::{
    FlashLoanDetector, MEVDetector, PriceManipulationDetector,
    LiquidityAttackDetector, GovernanceAttackDetector, DeFiDetector
};
use crate::cross_contract::{CrossContractAnalyzer, CrossContractContext, CrossContractConfig};
use crate::taint::{TaintAnalyzer, TaintAnalysisConfig};
use crate::types::{DetectorResult, AnalysisContext, Severity};
use std::collections::HashMap;

/// Advanced security analysis engine combining DeFi, cross-contract, and taint analysis
pub struct AdvancedSecurityEngine {
    defi_detectors: Vec<Box<dyn DeFiDetector>>,
    cross_contract_analyzer: CrossContractAnalyzer,
    taint_analyzer: TaintAnalyzer,
    config: AdvancedSecurityConfig,
}

/// Configuration for advanced security analysis
#[derive(Debug, Clone)]
pub struct AdvancedSecurityConfig {
    pub enable_defi_analysis: bool,
    pub enable_cross_contract_analysis: bool,
    pub enable_taint_analysis: bool,
    pub cross_contract_config: CrossContractConfig,
    pub taint_config: TaintAnalysisConfig,
    pub severity_threshold: Severity,
}

impl Default for AdvancedSecurityConfig {
    fn default() -> Self {
        Self {
            enable_defi_analysis: true,
            enable_cross_contract_analysis: true,
            enable_taint_analysis: true,
            cross_contract_config: CrossContractConfig::default(),
            taint_config: TaintAnalysisConfig::default(),
            severity_threshold: Severity::Low,
        }
    }
}

/// Comprehensive analysis result
#[derive(Debug, Clone)]
pub struct AdvancedAnalysisResult {
    pub defi_findings: Vec<DetectorResult>,
    pub cross_contract_findings: Vec<crate::cross_contract::CrossContractFinding>,
    pub taint_findings: Vec<crate::taint::TaintFinding>,
    pub integrated_findings: Vec<IntegratedFinding>,
    pub risk_assessment: RiskAssessment,
    pub recommendations: Vec<SecurityRecommendation>,
}

/// Integrated finding combining multiple analysis types
#[derive(Debug, Clone)]
pub struct IntegratedFinding {
    pub finding_id: String,
    pub primary_vulnerability: String,
    pub contributing_factors: Vec<String>,
    pub severity: Severity,
    pub confidence: f64,
    pub affected_components: Vec<String>,
    pub attack_scenarios: Vec<AttackScenario>,
    pub mitigation_strategies: Vec<String>,
}

/// Attack scenario description
#[derive(Debug, Clone)]
pub struct AttackScenario {
    pub scenario_id: String,
    pub description: String,
    pub attack_vector: String,
    pub prerequisites: Vec<String>,
    pub impact: String,
    pub likelihood: f64,
}

/// Overall risk assessment
#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub overall_risk_score: f64,
    pub critical_vulnerabilities: usize,
    pub high_risk_components: Vec<String>,
    pub systemic_risks: Vec<String>,
    pub compliance_issues: Vec<String>,
}

/// Security recommendation
#[derive(Debug, Clone)]
pub struct SecurityRecommendation {
    pub category: RecommendationCategory,
    pub priority: Priority,
    pub description: String,
    pub implementation_effort: ImplementationEffort,
    pub business_impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecommendationCategory {
    CodeFix,
    ArchitecturalChange,
    AccessControl,
    Monitoring,
    Testing,
    Documentation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImplementationEffort {
    Low,     // < 1 day
    Medium,  // 1-5 days
    High,    // 1-2 weeks
    VeryHigh, // > 2 weeks
}

impl AdvancedSecurityEngine {
    pub fn new(config: AdvancedSecurityConfig) -> Self {
        let mut defi_detectors: Vec<Box<dyn DeFiDetector>> = Vec::new();

        // Add DeFi detectors
        defi_detectors.push(Box::new(FlashLoanDetector));
        defi_detectors.push(Box::new(MEVDetector));
        defi_detectors.push(Box::new(PriceManipulationDetector));
        defi_detectors.push(Box::new(LiquidityAttackDetector));
        defi_detectors.push(Box::new(GovernanceAttackDetector));

        let cross_contract_analyzer = CrossContractAnalyzer::new();
        let taint_analyzer = TaintAnalyzer::new(config.taint_config.clone());

        Self {
            defi_detectors,
            cross_contract_analyzer,
            taint_analyzer,
            config,
        }
    }

    /// Run comprehensive advanced security analysis
    pub fn analyze_comprehensive(&mut self, contexts: HashMap<String, &AnalysisContext>) -> AdvancedAnalysisResult {
        let mut result = AdvancedAnalysisResult {
            defi_findings: Vec::new(),
            cross_contract_findings: Vec::new(),
            taint_findings: Vec::new(),
            integrated_findings: Vec::new(),
            risk_assessment: RiskAssessment {
                overall_risk_score: 0.0,
                critical_vulnerabilities: 0,
                high_risk_components: Vec::new(),
                systemic_risks: Vec::new(),
                compliance_issues: Vec::new(),
            },
            recommendations: Vec::new(),
        };

        // Run DeFi-specific analysis
        if self.config.enable_defi_analysis {
            result.defi_findings = self.run_defi_analysis(&contexts);
        }

        // Run cross-contract analysis
        if self.config.enable_cross_contract_analysis && contexts.len() > 1 {
            result.cross_contract_findings = self.run_cross_contract_analysis(&contexts);
        }

        // Run taint analysis
        if self.config.enable_taint_analysis {
            result.taint_findings = self.run_taint_analysis(&contexts);
        }

        // Integrate findings
        result.integrated_findings = self.integrate_findings(&result);

        // Assess overall risk
        result.risk_assessment = self.assess_risk(&result);

        // Generate recommendations
        result.recommendations = self.generate_recommendations(&result);

        result
    }

    /// Run DeFi-specific vulnerability detection
    fn run_defi_analysis(&self, contexts: &HashMap<String, &AnalysisContext>) -> Vec<DetectorResult> {
        let mut all_findings = Vec::new();

        for (_contract_name, context) in contexts {
            for detector in &self.defi_detectors {
                if detector.applies_to_contract(context) {
                    let findings = detector.detect_defi_vulnerabilities(context);
                    all_findings.extend(findings);
                }
            }
        }

        // Filter by severity threshold
        all_findings.retain(|finding| {
            self.severity_meets_threshold(&finding.finding.severity)
        });

        all_findings
    }

    /// Run cross-contract vulnerability analysis
    fn run_cross_contract_analysis(&self, contexts: &HashMap<String, &AnalysisContext>) -> Vec<crate::cross_contract::CrossContractFinding> {
        let mut cross_contract_context = CrossContractContext::new(contexts.clone())
            .with_config(self.config.cross_contract_config.clone());

        cross_contract_context.build_interaction_graph();
        cross_contract_context.detect_protocol_patterns();

        self.cross_contract_analyzer.analyze(&cross_contract_context)
    }

    /// Run taint analysis across contracts
    fn run_taint_analysis(&mut self, contexts: &HashMap<String, &AnalysisContext>) -> Vec<crate::taint::TaintFinding> {
        let mut all_taint_findings = Vec::new();

        for (_contract_name, context) in contexts {
            let analysis_result = self.taint_analyzer.analyze(context);
            all_taint_findings.extend(analysis_result.findings);
        }

        all_taint_findings
    }

    /// Integrate findings from different analysis types
    fn integrate_findings(&self, result: &AdvancedAnalysisResult) -> Vec<IntegratedFinding> {
        let mut integrated = Vec::new();

        // Look for patterns across different finding types
        integrated.extend(self.detect_flash_loan_mev_combinations(result));
        integrated.extend(self.detect_cross_contract_taint_flows(result));
        integrated.extend(self.detect_governance_manipulation_chains(result));
        integrated.extend(self.detect_liquidity_oracle_attacks(result));

        integrated
    }

    /// Detect flash loan + MEV attack combinations
    fn detect_flash_loan_mev_combinations(&self, result: &AdvancedAnalysisResult) -> Vec<IntegratedFinding> {
        let mut findings = Vec::new();

        let flash_loan_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("flash-loan"))
            .collect();

        let mev_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("mev"))
            .collect();

        if !flash_loan_findings.is_empty() && !mev_findings.is_empty() {
            findings.push(IntegratedFinding {
                finding_id: "INTEGRATED_FLASH_MEV_001".to_string(),
                primary_vulnerability: "Flash Loan + MEV Attack Combination".to_string(),
                contributing_factors: vec![
                    "Flash loan vulnerability present".to_string(),
                    "MEV extraction opportunities available".to_string(),
                    "Price manipulation possible".to_string(),
                ],
                severity: Severity::Critical,
                confidence: 0.85,
                affected_components: vec!["Flash loan functions".to_string(), "Price-dependent logic".to_string()],
                attack_scenarios: vec![
                    AttackScenario {
                        scenario_id: "FLASH_MEV_ARBITRAGE".to_string(),
                        description: "Attacker uses flash loans to manipulate prices and extract MEV through arbitrage".to_string(),
                        attack_vector: "Flash loan → Price manipulation → MEV extraction → Repay loan".to_string(),
                        prerequisites: vec![
                            "Access to flash loan providers".to_string(),
                            "Price-dependent contract logic".to_string(),
                            "Arbitrage opportunities".to_string(),
                        ],
                        impact: "Significant value extraction from protocol and users".to_string(),
                        likelihood: 0.7,
                    }
                ],
                mitigation_strategies: vec![
                    "Implement time-weighted average pricing (TWAP)".to_string(),
                    "Add flash loan detection and protection".to_string(),
                    "Use multiple oracle sources".to_string(),
                    "Implement MEV-resistant mechanisms".to_string(),
                ],
            });
        }

        findings
    }

    /// Detect cross-contract taint flows
    fn detect_cross_contract_taint_flows(&self, result: &AdvancedAnalysisResult) -> Vec<IntegratedFinding> {
        let mut findings = Vec::new();

        // Look for taint flows that cross contract boundaries
        let cross_contract_taint_flows: Vec<_> = result.taint_findings.iter()
            .filter(|f| f.taint_path.len() > 3) // Likely cross-contract
            .collect();

        if !cross_contract_taint_flows.is_empty() {
            findings.push(IntegratedFinding {
                finding_id: "INTEGRATED_CROSS_TAINT_001".to_string(),
                primary_vulnerability: "Cross-Contract Taint Propagation".to_string(),
                contributing_factors: vec![
                    "Untrusted data flows across contract boundaries".to_string(),
                    "Insufficient validation at trust boundaries".to_string(),
                ],
                severity: Severity::High,
                confidence: 0.75,
                affected_components: vec!["Multiple contracts in interaction chain".to_string()],
                attack_scenarios: vec![
                    AttackScenario {
                        scenario_id: "CROSS_TAINT_EXPLOIT".to_string(),
                        description: "Malicious data propagates through multiple contracts to reach sensitive sinks".to_string(),
                        attack_vector: "Inject malicious data → Cross-contract propagation → Exploit vulnerable sink".to_string(),
                        prerequisites: vec![
                            "Access to taint source".to_string(),
                            "Cross-contract interaction path".to_string(),
                            "Vulnerable sink in target contract".to_string(),
                        ],
                        impact: "Potential for privilege escalation or unauthorized operations".to_string(),
                        likelihood: 0.6,
                    }
                ],
                mitigation_strategies: vec![
                    "Implement input validation at all contract boundaries".to_string(),
                    "Use whitelisting for trusted contracts".to_string(),
                    "Add comprehensive access controls".to_string(),
                ],
            });
        }

        findings
    }

    /// Detect governance manipulation attack chains
    fn detect_governance_manipulation_chains(&self, result: &AdvancedAnalysisResult) -> Vec<IntegratedFinding> {
        let mut findings = Vec::new();

        let governance_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("governance"))
            .collect();

        let flash_loan_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("flash-loan"))
            .collect();

        if !governance_findings.is_empty() && !flash_loan_findings.is_empty() {
            findings.push(IntegratedFinding {
                finding_id: "INTEGRATED_GOV_FLASH_001".to_string(),
                primary_vulnerability: "Governance Flash Loan Attack".to_string(),
                contributing_factors: vec![
                    "Governance tokens can be flash borrowed".to_string(),
                    "Voting power based on current balance".to_string(),
                    "No time-weighted voting mechanism".to_string(),
                ],
                severity: Severity::Critical,
                confidence: 0.90,
                affected_components: vec!["Governance system".to_string(), "Voting mechanism".to_string()],
                attack_scenarios: vec![
                    AttackScenario {
                        scenario_id: "GOV_FLASH_TAKEOVER".to_string(),
                        description: "Attacker flash borrows governance tokens to manipulate voting and pass malicious proposals".to_string(),
                        attack_vector: "Flash borrow tokens → Vote on proposal → Execute proposal → Repay loan".to_string(),
                        prerequisites: vec![
                            "Flash loan access to governance tokens".to_string(),
                            "Active governance proposals".to_string(),
                            "Insufficient voting safeguards".to_string(),
                        ],
                        impact: "Complete governance takeover and protocol control".to_string(),
                        likelihood: 0.8,
                    }
                ],
                mitigation_strategies: vec![
                    "Implement time-weighted voting power".to_string(),
                    "Add minimum holding periods for voting".to_string(),
                    "Use snapshot-based voting".to_string(),
                    "Implement proposal delays and timelocks".to_string(),
                ],
            });
        }

        findings
    }

    /// Detect liquidity + oracle attack combinations
    fn detect_liquidity_oracle_attacks(&self, result: &AdvancedAnalysisResult) -> Vec<IntegratedFinding> {
        let mut findings = Vec::new();

        let liquidity_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("liquidity"))
            .collect();

        let price_findings: Vec<_> = result.defi_findings.iter()
            .filter(|f| f.finding.detector_id.to_string().contains("price"))
            .collect();

        if !liquidity_findings.is_empty() && !price_findings.is_empty() {
            findings.push(IntegratedFinding {
                finding_id: "INTEGRATED_LIQ_ORACLE_001".to_string(),
                primary_vulnerability: "Liquidity-Oracle Manipulation Attack".to_string(),
                contributing_factors: vec![
                    "Liquidity can be manipulated".to_string(),
                    "Price oracles depend on manipulable sources".to_string(),
                    "Insufficient price validation".to_string(),
                ],
                severity: Severity::High,
                confidence: 0.80,
                affected_components: vec!["Liquidity pools".to_string(), "Price oracles".to_string()],
                attack_scenarios: vec![
                    AttackScenario {
                        scenario_id: "LIQ_ORACLE_MANIP".to_string(),
                        description: "Attacker manipulates liquidity to distort oracle prices and exploit price-dependent logic".to_string(),
                        attack_vector: "Manipulate liquidity → Distort oracle price → Exploit price-dependent function".to_string(),
                        prerequisites: vec![
                            "Access to liquidity manipulation".to_string(),
                            "Oracle dependency on manipulable price source".to_string(),
                            "Price-dependent vulnerable logic".to_string(),
                        ],
                        impact: "Financial loss through price manipulation".to_string(),
                        likelihood: 0.65,
                    }
                ],
                mitigation_strategies: vec![
                    "Use multiple independent price sources".to_string(),
                    "Implement TWAP for price calculations".to_string(),
                    "Add liquidity manipulation detection".to_string(),
                    "Use price deviation limits".to_string(),
                ],
            });
        }

        findings
    }

    /// Assess overall risk based on findings
    fn assess_risk(&self, result: &AdvancedAnalysisResult) -> RiskAssessment {
        let mut risk_score = 0.0;
        let mut critical_count = 0;
        let mut high_risk_components = HashSet::new();
        let mut systemic_risks = Vec::new();

        // Count critical vulnerabilities
        critical_count += result.defi_findings.iter()
            .filter(|f| f.finding.severity == Severity::Critical)
            .count();

        critical_count += result.integrated_findings.iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();

        // Calculate risk score
        risk_score += critical_count as f64 * 10.0;
        risk_score += result.defi_findings.iter()
            .filter(|f| f.finding.severity == Severity::High)
            .count() as f64 * 5.0;
        risk_score += result.cross_contract_findings.iter()
            .filter(|f| f.severity == Severity::High)
            .count() as f64 * 3.0;

        // Identify systemic risks
        if result.cross_contract_findings.len() > 3 {
            systemic_risks.push("Multiple cross-contract vulnerabilities indicate systemic design issues".to_string());
        }

        if result.integrated_findings.len() > 1 {
            systemic_risks.push("Complex attack chains possible through vulnerability combinations".to_string());
        }

        // Identify high-risk components
        for finding in &result.defi_findings {
            if finding.finding.severity == Severity::Critical || finding.finding.severity == Severity::High {
                high_risk_components.insert(finding.finding.primary_location.file.clone());
            }
        }

        RiskAssessment {
            overall_risk_score: risk_score.min(100.0),
            critical_vulnerabilities: critical_count,
            high_risk_components: high_risk_components.into_iter().collect(),
            systemic_risks,
            compliance_issues: Vec::new(), // Would be populated based on specific compliance requirements
        }
    }

    /// Generate security recommendations
    fn generate_recommendations(&self, result: &AdvancedAnalysisResult) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();

        // Critical fixes
        if result.risk_assessment.critical_vulnerabilities > 0 {
            recommendations.push(SecurityRecommendation {
                category: RecommendationCategory::CodeFix,
                priority: Priority::Critical,
                description: "Immediately address all critical vulnerabilities before deployment".to_string(),
                implementation_effort: ImplementationEffort::High,
                business_impact: "Prevents potential total loss of funds".to_string(),
            });
        }

        // Architectural recommendations
        if !result.cross_contract_findings.is_empty() {
            recommendations.push(SecurityRecommendation {
                category: RecommendationCategory::ArchitecturalChange,
                priority: Priority::High,
                description: "Review and strengthen cross-contract interaction patterns".to_string(),
                implementation_effort: ImplementationEffort::VeryHigh,
                business_impact: "Improves overall system security and reliability".to_string(),
            });
        }

        // Monitoring recommendations
        recommendations.push(SecurityRecommendation {
            category: RecommendationCategory::Monitoring,
            priority: Priority::Medium,
            description: "Implement real-time monitoring for detected vulnerability patterns".to_string(),
            implementation_effort: ImplementationEffort::Medium,
            business_impact: "Enables early detection and response to attacks".to_string(),
        });

        // Testing recommendations
        recommendations.push(SecurityRecommendation {
            category: RecommendationCategory::Testing,
            priority: Priority::High,
            description: "Develop comprehensive test suites covering identified attack scenarios".to_string(),
            implementation_effort: ImplementationEffort::High,
            business_impact: "Prevents regression and validates security improvements".to_string(),
        });

        recommendations
    }

    fn severity_meets_threshold(&self, severity: &Severity) -> bool {
        use Severity::*;
        let severity_value = match severity {
            Critical => 4,
            High => 3,
            Medium => 2,
            Low => 1,
            Info => 0,
        };
        let threshold_value = match self.config.severity_threshold {
            Critical => 4,
            High => 3,
            Medium => 2,
            Low => 1,
            Info => 0,
        };
        severity_value >= threshold_value
    }
}

use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let config = AdvancedSecurityConfig::default();
        let engine = AdvancedSecurityEngine::new(config);
        assert_eq!(engine.defi_detectors.len(), 5);
    }

    #[test]
    fn test_severity_threshold() {
        let config = AdvancedSecurityConfig {
            severity_threshold: Severity::High,
            ..Default::default()
        };
        let engine = AdvancedSecurityEngine::new(config);

        assert!(engine.severity_meets_threshold(&Severity::Critical));
        assert!(engine.severity_meets_threshold(&Severity::High));
        assert!(!engine.severity_meets_threshold(&Severity::Medium));
    }

    #[test]
    fn test_risk_assessment() {
        let config = AdvancedSecurityConfig::default();
        let engine = AdvancedSecurityEngine::new(config);

        let result = AdvancedAnalysisResult {
            defi_findings: Vec::new(),
            cross_contract_findings: Vec::new(),
            taint_findings: Vec::new(),
            integrated_findings: vec![
                IntegratedFinding {
                    finding_id: "TEST_001".to_string(),
                    primary_vulnerability: "Test".to_string(),
                    contributing_factors: Vec::new(),
                    severity: Severity::Critical,
                    confidence: 0.9,
                    affected_components: Vec::new(),
                    attack_scenarios: Vec::new(),
                    mitigation_strategies: Vec::new(),
                }
            ],
            risk_assessment: RiskAssessment {
                overall_risk_score: 0.0,
                critical_vulnerabilities: 0,
                high_risk_components: Vec::new(),
                systemic_risks: Vec::new(),
                compliance_issues: Vec::new(),
            },
            recommendations: Vec::new(),
        };

        let risk_assessment = engine.assess_risk(&result);
        assert!(risk_assessment.overall_risk_score > 0.0);
    }
}
