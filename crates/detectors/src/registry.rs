use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::detector::{Detector, DetectorCategory};
use crate::types::{DetectorId, Finding, AnalysisContext, AnalysisResult};

/// Registry for managing and executing vulnerability detectors
pub struct DetectorRegistry {
    /// All registered detectors
    detectors: HashMap<DetectorId, Arc<dyn Detector>>,
    /// Enabled detector IDs
    enabled_detectors: Vec<DetectorId>,
    /// Configuration for the registry
    config: RegistryConfig,
}

/// Configuration for the detector registry
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Maximum number of threads to use for parallel execution
    pub max_threads: usize,
    /// Timeout for individual detector execution (in seconds)
    pub detector_timeout_secs: u64,
    /// Whether to stop on first error or continue
    pub fail_fast: bool,
    /// Minimum severity level to include in results
    pub min_severity: crate::types::Severity,
    /// Minimum confidence level to include in results
    pub min_confidence: crate::types::Confidence,
    /// Categories to include (empty means all)
    pub enabled_categories: Vec<DetectorCategory>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_threads: 1, // Single-threaded for now
            detector_timeout_secs: 30,
            fail_fast: false,
            min_severity: crate::types::Severity::Info,
            min_confidence: crate::types::Confidence::Low,
            enabled_categories: Vec::new(), // Empty means all categories
        }
    }
}

impl DetectorRegistry {
    /// Create a new detector registry
    pub fn new() -> Self {
        Self {
            detectors: HashMap::new(),
            enabled_detectors: Vec::new(),
            config: RegistryConfig::default(),
        }
    }

    /// Create a new detector registry with configuration
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            detectors: HashMap::new(),
            enabled_detectors: Vec::new(),
            config,
        }
    }

    /// Create a new detector registry with all built-in detectors
    pub fn with_all_detectors() -> Self {
        let mut registry = Self::new();
        registry.register_built_in_detectors();
        registry
    }

    /// Create a new detector registry with all built-in detectors and config
    pub fn with_all_detectors_and_config(config: RegistryConfig) -> Self {
        let mut registry = Self::with_config(config);
        registry.register_built_in_detectors();
        registry
    }

    /// Register a detector in the registry
    pub fn register(&mut self, detector: Arc<dyn Detector>) {
        let id = detector.id();
        if detector.is_enabled() {
            self.enabled_detectors.push(id.clone());
        }
        self.detectors.insert(id, detector);
    }

    /// Register multiple detectors
    pub fn register_all(&mut self, detectors: Vec<Arc<dyn Detector>>) {
        for detector in detectors {
            self.register(detector);
        }
    }

    /// Enable a detector by ID
    pub fn enable_detector(&mut self, id: &DetectorId) -> Result<()> {
        if !self.detectors.contains_key(id) {
            return Err(anyhow!("Detector not found: {}", id));
        }

        if !self.enabled_detectors.contains(id) {
            self.enabled_detectors.push(id.clone());
        }
        Ok(())
    }

    /// Disable a detector by ID
    pub fn disable_detector(&mut self, id: &DetectorId) {
        self.enabled_detectors.retain(|detector_id| detector_id != id);
    }

    /// Enable detectors by category
    pub fn enable_category(&mut self, category: DetectorCategory) {
        for (id, detector) in &self.detectors {
            if detector.categories().contains(&category) && !self.enabled_detectors.contains(id) {
                self.enabled_detectors.push(id.clone());
            }
        }
    }

    /// Disable detectors by category
    pub fn disable_category(&mut self, category: DetectorCategory) {
        self.enabled_detectors.retain(|id| {
            if let Some(detector) = self.detectors.get(id) {
                !detector.categories().contains(&category)
            } else {
                false
            }
        });
    }

    /// Get all registered detector IDs
    pub fn get_detector_ids(&self) -> Vec<DetectorId> {
        self.detectors.keys().cloned().collect()
    }

    /// Get enabled detector IDs
    pub fn get_enabled_detector_ids(&self) -> Vec<DetectorId> {
        self.enabled_detectors.clone()
    }

    /// Get detector by ID
    pub fn get_detector(&self, id: &DetectorId) -> Option<&Arc<dyn Detector>> {
        self.detectors.get(id)
    }

    /// Get detectors by category
    pub fn get_detectors_by_category(&self, category: DetectorCategory) -> Vec<&Arc<dyn Detector>> {
        self.detectors
            .values()
            .filter(|detector| detector.categories().contains(&category))
            .collect()
    }

    /// Update registry configuration
    pub fn set_config(&mut self, config: RegistryConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &RegistryConfig {
        &self.config
    }

    /// Run all enabled detectors on the given analysis context
    pub fn run_analysis(&self, ctx: &AnalysisContext<'_>) -> Result<AnalysisResult> {
        let start_time = Instant::now();
        let mut result = AnalysisResult::new();

        // Filter detectors based on configuration
        let detectors_to_run: Vec<_> = self
            .enabled_detectors
            .iter()
            .filter_map(|id| self.detectors.get(id))
            .filter(|detector| self.should_run_detector(detector))
            .collect();

        result.stats.detectors_run = detectors_to_run.len();

        // Sort detectors by priority (highest first)
        let mut sorted_detectors = detectors_to_run;
        sorted_detectors.sort_by(|a, b| b.priority().cmp(&a.priority()));

        // Run detectors sequentially for now due to AST thread safety issues
        // TODO: Implement parallel execution with thread-safe AST
        let findings: Result<Vec<Vec<Finding>>> = self.run_sequential(&sorted_detectors, ctx);

        match findings {
            Ok(all_findings) => {
                // Flatten and filter findings
                for detector_findings in all_findings {
                    for finding in detector_findings {
                        if self.should_include_finding(&finding) {
                            result.stats.record_finding(&finding);
                            result.add_finding(finding);
                        }
                    }
                }
            }
            Err(e) => {
                result.add_error(format!("Analysis failed: {}", e));
            }
        }

        result.stats.total_time_ms = start_time.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Run a specific detector by ID
    pub fn run_detector(&self, id: &DetectorId, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let detector = self
            .detectors
            .get(id)
            .ok_or_else(|| anyhow!("Detector not found: {}", id))?;

        let start_time = Instant::now();
        let result = detector.detect(ctx);
        let duration = start_time.elapsed();

        match result {
            Ok(findings) => {
                log::debug!(
                    "Detector {} completed in {:?} with {} findings",
                    id,
                    duration,
                    findings.len()
                );
                Ok(findings)
            }
            Err(e) => {
                log::error!("Detector {} failed: {}", id, e);
                Err(e)
            }
        }
    }

    /// Run detectors sequentially
    fn run_sequential(
        &self,
        detectors: &[&Arc<dyn Detector>],
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Vec<Finding>>> {
        let mut results = Vec::new();

        for detector in detectors {
            match self.run_single_detector(detector, ctx) {
                Ok(findings) => results.push(findings),
                Err(e) => {
                    if self.config.fail_fast {
                        return Err(e);
                    } else {
                        log::warn!("Detector {} failed: {}", detector.id(), e);
                        results.push(Vec::new());
                    }
                }
            }
        }

        Ok(results)
    }

    /// Run detectors in parallel (disabled due to AST thread safety issues)
    #[allow(dead_code)]
    fn run_parallel(
        &self,
        _detectors: &[&Arc<dyn Detector>],
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Vec<Finding>>> {
        // TODO: Implement parallel execution with thread-safe AST
        // For now, fallback to sequential execution
        Err(anyhow!("Parallel execution not yet implemented - AST is not thread-safe"))
    }

    /// Run a single detector with timeout handling
    fn run_single_detector(
        &self,
        detector: &Arc<dyn Detector>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(self.config.detector_timeout_secs);

        // TODO: Implement proper timeout handling
        // For now, just run the detector directly
        let result = detector.detect(ctx);

        let duration = start_time.elapsed();
        if duration > timeout {
            log::warn!(
                "Detector {} exceeded timeout ({:?} > {:?})",
                detector.id(),
                duration,
                timeout
            );
        }

        result
    }

    /// Check if a detector should be run based on configuration
    fn should_run_detector(&self, detector: &Arc<dyn Detector>) -> bool {
        // Check if categories are restricted and detector matches
        if !self.config.enabled_categories.is_empty() {
            let detector_categories = detector.categories();
            let has_enabled_category = detector_categories
                .iter()
                .any(|cat| self.config.enabled_categories.contains(cat));

            if !has_enabled_category {
                return false;
            }
        }

        true
    }

    /// Check if a finding should be included in results based on configuration
    fn should_include_finding(&self, finding: &Finding) -> bool {
        finding.severity >= self.config.min_severity
            && finding.confidence >= self.config.min_confidence
    }

    /// Get metrics for all detectors
    pub fn get_all_metrics(&self) -> HashMap<DetectorId, crate::detector::DetectorMetrics> {
        let mut metrics = HashMap::new();

        // Note: This implementation is incomplete due to trait object limitations
        // In practice, we'd need a different approach for accessing metrics
        for (id, _detector) in &self.detectors {
            // Placeholder - would need to implement a different pattern
            metrics.insert(id.clone(), crate::detector::DetectorMetrics::new());
        }

        metrics
    }

    /// Reset metrics for all detectors
    pub fn reset_all_metrics(&self) {
        // Note: This implementation is incomplete due to trait object limitations
        // In practice, we'd need a different approach for mutable operations on trait objects
        // This would require either:
        // 1. Interior mutability (RefCell/Mutex)
        // 2. A different API design
        // 3. Returning a new registry with reset metrics
    }

    /// Register all built-in detectors
    fn register_built_in_detectors(&mut self) {
        // Access Control Detectors
        self.register(Arc::new(crate::access_control::MissingModifiersDetector::new()));
        self.register(Arc::new(crate::access_control::UnprotectedInitializerDetector::new()));
        self.register(Arc::new(crate::access_control::DefaultVisibilityDetector::new()));

        // Reentrancy Detectors
        self.register(Arc::new(crate::reentrancy::ClassicReentrancyDetector::new()));
        self.register(Arc::new(crate::reentrancy::ReadOnlyReentrancyDetector::new()));

        // Logic Detectors
        self.register(Arc::new(crate::logic::division_order::DivisionOrderDetector::new()));
        self.register(Arc::new(crate::logic::state_machine::StateMachineDetector::new()));

        // Validation Detectors
        self.register(Arc::new(crate::validation::zero_address::ZeroAddressDetector::new()));
        self.register(Arc::new(crate::validation::array_bounds::ArrayBoundsDetector::new()));
        self.register(Arc::new(crate::validation::parameter_check::ParameterConsistencyDetector::new()));

        // Oracle Detectors
        self.register(Arc::new(crate::oracle::SingleSourceDetector::new()));
        self.register(Arc::new(crate::oracle::PriceValidationDetector::new()));

        // Flash Loan Detectors
        self.register(Arc::new(crate::flashloan::VulnerablePatternsDetector::new()));

        // External Call Detectors
        self.register(Arc::new(crate::external::UncheckedCallDetector::new()));

        // MEV Detectors
        self.register(Arc::new(crate::mev::SandwichAttackDetector::new()));
        self.register(Arc::new(crate::mev::FrontRunningDetector::new()));

        // Timestamp Detectors
        self.register(Arc::new(crate::timestamp::BlockDependencyDetector::new()));

        // Auth Detectors
        self.register(Arc::new(crate::auth::TxOriginDetector::new()));

        // Governance Detectors
        self.register(Arc::new(crate::governance::GovernanceDetector::new()));
        self.register(Arc::new(crate::governance::ExternalCallsLoopDetector::new()));
        self.register(Arc::new(crate::governance::SignatureReplayDetector::new()));
        self.register(Arc::new(crate::governance::EmergencyPauseCentralizationDetector::new()));

        // Critical Priority Detectors (2025 Vulnerabilities - Phase 1)
        self.register(Arc::new(crate::cross_chain_replay::CrossChainReplayDetector::new()));
        self.register(Arc::new(crate::flash_loan_staking::FlashLoanStakingDetector::new()));
        self.register(Arc::new(crate::oracle_manipulation::OracleManipulationDetector::new()));

        // High Priority Detectors (2025 Vulnerabilities - Phase 2)
        self.register(Arc::new(crate::slippage_protection::SlippageProtectionDetector::new()));
        self.register(Arc::new(crate::delegation_loop::DelegationLoopDetector::new()));
        self.register(Arc::new(crate::weak_signature_validation::WeakSignatureValidationDetector::new()));
        self.register(Arc::new(crate::auction_timing::AuctionTimingDetector::new()));

        // Medium Priority Detectors (2025 Vulnerabilities - Phase 3)
        self.register(Arc::new(crate::weak_commit_reveal::WeakCommitRevealDetector::new()));
        self.register(Arc::new(crate::reward_calculation::RewardCalculationDetector::new()));
        self.register(Arc::new(crate::emergency_function_abuse::EmergencyFunctionAbuseDetector::new()));
        self.register(Arc::new(crate::gas_price_manipulation::GasPriceManipulationDetector::new()));
        self.register(Arc::new(crate::emergency_withdrawal_abuse::EmergencyWithdrawalAbuseDetector::new()));

        // Critical Infrastructure Detectors (Phase 4)
        self.register(Arc::new(crate::storage_collision::StorageCollisionDetector::new()));
        self.register(Arc::new(crate::dangerous_delegatecall::DangerousDelegatecallDetector::new()));
        self.register(Arc::new(crate::selfdestruct_abuse::SelfdestructAbuseDetector::new()));
        self.register(Arc::new(crate::integer_overflow::IntegerOverflowDetector::new()));
        self.register(Arc::new(crate::uninitialized_storage::UninitializedStorageDetector::new()));
        self.register(Arc::new(crate::signature_malleability::SignatureMalleabilityDetector::new()));

        // DeFi Advanced Protocols (Phase 5)
        self.register(Arc::new(crate::amm_liquidity_manipulation::AmmLiquidityManipulationDetector::new()));
        self.register(Arc::new(crate::lending_liquidation_abuse::LendingLiquidationAbuseDetector::new()));
        self.register(Arc::new(crate::vault_share_inflation::VaultShareInflationDetector::new()));
        self.register(Arc::new(crate::vault_donation_attack::VaultDonationAttackDetector::new()));
        self.register(Arc::new(crate::vault_withdrawal_dos::VaultWithdrawalDosDetector::new()));
        self.register(Arc::new(crate::vault_fee_manipulation::VaultFeeManipulationDetector::new()));
        self.register(Arc::new(crate::vault_hook_reentrancy::VaultHookReentrancyDetector::new()));
        self.register(Arc::new(crate::price_impact_manipulation::PriceImpactManipulationDetector::new()));
        self.register(Arc::new(crate::sandwich_resistant_swap::SandwichResistantSwapDetector::new()));
        self.register(Arc::new(crate::liquidity_bootstrapping_abuse::LiquidityBootstrappingAbuseDetector::new()));

        // MEV & Timing Attacks (Phase 6)
        self.register(Arc::new(crate::timestamp_manipulation::TimestampManipulationDetector::new()));
        self.register(Arc::new(crate::block_stuffing_vulnerable::BlockStuffingVulnerableDetector::new()));
        self.register(Arc::new(crate::mev_extractable_value::MevExtractableValueDetector::new()));
        self.register(Arc::new(crate::deadline_manipulation::DeadlineManipulationDetector::new()));
        self.register(Arc::new(crate::nonce_reuse::NonceReuseDetector::new()));

        // Staking & Validator Security (Phase 7)
        self.register(Arc::new(crate::slashing_mechanism::SlashingMechanismDetector::new()));
        self.register(Arc::new(crate::validator_griefing::ValidatorGriefingDetector::new()));
        self.register(Arc::new(crate::withdrawal_delay::WithdrawalDelayDetector::new()));
        self.register(Arc::new(crate::validator_front_running::ValidatorFrontRunningDetector::new()));

        // Upgradeable Contracts & Dependencies (Phase 8)
        self.register(Arc::new(crate::upgradeable_proxy_issues::UpgradeableProxyIssuesDetector::new()));
        self.register(Arc::new(crate::token_supply_manipulation::TokenSupplyManipulationDetector::new()));
        self.register(Arc::new(crate::circular_dependency::CircularDependencyDetector::new()));

        // Gas & Optimization Issues (Phase 9)
        self.register(Arc::new(crate::gas_griefing::GasGriefingDetector::new()));
        self.register(Arc::new(crate::dos_unbounded_operation::DosUnboundedOperationDetector::new()));
        self.register(Arc::new(crate::excessive_gas_usage::ExcessiveGasUsageDetector::new()));
        self.register(Arc::new(crate::inefficient_storage::InefficientStorageDetector::new()));
        self.register(Arc::new(crate::redundant_checks::RedundantChecksDetector::new()));

        // Advanced Security (Phase 10)
        self.register(Arc::new(crate::front_running_mitigation::FrontRunningMitigationDetector::new()));
        self.register(Arc::new(crate::price_oracle_stale::PriceOracleStaleDetector::new()));
        self.register(Arc::new(crate::centralization_risk::CentralizationRiskDetector::new()));
        self.register(Arc::new(crate::insufficient_randomness::InsufficientRandomnessDetector::new()));

        // Code Quality & Best Practices (Phase 11)
        self.register(Arc::new(crate::shadowing_variables::ShadowingVariablesDetector::new()));
        self.register(Arc::new(crate::unchecked_math::UncheckedMathDetector::new()));
        self.register(Arc::new(crate::missing_input_validation::MissingInputValidationDetector::new()));
        self.register(Arc::new(crate::deprecated_functions::DeprecatedFunctionsDetector::new()));
        self.register(Arc::new(crate::unsafe_type_casting::UnsafeTypeCastingDetector::new()));

        // Account Abstraction & ERC-4337 (Phase 12 - 2025)
        self.register(Arc::new(crate::erc4337_entrypoint_trust::Erc4337EntrypointTrustDetector::new()));
        self.register(Arc::new(crate::aa_initialization_vulnerability::AaInitializationVulnerabilityDetector::new()));
        self.register(Arc::new(crate::aa_account_takeover::AaAccountTakeoverDetector::new()));
        self.register(Arc::new(crate::aa_bundler_dos::AaBundlerDosDetector::new()));
        self.register(Arc::new(crate::hardware_wallet_delegation::HardwareWalletDelegationDetector::new()));

        // Cross-Chain Intent & Bridge Security (Phase 13 - 2025)
        self.register(Arc::new(crate::erc7683_settlement_validation::SettlementValidationDetector::new()));
        self.register(Arc::new(crate::erc7683_replay_attack::ReplayAttackDetector::new()));
        self.register(Arc::new(crate::erc7683_filler_frontrunning::FillerFrontrunningDetector::new()));
        self.register(Arc::new(crate::erc7683_oracle_dependency::OracleDependencyDetector::new()));
        self.register(Arc::new(crate::erc7683_permit2_integration::Permit2IntegrationDetector::new()));
        self.register(Arc::new(crate::bridge_token_minting::TokenMintingDetector::new()));
        self.register(Arc::new(crate::bridge_message_verification::MessageVerificationDetector::new()));
        self.register(Arc::new(crate::bridge_chain_id_validation::ChainIdValidationDetector::new()));

        // Account Abstraction Advanced (Phase 14 - 2025)
        self.register(Arc::new(crate::erc4337_paymaster_abuse::PaymasterAbuseDetector::new()));
        self.register(Arc::new(crate::aa_session_key_vulnerabilities::SessionKeyVulnerabilitiesDetector::new()));
        self.register(Arc::new(crate::aa_signature_aggregation::SignatureAggregationDetector::new()));
        self.register(Arc::new(crate::aa_social_recovery::SocialRecoveryDetector::new()));
        self.register(Arc::new(crate::aa_nonce_management::NonceManagementDetector::new()));

        // DeFi Protocol Security (Phase 15 - 2025)
        self.register(Arc::new(crate::defi_liquidity_pool_manipulation::LiquidityPoolManipulationDetector::new()));
        self.register(Arc::new(crate::defi_jit_liquidity::JitLiquidityDetector::new()));
        self.register(Arc::new(crate::defi_yield_farming::YieldFarmingDetector::new()));

        // Token Standard Edge Cases (Phase 17 - 2025)
        self.register(Arc::new(crate::erc20_approve_race::Erc20ApproveRaceDetector::new()));
        self.register(Arc::new(crate::erc20_infinite_approval::Erc20InfiniteApprovalDetector::new()));
        self.register(Arc::new(crate::erc777_reentrancy_hooks::Erc777ReentrancyHooksDetector::new()));
        self.register(Arc::new(crate::erc721_callback_reentrancy::Erc721CallbackReentrancyDetector::new()));
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating detector registries
pub struct DetectorRegistryBuilder {
    registry: DetectorRegistry,
}

impl DetectorRegistryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            registry: DetectorRegistry::new(),
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: RegistryConfig) -> Self {
        self.registry.set_config(config);
        self
    }

    /// Add a detector
    pub fn with_detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.registry.register(detector);
        self
    }

    /// Add multiple detectors
    pub fn with_detectors(mut self, detectors: Vec<Arc<dyn Detector>>) -> Self {
        self.registry.register_all(detectors);
        self
    }

    /// Enable a specific category
    pub fn with_category(mut self, category: DetectorCategory) -> Self {
        self.registry.enable_category(category);
        self
    }

    /// Set maximum threads
    pub fn with_max_threads(mut self, max_threads: usize) -> Self {
        self.registry.config.max_threads = max_threads;
        self
    }

    /// Set minimum severity
    pub fn with_min_severity(mut self, min_severity: crate::types::Severity) -> Self {
        self.registry.config.min_severity = min_severity;
        self
    }

    /// Build the registry
    pub fn build(self) -> DetectorRegistry {
        self.registry
    }
}

impl Default for DetectorRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
