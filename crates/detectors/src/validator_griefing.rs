use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::safe_call_patterns::is_view_or_pure_function;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::has_access_control_modifier;

/// Detector for validator griefing attack vulnerabilities.
///
/// This detector targets contracts that manage validator sets, staking protocols,
/// and slashing mechanisms. It identifies patterns where validators can be griefed
/// through low-cost or zero-cost malicious actions.
///
/// To reduce false positives, the detector:
/// - Requires contract-level staking/validator context (not just incidental keyword matches)
/// - Skips view/pure functions (read-only cannot grief)
/// - Skips internal/private functions (access control is at caller level)
/// - Skips access-controlled functions (already protected by modifiers)
/// - Excludes non-staking contract types (bridges, vaults, AMMs, governance, proxies)
pub struct ValidatorGriefingDetector {
    base: BaseDetector,
}

impl Default for ValidatorGriefingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("validator-griefing".to_string()),
                "Validator Griefing Attack".to_string(),
                "Detects vulnerabilities where validators can be griefed through malicious actions that harm validators without benefiting attackers".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Detector for ValidatorGriefingDetector {
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

        // Early exit: only analyze contracts that are actually validator/staking systems
        if !self.is_validator_staking_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(griefing_issue) = self.check_validator_griefing(function, ctx) {
                let message = format!(
                    "Function '{}' has validator griefing vulnerability. {} \
                    Attackers can harm validators without economic benefit, leading to validator exits and network destabilization.",
                    function.name.name, griefing_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(405) // CWE-405: Asymmetric Resource Consumption (Amplification)
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_fix_suggestion(format!(
                    "Mitigate validator griefing in '{}'. \
                    Implement griefing-cost mechanisms (deposit requirements), add rate limiting per address, \
                    require minimum stake for reporting, implement reputation systems, \
                    add penalties for false accusations, and create validator insurance pools.",
                    function.name.name
                ));

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

impl ValidatorGriefingDetector {
    /// Determine whether this contract is a validator/staking system.
    ///
    /// We require strong contract-level signals that indicate the contract manages
    /// validators, staking, or slashing. Contracts that merely mention "stake" in a
    /// DeFi deposit context or "validator" as a parameter name are excluded.
    fn is_validator_staking_contract(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Exclude contract types that are clearly not validator management
        if self.is_non_validator_contract_type(&source_lower, &contract_name) {
            return false;
        }

        // Require strong validator/staking indicators at the contract level.
        // A single keyword like "stake" is insufficient; we need patterns that
        // indicate actual validator set management or slashing mechanisms.
        let has_validator_set_management = source_lower.contains("validatorset")
            || source_lower.contains("validator_set")
            || source_lower.contains("validatorcount")
            || source_lower.contains("validatorinfo")
            || source_lower.contains("activevalidator")
            || source_lower.contains("validatorstatus")
            || source_lower.contains("registeredvalidator")
            || (source_lower.contains("mapping") && source_lower.contains("validator"));

        let has_staking_protocol = (source_lower.contains("stake")
            && source_lower.contains("unstake"))
            || (source_lower.contains("stake") && source_lower.contains("slash"))
            || source_lower.contains("slasher")
            || source_lower.contains("slashable")
            || source_lower.contains("beaconchain")
            || source_lower.contains("beacon_chain")
            || source_lower.contains("epochnumber")
            || source_lower.contains("validatorindex");

        let has_slashing_mechanism = source_lower.contains("slashoperator")
            || source_lower.contains("slash_operator")
            || source_lower.contains("slashingstake")
            || source_lower.contains("slashableamount")
            || source_lower.contains("slashingfactor")
            || source_lower.contains("isslashed");

        // Contract name strongly suggests validator/staking domain
        let name_suggests_staking = contract_name.contains("validator")
            || contract_name.contains("staking")
            || contract_name.contains("slasher")
            || contract_name.contains("restaking")
            || contract_name.contains("eigenlayer");

        has_validator_set_management
            || has_staking_protocol
            || has_slashing_mechanism
            || name_suggests_staking
    }

    /// Exclude contract types that are not validator/staking systems but may
    /// incidentally contain keywords like "stake", "validator", or "slash".
    fn is_non_validator_contract_type(&self, source_lower: &str, contract_name: &str) -> bool {
        // Bridge contracts (may reference validators for consensus but are not staking)
        let is_bridge = (contract_name.contains("bridge") || source_lower.contains("bridgevault"))
            && !contract_name.contains("validator");

        // AMM/DEX contracts
        let is_amm = contract_name.contains("pool")
            || contract_name.contains("swap")
            || contract_name.contains("amm")
            || contract_name.contains("router")
            || contract_name.contains("pair");

        // Vault contracts (ERC-4626, etc.)
        let is_vault = (contract_name.contains("vault") && !contract_name.contains("staking"))
            || source_lower.contains("erc4626")
            || source_lower.contains("erc-4626");

        // Pure governance contracts
        let is_governance = contract_name.contains("governor")
            || contract_name.contains("governance")
            || (source_lower.contains("proposal") && source_lower.contains("vote"));

        // Proxy contracts
        let is_proxy = contract_name.contains("proxy")
            || contract_name.contains("delegatecall")
            || source_lower.contains("_implementation()");

        // Token contracts
        let is_token = contract_name.contains("token")
            || contract_name.contains("erc20")
            || contract_name.contains("erc721")
            || contract_name.contains("erc1155");

        // Liquidity mining / yield farming (uses "stake" but not validator staking)
        let is_yield = contract_name.contains("farming")
            || contract_name.contains("mining")
            || contract_name.contains("reward")
            || contract_name.contains("liquiditymining");

        is_bridge || is_amm || is_vault || is_governance || is_proxy || is_token || is_yield
    }

    /// Check if a function has access control through AST modifiers.
    fn function_has_access_control(&self, function: &ast::Function<'_>) -> bool {
        function.modifiers.iter().any(|m| {
            let name = m.name.name.to_lowercase();
            name.contains("only")
                || name.contains("auth")
                || name.contains("restricted")
                || name.contains("admin")
                || name.contains("owner")
                || name.contains("governance")
                || name.contains("operator")
                || name.contains("role")
                || name.contains("paused")
        })
    }

    /// Check for validator griefing vulnerabilities
    fn check_validator_griefing(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // Skip view/pure functions -- read-only functions cannot grief validators
        if is_view_or_pure_function(function) {
            return None;
        }

        // Skip internal/private functions -- access control is at the caller level
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Skip functions with access control modifiers (AST-level check)
        if self.function_has_access_control(function) {
            return None;
        }

        // Skip functions with access control modifiers (source-level check as fallback)
        if has_access_control_modifier(&func_source) {
            return None;
        }

        // Check if function directly affects validators (tighter matching)
        let func_name_lower = function.name.name.to_lowercase();
        let affects_validators = func_source.contains("validator")
            || func_source.contains("Validator")
            || (func_source.contains("slash") && !func_source.contains("slashingFactor"))
            || (func_name_lower.contains("stake") && !func_name_lower.contains("unstake"));

        if !affects_validators {
            return None;
        }

        // Pattern 1: Free or low-cost slashing reports
        // Only flag functions whose name or direct purpose is reporting/accusing
        let is_report_function = func_name_lower.contains("report")
            || func_name_lower.contains("accuse")
            || (func_name_lower.contains("slash")
                && !func_name_lower.contains("get")
                && !func_name_lower.contains("clear")
                && !func_name_lower.contains("factor"));

        let no_cost_to_report = is_report_function
            && !func_source.contains("require(msg.value")
            && !func_source.contains("deposit")
            && !func_source.contains("bond")
            && !func_source.contains("msg.value >=")
            && !func_source.contains("msg.value >")
            && !func_source.contains("transferFrom");

        if no_cost_to_report {
            return Some(
                "Validator reporting or slashing has no cost to reporter, \
                enables free griefing attacks through false accusations"
                    .to_string(),
            );
        }

        // Pattern 5: Exit queue can be flooded
        // Only flag functions whose explicit purpose is exiting or unstaking
        let is_exit_function = func_name_lower.contains("exit")
            || func_name_lower == "unstake"
            || func_name_lower == "undelegate";

        let no_exit_limit = is_exit_function
            && !func_source.contains("MAX_EXIT")
            && !func_source.contains("exitQueue")
            && !func_source.contains("maxExits")
            && !func_source.contains("exitCooldown")
            && !func_source.contains("rateLimit");

        if no_exit_limit {
            return Some(
                "Validator exit queue has no flood protection, \
                mass exit can delay legitimate withdrawals (griefing)"
                    .to_string(),
            );
        }

        // Pattern 7: Validator registration without deposit
        let is_registration = func_name_lower.contains("register")
            && (func_name_lower.contains("validator") || func_source.contains("validatorSet"));

        let no_registration_deposit = is_registration
            && !func_source.contains("deposit")
            && !func_source.contains("stake")
            && !func_source.contains("msg.value")
            && !func_source.contains("transferFrom");

        if no_registration_deposit {
            return Some(
                "Validator registration without deposit requirement, \
                enables Sybil attacks to spam validator set (griefing)"
                    .to_string(),
            );
        }

        // Pattern 8: Reward distribution can be blocked
        let is_reward_function =
            func_name_lower.contains("reward") || func_name_lower.contains("distribute");

        let blockable_rewards = is_reward_function
            && func_source.contains("revert")
            && !func_source.contains("try")
            && !func_source.contains("pull")
            && func_source.contains(".call{value:");

        if blockable_rewards {
            return Some(
                "Reward distribution uses push pattern that can be blocked, \
                single failing validator can prevent all rewards (griefing)"
                    .to_string(),
            );
        }

        None
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ValidatorGriefingDetector::new();
        assert_eq!(detector.name(), "Validator Griefing Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_non_validator_contract_exclusion() {
        let detector = ValidatorGriefingDetector::new();

        // Bridge contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract bridgevault { function stake() {} }",
            "bridgevault"
        ));

        // AMM contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract uniswappool { function swap() {} }",
            "uniswappool"
        ));

        // Vault contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract erc4626 vault { function deposit() {} }",
            "myvault"
        ));

        // Governance contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract governor { function proposal() { vote(); } }",
            "governor"
        ));

        // Proxy contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract myproxy { function delegatecall() {} }",
            "myproxy"
        ));

        // Yield farming contracts should be excluded
        assert!(detector.is_non_validator_contract_type(
            "contract liquiditymining { function stake() {} }",
            "liquiditymining"
        ));

        // Staking validator contracts should NOT be excluded
        assert!(!detector.is_non_validator_contract_type(
            "contract slasher { function slashOperator() {} }",
            "slasher"
        ));

        // Generic contracts should NOT be excluded
        assert!(!detector.is_non_validator_contract_type(
            "contract validatormanager { function registerValidator() {} }",
            "validatormanager"
        ));
    }
}
