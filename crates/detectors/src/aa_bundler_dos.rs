use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for verification logic susceptible to DoS attacks in ERC-4337
pub struct AaBundlerDosDetector {
    base: BaseDetector,
}

impl Default for AaBundlerDosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AaBundlerDosDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-bundler-dos".to_string()),
                "Account Abstraction Bundler DoS".to_string(),
                "Detects verification logic in ERC-4337 validateUserOp that is susceptible to denial-of-service attacks against bundlers".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for AaBundlerDosDetector {
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

        let contract_source = ctx.source_code.as_str();

        // Check for ERC-4337 patterns
        if !self.is_erc4337_contract(contract_source) {
            return Ok(findings);
        }

        // Pattern 1: External calls in validateUserOp
        if let Some(external_call_issues) = self.check_external_calls_in_validation(contract_source)
        {
            for (line, issue) in external_call_issues {
                let message = format!(
                    "validateUserOp contains external calls causing bundler DoS. {} \
                    External calls in validation can fail unpredictably, causing bundlers to reject all UserOps from this account.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_fix_suggestion(
                        "Remove external calls from validateUserOp: \
                    (1) Move external calls to execution phase, \
                    (2) Use view-only calls for validation, \
                    (3) Cache validation data on-chain, \
                    (4) Follow ERC-4337 validation restrictions, \
                    (5) Minimize storage access in validation."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 2: Unbounded loops in validation
        if let Some(loop_issues) = self.check_unbounded_loops(contract_source) {
            for (line, issue) in loop_issues {
                let message = format!(
                    "validateUserOp contains unbounded loop causing DoS. {} \
                    Unbounded loops can exceed gas limits, causing bundlers to permanently ban the account.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_cwe(606) // CWE-606: Unchecked Input for Loop Condition
                    .with_fix_suggestion(
                        "Remove or bound loops in validateUserOp: \
                    (1) Avoid loops in validation phase, \
                    (2) Use fixed-size arrays if needed, \
                    (3) Move iteration to execution phase, \
                    (4) Add maximum iteration limits, \
                    (5) Simplify validation logic."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 3: Storage access violations
        if let Some(storage_issues) = self.check_storage_violations(contract_source) {
            for (line, issue) in storage_issues {
                let message = format!(
                    "validateUserOp accesses forbidden storage slots. {} \
                    Accessing non-account storage violates ERC-4337 rules and causes bundler rejection.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(1321) // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
                    .with_cwe(913) // CWE-913: Improper Control of Dynamically-Managed Code Resources
                    .with_fix_suggestion(
                        "Restrict storage access in validateUserOp: \
                    (1) Only access account's own storage, \
                    (2) Avoid accessing other contracts' storage, \
                    (3) Use associated storage slots only, \
                    (4) Follow ERC-4337 storage access rules, \
                    (5) Validate with bundler simulation."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 4: Excessive gas consumption
        if let Some(gas_issues) = self.check_excessive_gas(contract_source) {
            for (line, issue) in gas_issues {
                let message = format!(
                    "validateUserOp has excessive gas consumption. {} \
                    High gas usage in validation increases costs and may cause bundler rejection.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(405) // CWE-405: Asymmetric Resource Consumption
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(
                        "Optimize validation gas usage: \
                    (1) Minimize storage reads (use memory), \
                    (2) Avoid complex computations, \
                    (3) Cache frequently used values, \
                    (4) Use efficient signature schemes (ECDSA), \
                    (5) Keep validation under 100k gas."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 5: Timestamp/block dependency
        if let Some(time_issues) = self.check_time_dependency(contract_source) {
            for (line, issue) in time_issues {
                let message = format!(
                    "validateUserOp depends on block timestamp/number. {} \
                    Time-dependent validation can fail between simulation and execution, causing bundler issues.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use Race Condition
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_fix_suggestion(
                        "Remove time dependency from validation: \
                    (1) Avoid block.timestamp in validateUserOp, \
                    (2) Avoid block.number checks, \
                    (3) Use validUntil/validAfter in UserOp instead, \
                    (4) Move time checks to execution phase, \
                    (5) Follow ERC-4337 validation rules."
                            .to_string(),
                    );

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

impl AaBundlerDosDetector {
    fn is_erc4337_contract(&self, source: &str) -> bool {
        source.contains("validateUserOp")
            || source.contains("IAccount")
            || source.contains("BaseAccount")
    }

    fn check_external_calls_in_validation(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate = true;
            }

            if in_validate {
                // Check for external calls
                if trimmed.contains(".call(")
                    || trimmed.contains(".delegatecall(")
                    || trimmed.contains(".staticcall(")
                    || (trimmed.contains(".") && trimmed.contains("(") && !trimmed.contains("//"))
                {
                    // Ignore safe patterns
                    if !trimmed.contains("address(this)")
                        && !trimmed.contains("msg.sender")
                        && !trimmed.contains("ECDSA.")
                        && !trimmed.contains("SignatureChecker.")
                    {
                        issues.push((
                            (idx + 1) as u32,
                            "External call in validateUserOp can cause bundler DoS".to_string(),
                        ));
                    }
                }

                if trimmed == "}" {
                    in_validate = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_unbounded_loops(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate = true;
            }

            if in_validate {
                // Check for loops
                if trimmed.contains("for (")
                    || trimmed.contains("for(")
                    || trimmed.contains("while (")
                    || trimmed.contains("while(")
                {
                    // Check if loop has fixed bound
                    let has_fixed_bound = trimmed.contains("< ")
                        && (trimmed.contains("< 10")
                            || trimmed.contains("< 5")
                            || trimmed.contains("< MAX_"));

                    if !has_fixed_bound {
                        issues.push((
                            (idx + 1) as u32,
                            "Unbounded loop in validateUserOp can exhaust gas".to_string(),
                        ));
                    }
                }

                if trimmed == "}" {
                    in_validate = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_storage_violations(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate = true;
            }

            if in_validate {
                // Check for storage access via external contracts
                if (trimmed.contains("someContract.") || trimmed.contains("IContract("))
                    && !trimmed.contains("//")
                {
                    issues.push((
                        (idx + 1) as u32,
                        "Accessing external contract storage in validateUserOp".to_string(),
                    ));
                }

                if trimmed == "}" {
                    in_validate = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_excessive_gas(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate = false;
        let mut validate_start = 0;
        let mut operation_count = 0;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate = true;
                validate_start = idx;
                operation_count = 0;
            }

            if in_validate {
                // Count potentially expensive operations
                if trimmed.contains("sload") || trimmed.contains("storage") {
                    operation_count += 2;
                }
                if trimmed.contains("keccak256") || trimmed.contains("sha256") {
                    operation_count += 3;
                }
                if trimmed.contains("ecrecover") {
                    operation_count += 5;
                }

                if trimmed == "}" {
                    if operation_count > 10 {
                        issues.push((
                            (validate_start + 1) as u32,
                            format!(
                                "High gas consumption in validateUserOp ({} expensive operations)",
                                operation_count
                            ),
                        ));
                    }
                    in_validate = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_time_dependency(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate = true;
            }

            if in_validate {
                if trimmed.contains("block.timestamp") || trimmed.contains("block.number") {
                    issues.push((
                        (idx + 1) as u32,
                        "Time-dependent validation violates ERC-4337 rules".to_string(),
                    ));
                }

                if trimmed == "}" {
                    in_validate = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = AaBundlerDosDetector::new();
        assert_eq!(detector.name(), "Account Abstraction Bundler DoS");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}
