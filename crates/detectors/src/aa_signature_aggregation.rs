//! Account Abstraction Signature Aggregation Issues Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct SignatureAggregationDetector {
    base: BaseDetector,
}

impl SignatureAggregationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-signature-aggregation".to_string()),
                "Signature Aggregation Issues".to_string(),
                "Detects missing individual signature validation and aggregation bypass vulnerabilities".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    fn is_signature_aggregator(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("iaggregator") || source.contains("aggregator"))
            && (source.contains("validateuseropssignature")
                || source.contains("aggregatesignature"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check validateUserOpSignature or validateSignatures
        if name.contains("validatesignature") || name.contains("validateuserops") {
            // Check for missing individual signature validation
            let has_individual_check = source_lower.contains("for")
                && (source_lower.contains("verify") || source_lower.contains("recover"));
            let has_each_validation = source_lower.contains("each")
                || (source_lower.contains("[i]") && source_lower.contains("signature"));

            if !has_individual_check && !has_each_validation {
                issues.push((
                    "Missing individual signature validation in aggregator".to_string(),
                    Severity::Critical,
                    "Validate each signature: for (uint i = 0; i < signatures.length; i++) { require(verify(userOps[i], signatures[i])); }".to_string()
                ));
            }

            // Check for aggregation bypass (accepting empty aggregator)
            let has_empty_check = source_lower.contains("length")
                && (source_lower.contains("> 0") || source_lower.contains("!= 0"));
            let has_count_validation =
                source_lower.contains("count") && source_lower.contains("require");

            if !has_empty_check && !has_count_validation {
                issues.push((
                    "No validation for empty signature batch (bypass risk)".to_string(),
                    Severity::High,
                    "Validate batch: require(signatures.length > 0 && signatures.length == userOps.length, \"Invalid batch\");".to_string()
                ));
            }

            // Check for missing signer verification
            let has_signer_check = source_lower.contains("signer")
                || (source_lower.contains("recover") && source_lower.contains("=="));
            let has_owner_validation =
                source_lower.contains("owner") && source_lower.contains("require");

            if !has_signer_check && !has_owner_validation {
                issues.push((
                    "No signer verification in signature validation".to_string(),
                    Severity::Critical,
                    "Verify signer: address signer = ECDSA.recover(hash, signature); require(signer == expectedSigner);".to_string()
                ));
            }

            // Check for signature malleability
            let has_malleability_check =
                source_lower.contains("uint256(s)") || source_lower.contains("malleability");

            if !has_malleability_check {
                issues.push((
                    "No signature malleability protection".to_string(),
                    Severity::Medium,
                    "Check malleability: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);".to_string()
                ));
            }
        }

        // Check aggregateSignatures function
        if name.contains("aggregate") && name.contains("signature") {
            // Check for proper signature format validation
            let has_format_check = source_lower.contains("length")
                && (source_lower.contains("== 65") || source_lower.contains("% 65"));

            if !has_format_check {
                issues.push((
                    "Missing signature format validation in aggregation".to_string(),
                    Severity::High,
                    "Validate format: require(signature.length == 65, \"Invalid signature length\");".to_string()
                ));
            }

            // Check for replay protection across aggregations
            let has_nonce = source_lower.contains("nonce");
            let has_unique_id =
                source_lower.contains("uniqueid") || source_lower.contains("requestid");

            if !has_nonce && !has_unique_id {
                issues.push((
                    "No replay protection in signature aggregation".to_string(),
                    Severity::High,
                    "Add replay protection: require(!usedHashes[aggregationHash], \"Already used\");".to_string()
                ));
            }
        }

        // Check validateUserOp with aggregator
        if name.contains("validateuserop") {
            // Check if aggregator is properly validated
            let has_aggregator_check = source_lower.contains("aggregator")
                && (source_lower.contains("!= address(0)")
                    || source_lower.contains("== address(0)"));

            if source_lower.contains("aggregator") && !has_aggregator_check {
                issues.push((
                    "Aggregator address not validated (anyone can set aggregator)".to_string(),
                    Severity::High,
                    "Validate aggregator: require(aggregator == address(0) || trustedAggregators[aggregator], \"Invalid aggregator\");".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for SignatureAggregationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SignatureAggregationDetector {
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

        if !self.is_signature_aggregator(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
