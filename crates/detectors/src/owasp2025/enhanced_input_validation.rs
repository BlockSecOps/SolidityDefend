//! Enhanced Input Validation Detector (OWASP 2025)
//!
//! Detects missing comprehensive bounds checking that led to $14.6M in losses.
//! Array length validation, parameter bounds, zero-value checks.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EnhancedInputValidationDetector {
    base: BaseDetector,
}

impl EnhancedInputValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("enhanced-input-validation".to_string()),
                "Enhanced Input Validation".to_string(),
                "Detects missing bounds checking and array validation ($14.6M impact)".to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }
}

impl Default for EnhancedInputValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EnhancedInputValidationDetector {
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
        let source = &ctx.source_code;

        // Check for array access without length validation
        if source.contains("[") && source.contains("]") {
            let has_length_check = source.contains(".length")
                && (source.contains("require") || source.contains("if"));

            if !has_length_check {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    "Array access without length validation - can cause out-of-bounds access".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                ).with_fix_suggestion(
                    "❌ MISSING ARRAY VALIDATION (OWASP 2025 - $14.6M impact):\n\
                     function process(uint256[] calldata ids) external {\n\
                         for (uint256 i = 0; i < ids.length; i++) {\n\
                             // What if ids is empty? Or too large?\n\
                         }\n\
                     }\n\
                     \n\
                     ✅ VALIDATE ARRAY LENGTH:\n\
                     function process(uint256[] calldata ids) external {\n\
                         // Check minimum length\n\
                         require(ids.length > 0, \"Empty array\");\n\
                         \n\
                         // Check maximum length (prevent DoS)\n\
                         require(ids.length <= MAX_BATCH_SIZE, \"Batch too large\");\n\
                         \n\
                         for (uint256 i = 0; i < ids.length; i++) {\n\
                             // Safe to access ids[i]\n\
                         }\n\
                     }\n\
                     \n\
                     ✅ VALIDATE ARRAY MATCHING:\n\
                     function batchTransfer(\n\
                         address[] calldata recipients,\n\
                         uint256[] calldata amounts\n\
                     ) external {\n\
                         // Arrays must match in length\n\
                         require(\n\
                             recipients.length == amounts.length,\n\
                             \"Length mismatch\"\n\
                         );\n\
                         require(recipients.length > 0, \"Empty arrays\");\n\
                         require(recipients.length <= MAX_BATCH, \"Too many\");\n\
                         \n\
                         for (uint256 i = 0; i < recipients.length; i++) {\n\
                             // Safe parallel access\n\
                         }\n\
                     }".to_string()
                );
                findings.push(finding);
            }
        }

        // Check for transfer/payment functions without zero-value check
        let has_transfer = source.contains("transfer") || source.contains("send")
            || source.contains("call{value:");
        let has_amount = source.contains("amount") || source.contains("value");
        let has_zero_check = source.contains("amount > 0") || source.contains("amount != 0")
            || source.contains("value > 0") || source.contains("value != 0");

        if has_transfer && has_amount && !has_zero_check {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Transfer function without zero-value check - validate non-zero amounts".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            ).with_fix_suggestion(
                "❌ MISSING ZERO-VALUE CHECK:\n\
                 function transfer(address to, uint256 amount) external {\n\
                     _transfer(msg.sender, to, amount);\n\
                     // What if amount is 0? Wastes gas, may break accounting\n\
                 }\n\
                 \n\
                 ✅ VALIDATE NON-ZERO:\n\
                 function transfer(address to, uint256 amount) external {\n\
                     require(amount > 0, \"Zero amount\");\n\
                     require(to != address(0), \"Zero address\");\n\
                     _transfer(msg.sender, to, amount);\n\
                 }\n\
                 \n\
                 ✅ COMPLETE VALIDATION:\n\
                 function deposit(uint256 amount) external payable {\n\
                     // For ERC20 deposits\n\
                     require(amount > 0, \"Zero amount\");\n\
                     require(amount <= MAX_DEPOSIT, \"Exceeds maximum\");\n\
                     \n\
                     // For native ETH deposits\n\
                     if (msg.value > 0) {\n\
                         require(msg.value == amount, \"Value mismatch\");\n\
                     }\n\
                     \n\
                     // Proceed with deposit\n\
                 }".to_string()
            );
            findings.push(finding);
        }

        // Check for missing address validation
        let has_address_param = source.contains("address") && source.contains("function");
        let has_address_check = source.contains("address(0)")
            && (source.contains("require") || source.contains("if"));

        if has_address_param && !has_address_check {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Address parameter without zero-address validation".to_string(),
                1,
                0,
                20,
                Severity::Medium,
            ).with_fix_suggestion(
                "❌ MISSING ADDRESS VALIDATION:\n\
                 function setOwner(address newOwner) external {\n\
                     owner = newOwner;  // What if newOwner is address(0)?\n\
                 }\n\
                 \n\
                 ✅ VALIDATE ADDRESS:\n\
                 function setOwner(address newOwner) external onlyOwner {\n\
                     require(newOwner != address(0), \"Zero address\");\n\
                     require(newOwner != owner, \"Same address\");\n\
                     owner = newOwner;\n\
                 }\n\
                 \n\
                 ✅ VALIDATE MULTIPLE ADDRESSES:\n\
                 function initialize(\n\
                     address _token,\n\
                     address _oracle,\n\
                     address _treasury\n\
                 ) external {\n\
                     require(_token != address(0), \"Zero token\");\n\
                     require(_oracle != address(0), \"Zero oracle\");\n\
                     require(_treasury != address(0), \"Zero treasury\");\n\
                     \n\
                     // Check for duplicates if needed\n\
                     require(_token != _oracle, \"Token == oracle\");\n\
                     require(_token != _treasury, \"Token == treasury\");\n\
                     \n\
                     token = _token;\n\
                     oracle = _oracle;\n\
                     treasury = _treasury;\n\
                 }".to_string()
            );
            findings.push(finding);
        }

        // Check for percentage/ratio validation
        let has_percentage = source.contains("percent") || source.contains("ratio")
            || source.contains("fee") || source.contains("basis");

        if has_percentage && source.contains("function") {
            let has_bounds = source.contains("<=") || source.contains("<");

            if !has_bounds {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    "Percentage/fee parameter without bounds validation".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                ).with_fix_suggestion(
                    "❌ UNBOUNDED PERCENTAGE:\n\
                     function setFee(uint256 newFee) external {\n\
                         fee = newFee;  // Could be set to 100% or higher!\n\
                     }\n\
                     \n\
                     ✅ VALIDATE PERCENTAGE BOUNDS:\n\
                     uint256 public constant MAX_FEE = 1000;  // 10% in basis points\n\
                     uint256 public constant BASIS_POINTS = 10000;  // 100%\n\
                     \n\
                     function setFee(uint256 newFee) external onlyOwner {\n\
                         require(newFee <= MAX_FEE, \"Fee too high\");\n\
                         fee = newFee;\n\
                     }\n\
                     \n\
                     ✅ COMPREHENSIVE RATIO VALIDATION:\n\
                     function setCollateralRatio(uint256 ratio) external {\n\
                         // Must be between 110% and 200%\n\
                         uint256 MIN_RATIO = 11000;  // 110%\n\
                         uint256 MAX_RATIO = 20000;  // 200%\n\
                         \n\
                         require(ratio >= MIN_RATIO, \"Ratio too low\");\n\
                         require(ratio <= MAX_RATIO, \"Ratio too high\");\n\
                         collateralRatio = ratio;\n\
                     }".to_string()
                );
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
