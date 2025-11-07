//! Post-0.8.0 Overflow Detector (OWASP 2025)
//!
//! Detects unchecked block overflows and assembly arithmetic.
//! Even with Solidity 0.8.0+ overflow protection, unchecked blocks bypass it.
//! $223M Cetus DEX hack (May 2025) was caused by assembly overflow.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct Post080OverflowDetector {
    base: BaseDetector,
}

impl Post080OverflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("post-080-overflow".to_string()),
                "Post-0.8.0 Overflow Detection".to_string(),
                "Detects unchecked blocks and assembly arithmetic ($223M Cetus impact)".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }
}

impl Default for Post080OverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Post080OverflowDetector {
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

        // Check for unchecked blocks
        if source.contains("unchecked") {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Unchecked block found - overflows/underflows won't revert (OWASP 2025)"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "⚠️ UNCHECKED BLOCKS BYPASS SOLIDITY 0.8.0+ PROTECTION!\n\
                 \n\
                 Solidity 0.8.0+ has automatic overflow/underflow checks,\n\
                 but 'unchecked' blocks disable this protection.\n\
                 \n\
                 ❌ DANGEROUS if user input involved:\n\
                 unchecked {\n\
                     balance += amount;  // Can overflow!\n\
                     total = a * b;      // Can overflow!\n\
                 }\n\
                 \n\
                 ✅ SAFE usage (loop counters only):\n\
                 for (uint256 i = 0; i < items.length;) {\n\
                     // Process items[i]\n\
                     \n\
                     unchecked {\n\
                         ++i;  // Safe: loop counter can't realistically overflow\n\
                     }\n\
                 }\n\
                 \n\
                 ✅ SAFE usage (guaranteed no overflow):\n\
                 unchecked {\n\
                     // Safe: subtraction after comparison\n\
                     if (a >= b) {\n\
                         result = a - b;  // No underflow possible\n\
                     }\n\
                 }\n\
                 \n\
                 ❌ NEVER use unchecked for:\n\
                 - User-supplied values\n\
                 - Token amounts\n\
                 - Financial calculations\n\
                 - Multiplication of arbitrary values\n\
                 \n\
                 Only use unchecked when:\n\
                 1. Loop counters (i++, ++i)\n\
                 2. Mathematically proven safe\n\
                 3. Gas optimization with careful review"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for assembly arithmetic
        if source.contains("assembly") {
            let has_arithmetic = source.contains("add(")
                || source.contains("sub(")
                || source.contains("mul(")
                || source.contains("div(");

            if has_arithmetic {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        "Assembly arithmetic detected - no overflow protection! ($223M Cetus DEX)"
                            .to_string(),
                        1,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion(
                        "🚨 CRITICAL: Assembly has NO overflow protection!\n\
                     \n\
                     Real incident: Cetus DEX - $223M loss (May 2025)\n\
                     Cause: Assembly arithmetic overflow\n\
                     \n\
                     ❌ VULNERABLE (Cetus-style vulnerability):\n\
                     assembly {\n\
                         let result := add(a, b)  // NO OVERFLOW CHECK!\n\
                         let product := mul(x, y) // NO OVERFLOW CHECK!\n\
                         mstore(0x00, result)\n\
                     }\n\
                     \n\
                     ✅ SOLUTION 1 - Add manual checks:\n\
                     assembly {\n\
                         let result := add(a, b)\n\
                         // Manual overflow check\n\
                         if lt(result, a) {\n\
                             revert(0, 0)  // Overflow detected\n\
                         }\n\
                     }\n\
                     \n\
                     ✅ SOLUTION 2 - Use Solidity instead:\n\
                     // Let Solidity handle overflow checks\n\
                     uint256 result = a + b;  // Automatic overflow check\n\
                     \n\
                     ✅ SOLUTION 3 - SafeMath for assembly:\n\
                     function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {\n\
                         uint256 c;\n\
                         assembly {\n\
                             c := add(a, b)\n\
                         }\n\
                         require(c >= a, \"Overflow\");  // Check outside assembly\n\
                         return c;\n\
                     }\n\
                     \n\
                     Assembly arithmetic operations with NO checks:\n\
                     - add(a, b)     → wraps on overflow\n\
                     - sub(a, b)     → wraps on underflow\n\
                     - mul(a, b)     → wraps on overflow\n\
                     - div(a, b)     → returns 0 if b is 0 (no revert!)\n\
                     \n\
                     ⚠️ Only use assembly arithmetic when absolutely necessary\n\
                     and with manual overflow checks!"
                            .to_string(),
                    );
                findings.push(finding);
            }
        }

        // Check for assembly division by zero
        if source.contains("assembly") && source.contains("div(") {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Assembly division - no automatic division-by-zero protection".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "❌ ASSEMBLY DIVISION - NO PROTECTION:\n\
                 assembly {\n\
                     let result := div(a, b)  // Returns 0 if b == 0, NO REVERT!\n\
                 }\n\
                 \n\
                 ✅ ADD MANUAL CHECK:\n\
                 assembly {\n\
                     // Check divisor is not zero\n\
                     if iszero(b) {\n\
                         revert(0, 0)\n\
                     }\n\
                     let result := div(a, b)\n\
                 }\n\
                 \n\
                 ✅ BETTER - Use Solidity:\n\
                 uint256 result = a / b;  // Automatic div-by-zero check\n\
                 \n\
                 Assembly division behavior:\n\
                 - div(a, 0) = 0  (no revert!)\n\
                 - Solidity a / 0 = REVERT\n\
                 \n\
                 Same issue with mod:\n\
                 - mod(a, 0) = 0  (no revert!)\n\
                 - Solidity a % 0 = REVERT"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for type casting that might overflow
        if (source.contains("uint8") || source.contains("uint16") || source.contains("uint32"))
            && source.contains("uint256")
        {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Type casting to smaller uint - verify no overflow on downcast".to_string(),
                    1,
                    0,
                    20,
                    Severity::Low,
                )
                .with_fix_suggestion(
                    "Downcasting can silently overflow even in Solidity 0.8.0+!\n\
                     \n\
                     ❌ UNSAFE DOWNCAST:\n\
                     uint256 bigValue = 1000;\n\
                     uint8 smallValue = uint8(bigValue);  // Wraps to 232! (1000 % 256)\n\
                     \n\
                     ✅ SAFE DOWNCAST with validation:\n\
                     uint256 bigValue = 1000;\n\
                     require(bigValue <= type(uint8).max, \"Value too large\");\n\
                     uint8 smallValue = uint8(bigValue);  // Safe now\n\
                     \n\
                     ✅ USE SafeCast library (OpenZeppelin):\n\
                     import \"@openzeppelin/contracts/utils/math/SafeCast.sol\";\n\
                     \n\
                     uint256 bigValue = 1000;\n\
                     uint8 smallValue = SafeCast.toUint8(bigValue);  // Reverts if > 255\n\
                     \n\
                     Type limits:\n\
                     - uint8:   0 to 255\n\
                     - uint16:  0 to 65,535\n\
                     - uint32:  0 to 4,294,967,295\n\
                     - uint64:  0 to 18,446,744,073,709,551,615\n\
                     - uint256: 0 to 2^256-1"
                        .to_string(),
                );
            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
