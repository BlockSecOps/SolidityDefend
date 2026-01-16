use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via unbounded storage operations
///
/// Detects patterns where storage operations grow without bounds,
/// making subsequent operations increasingly expensive.
pub struct DosUnboundedStorageDetector {
    base: BaseDetector,
}

impl Default for DosUnboundedStorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosUnboundedStorageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-unbounded-storage"),
                "DoS Unbounded Storage".to_string(),
                "Detects unbounded storage operations that can lead to denial of service \
                 through excessive gas costs or storage exhaustion."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find unbounded storage arrays
    fn find_unbounded_arrays(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect array state variable declarations
            if trimmed.contains("[]") && !trimmed.contains("memory") && !trimmed.contains("calldata")
                && (trimmed.contains("public") || trimmed.contains("private") || trimmed.contains("internal"))
            {
                // Check if it's a state variable (contains type + visibility)
                if trimmed.contains("address") || trimmed.contains("uint") || trimmed.contains("bytes")
                    || trimmed.contains("string") || trimmed.contains("struct")
                {
                    if let Some(var_name) = self.extract_variable_name(trimmed) {
                        // Check if there's a max length check when pushing
                        if !self.has_length_check(source, &var_name) {
                            findings.push((line_num as u32 + 1, var_name));
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find unbounded mapping of arrays
    fn find_unbounded_mapping_arrays(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect mapping to array pattern
            if trimmed.contains("mapping(") && trimmed.contains("[]") {
                if let Some(var_name) = self.extract_variable_name(trimmed) {
                    // Check for push without bounds
                    if self.has_unbounded_push(source, &var_name) {
                        findings.push((line_num as u32 + 1, var_name));
                    }
                }
            }
        }

        findings
    }

    /// Find storage deletion in loops
    fn find_deletion_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let func_name = self.find_containing_function(&lines, line_num);
                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for delete operations in loop
                if loop_body.contains("delete ") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find nested mappings that grow unbounded
    fn find_nested_mapping_growth(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect nested mapping assignments in external functions
            if trimmed.contains("function ")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Skip standard ERC20/ERC721 approve patterns - this is expected behavior
                if self.is_standard_token_pattern(&func_name, &func_body) {
                    continue;
                }

                // Check for nested mapping writes
                if func_body.contains("][") && func_body.contains("=")
                    && !func_body.contains("require") && !func_body.contains("onlyOwner")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Check if this is a standard token pattern (ERC20/ERC721 approve)
    fn is_standard_token_pattern(&self, func_name: &str, func_body: &str) -> bool {
        // Skip ERC20/ERC721 approve functions - standard expected behavior
        if func_name == "approve" || func_name == "_approve" {
            if func_body.contains("allowance") || func_body.contains("Approval") {
                return true;
            }
        }

        // Skip ERC721 setApprovalForAll
        if func_name == "setApprovalForAll" || func_name == "_setApprovalForAll" {
            if func_body.contains("operatorApprovals") || func_body.contains("ApprovalForAll") {
                return true;
            }
        }

        // Skip permit functions (EIP-2612)
        if func_name == "permit" {
            if func_body.contains("allowance") || func_body.contains("nonces") {
                return true;
            }
        }

        false
    }

    fn extract_variable_name(&self, line: &str) -> Option<String> {
        // Extract variable name from declaration
        let parts: Vec<&str> = line.split(|c: char| c.is_whitespace() || c == ';').collect();

        for (i, part) in parts.iter().enumerate() {
            if part.contains("[]") || *part == "public" || *part == "private" || *part == "internal" {
                // Look for the identifier (usually after [] or visibility)
                if i + 1 < parts.len() && !parts[i + 1].is_empty()
                   && !["public", "private", "internal", "=", ";"].contains(&parts[i + 1])
                {
                    return Some(parts[i + 1].trim_matches(';').to_string());
                }
            }
        }

        // Alternative: last identifier before = or ;
        let trimmed = line.trim().trim_end_matches(';');
        if let Some(eq_pos) = trimmed.find('=') {
            let before_eq = &trimmed[..eq_pos];
            let tokens: Vec<&str> = before_eq.split_whitespace().collect();
            if let Some(last) = tokens.last() {
                return Some(last.to_string());
            }
        } else {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(last) = tokens.last() {
                return Some(last.to_string());
            }
        }

        None
    }

    fn has_length_check(&self, source: &str, array_name: &str) -> bool {
        // Check if there's a length validation before push
        let check_pattern = format!("{}.length", array_name);
        let push_pattern = format!("{}.push", array_name);

        if source.contains(&push_pattern) {
            // Look for require with length check
            for line in source.lines() {
                if line.contains("require") && line.contains(&check_pattern) {
                    return true;
                }
            }
        }
        false
    }

    fn has_unbounded_push(&self, source: &str, var_name: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for push to this mapping's array
            if trimmed.contains(&format!("{}[", var_name)) && trimmed.contains(".push(") {
                // Check if the containing function has bounds
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_block_end(&lines, func_start);
                let func_body: String = lines[func_start..func_end].join("\n");

                if !func_body.contains(".length <") && !func_body.contains(".length <=") {
                    return true;
                }
            }
        }
        false
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_block_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DosUnboundedStorageDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, array_name) in self.find_unbounded_arrays(source) {
            let message = format!(
                "Contract '{}' has unbounded storage array '{}'. \
                 Users can grow array indefinitely, causing gas issues.",
                contract_name, array_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Bound storage array growth:\n\n\
                     1. Add maximum size constant:\n\
                     uint256 constant MAX_SIZE = 1000;\n\n\
                     2. Check before push:\n\
                     require(array.length < MAX_SIZE, \"Max size reached\");\n\n\
                     3. Consider using mapping with index counter"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, mapping_name) in self.find_unbounded_mapping_arrays(source) {
            let message = format!(
                "Contract '{}' has unbounded mapping array '{}'. \
                 Each user can grow their array without limits.",
                contract_name, mapping_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit per-user array growth:\n\n\
                     mapping(address => uint256[]) userItems;\n\
                     uint256 constant MAX_ITEMS_PER_USER = 100;\n\n\
                     require(\n\
                         userItems[msg.sender].length < MAX_ITEMS_PER_USER,\n\
                         \"Max items reached\"\n\
                     );"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_deletion_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' deletes storage in a loop. \
                 Large arrays will exceed gas limits during deletion.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid bulk storage deletion:\n\n\
                     1. Delete in batches with pagination\n\
                     2. Mark as deleted instead of actual delete\n\
                     3. Use mapping with version counter\n\
                     4. Let storage be overwritten naturally"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_nested_mapping_growth(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows unbounded nested mapping writes. \
                 Attackers can bloat storage without restrictions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Restrict nested mapping writes:\n\n\
                     1. Add access control\n\
                     2. Limit entries per user\n\
                     3. Require payment to cover storage costs\n\
                     4. Implement cleanup mechanisms"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DosUnboundedStorageDetector::new();
        assert_eq!(detector.name(), "DoS Unbounded Storage");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
