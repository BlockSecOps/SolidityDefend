/// Taint sanitizers - mechanisms that clean or validate tainted data
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum TaintSanitizer {
    RequireStatement,     // require()
    AssertStatement,      // assert()
    RevertStatement,      // revert()
    AccessControl,        // onlyOwner, onlyAdmin, etc.
    BoundsCheck,          // Array bounds checking
    NullCheck,           // Null/zero address checking
    TypeCast,            // Type conversions
    Hashing,             // keccak256, sha256, etc.
    Custom(String),      // Custom sanitizer
}

/// Detector for taint sanitizers
pub struct SanitizerDetector;

impl SanitizerDetector {
    pub fn detect_sanitizers(code: &str) -> Vec<(usize, TaintSanitizer)> {
        let mut sanitizers = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_number = line_idx + 1;

            // Check for various sanitizers
            if line.contains("require(") {
                sanitizers.push((line_number, TaintSanitizer::RequireStatement));
            }
            if line.contains("assert(") {
                sanitizers.push((line_number, TaintSanitizer::AssertStatement));
            }
            if line.contains("revert(") {
                sanitizers.push((line_number, TaintSanitizer::RevertStatement));
            }
            if line.contains("onlyOwner") || line.contains("onlyAdmin") || line.contains("restricted") {
                sanitizers.push((line_number, TaintSanitizer::AccessControl));
            }
            if Self::has_bounds_check(line) {
                sanitizers.push((line_number, TaintSanitizer::BoundsCheck));
            }
            if Self::has_null_check(line) {
                sanitizers.push((line_number, TaintSanitizer::NullCheck));
            }
            if line.contains("keccak256") || line.contains("sha256") || line.contains("ripemd160") {
                sanitizers.push((line_number, TaintSanitizer::Hashing));
            }
        }

        sanitizers
    }

    fn has_bounds_check(line: &str) -> bool {
        line.contains("< length") || line.contains("> 0") ||
        line.contains("<=") || line.contains(">=") ||
        line.contains("bounds") || line.contains("range")
    }

    fn has_null_check(line: &str) -> bool {
        line.contains("!= address(0)") || line.contains("!= 0") ||
        line.contains("== address(0)") || line.contains("== 0")
    }
}