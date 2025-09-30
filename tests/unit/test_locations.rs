use ast::{SourceLocation, Position, SourceRange};
use std::path::PathBuf;

/// Unit tests for source location tracking
/// These tests must fail initially and pass after implementation

#[test]
fn test_position_creation() {
    let pos = Position::new(10, 5, 245);

    assert_eq!(pos.line(), 10);
    assert_eq!(pos.column(), 5);
    assert_eq!(pos.offset(), 245);
}

#[test]
fn test_position_ordering() {
    let pos1 = Position::new(1, 1, 0);
    let pos2 = Position::new(1, 5, 4);
    let pos3 = Position::new(2, 1, 10);

    assert!(pos1 < pos2);
    assert!(pos2 < pos3);
    assert!(pos1 < pos3);
}

#[test]
fn test_position_from_offset() {
    let source = "line1\nline2\nline3\nline4";

    let pos_start = Position::from_offset(source, 0);
    assert_eq!(pos_start.line(), 1);
    assert_eq!(pos_start.column(), 1);
    assert_eq!(pos_start.offset(), 0);

    let pos_newline = Position::from_offset(source, 5);
    assert_eq!(pos_newline.line(), 1);
    assert_eq!(pos_newline.column(), 6);

    let pos_second_line = Position::from_offset(source, 6);
    assert_eq!(pos_second_line.line(), 2);
    assert_eq!(pos_second_line.column(), 1);

    let pos_third_line = Position::from_offset(source, 12);
    assert_eq!(pos_third_line.line(), 3);
    assert_eq!(pos_third_line.column(), 1);
}

#[test]
fn test_position_to_offset() {
    let source = "line1\nline2\nline3\nline4";

    let pos1 = Position::new(1, 1, 0);
    assert_eq!(pos1.to_offset(source), 0);

    let pos2 = Position::new(2, 1, 6);
    assert_eq!(pos2.to_offset(source), 6);

    let pos3 = Position::new(2, 3, 8);
    assert_eq!(pos3.to_offset(source), 8);
}

#[test]
fn test_source_location_creation() {
    let start = Position::new(5, 10, 100);
    let end = Position::new(5, 20, 110);

    let location = SourceLocation::new(
        PathBuf::from("test.sol"),
        start,
        end,
    );

    assert_eq!(location.file().as_os_str(), "test.sol");
    assert_eq!(location.start(), &start);
    assert_eq!(location.end(), &end);
}

#[test]
fn test_source_location_span() {
    let start = Position::new(1, 1, 0);
    let end = Position::new(3, 5, 25);

    let location = SourceLocation::new(
        PathBuf::from("contract.sol"),
        start,
        end,
    );

    assert_eq!(location.line_span(), (1, 3));
    assert_eq!(location.column_span(), (1, 5));
    assert_eq!(location.byte_length(), 25);
}

#[test]
fn test_source_location_contains() {
    let start = Position::new(5, 1, 50);
    let end = Position::new(10, 20, 150);

    let location = SourceLocation::new(
        PathBuf::from("test.sol"),
        start,
        end,
    );

    // Position inside
    let inside = Position::new(7, 10, 100);
    assert!(location.contains(&inside));

    // Position at start
    assert!(location.contains(&start));

    // Position at end
    assert!(location.contains(&end));

    // Position before
    let before = Position::new(4, 5, 40);
    assert!(!location.contains(&before));

    // Position after
    let after = Position::new(11, 1, 160);
    assert!(!location.contains(&after));
}

#[test]
fn test_source_location_overlaps() {
    let loc1 = SourceLocation::new(
        PathBuf::from("test.sol"),
        Position::new(5, 1, 50),
        Position::new(10, 10, 150),
    );

    let loc2 = SourceLocation::new(
        PathBuf::from("test.sol"),
        Position::new(7, 5, 100),
        Position::new(12, 1, 200),
    );

    let loc3 = SourceLocation::new(
        PathBuf::from("test.sol"),
        Position::new(15, 1, 250),
        Position::new(20, 10, 350),
    );

    assert!(loc1.overlaps(&loc2));
    assert!(loc2.overlaps(&loc1));
    assert!(!loc1.overlaps(&loc3));
    assert!(!loc3.overlaps(&loc1));
}

#[test]
fn test_source_range_text_extraction() {
    let source = r#"pragma solidity ^0.8.0;

contract Test {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}"#;

    // Extract the contract name
    let contract_start = Position::from_offset(source, source.find("Test").unwrap());
    let contract_end = Position::from_offset(source, source.find("Test").unwrap() + 4);
    let contract_range = SourceRange::new(contract_start, contract_end);

    assert_eq!(contract_range.text(source), "Test");

    // Extract the function name
    let func_start = Position::from_offset(source, source.find("setValue").unwrap());
    let func_end = Position::from_offset(source, source.find("setValue").unwrap() + 8);
    let func_range = SourceRange::new(func_start, func_end);

    assert_eq!(func_range.text(source), "setValue");

    // Extract a full line
    let line_start = Position::from_offset(source, source.find("uint256 public value").unwrap());
    let line_end = Position::from_offset(source, source.find("uint256 public value;").unwrap() + 21);
    let line_range = SourceRange::new(line_start, line_end);

    assert_eq!(line_range.text(source), "uint256 public value;");
}

#[test]
fn test_source_location_with_unicode() {
    let source = "// 한글 주석\ncontract 测试 {\n    // ٱلْعَرَبِيَّة\n}";

    // Test position calculation with Unicode characters
    let contract_pos = Position::from_offset(source, source.find("contract").unwrap());
    assert_eq!(contract_pos.line(), 2);
    assert_eq!(contract_pos.column(), 1);

    let test_pos = Position::from_offset(source, source.find("测试").unwrap());
    assert_eq!(test_pos.line(), 2);
    assert_eq!(test_pos.column(), 10); // After "contract "

    // Test text extraction with Unicode
    let test_start = Position::from_offset(source, source.find("测试").unwrap());
    let test_end = Position::from_offset(source, source.find("测试").unwrap() + "测试".len());
    let test_range = SourceRange::new(test_start, test_end);

    assert_eq!(test_range.text(source), "测试");
}

#[test]
fn test_source_location_multiline_span() {
    let source = r#"function complexFunction(
    address param1,
    uint256 param2,
    bool param3
) public pure returns (
    bool success,
    bytes memory data
) {
    return (true, "");
}"#;

    let func_start = Position::from_offset(source, 0);
    let func_end = Position::from_offset(source, source.len() - 1);

    let location = SourceLocation::new(
        PathBuf::from("multiline.sol"),
        func_start,
        func_end,
    );

    assert_eq!(location.line_span(), (1, 10));
    assert!(location.is_multiline());

    // Test context extraction
    let context = location.context_lines(source, 1);
    assert!(context.len() > 1);
    assert!(context[0].contains("function complexFunction"));
}

#[test]
fn test_source_location_error_reporting() {
    let source = r#"contract ErrorExample {
    function badFunction() public {
        // This line has an error
        uint256 x = undefinedVariable;
        return x;
    }
}"#;

    let error_start = Position::from_offset(source, source.find("undefinedVariable").unwrap());
    let error_end = Position::from_offset(source, source.find("undefinedVariable").unwrap() + 17);

    let error_location = SourceLocation::new(
        PathBuf::from("error.sol"),
        error_start,
        error_end,
    );

    // Test error context generation
    let error_context = error_location.error_context(source);
    assert!(error_context.contains("undefinedVariable"));
    assert!(error_context.contains("^")); // Should show caret pointing to error

    // Test line/column display
    let display = error_location.display_position();
    assert!(display.contains("4:")); // Line 4
    assert!(display.contains("21:")); // Approximate column
}

#[test]
fn test_source_location_performance() {
    use std::time::Instant;

    // Generate a large source file
    let mut large_source = String::new();
    for i in 0..1000 {
        large_source.push_str(&format!("    uint256 variable_{};\n", i));
    }

    let start = Instant::now();

    // Perform many position calculations
    for i in 0..100 {
        let offset = large_source.find(&format!("variable_{}", i * 10)).unwrap_or(0);
        let _pos = Position::from_offset(&large_source, offset);
    }

    let duration = start.elapsed();

    // Should be fast even for large files
    assert!(duration.as_millis() < 10);
}

#[test]
fn test_source_location_serialization() {
    use serde_json;

    let location = SourceLocation::new(
        PathBuf::from("/path/to/contract.sol"),
        Position::new(42, 15, 1024),
        Position::new(42, 25, 1034),
    );

    // Test serialization
    let serialized = serde_json::to_string(&location).unwrap();
    assert!(serialized.contains("contract.sol"));
    assert!(serialized.contains("42"));
    assert!(serialized.contains("15"));

    // Test deserialization
    let deserialized: SourceLocation = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.file(), location.file());
    assert_eq!(deserialized.start(), location.start());
    assert_eq!(deserialized.end(), location.end());
}

#[test]
fn test_source_location_relative_paths() {
    let location1 = SourceLocation::new(
        PathBuf::from("contracts/Token.sol"),
        Position::new(1, 1, 0),
        Position::new(1, 10, 9),
    );

    let location2 = SourceLocation::new(
        PathBuf::from("./contracts/Token.sol"),
        Position::new(1, 1, 0),
        Position::new(1, 10, 9),
    );

    // Test path normalization
    assert_eq!(location1.normalized_path(), location2.normalized_path());

    // Test relative path display
    let display1 = location1.relative_display("/project");
    let display2 = location2.relative_display("/project");
    assert_eq!(display1, display2);
}