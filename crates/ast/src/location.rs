use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};

/// A position in source code, tracking line, column, and byte offset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Position {
    /// 1-based line number
    line: usize,
    /// 1-based column number
    column: usize,
    /// 0-based byte offset from start of file
    offset: usize,
}

impl Position {
    /// Create a new position
    pub fn new(line: usize, column: usize, offset: usize) -> Self {
        Self {
            line,
            column,
            offset,
        }
    }

    /// Get the line number (1-based)
    pub fn line(&self) -> usize {
        self.line
    }

    /// Get the column number (1-based)
    pub fn column(&self) -> usize {
        self.column
    }

    /// Get the byte offset (0-based)
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Create a position from a byte offset in source text
    pub fn from_offset(source: &str, offset: usize) -> Self {
        let mut line = 1;
        let mut column = 1;
        let mut current_offset = 0;

        for ch in source.chars() {
            if current_offset >= offset {
                break;
            }

            if ch == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }

            current_offset += ch.len_utf8();
        }

        Self {
            line,
            column,
            offset,
        }
    }

    /// Convert position back to byte offset (validates against source)
    pub fn to_offset(&self, source: &str) -> usize {
        let mut line = 1;
        let mut column = 1;
        let mut offset = 0;

        for ch in source.chars() {
            if line == self.line && column == self.column {
                return offset;
            }

            if ch == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }

            offset += ch.len_utf8();
        }

        offset
    }

    /// Create a position at the start of a file
    pub fn start() -> Self {
        Self::new(1, 1, 0)
    }

    /// Advance position by one character
    pub fn advance(mut self, ch: char) -> Self {
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        self.offset += ch.len_utf8();
        self
    }
}

impl PartialOrd for Position {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Position {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset.cmp(&other.offset)
    }
}

impl Default for Position {
    fn default() -> Self {
        Self::start()
    }
}

/// A range of text in source code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceRange {
    start: Position,
    end: Position,
}

impl SourceRange {
    /// Create a new source range
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }

    /// Get the start position
    pub fn start(&self) -> &Position {
        &self.start
    }

    /// Get the end position
    pub fn end(&self) -> &Position {
        &self.end
    }

    /// Check if this range contains a position
    pub fn contains(&self, pos: &Position) -> bool {
        self.start <= *pos && *pos <= self.end
    }

    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &SourceRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Extract the text covered by this range from source
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        let start_offset = self.start.offset;
        let end_offset = self.end.offset;

        &source[start_offset..end_offset.min(source.len())]
    }

    /// Get the byte length of this range
    pub fn len(&self) -> usize {
        self.end.offset.saturating_sub(self.start.offset)
    }

    /// Check if this range is empty
    pub fn is_empty(&self) -> bool {
        self.start.offset >= self.end.offset
    }

    /// Create a range spanning a single position
    pub fn single(pos: Position) -> Self {
        Self {
            start: pos,
            end: pos,
        }
    }
}

/// Complete source location information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    file: PathBuf,
    start: Position,
    end: Position,
}

impl SourceLocation {
    /// Create a new source location
    pub fn new(file: PathBuf, start: Position, end: Position) -> Self {
        Self { file, start, end }
    }

    /// Get the file path
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Get the start position
    pub fn start(&self) -> &Position {
        &self.start
    }

    /// Get the end position
    pub fn end(&self) -> &Position {
        &self.end
    }

    /// Get line span (start_line, end_line)
    pub fn line_span(&self) -> (usize, usize) {
        (self.start.line, self.end.line)
    }

    /// Get column span (start_column, end_column)
    pub fn column_span(&self) -> (usize, usize) {
        (self.start.column, self.end.column)
    }

    /// Get the byte length of this location
    pub fn byte_length(&self) -> usize {
        self.end.offset.saturating_sub(self.start.offset)
    }

    /// Check if this location spans multiple lines
    pub fn is_multiline(&self) -> bool {
        self.start.line != self.end.line
    }

    /// Check if this location contains a position
    pub fn contains(&self, pos: &Position) -> bool {
        self.start <= *pos && *pos <= self.end
    }

    /// Check if this location overlaps with another
    pub fn overlaps(&self, other: &SourceLocation) -> bool {
        self.file == other.file &&
        self.start <= other.end &&
        other.start <= self.end
    }

    /// Get context lines around this location
    pub fn context_lines(&self, source: &str, context: usize) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let start_line = self.start.line.saturating_sub(1).saturating_sub(context);
        let end_line = (self.end.line + context).min(lines.len());

        lines[start_line..end_line]
            .iter()
            .map(|line| line.to_string())
            .collect()
    }

    /// Generate error context with caret pointing to location
    pub fn error_context(&self, source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        if self.start.line == 0 || self.start.line > lines.len() {
            return String::new();
        }

        let line = lines[self.start.line - 1];
        let mut context = format!("{}\n", line);

        // Add caret line
        let spaces = " ".repeat(self.start.column.saturating_sub(1));
        let carets = "^".repeat((self.end.column - self.start.column).max(1));
        context.push_str(&format!("{}{}", spaces, carets));

        context
    }

    /// Display position in "file:line:column" format
    pub fn display_position(&self) -> String {
        format!("{}:{}:{}",
                self.file.display(),
                self.start.line,
                self.start.column)
    }

    /// Get normalized file path (resolving relative paths)
    pub fn normalized_path(&self) -> PathBuf {
        // Normalize path by resolving . and .. components
        let mut normalized = PathBuf::new();
        for component in self.file.components() {
            match component {
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::CurDir => {
                    // Skip current directory
                }
                _ => {
                    normalized.push(component);
                }
            }
        }
        normalized
    }

    /// Display path relative to a base directory
    pub fn relative_display(&self, base: &str) -> String {
        let base_path = Path::new(base);
        let normalized = self.normalized_path();

        match normalized.strip_prefix(base_path) {
            Ok(relative) => format!("{}:{}:{}",
                                  relative.display(),
                                  self.start.line,
                                  self.start.column),
            Err(_) => self.display_position(),
        }
    }

    /// Convert to a SourceRange
    pub fn to_range(&self) -> SourceRange {
        SourceRange::new(self.start, self.end)
    }

    /// Create a location spanning a single position
    pub fn single(file: PathBuf, pos: Position) -> Self {
        Self {
            file,
            start: pos,
            end: pos,
        }
    }

    /// Create a location at the start of a file
    pub fn file_start(file: PathBuf) -> Self {
        let pos = Position::start();
        Self {
            file,
            start: pos,
            end: pos,
        }
    }
}

impl Default for SourceLocation {
    fn default() -> Self {
        Self {
            file: PathBuf::new(),
            start: Position::default(),
            end: Position::default(),
        }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}",
               self.file.display(),
               self.start.line,
               self.start.column)
    }
}

/// Trait for AST nodes that have source location information
pub trait Located {
    /// Get the source location of this node
    fn location(&self) -> &SourceLocation;

    /// Get the source file of this node
    fn file(&self) -> &Path {
        self.location().file()
    }

    /// Get the start position of this node
    fn start(&self) -> &Position {
        self.location().start()
    }

    /// Get the end position of this node
    fn end(&self) -> &Position {
        self.location().end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_basic() {
        let pos = Position::new(10, 5, 245);
        assert_eq!(pos.line(), 10);
        assert_eq!(pos.column(), 5);
        assert_eq!(pos.offset(), 245);
    }

    #[test]
    fn test_position_from_offset() {
        let source = "line1\nline2\nline3";

        let pos0 = Position::from_offset(source, 0);
        assert_eq!(pos0.line(), 1);
        assert_eq!(pos0.column(), 1);

        let pos6 = Position::from_offset(source, 6);
        assert_eq!(pos6.line(), 2);
        assert_eq!(pos6.column(), 1);
    }

    #[test]
    fn test_source_range() {
        let start = Position::new(1, 1, 0);
        let end = Position::new(1, 5, 4);
        let range = SourceRange::new(start, end);

        let mid = Position::new(1, 3, 2);
        assert!(range.contains(&mid));
        assert!(range.contains(&start));
        assert!(range.contains(&end));

        let outside = Position::new(1, 10, 9);
        assert!(!range.contains(&outside));
    }

    #[test]
    fn test_source_location() {
        let location = SourceLocation::new(
            PathBuf::from("test.sol"),
            Position::new(5, 1, 50),
            Position::new(10, 20, 150),
        );

        assert_eq!(location.line_span(), (5, 10));
        assert_eq!(location.byte_length(), 100);
        assert!(location.is_multiline());
    }
}