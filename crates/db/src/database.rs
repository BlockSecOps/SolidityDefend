use std::path::PathBuf;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

use ast::{AstArena, SourceFile, Visibility};
use parser::{Parser, ParseErrors};

/// Source file identifier for Salsa database
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
pub struct SourceFileId(usize);

impl SourceFileId {
    pub fn new(id: usize) -> Self {
        SourceFileId(id)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for SourceFileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SourceFile({})", self.0)
    }
}

/// Input file content with metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Serialize, Deserialize)]
pub struct SourceFileInput {
    pub path: PathBuf,
    pub content: String,
    pub content_hash: String,
}

impl SourceFileInput {
    pub fn new(path: impl Into<PathBuf>, content: impl Into<String>) -> Self {
        let content = content.into();
        let content_hash = Self::compute_hash(&content);

        Self {
            path: path.into(),
            content,
            content_hash,
        }
    }

    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn update_content(&mut self, new_content: impl Into<String>) {
        self.content = new_content.into();
        self.content_hash = Self::compute_hash(&self.content);
    }
}

/// Parse result containing AST or error information
#[derive(Debug, Clone)]
pub enum ParseResult<'arena> {
    Success(SourceFile<'arena>),
    Error(ParseErrors),
}

impl<'arena> ParseResult<'arena> {
    pub fn is_ok(&self) -> bool {
        matches!(self, ParseResult::Success(_))
    }

    pub fn is_err(&self) -> bool {
        matches!(self, ParseResult::Error(_))
    }

    pub fn unwrap(self) -> SourceFile<'arena> {
        match self {
            ParseResult::Success(ast) => ast,
            ParseResult::Error(errors) => panic!("Called unwrap on error: {:?}", errors),
        }
    }
}

/// Performance tracking metrics
#[derive(Debug, Default)]
struct PerformanceMetrics {
    total_queries: usize,
    cache_hits: usize,
    cache_misses: usize,
    invalidations: usize,
    total_query_time_ms: u64,
}

impl PerformanceMetrics {
    fn record_query(&mut self, is_cache_hit: bool, duration_ms: u64) {
        self.total_queries += 1;
        self.total_query_time_ms += duration_ms;

        if is_cache_hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }
    }

    fn record_invalidation(&mut self) {
        self.invalidations += 1;
    }

    fn cache_hit_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_queries as f64
        }
    }

    fn average_query_time(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.total_query_time_ms as f64 / self.total_queries as f64
        }
    }
}

/// Simplified database implementation for incremental computation
/// Note: This is a simplified version without full Salsa integration for now
/// Full Salsa integration will be added in later phases when we resolve lifetime issues
///
/// # Arena Lifecycle and Memory Management
///
/// The `arena` field uses bump allocation via `AstArena` for efficient memory management
/// of parsed AST nodes. The arena has the following lifecycle characteristics:
///
/// - **Lifetime**: The arena lives for the entire lifetime of the Database instance
/// - **Allocation**: All AST nodes are allocated in the arena with lifetime 'arena
/// - **References**: AST node references (like `&'arena str`) are valid as long as the Database exists
/// - **Memory Growth**: The arena only grows - memory is never freed until the Database is dropped
/// - **Thread Safety**: The arena is not thread-safe and requires exclusive access for parsing
///
/// ## Current Limitation with AST Storage
///
/// Currently, we extract data (like function names) from AST nodes and store them as owned Strings
/// in the cache rather than storing references to arena-allocated AST nodes. This is because:
///
/// 1. Storing `&'arena str` references would require lifetime parameters throughout the cache system
/// 2. The cache would become tied to the arena lifetime, making the API more complex
/// 3. Future Salsa integration may require different lifetime management approaches
///
/// ## Future Improvements
///
/// Consider these approaches for better memory efficiency:
/// - String interning for commonly used identifiers
/// - Separate short-lived arenas for temporary parsing operations
/// - Integration with Salsa's built-in memory management once lifetime issues are resolved
pub struct Database {
    /// Bump allocator arena for AST node storage. All parsed AST nodes are allocated here
    /// and remain valid for the lifetime of this Database instance.
    arena: AstArena,
    parser: Parser,
    file_counter: usize,
    file_registry: HashMap<SourceFileId, SourceFileInput>,
    performance_metrics: PerformanceMetrics,
    /// Simple cache storing extracted data as owned Strings rather than arena references.
    /// This avoids lifetime complications but creates allocation overhead.
    /// TODO: Consider more structured cache with better key/value system for complex queries.
    cache: HashMap<SourceFileId, Result<Vec<String>, String>>,
}

/// Helper function to validate file path UTF-8 encoding
/// This is a standalone function since it doesn't access any instance data
fn validate_file_path(input: &SourceFileInput) -> Result<&str> {
    input.path.to_str()
        .ok_or_else(|| anyhow!("Invalid UTF-8 in file path: {:?}", input.path))
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

impl Database {

    /// Create a new database instance
    pub fn new() -> Self {
        Self {
            arena: AstArena::new(),
            parser: Parser::new(),
            file_counter: 0,
            file_registry: HashMap::new(),
            performance_metrics: PerformanceMetrics::default(),
            cache: HashMap::new(),
        }
    }

    /// Add a new source file to the database
    pub fn add_source_file(&mut self, path: impl Into<PathBuf>, content: impl Into<String>) -> SourceFileId {
        let file_id = SourceFileId::new(self.file_counter);
        self.file_counter += 1;

        let input = SourceFileInput::new(path, content);
        self.file_registry.insert(file_id, input);

        // Invalidate cache for this file
        self.cache.remove(&file_id);

        file_id
    }

    /// Update an existing source file
    pub fn update_source_file(&mut self, id: SourceFileId, new_content: impl Into<String>) {
        if let Some(mut input) = self.file_registry.get(&id).cloned() {
            input.update_content(new_content);
            self.file_registry.insert(id, input);

            // Invalidate cache for this file
            self.cache.remove(&id);
            self.performance_metrics.record_invalidation();
        }
    }

    /// Get source file content
    pub fn get_source_content(&self, id: SourceFileId) -> &str {
        self.file_registry.get(&id)
            .map(|input| input.content.as_str())
            .unwrap_or("")
    }

    /// Get source file path
    /// Returns an error if the file ID is not found or path contains invalid UTF-8
    pub fn get_source_path(&self, id: SourceFileId) -> Result<&str> {
        let input = self.file_registry.get(&id)
            .ok_or_else(|| anyhow!("Source file with ID {} not found", id))?;

        input.path.to_str()
            .ok_or_else(|| anyhow!("Invalid UTF-8 in file path: {:?}", input.path))
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.file_registry.is_empty()
    }

    /// Get total number of source files
    pub fn source_file_count(&self) -> usize {
        self.file_registry.len()
    }

    /// Check if file has dependency on another file
    pub fn has_dependency(&self, dependent: SourceFileId, dependency: SourceFileId) -> bool {
        // Simple implementation - in real world this would analyze imports
        if let Ok(deps) = self.get_contract_dependencies(dependent) {
            deps.contains(&dependency)
        } else {
            false
        }
    }

    /// Get cache hit rate
    pub fn get_cache_hit_rate(&self) -> f64 {
        self.performance_metrics.cache_hit_rate()
    }

    /// Get total number of queries executed
    pub fn get_total_queries(&self) -> usize {
        self.performance_metrics.total_queries
    }

    /// Get number of cache invalidations
    pub fn get_invalidation_count(&self) -> usize {
        self.performance_metrics.invalidations
    }

    /// Get average query execution time
    pub fn get_average_query_time(&self) -> f64 {
        self.performance_metrics.average_query_time()
    }

    /// Get estimated memory usage in bytes
    /// Note: This is an approximation including data structure overhead
    pub fn get_memory_usage(&self) -> usize {
        let mut total = 0;

        // Arena memory (actual allocated bytes)
        total += self.arena.allocated_bytes();

        // File registry memory
        for input in self.file_registry.values() {
            // SourceFileId overhead
            total += std::mem::size_of::<SourceFileId>();

            // SourceFileInput struct overhead
            total += std::mem::size_of::<SourceFileInput>();

            // PathBuf memory (includes String backing)
            total += input.path.as_os_str().len();
            total += std::mem::size_of::<std::path::PathBuf>();

            // Content String memory
            total += input.content.capacity(); // Use capacity, not len for accurate memory
            total += std::mem::size_of::<String>();

            // Content hash String memory
            total += input.content_hash.capacity();
            total += std::mem::size_of::<String>();
        }

        // HashMap overhead for file_registry
        // HashMap has overhead per entry plus table capacity
        total += self.file_registry.capacity() * std::mem::size_of::<(SourceFileId, SourceFileInput)>();
        total += std::mem::size_of::<HashMap<SourceFileId, SourceFileInput>>();

        // Cache memory
        for result in self.cache.values() {
            // Key overhead
            total += std::mem::size_of::<SourceFileId>();

            // Value overhead depends on success/error
            match result {
                Ok(functions) => {
                    total += std::mem::size_of::<Result<Vec<String>, String>>();
                    total += functions.capacity() * std::mem::size_of::<String>();
                    for function_name in functions {
                        total += function_name.capacity();
                        total += std::mem::size_of::<String>();
                    }
                }
                Err(error_msg) => {
                    total += std::mem::size_of::<Result<Vec<String>, String>>();
                    total += error_msg.capacity();
                    total += std::mem::size_of::<String>();
                }
            }
        }

        // HashMap overhead for cache
        total += self.cache.capacity() * std::mem::size_of::<(SourceFileId, Result<Vec<String>, String>)>();
        total += std::mem::size_of::<HashMap<SourceFileId, Result<Vec<String>, String>>>();

        // Performance metrics overhead
        total += std::mem::size_of::<PerformanceMetrics>();

        // Parser overhead
        total += std::mem::size_of::<Parser>();

        // Base struct overhead
        total += std::mem::size_of::<Database>();

        total
    }

    /// Parse a source file and return the result
    pub fn parse_source_file(&mut self, id: SourceFileId) -> Result<Vec<String>> {
        let start_time = std::time::Instant::now();

        // Check cache first
        if let Some(cached_result) = self.cache.get(&id) {
            self.performance_metrics.record_query(true, start_time.elapsed().as_millis() as u64);
            return cached_result.clone().map_err(|e| anyhow!("{}", e));
        }

        // Cache miss - perform actual parsing
        let result = if let Some(input) = self.file_registry.get(&id) {
            // Convert path to string with proper error handling instead of silent fallback
            let path_str = validate_file_path(input)?;

            match self.parser.parse(&self.arena, &input.content, path_str) {
                Ok(source_file) => {
                    let mut function_names = Vec::new();
                    for contract in &source_file.contracts {
                        for function in &contract.functions {
                            // Note: This creates String allocations for each function name.
                            // TODO: Consider using string interning or lifetime-parameterized storage
                            // to avoid repeated allocations when the same functions are parsed multiple times.
                            function_names.push(function.name.name.to_string());
                        }
                    }
                    Ok(function_names)
                }
                Err(errors) => Err(anyhow!("Parse error: {:?}", errors)),
            }
        } else {
            Err(anyhow!("Source file not found"))
        };

        // Cache the result
        let cache_result = match &result {
            Ok(functions) => Ok(functions.clone()),
            Err(e) => Err(e.to_string()),
        };
        self.cache.insert(id, cache_result);

        self.performance_metrics.record_query(false, start_time.elapsed().as_millis() as u64);
        result
    }

    /// Get all functions from a source file
    pub fn get_all_functions(&mut self, id: SourceFileId) -> Result<Vec<String>> {
        self.parse_source_file(id)
    }

    /// Get public functions from a source file
    pub fn get_public_functions(&mut self, id: SourceFileId) -> Result<Vec<String>> {
        // TODO: Implement proper caching for public functions to avoid re-parsing
        // This method currently re-parses on every call instead of utilizing cached results

        // Parse the file to get actual visibility information from AST
        if let Some(input) = self.file_registry.get(&id) {
            // Convert path to string with proper error handling
            let path_str = validate_file_path(input)?;

            match self.parser.parse(&self.arena, &input.content, path_str) {
                Ok(source_file) => {
                    let mut public_functions = Vec::new();
                    for contract in &source_file.contracts {
                        for function in &contract.functions {
                            // Check actual visibility from AST instead of name patterns
                            if matches!(function.visibility, Visibility::Public | Visibility::External) {
                                public_functions.push(function.name.name.to_string());
                            }
                        }
                    }
                    Ok(public_functions)
                }
                Err(errors) => Err(anyhow!("Parse error: {:?}", errors)),
            }
        } else {
            Err(anyhow!("Source file not found"))
        }
    }

    /// Get contract dependencies for a source file
    pub fn get_contract_dependencies(&self, id: SourceFileId) -> Result<Vec<SourceFileId>> {
        if let Some(input) = self.file_registry.get(&id) {
            let mut dependencies = Vec::new();

            // Simple dependency analysis - look for import statements
            for line in input.content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("import") {
                    // Extract import path from various import formats:
                    // import "./path/file.sol";
                    // import "path/file.sol";
                    // import {Symbol} from "./path.sol";

                    if let Some(path) = self.extract_import_path(trimmed) {
                        // Find matching file in registry by path
                        for (file_id, file_input) in &self.file_registry {
                            if let Some(file_path_str) = file_input.path.to_str() {
                                // Match by filename or relative path
                                if file_path_str.ends_with(&path) ||
                                   file_path_str == path ||
                                   self.paths_match(&path, file_path_str) {
                                    dependencies.push(*file_id);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            Ok(dependencies)
        } else {
            Err(anyhow!("Source file not found"))
        }
    }

    /// Extract import path from import statement
    fn extract_import_path(&self, import_line: &str) -> Option<String> {
        // Handle different import formats
        if let Some(start) = import_line.find('"') {
            if let Some(end) = import_line[start + 1..].find('"') {
                let path = &import_line[start + 1..start + 1 + end];
                // Normalize path - remove leading "./"
                let normalized = path.strip_prefix("./").unwrap_or(path);
                return Some(normalized.to_string());
            }
        }
        None
    }

    /// Check if two paths refer to the same file
    fn paths_match(&self, import_path: &str, file_path: &str) -> bool {
        // Simple path matching - in practice would need more sophisticated resolution
        let import_file = import_path.split('/').next_back().unwrap_or(import_path);
        let file_name = file_path.split('/').next_back().unwrap_or(file_path);
        import_file == file_name
    }

    /// Get source file input by ID (for internal use)
    pub fn get_source_file_input(&self, id: SourceFileId) -> Option<&SourceFileInput> {
        self.file_registry.get(&id)
    }
}

