use anyhow::Result;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use cache::CacheManager;

/// Advanced dependency tracking and smart cache invalidation
pub struct DependencyTracker {
    /// Dependency graph: file -> set of files it depends on
    dependencies: Arc<DashMap<PathBuf, HashSet<PathBuf>>>,
    /// Reverse dependency graph: file -> set of files that depend on it
    dependents: Arc<DashMap<PathBuf, HashSet<PathBuf>>>,
    /// File metadata for change detection
    file_metadata: Arc<DashMap<PathBuf, FileMetadata>>,
    /// Cache manager for persistent storage
    cache_manager: Arc<CacheManager>,
    /// Dependency cache for resolved imports
    dependency_cache: Arc<DashMap<String, ResolvedDependency>>,
    /// Configuration
    config: DependencyConfig,
}

/// Configuration for dependency tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConfig {
    /// Enable import resolution
    pub enable_import_resolution: bool,
    /// Enable inheritance tracking
    pub enable_inheritance_tracking: bool,
    /// Enable interface dependency tracking
    pub enable_interface_tracking: bool,
    /// Maximum dependency depth to track
    pub max_dependency_depth: usize,
    /// Enable circular dependency detection
    pub detect_circular_dependencies: bool,
    /// Cache dependency resolution results
    pub cache_dependency_resolution: bool,
}

impl Default for DependencyConfig {
    fn default() -> Self {
        Self {
            enable_import_resolution: true,
            enable_inheritance_tracking: true,
            enable_interface_tracking: true,
            max_dependency_depth: 50,
            detect_circular_dependencies: true,
            cache_dependency_resolution: true,
        }
    }
}

/// Metadata for a file in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// File path
    pub path: PathBuf,
    /// Last modification time
    pub last_modified: SystemTime,
    /// Content hash
    pub content_hash: String,
    /// File size
    pub size: u64,
    /// Contracts defined in this file
    pub contracts: HashSet<String>,
    /// Interfaces defined in this file
    pub interfaces: HashSet<String>,
    /// Libraries defined in this file
    pub libraries: HashSet<String>,
    /// External contracts referenced
    pub external_references: HashSet<String>,
}

/// Resolved dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDependency {
    /// Import path as written in code
    pub import_path: String,
    /// Resolved file path
    pub resolved_path: PathBuf,
    /// Specific symbols imported (empty = all)
    pub imported_symbols: HashSet<String>,
    /// Dependency type
    pub dependency_type: DependencyType,
    /// Resolution timestamp
    pub resolved_at: SystemTime,
}

/// Type of dependency relationship
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyType {
    /// Direct import statement
    Import,
    /// Contract inheritance
    Inheritance,
    /// Interface implementation
    Interface,
    /// Library usage
    Library,
    /// External contract call
    ExternalCall,
}

/// Result of dependency analysis
#[derive(Debug, Clone)]
pub struct DependencyAnalysisResult {
    /// All dependencies found
    pub dependencies: HashMap<PathBuf, HashSet<PathBuf>>,
    /// Circular dependencies detected
    pub circular_dependencies: Vec<Vec<PathBuf>>,
    /// Files with missing dependencies
    pub missing_dependencies: HashMap<PathBuf, Vec<String>>,
    /// Dependency resolution metrics
    pub metrics: DependencyMetrics,
}

/// Metrics for dependency analysis
#[derive(Debug, Default, Clone)]
pub struct DependencyMetrics {
    /// Total files analyzed
    pub files_analyzed: usize,
    /// Total dependencies found
    pub dependencies_found: usize,
    /// Cache hits during resolution
    pub cache_hits: usize,
    /// Cache misses during resolution
    pub cache_misses: usize,
    /// Time spent on dependency resolution
    pub resolution_time: std::time::Duration,
    /// Number of circular dependencies
    pub circular_dependencies_count: usize,
}

/// Cache invalidation strategy
#[derive(Debug, Clone)]
pub enum InvalidationStrategy {
    /// Invalidate only the changed file
    FileOnly,
    /// Invalidate direct dependencies
    DirectDependencies,
    /// Invalidate entire dependency tree
    DependencyTree,
    /// Smart invalidation based on change type
    Smart,
}

impl DependencyTracker {
    pub fn new(cache_manager: Arc<CacheManager>, config: DependencyConfig) -> Self {
        Self {
            dependencies: Arc::new(DashMap::new()),
            dependents: Arc::new(DashMap::new()),
            file_metadata: Arc::new(DashMap::new()),
            cache_manager,
            dependency_cache: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Analyze dependencies for a set of files
    pub fn analyze_dependencies<I>(&self, file_paths: I) -> Result<DependencyAnalysisResult>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let start_time = std::time::Instant::now();
        let mut metrics = DependencyMetrics::default();
        let mut all_dependencies = HashMap::new();
        let missing_dependencies = HashMap::new();

        for file_path in file_paths {
            if let Ok(content) = std::fs::read_to_string(&file_path) {
                metrics.files_analyzed += 1;

                // Extract file metadata
                let metadata = self.extract_file_metadata(&file_path, &content)?;
                self.file_metadata.insert(file_path.clone(), metadata);

                // Extract dependencies
                let dependencies = self.extract_dependencies(&file_path, &content, &mut metrics)?;
                all_dependencies.insert(file_path.clone(), dependencies.clone());

                // Update dependency graph
                self.update_dependency_graph(&file_path, dependencies);
            }
        }

        // Detect circular dependencies
        let circular_dependencies = if self.config.detect_circular_dependencies {
            self.detect_circular_dependencies()
        } else {
            Vec::new()
        };

        metrics.circular_dependencies_count = circular_dependencies.len();
        metrics.resolution_time = start_time.elapsed();

        Ok(DependencyAnalysisResult {
            dependencies: all_dependencies,
            circular_dependencies,
            missing_dependencies,
            metrics,
        })
    }

    /// Extract dependencies from file content
    fn extract_dependencies(
        &self,
        file_path: &Path,
        content: &str,
        metrics: &mut DependencyMetrics,
    ) -> Result<HashSet<PathBuf>> {
        let mut dependencies = HashSet::new();

        // Parse import statements
        if self.config.enable_import_resolution {
            dependencies.extend(self.extract_imports(file_path, content, metrics)?);
        }

        // Parse inheritance relationships
        if self.config.enable_inheritance_tracking {
            dependencies.extend(self.extract_inheritance(file_path, content, metrics)?);
        }

        // Parse interface implementations
        if self.config.enable_interface_tracking {
            dependencies.extend(self.extract_interfaces(file_path, content, metrics)?);
        }

        Ok(dependencies)
    }

    /// Extract import dependencies
    fn extract_imports(
        &self,
        file_path: &Path,
        content: &str,
        metrics: &mut DependencyMetrics,
    ) -> Result<HashSet<PathBuf>> {
        let mut imports = HashSet::new();

        // Simple regex-based import extraction
        // In a real implementation, you'd use the AST parser
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("import") {
                if let Some(import_path) = self.parse_import_statement(line) {
                    // Check cache first
                    let cache_key = format!("{}:{}", file_path.display(), import_path);

                    if let Some(resolved) = self.dependency_cache.get(&cache_key) {
                        metrics.cache_hits += 1;
                        imports.insert(resolved.resolved_path.clone());
                    } else {
                        metrics.cache_misses += 1;

                        // Resolve import path
                        if let Some(resolved_path) = self.resolve_import_path(file_path, &import_path)? {
                            imports.insert(resolved_path.clone());
                            metrics.dependencies_found += 1;

                            // Cache the resolution
                            if self.config.cache_dependency_resolution {
                                let resolved_dep = ResolvedDependency {
                                    import_path: import_path.clone(),
                                    resolved_path,
                                    imported_symbols: HashSet::new(), // TODO: Parse specific symbols
                                    dependency_type: DependencyType::Import,
                                    resolved_at: SystemTime::now(),
                                };
                                self.dependency_cache.insert(cache_key, resolved_dep);
                            }
                        }
                    }
                }
            }
        }

        Ok(imports)
    }

    /// Extract inheritance dependencies
    fn extract_inheritance(
        &self,
        file_path: &Path,
        content: &str,
        metrics: &mut DependencyMetrics,
    ) -> Result<HashSet<PathBuf>> {
        let mut inheritance = HashSet::new();

        // Simple inheritance pattern matching
        for line in content.lines() {
            let line = line.trim();
            if line.contains("contract ") && line.contains(" is ") {
                // Extract parent contracts
                if let Some(is_pos) = line.find(" is ") {
                    let parents_part = &line[is_pos + 4..];
                    if let Some(brace_pos) = parents_part.find('{') {
                        let parents = &parents_part[..brace_pos];
                        for parent in parents.split(',') {
                            let parent = parent.trim();
                            if let Some(resolved_path) = self.resolve_contract_reference(file_path, parent)? {
                                inheritance.insert(resolved_path);
                                metrics.dependencies_found += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(inheritance)
    }

    /// Extract interface dependencies
    fn extract_interfaces(
        &self,
        _file_path: &Path,
        _content: &str,
        _metrics: &mut DependencyMetrics,
    ) -> Result<HashSet<PathBuf>> {
        let interfaces = HashSet::new();

        // Simple interface pattern matching
        // This would be more sophisticated in a real implementation

        Ok(interfaces)
    }

    /// Parse an import statement to extract the path
    fn parse_import_statement(&self, line: &str) -> Option<String> {
        // Simple regex-based parsing
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    /// Resolve import path to actual file path
    fn resolve_import_path(&self, current_file: &Path, import_path: &str) -> Result<Option<PathBuf>> {
        // Handle relative imports
        if import_path.starts_with("./") || import_path.starts_with("../") {
            if let Some(parent) = current_file.parent() {
                let resolved = parent.join(import_path);
                if resolved.exists() {
                    return Ok(Some(resolved));
                }
                // Try with .sol extension
                let with_sol = resolved.with_extension("sol");
                if with_sol.exists() {
                    return Ok(Some(with_sol));
                }
            }
        }

        // Handle absolute imports (would need node_modules resolution in real implementation)
        // For now, just return None for unresolved imports
        Ok(None)
    }

    /// Resolve contract reference to file path
    fn resolve_contract_reference(&self, _current_file: &Path, _contract_name: &str) -> Result<Option<PathBuf>> {
        // Look for contract in current file's dependencies
        // This is a simplified implementation
        Ok(None)
    }

    /// Extract file metadata
    fn extract_file_metadata(&self, file_path: &Path, content: &str) -> Result<FileMetadata> {
        let metadata = std::fs::metadata(file_path)?;
        let content_hash = self.calculate_content_hash(content);

        let mut contracts = HashSet::new();
        let mut interfaces = HashSet::new();
        let mut libraries = HashSet::new();

        // Extract contract/interface/library names
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("contract ") {
                if let Some(name) = self.extract_name_after_keyword(line, "contract") {
                    contracts.insert(name);
                }
            } else if line.starts_with("interface ") {
                if let Some(name) = self.extract_name_after_keyword(line, "interface") {
                    interfaces.insert(name);
                }
            } else if line.starts_with("library ") {
                if let Some(name) = self.extract_name_after_keyword(line, "library") {
                    libraries.insert(name);
                }
            }
        }

        Ok(FileMetadata {
            path: file_path.to_path_buf(),
            last_modified: metadata.modified()?,
            content_hash,
            size: metadata.len(),
            contracts,
            interfaces,
            libraries,
            external_references: HashSet::new(),
        })
    }

    /// Extract name after a keyword
    fn extract_name_after_keyword(&self, line: &str, keyword: &str) -> Option<String> {
        if let Some(start) = line.find(keyword) {
            let after_keyword = &line[start + keyword.len()..];
            let name = after_keyword.trim().split_whitespace().next()?;
            // Remove any trailing characters like '{' or 'is'
            let clean_name = name.split(|c: char| !c.is_alphanumeric() && c != '_').next()?;
            if !clean_name.is_empty() {
                return Some(clean_name.to_string());
            }
        }
        None
    }

    /// Update the dependency graph
    fn update_dependency_graph(&self, file_path: &Path, dependencies: HashSet<PathBuf>) {
        // Update forward dependencies
        self.dependencies.insert(file_path.to_path_buf(), dependencies.clone());

        // Update reverse dependencies
        for dep_path in dependencies {
            self.dependents
                .entry(dep_path)
                .or_insert_with(HashSet::new)
                .insert(file_path.to_path_buf());
        }
    }

    /// Detect circular dependencies using DFS
    fn detect_circular_dependencies(&self) -> Vec<Vec<PathBuf>> {
        let mut circular = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for file_path in self.dependencies.iter().map(|entry| entry.key().clone()) {
            if !visited.contains(&file_path) {
                if let Some(cycle) = self.dfs_cycle_detection(
                    &file_path,
                    &mut visited,
                    &mut rec_stack,
                    &mut Vec::new(),
                ) {
                    circular.push(cycle);
                }
            }
        }

        circular
    }

    /// DFS-based cycle detection
    fn dfs_cycle_detection(
        &self,
        file_path: &PathBuf,
        visited: &mut HashSet<PathBuf>,
        rec_stack: &mut HashSet<PathBuf>,
        path: &mut Vec<PathBuf>,
    ) -> Option<Vec<PathBuf>> {
        visited.insert(file_path.clone());
        rec_stack.insert(file_path.clone());
        path.push(file_path.clone());

        if let Some(deps) = self.dependencies.get(file_path) {
            for dep in deps.iter() {
                if !visited.contains(dep) {
                    if let Some(cycle) = self.dfs_cycle_detection(dep, visited, rec_stack, path) {
                        return Some(cycle);
                    }
                } else if rec_stack.contains(dep) {
                    // Found a cycle
                    let cycle_start = path.iter().position(|p| p == dep).unwrap();
                    return Some(path[cycle_start..].to_vec());
                }
            }
        }

        path.pop();
        rec_stack.remove(file_path);
        None
    }

    /// Get files that should be invalidated when a file changes
    pub fn get_invalidation_targets(
        &self,
        changed_file: &Path,
        strategy: InvalidationStrategy,
    ) -> HashSet<PathBuf> {
        match strategy {
            InvalidationStrategy::FileOnly => {
                let mut targets = HashSet::new();
                targets.insert(changed_file.to_path_buf());
                targets
            }
            InvalidationStrategy::DirectDependencies => {
                let mut targets = HashSet::new();
                targets.insert(changed_file.to_path_buf());
                if let Some(dependents) = self.dependents.get(changed_file) {
                    targets.extend(dependents.iter().cloned());
                }
                targets
            }
            InvalidationStrategy::DependencyTree => {
                self.get_all_dependents(changed_file)
            }
            InvalidationStrategy::Smart => {
                self.smart_invalidation(changed_file)
            }
        }
    }

    /// Get all files that transitively depend on the given file
    fn get_all_dependents(&self, file_path: &Path) -> HashSet<PathBuf> {
        let mut all_dependents = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(file_path.to_path_buf());
        all_dependents.insert(file_path.to_path_buf());

        while let Some(current) = queue.pop_front() {
            if let Some(dependents) = self.dependents.get(&current) {
                for dependent in dependents.iter() {
                    if all_dependents.insert(dependent.clone()) {
                        queue.push_back(dependent.clone());
                    }
                }
            }
        }

        all_dependents
    }

    /// Smart invalidation based on change analysis
    fn smart_invalidation(&self, changed_file: &Path) -> HashSet<PathBuf> {
        // For now, use direct dependencies strategy
        // In a real implementation, you'd analyze what changed in the file
        // and only invalidate if the change affects the public interface
        self.get_invalidation_targets(changed_file, InvalidationStrategy::DirectDependencies)
    }

    /// Calculate content hash
    fn calculate_content_hash(&self, content: &str) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(content.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Get dependency graph statistics
    pub fn get_statistics(&self) -> DependencyStatistics {
        let total_files = self.dependencies.len();
        let total_dependencies: usize = self.dependencies.iter().map(|entry| entry.value().len()).sum();
        let avg_dependencies = if total_files > 0 {
            total_dependencies as f64 / total_files as f64
        } else {
            0.0
        };

        DependencyStatistics {
            total_files,
            total_dependencies,
            average_dependencies_per_file: avg_dependencies,
            cache_entries: self.dependency_cache.len(),
            circular_dependencies: self.detect_circular_dependencies().len(),
        }
    }

    /// Clear all dependency data
    pub fn clear(&self) {
        self.dependencies.clear();
        self.dependents.clear();
        self.file_metadata.clear();
        self.dependency_cache.clear();
    }
}

/// Statistics for dependency tracking
#[derive(Debug, Clone)]
pub struct DependencyStatistics {
    pub total_files: usize,
    pub total_dependencies: usize,
    pub average_dependencies_per_file: f64,
    pub cache_entries: usize,
    pub circular_dependencies: usize,
}