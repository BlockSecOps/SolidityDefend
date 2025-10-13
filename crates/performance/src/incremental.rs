use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use cache::CacheManager;
use detectors::types::Finding;

/// File change tracking and incremental analysis
pub struct IncrementalAnalyzer {
    /// File state tracking
    file_states: Arc<DashMap<PathBuf, FileState>>,
    /// Dependency graph for change propagation
    dependency_graph: Arc<DashMap<PathBuf, HashSet<PathBuf>>>,
    /// Cache manager for persistence
    _cache_manager: Arc<CacheManager>,
    /// Analysis queue for changed files
    analysis_queue: Arc<DashMap<PathBuf, AnalysisTask>>,
    /// Configuration
    config: IncrementalConfig,
}

/// Configuration for incremental analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Enable change detection
    pub enable_change_detection: bool,
    /// Enable dependency tracking
    pub enable_dependency_tracking: bool,
    /// Maximum files to analyze in a batch
    pub max_batch_size: usize,
    /// Debounce delay for file changes (milliseconds)
    pub debounce_delay_ms: u64,
    /// Enable smart invalidation
    pub smart_invalidation: bool,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            enable_change_detection: true,
            enable_dependency_tracking: true,
            max_batch_size: 50,
            debounce_delay_ms: 500,
            smart_invalidation: true,
        }
    }
}

/// State of a file for incremental analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    /// File path
    pub path: PathBuf,
    /// Last modification time
    pub last_modified: SystemTime,
    /// Content hash for change detection
    pub content_hash: String,
    /// File size in bytes
    pub size: u64,
    /// Last analysis timestamp
    pub last_analyzed: Option<SystemTime>,
    /// Dependencies (imports, inheritance)
    pub dependencies: HashSet<PathBuf>,
    /// Dependents (files that depend on this file)
    pub dependents: HashSet<PathBuf>,
    /// Analysis status
    pub status: AnalysisStatus,
    /// Cached findings
    pub cached_findings: Option<Vec<Finding>>,
}

/// Analysis status for a file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisStatus {
    /// File has not been analyzed
    NotAnalyzed,
    /// File is queued for analysis
    Queued,
    /// File is currently being analyzed
    InProgress,
    /// File has been analyzed successfully
    Analyzed,
    /// Analysis failed
    Failed(String),
    /// File needs re-analysis due to changes
    Stale,
}

/// Analysis task for the queue
#[derive(Debug, Clone)]
pub struct AnalysisTask {
    /// File to analyze
    pub file_path: PathBuf,
    /// Priority (higher = more urgent)
    pub priority: i32,
    /// Timestamp when task was created
    pub created_at: Instant,
    /// Reason for analysis
    pub reason: AnalysisReason,
}

/// Reason for triggering analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisReason {
    /// File was modified
    FileChanged,
    /// Dependency was modified
    DependencyChanged,
    /// Initial analysis
    Initial,
    /// Forced re-analysis
    Forced,
    /// Cache invalidation
    CacheInvalidated,
}

/// Results of incremental analysis
#[derive(Debug, Clone)]
pub struct IncrementalAnalysisResult {
    /// Files that were analyzed
    pub analyzed_files: Vec<PathBuf>,
    /// Files that were skipped (unchanged)
    pub skipped_files: Vec<PathBuf>,
    /// All findings from analysis
    pub findings: Vec<Finding>,
    /// Analysis performance metrics
    pub metrics: IncrementalMetrics,
}

/// Performance metrics for incremental analysis
#[derive(Debug, Default, Clone)]
pub struct IncrementalMetrics {
    /// Number of files checked
    pub files_checked: usize,
    /// Number of files analyzed
    pub files_analyzed: usize,
    /// Number of files skipped
    pub files_skipped: usize,
    /// Time saved by skipping unchanged files
    pub time_saved: std::time::Duration,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Dependency resolution time
    pub dependency_resolution_time: std::time::Duration,
}

impl IncrementalAnalyzer {
    pub fn new(cache_manager: Arc<CacheManager>, config: IncrementalConfig) -> Self {
        Self {
            file_states: Arc::new(DashMap::new()),
            dependency_graph: Arc::new(DashMap::new()),
            _cache_manager: cache_manager,
            analysis_queue: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Add files to track for incremental analysis
    pub fn add_files<I>(&self, file_paths: I) -> Result<()>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        for file_path in file_paths {
            self.track_file(&file_path)?;
        }
        Ok(())
    }

    /// Track a single file for changes
    pub fn track_file(&self, file_path: &Path) -> Result<()> {
        let metadata = std::fs::metadata(file_path)?;
        let content = std::fs::read_to_string(file_path)?;
        let content_hash = self.calculate_content_hash(&content);

        let file_state = FileState {
            path: file_path.to_path_buf(),
            last_modified: metadata.modified()?,
            content_hash,
            size: metadata.len(),
            last_analyzed: None,
            dependencies: HashSet::new(),
            dependents: HashSet::new(),
            status: AnalysisStatus::NotAnalyzed,
            cached_findings: None,
        };

        self.file_states.insert(file_path.to_path_buf(), file_state);

        // Extract dependencies if enabled
        if self.config.enable_dependency_tracking {
            self.extract_dependencies(file_path, &content)?;
        }

        Ok(())
    }

    /// Check for file changes and update states
    pub fn check_file_changes(&self) -> Result<Vec<PathBuf>> {
        let mut changed_files = Vec::new();

        for mut entry in self.file_states.iter_mut() {
            let file_path = entry.key().clone();
            let file_state = entry.value_mut();

            if let Ok(metadata) = std::fs::metadata(&file_path) {
                let current_modified = metadata.modified()?;
                let current_size = metadata.len();

                if current_modified != file_state.last_modified || current_size != file_state.size {
                    // File has changed, verify with content hash
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let new_hash = self.calculate_content_hash(&content);
                        if new_hash != file_state.content_hash {
                            file_state.last_modified = current_modified;
                            file_state.size = current_size;
                            file_state.content_hash = new_hash;
                            file_state.status = AnalysisStatus::Stale;

                            changed_files.push(file_path.clone());

                            // Queue file for analysis
                            self.queue_file_for_analysis(
                                file_path.clone(),
                                AnalysisReason::FileChanged,
                                1,
                            );

                            // Update dependencies
                            if self.config.enable_dependency_tracking {
                                self.extract_dependencies(&file_path, &content)?;
                            }
                        }
                    }
                }
            }
        }

        // Propagate changes to dependents
        if self.config.smart_invalidation {
            self.propagate_changes(&changed_files)?;
        }

        Ok(changed_files)
    }

    /// Queue a file for analysis with given priority
    pub fn queue_file_for_analysis(
        &self,
        file_path: PathBuf,
        reason: AnalysisReason,
        priority: i32,
    ) {
        let task = AnalysisTask {
            file_path: file_path.clone(),
            priority,
            created_at: Instant::now(),
            reason,
        };

        self.analysis_queue.insert(file_path.clone(), task);

        // Update file status
        if let Some(mut file_state) = self.file_states.get_mut(&file_path) {
            file_state.status = AnalysisStatus::Queued;
        }
    }

    /// Get next batch of files to analyze
    pub fn get_analysis_batch(&self) -> Vec<AnalysisTask> {
        let mut tasks: Vec<_> = self
            .analysis_queue
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Sort by priority (highest first) and creation time
        tasks.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });

        // Take up to max_batch_size tasks
        let batch_size = tasks.len().min(self.config.max_batch_size);
        let batch: Vec<AnalysisTask> = tasks.into_iter().take(batch_size).collect();

        // Remove batched tasks from queue
        for task in batch.iter() {
            let _ = self.analysis_queue.remove(&task.file_path);
            if let Some(mut file_state) = self.file_states.get_mut(&task.file_path) {
                file_state.status = AnalysisStatus::InProgress;
            }
        }

        batch
    }

    /// Mark file analysis as complete
    pub fn complete_analysis(&self, file_path: &Path, findings: Vec<Finding>) -> Result<()> {
        if let Some(mut file_state) = self.file_states.get_mut(file_path) {
            file_state.status = AnalysisStatus::Analyzed;
            file_state.last_analyzed = Some(SystemTime::now());
            file_state.cached_findings = Some(findings);
        }

        Ok(())
    }

    /// Mark file analysis as failed
    pub fn mark_analysis_failed(&self, file_path: &Path, error: String) {
        if let Some(mut file_state) = self.file_states.get_mut(file_path) {
            file_state.status = AnalysisStatus::Failed(error);
        }
    }

    /// Check if a file needs analysis
    pub fn needs_analysis(&self, file_path: &Path) -> bool {
        if let Some(file_state) = self.file_states.get(file_path) {
            matches!(
                file_state.status,
                AnalysisStatus::NotAnalyzed | AnalysisStatus::Stale
            )
        } else {
            true // Unknown files need analysis
        }
    }

    /// Get cached findings for a file
    pub fn get_cached_findings(&self, file_path: &Path) -> Option<Vec<Finding>> {
        self.file_states
            .get(file_path)
            .and_then(|state| state.cached_findings.clone())
    }

    /// Extract dependencies from file content (simplified)
    fn extract_dependencies(&self, file_path: &Path, content: &str) -> Result<()> {
        let mut dependencies = HashSet::new();

        // Simple regex-based dependency extraction
        // In a real implementation, you'd use the parser to extract proper imports
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("import") {
                // Extract import path (simplified)
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let import_path = &line[start + 1..start + 1 + end];
                        if let Some(parent) = file_path.parent() {
                            let resolved_path = parent.join(import_path);
                            dependencies.insert(resolved_path);
                        }
                    }
                }
            }
        }

        // Update file state with dependencies
        if let Some(mut file_state) = self.file_states.get_mut(file_path) {
            // Remove old dependencies
            for old_dep in &file_state.dependencies {
                if let Some(mut dep_state) = self.file_states.get_mut(old_dep) {
                    dep_state.dependents.remove(file_path);
                }
            }

            // Add new dependencies
            file_state.dependencies = dependencies.clone();
            for dep_path in &dependencies {
                if let Some(mut dep_state) = self.file_states.get_mut(dep_path) {
                    dep_state.dependents.insert(file_path.to_path_buf());
                }
            }
        }

        // Update dependency graph
        self.dependency_graph
            .insert(file_path.to_path_buf(), dependencies);

        Ok(())
    }

    /// Propagate changes to dependent files
    fn propagate_changes(&self, changed_files: &[PathBuf]) -> Result<()> {
        let mut propagation_queue = changed_files.to_vec();
        let mut visited = HashSet::new();

        while let Some(file_path) = propagation_queue.pop() {
            if visited.contains(&file_path) {
                continue;
            }
            visited.insert(file_path.clone());

            if let Some(file_state) = self.file_states.get(&file_path) {
                for dependent in &file_state.dependents {
                    if !visited.contains(dependent) {
                        // Queue dependent for analysis
                        self.queue_file_for_analysis(
                            dependent.clone(),
                            AnalysisReason::DependencyChanged,
                            0, // Lower priority than direct changes
                        );
                        propagation_queue.push(dependent.clone());
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate content hash for change detection
    fn calculate_content_hash(&self, content: &str) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(content.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Get dependency graph for a file
    pub fn get_dependencies(&self, file_path: &Path) -> HashSet<PathBuf> {
        self.dependency_graph
            .get(file_path)
            .map(|deps| deps.clone())
            .unwrap_or_default()
    }

    /// Get files that depend on the given file
    pub fn get_dependents(&self, file_path: &Path) -> HashSet<PathBuf> {
        self.file_states
            .get(file_path)
            .map(|state| state.dependents.clone())
            .unwrap_or_default()
    }

    /// Clear all tracking state
    pub fn clear(&self) {
        self.file_states.clear();
        self.dependency_graph.clear();
        self.analysis_queue.clear();
    }

    /// Get incremental analysis statistics
    pub fn get_statistics(&self) -> IncrementalStatistics {
        let total_files = self.file_states.len();
        let mut analyzed = 0;
        let mut stale = 0;
        let mut queued = 0;
        let mut failed = 0;

        for file_state in self.file_states.iter() {
            match file_state.status {
                AnalysisStatus::Analyzed => analyzed += 1,
                AnalysisStatus::Stale => stale += 1,
                AnalysisStatus::Queued | AnalysisStatus::InProgress => queued += 1,
                AnalysisStatus::Failed(_) => failed += 1,
                _ => {}
            }
        }

        IncrementalStatistics {
            total_files,
            analyzed_files: analyzed,
            stale_files: stale,
            queued_files: queued,
            failed_files: failed,
            total_dependencies: self.dependency_graph.len(),
        }
    }
}

/// Statistics for incremental analysis
#[derive(Debug, Clone)]
pub struct IncrementalStatistics {
    pub total_files: usize,
    pub analyzed_files: usize,
    pub stale_files: usize,
    pub queued_files: usize,
    pub failed_files: usize,
    pub total_dependencies: usize,
}
