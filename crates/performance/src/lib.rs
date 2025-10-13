pub mod dependency;
pub mod incremental;
pub mod memory;
pub mod parallel;
pub mod streaming;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Performance configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable incremental analysis
    pub incremental_analysis: bool,
    /// Enable parallel detector execution
    pub parallel_execution: bool,
    /// Maximum memory usage in bytes (0 = unlimited)
    pub max_memory_usage: usize,
    /// Number of worker threads for parallel execution
    pub worker_threads: usize,
    /// Enable streaming analysis for large files
    pub streaming_analysis: bool,
    /// Streaming chunk size in bytes
    pub streaming_chunk_size: usize,
    /// Enable persistent caching
    pub persistent_cache: bool,
    /// Enable dependency tracking
    pub dependency_tracking: bool,
    /// Memory pool size for arena allocations
    pub memory_pool_size: usize,
    /// Garbage collection threshold
    pub gc_threshold: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            incremental_analysis: true,
            parallel_execution: false, // Disabled until AST is thread-safe
            max_memory_usage: 1024 * 1024 * 1024, // 1GB
            worker_threads: num_cpus::get().min(8),
            streaming_analysis: true,
            streaming_chunk_size: 64 * 1024, // 64KB
            persistent_cache: true,
            dependency_tracking: true,
            memory_pool_size: 16 * 1024 * 1024, // 16MB
            gc_threshold: 100 * 1024 * 1024,    // 100MB
        }
    }
}

/// Performance metrics collected during analysis
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total analysis time
    pub total_duration: Duration,
    /// Time spent parsing
    pub parse_duration: Duration,
    /// Time spent in detectors
    pub detection_duration: Duration,
    /// Memory usage statistics
    pub memory_stats: MemoryStats,
    /// Cache performance
    pub cache_stats: CachePerformanceStats,
    /// Number of files analyzed
    pub files_analyzed: usize,
    /// Number of detectors run
    pub detectors_run: usize,
    /// Incremental analysis savings
    pub incremental_savings: Duration,
    /// Parallel execution speedup
    pub parallel_speedup: f64,
}

/// Memory usage statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Peak memory usage in bytes
    pub peak_memory: usize,
    /// Current memory usage in bytes
    pub current_memory: usize,
    /// Arena allocations in bytes
    pub arena_allocations: usize,
    /// Number of garbage collections
    pub gc_runs: usize,
    /// Memory freed by GC in bytes
    pub memory_freed: usize,
}

/// Cache performance statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CachePerformanceStats {
    /// Analysis cache hit ratio
    pub analysis_hit_ratio: f64,
    /// Dependency cache hit ratio
    pub dependency_hit_ratio: f64,
    /// Parse cache hit ratio
    pub parse_hit_ratio: f64,
    /// Time saved by caching
    pub time_saved: Duration,
    /// Memory saved by caching
    pub memory_saved: usize,
}

/// Performance optimization manager
pub struct PerformanceManager {
    config: PerformanceConfig,
    metrics: parking_lot::RwLock<PerformanceMetrics>,
    start_time: Instant,
}

impl PerformanceManager {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            config,
            metrics: parking_lot::RwLock::new(PerformanceMetrics::default()),
            start_time: Instant::now(),
        }
    }

    /// Get current performance configuration
    pub fn config(&self) -> &PerformanceConfig {
        &self.config
    }

    /// Get current performance metrics
    pub fn metrics(&self) -> PerformanceMetrics {
        self.metrics.read().clone()
    }

    /// Update performance metrics
    pub fn update_metrics<F>(&self, updater: F)
    where
        F: FnOnce(&mut PerformanceMetrics),
    {
        let mut metrics = self.metrics.write();
        updater(&mut metrics);
    }

    /// Record timing for a specific operation
    pub fn time_operation<T, F>(&self, operation: F) -> Result<(T, Duration)>
    where
        F: FnOnce() -> Result<T>,
    {
        let start = Instant::now();
        let result = operation()?;
        let duration = start.elapsed();
        Ok((result, duration))
    }

    /// Check if memory usage is within limits
    pub fn check_memory_limits(&self) -> bool {
        if self.config.max_memory_usage == 0 {
            return true;
        }

        let current_memory = self.get_current_memory_usage();
        current_memory <= self.config.max_memory_usage
    }

    /// Get current memory usage estimation
    pub fn get_current_memory_usage(&self) -> usize {
        // This is a simplified estimation
        // In a real implementation, you'd use more sophisticated memory tracking
        self.metrics.read().memory_stats.current_memory
    }

    /// Update memory statistics
    pub fn update_memory_stats(&self, current: usize, arena: usize) {
        self.update_metrics(|metrics| {
            metrics.memory_stats.current_memory = current;
            metrics.memory_stats.arena_allocations = arena;
            if current > metrics.memory_stats.peak_memory {
                metrics.memory_stats.peak_memory = current;
            }
        });
    }

    /// Record garbage collection run
    pub fn record_gc(&self, memory_freed: usize) {
        self.update_metrics(|metrics| {
            metrics.memory_stats.gc_runs += 1;
            metrics.memory_stats.memory_freed += memory_freed;
        });
    }

    /// Finalize metrics collection
    pub fn finalize(&self) {
        let total_duration = self.start_time.elapsed();
        self.update_metrics(|metrics| {
            metrics.total_duration = total_duration;
        });
    }

    /// Check if garbage collection should be triggered
    pub fn should_gc(&self) -> bool {
        self.get_current_memory_usage() > self.config.gc_threshold
    }

    /// Get performance summary as human-readable string
    pub fn performance_summary(&self) -> String {
        let metrics = self.metrics();
        format!(
            "Performance Summary:
  Total Duration: {:?}
  Parse Duration: {:?}
  Detection Duration: {:?}
  Files Analyzed: {}
  Detectors Run: {}
  Peak Memory: {} MB
  Cache Hit Ratio: {:.2}%
  Incremental Savings: {:?}
  Parallel Speedup: {:.2}x",
            metrics.total_duration,
            metrics.parse_duration,
            metrics.detection_duration,
            metrics.files_analyzed,
            metrics.detectors_run,
            metrics.memory_stats.peak_memory / (1024 * 1024),
            metrics.cache_stats.analysis_hit_ratio * 100.0,
            metrics.incremental_savings,
            metrics.parallel_speedup
        )
    }
}
