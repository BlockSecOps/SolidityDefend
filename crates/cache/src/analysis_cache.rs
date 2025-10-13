use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::RwLock;

use crate::{CacheConfig, CacheEntry, CacheKey};

/// Cached analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAnalysisResult {
    /// Findings from the analysis
    pub findings: Vec<CachedFinding>,
    /// Analysis metadata
    pub metadata: AnalysisMetadata,
    /// File path that was analyzed
    pub file_path: String,
    /// Analysis configuration used
    pub config_hash: String,
}

/// Simplified finding structure for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFinding {
    /// Detector ID that found this issue
    pub detector_id: String,
    /// Finding message
    pub message: String,
    /// Severity level
    pub severity: String,
    /// Location information
    pub location: CachedLocation,
    /// CWE numbers associated with this finding
    pub cwes: Vec<u32>,
    /// Fix suggestion
    pub fix_suggestion: Option<String>,
}

/// Location information for cached findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedLocation {
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
    /// Length of the issue span
    pub length: u32,
}

/// Analysis execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Analysis start time
    pub started_at: u64,
    /// Analysis completion time
    pub completed_at: u64,
    /// Detectors that were run
    pub detectors_run: Vec<String>,
    /// Analysis statistics
    pub stats: AnalysisStats,
}

/// Analysis execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Total findings count
    pub total_findings: usize,
    /// Findings by severity
    pub findings_by_severity: std::collections::HashMap<String, usize>,
    /// Analysis duration in milliseconds
    pub duration_ms: u64,
}

/// Analysis results cache with intelligent invalidation
pub struct AnalysisCache {
    /// In-memory cache
    cache: DashMap<String, CacheEntry<CachedAnalysisResult>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current memory usage estimate
    memory_usage: RwLock<usize>,
}

impl AnalysisCache {
    pub fn new(config: CacheConfig) -> Result<Self> {
        Ok(Self {
            cache: DashMap::new(),
            config,
            memory_usage: RwLock::new(0),
        })
    }

    /// Check if analysis results are cached and valid
    pub fn get_analysis(&self, key: &CacheKey) -> Option<CachedAnalysisResult> {
        let cache_key = self.cache_key_string(key);
        if let Some(mut entry) = self.cache.get_mut(&cache_key) {
            entry.access();
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Store analysis results in cache
    pub fn store_analysis(&self, key: CacheKey, result: CachedAnalysisResult) -> Result<()> {
        let cache_key = self.cache_key_string(&key);
        let entry = CacheEntry::new(result, key);

        self.cache.insert(cache_key, entry);
        self.update_memory_usage();
        self.evict_if_needed();

        Ok(())
    }

    /// Check if cache contains valid analysis for the given key
    pub fn contains(&self, key: &CacheKey) -> bool {
        let cache_key = self.cache_key_string(key);
        self.cache.contains_key(&cache_key)
    }

    /// Invalidate cache entry for a specific file
    pub fn invalidate_file(&self, file_path: &Path) {
        let file_path_str = file_path.to_string_lossy().to_string();

        // Remove all entries for this file path
        self.cache
            .retain(|_, entry| entry.data.file_path != file_path_str);

        self.update_memory_usage();
    }

    /// Invalidate entries based on configuration changes
    pub fn invalidate_config(&self, old_config_hash: &str) {
        // Remove all entries with the old configuration
        self.cache
            .retain(|_, entry| entry.data.config_hash != old_config_hash);

        self.update_memory_usage();
    }

    /// Get cache statistics
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn memory_usage(&self) -> usize {
        *self.memory_usage.read().unwrap()
    }

    /// Clear all cache entries
    pub fn clear(&self) -> Result<()> {
        self.cache.clear();
        *self.memory_usage.write().unwrap() = 0;
        Ok(())
    }

    /// Get cache hit statistics
    pub fn get_hit_statistics(&self) -> CacheHitStats {
        let total_entries = self.len();
        let memory_used = self.memory_usage();

        // Calculate average age of entries
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut total_age = 0u64;
        let mut oldest_entry = 0u64;
        let mut newest_entry = now;

        for entry in self.cache.iter() {
            let age = now.saturating_sub(entry.created_at);
            total_age += age;
            oldest_entry = oldest_entry.max(age);
            newest_entry = newest_entry.min(entry.created_at);
        }

        let average_age = if total_entries > 0 {
            total_age / total_entries as u64
        } else {
            0
        };

        CacheHitStats {
            total_entries,
            memory_used,
            average_age_seconds: average_age,
            oldest_entry_age_seconds: oldest_entry,
        }
    }

    /// Create cache key string for internal storage
    fn cache_key_string(&self, key: &CacheKey) -> String {
        format!("{}:{}:{}", key.file_path, key.content_hash, key.config_hash)
    }

    /// Update memory usage estimate
    fn update_memory_usage(&self) {
        let mut total = 0;
        for entry in self.cache.iter() {
            total += estimate_analysis_entry_size(entry.value());
        }
        *self.memory_usage.write().unwrap() = total;
    }

    /// Evict entries if cache is too large
    fn evict_if_needed(&self) {
        let current_usage = self.memory_usage();
        let current_count = self.len();

        if current_usage > self.config.max_memory_usage || current_count > self.config.max_entries {
            self.evict_lru_entries();
        }
    }

    /// Evict least recently used entries
    fn evict_lru_entries(&self) {
        // Collect entries with their access times
        let mut entries: Vec<_> = self
            .cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().accessed_at))
            .collect();

        // Sort by access time (oldest first)
        entries.sort_by_key(|(_, accessed_at)| *accessed_at);

        // Remove oldest entries until we're under limits
        let target_count = (self.config.max_entries * 80) / 100; // Keep 80% of max
        let target_memory = (self.config.max_memory_usage * 80) / 100;

        let mut removed = 0;
        for (key, _) in entries {
            if self.len() <= target_count && self.memory_usage() <= target_memory {
                break;
            }
            self.cache.remove(&key);
            removed += 1;
        }

        if removed > 0 {
            self.update_memory_usage();
        }
    }
}

/// Cache hit statistics
#[derive(Debug, Clone)]
pub struct CacheHitStats {
    pub total_entries: usize,
    pub memory_used: usize,
    pub average_age_seconds: u64,
    pub oldest_entry_age_seconds: u64,
}

/// Estimate memory usage of an analysis cache entry
fn estimate_analysis_entry_size(entry: &CacheEntry<CachedAnalysisResult>) -> usize {
    let findings_size: usize = entry
        .data
        .findings
        .iter()
        .map(|f| {
            f.detector_id.len() +
            f.message.len() +
            f.severity.len() +
            f.fix_suggestion.as_ref().map_or(0, |s| s.len()) +
            f.cwes.len() * 4 + // u32 size
            32 // Location overhead
        })
        .sum();

    let metadata_size = entry
        .data
        .metadata
        .detectors_run
        .iter()
        .map(|d| d.len())
        .sum::<usize>()
        + entry
            .data
            .metadata
            .stats
            .findings_by_severity
            .keys()
            .map(|k| k.len() + 8) // usize size
            .sum::<usize>()
        + 64; // Other metadata overhead

    findings_size
        + metadata_size
        + entry.data.file_path.len()
        + entry.data.config_hash.len()
        + entry.key.content_hash.len()
        + entry.key.file_path.len()
        + entry.key.config_hash.len()
        + 128 // Entry overhead
}
