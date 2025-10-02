pub mod query_cache;
pub mod file_cache;
pub mod analysis_cache;

use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Cache key for identifying cached items
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    /// Content hash of the source file
    pub content_hash: String,
    /// File path for identification
    pub file_path: String,
    /// Analysis configuration hash
    pub config_hash: String,
}

impl CacheKey {
    pub fn new(file_path: &str, content: &str, config_hash: &str) -> Self {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(content.as_bytes());
        let content_hash = hasher.finalize().to_hex().to_string();

        Self {
            content_hash,
            file_path: file_path.to_string(),
            config_hash: config_hash.to_string(),
        }
    }
}

/// Cache entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// Cached data
    pub data: T,
    /// Cache creation timestamp
    pub created_at: u64,
    /// Cache access timestamp
    pub accessed_at: u64,
    /// Cache key
    pub key: CacheKey,
}

impl<T> CacheEntry<T> {
    pub fn new(data: T, key: CacheKey) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            data,
            created_at: now,
            accessed_at: now,
            key,
        }
    }

    pub fn access(&mut self) {
        self.accessed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Main cache manager for SolidityDefend
pub struct CacheManager {
    /// File content cache
    file_cache: Arc<file_cache::FileCache>,
    /// Analysis results cache
    analysis_cache: Arc<analysis_cache::AnalysisCache>,
    /// Query cache for database queries
    query_cache: Arc<query_cache::QueryCache>,
    /// Cache configuration
    config: CacheConfig,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum memory usage in bytes
    pub max_memory_usage: usize,
    /// Maximum cache entries
    pub max_entries: usize,
    /// Cache directory path
    pub cache_dir: std::path::PathBuf,
    /// Enable persistent cache
    pub persistent: bool,
    /// Cache TTL in seconds
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: 256 * 1024 * 1024, // 256MB
            max_entries: 10000,
            cache_dir: std::env::temp_dir().join("soliditydefend_cache"),
            persistent: true,
            ttl_seconds: 3600, // 1 hour
        }
    }
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Result<Self> {
        // Create cache directory if it doesn't exist
        if config.persistent {
            std::fs::create_dir_all(&config.cache_dir)?;
        }

        let file_cache = Arc::new(file_cache::FileCache::new(config.clone())?);
        let analysis_cache = Arc::new(analysis_cache::AnalysisCache::new(config.clone())?);
        let query_cache = Arc::new(query_cache::QueryCache::new(config.clone())?);

        Ok(Self {
            file_cache,
            analysis_cache,
            query_cache,
            config,
        })
    }

    /// Get file cache
    pub fn file_cache(&self) -> &Arc<file_cache::FileCache> {
        &self.file_cache
    }

    /// Get analysis cache
    pub fn analysis_cache(&self) -> &Arc<analysis_cache::AnalysisCache> {
        &self.analysis_cache
    }

    /// Get query cache
    pub fn query_cache(&self) -> &Arc<query_cache::QueryCache> {
        &self.query_cache
    }

    /// Clear all caches
    pub fn clear_all(&self) -> Result<()> {
        self.file_cache.clear()?;
        self.analysis_cache.clear()?;
        self.query_cache.clear()?;
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            file_cache_entries: self.file_cache.len(),
            analysis_cache_entries: self.analysis_cache.len(),
            query_cache_entries: self.query_cache.len(),
            total_memory_usage: self.file_cache.memory_usage() +
                              self.analysis_cache.memory_usage() +
                              self.query_cache.memory_usage(),
        }
    }

    /// Check if a file needs re-analysis
    pub fn needs_analysis(&self, file_path: &Path, content: &str, config_hash: &str) -> bool {
        let key = CacheKey::new(
            file_path.to_string_lossy().as_ref(),
            content,
            config_hash,
        );

        !self.analysis_cache.contains(&key)
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub file_cache_entries: usize,
    pub analysis_cache_entries: usize,
    pub query_cache_entries: usize,
    pub total_memory_usage: usize,
}
