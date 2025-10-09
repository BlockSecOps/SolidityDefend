use std::path::{Path, PathBuf};
use std::sync::RwLock;
use dashmap::DashMap;
use anyhow::Result;
use serde::{Serialize, Deserialize};

use crate::{CacheKey, CacheEntry, CacheConfig};

/// Cached file content and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFile {
    /// File content
    pub content: String,
    /// File modification time
    pub modified_at: u64,
    /// File size in bytes
    pub size: u64,
    /// File path
    pub path: PathBuf,
}

impl CachedFile {
    pub fn new(path: PathBuf, content: String, metadata: &std::fs::Metadata) -> Self {
        let modified_at = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            content,
            modified_at,
            size: metadata.len(),
            path,
        }
    }

    /// Check if file has been modified since cache entry
    pub fn is_stale(&self, file_path: &Path) -> bool {
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let current_modified = metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            current_modified > self.modified_at || metadata.len() != self.size
        } else {
            true // File doesn't exist anymore
        }
    }
}

/// File content cache with LRU eviction
pub struct FileCache {
    /// In-memory cache
    cache: DashMap<String, CacheEntry<CachedFile>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current memory usage estimate
    memory_usage: RwLock<usize>,
}

impl FileCache {
    pub fn new(config: CacheConfig) -> Result<Self> {
        Ok(Self {
            cache: DashMap::new(),
            config,
            memory_usage: RwLock::new(0),
        })
    }

    /// Get file content from cache or filesystem
    pub fn get_file(&self, file_path: &Path) -> Result<String> {
        let path_str = file_path.to_string_lossy().to_string();

        // Check if we have it in cache and it's not stale
        if let Some(mut entry) = self.cache.get_mut(&path_str) {
            if !entry.data.is_stale(file_path) {
                entry.access();
                return Ok(entry.data.content.clone());
            } else {
                // Remove stale entry
                drop(entry);
                self.cache.remove(&path_str);
                self.update_memory_usage();
            }
        }

        // Read from filesystem and cache
        let content = std::fs::read_to_string(file_path)?;
        let metadata = std::fs::metadata(file_path)?;
        let cached_file = CachedFile::new(file_path.to_path_buf(), content.clone(), &metadata);

        // Create cache key (simplified for file cache)
        let key = CacheKey::new(&path_str, &content, "file_cache");
        let entry = CacheEntry::new(cached_file, key);

        // Add to cache
        self.cache.insert(path_str, entry);
        self.update_memory_usage();
        self.evict_if_needed();

        Ok(content)
    }

    /// Check if file is cached and up-to-date
    pub fn contains(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy().to_string();
        if let Some(entry) = self.cache.get(&path_str) {
            !entry.data.is_stale(file_path)
        } else {
            false
        }
    }

    /// Invalidate cache entry for a file
    pub fn invalidate(&self, file_path: &Path) {
        let path_str = file_path.to_string_lossy().to_string();
        self.cache.remove(&path_str);
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

    /// Update memory usage estimate
    fn update_memory_usage(&self) {
        let mut total = 0;
        for entry in self.cache.iter() {
            total += estimate_entry_size(entry.value());
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
        let mut entries: Vec<_> = self.cache.iter()
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

/// Estimate memory usage of a cache entry
fn estimate_entry_size(entry: &CacheEntry<CachedFile>) -> usize {
    entry.data.content.len() +
    entry.data.path.to_string_lossy().len() +
    entry.key.content_hash.len() +
    entry.key.file_path.len() +
    entry.key.config_hash.len() +
    64 // Approximate overhead
}