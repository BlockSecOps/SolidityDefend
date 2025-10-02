use std::sync::RwLock;
use dashmap::DashMap;
use anyhow::Result;
use serde::{Serialize, Deserialize};

use crate::{CacheKey, CacheEntry, CacheConfig};

/// Cached database query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedQueryResult {
    /// Query result data (JSON serialized)
    pub data: String,
    /// Query hash for identification
    pub query_hash: String,
    /// Parameters used in the query
    pub parameters: Vec<String>,
    /// Result metadata
    pub metadata: QueryMetadata,
}

/// Query execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMetadata {
    /// Query execution start time
    pub executed_at: u64,
    /// Query execution duration in microseconds
    pub duration_micros: u64,
    /// Number of rows returned
    pub row_count: usize,
    /// Whether the query was successful
    pub success: bool,
}

/// Database query cache for semantic analysis results
pub struct QueryCache {
    /// In-memory cache for query results
    cache: DashMap<String, CacheEntry<CachedQueryResult>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current memory usage estimate
    memory_usage: RwLock<usize>,
    /// Query execution statistics
    stats: RwLock<QueryCacheStats>,
}

/// Query cache statistics
#[derive(Debug, Clone, Default)]
pub struct QueryCacheStats {
    /// Total number of queries executed
    pub total_queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Total time saved by caching (microseconds)
    pub time_saved_micros: u64,
}

impl QueryCache {
    pub fn new(config: CacheConfig) -> Result<Self> {
        Ok(Self {
            cache: DashMap::new(),
            config,
            memory_usage: RwLock::new(0),
            stats: RwLock::new(QueryCacheStats::default()),
        })
    }

    /// Get cached query result
    pub fn get_query(&self, query: &str, parameters: &[String]) -> Option<CachedQueryResult> {
        let query_key = self.create_query_key(query, parameters);

        if let Some(mut entry) = self.cache.get_mut(&query_key) {
            // Check if entry is still valid (TTL)
            if self.is_entry_valid(&entry) {
                entry.access();

                // Update statistics
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.cache_hits += 1;
                    stats.time_saved_micros += entry.data.metadata.duration_micros;
                }

                return Some(entry.data.clone());
            } else {
                // Remove expired entry
                drop(entry);
                self.cache.remove(&query_key);
                self.update_memory_usage();
            }
        }

        // Update miss statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.cache_misses += 1;
        }

        None
    }

    /// Store query result in cache
    pub fn store_query(
        &self,
        query: &str,
        parameters: &[String],
        result_data: String,
        metadata: QueryMetadata,
    ) -> Result<()> {
        let query_key = self.create_query_key(query, parameters);
        let query_hash = self.hash_query(query);

        let cached_result = CachedQueryResult {
            data: result_data,
            query_hash,
            parameters: parameters.to_vec(),
            metadata,
        };

        // Create cache key (using query as content for hashing)
        let key = CacheKey::new(&query_key, query, "query_cache");
        let entry = CacheEntry::new(cached_result, key);

        self.cache.insert(query_key, entry);
        self.update_memory_usage();
        self.evict_if_needed();

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_queries += 1;
        }

        Ok(())
    }

    /// Check if cache contains result for the given query
    pub fn contains(&self, query: &str, parameters: &[String]) -> bool {
        let query_key = self.create_query_key(query, parameters);
        if let Some(entry) = self.cache.get(&query_key) {
            self.is_entry_valid(&entry)
        } else {
            false
        }
    }

    /// Invalidate all cached queries (useful when schema changes)
    pub fn invalidate_all_queries(&self) {
        self.cache.clear();
        *self.memory_usage.write().unwrap() = 0;
    }

    /// Invalidate queries matching a pattern
    pub fn invalidate_queries_matching(&self, pattern: &str) {
        self.cache.retain(|key, _| {
            !key.contains(pattern)
        });
        self.update_memory_usage();
    }

    /// Get cache statistics
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn memory_usage(&self) -> usize {
        *self.memory_usage.read().unwrap()
    }

    /// Get detailed cache statistics
    pub fn get_stats(&self) -> QueryCacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Get cache hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let stats = self.stats.read().unwrap();
        if stats.total_queries > 0 {
            stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64
        } else {
            0.0
        }
    }

    /// Clear all cache entries
    pub fn clear(&self) -> Result<()> {
        self.cache.clear();
        *self.memory_usage.write().unwrap() = 0;
        *self.stats.write().unwrap() = QueryCacheStats::default();
        Ok(())
    }

    /// Create a unique key for the query and parameters
    fn create_query_key(&self, query: &str, parameters: &[String]) -> String {
        let params_hash = self.hash_parameters(parameters);
        format!("{}:{}", self.hash_query(query), params_hash)
    }

    /// Hash the query string
    fn hash_query(&self, query: &str) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(query.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Hash the parameters
    fn hash_parameters(&self, parameters: &[String]) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        for param in parameters {
            hasher.update(param.as_bytes());
            hasher.update(b"|"); // Separator
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Check if cache entry is still valid based on TTL
    fn is_entry_valid(&self, entry: &CacheEntry<CachedQueryResult>) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        (now - entry.created_at) < self.config.ttl_seconds
    }

    /// Update memory usage estimate
    fn update_memory_usage(&self) {
        let mut total = 0;
        for entry in self.cache.iter() {
            total += estimate_query_entry_size(&entry.value());
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

/// Estimate memory usage of a query cache entry
fn estimate_query_entry_size(entry: &CacheEntry<CachedQueryResult>) -> usize {
    let params_size: usize = entry.data.parameters.iter()
        .map(|p| p.len())
        .sum();

    entry.data.data.len() +
    entry.data.query_hash.len() +
    params_size +
    entry.key.content_hash.len() +
    entry.key.file_path.len() +
    entry.key.config_hash.len() +
    96 // Metadata and overhead
}