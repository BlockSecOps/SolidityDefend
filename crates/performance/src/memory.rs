use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
use std::time::{Duration, Instant};

/// Memory management and optimization for large codebases
pub struct MemoryManager {
    /// Memory pools for different allocation sizes
    memory_pools: Arc<RwLock<HashMap<usize, MemoryPool>>>,
    /// Global memory statistics
    stats: Arc<MemoryStats>,
    /// Memory pressure monitor
    pressure_monitor: Arc<MemoryPressureMonitor>,
    /// Configuration
    config: MemoryConfig,
    /// Active allocations tracking
    allocations: Arc<RwLock<BTreeMap<usize, AllocationInfo>>>,
    /// Next allocation ID
    next_alloc_id: AtomicUsize,
}

/// Configuration for memory management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Enable memory pooling
    pub enable_pooling: bool,
    /// Maximum memory usage in bytes
    pub max_memory_usage: usize,
    /// Memory pressure threshold (0.0 - 1.0)
    pub pressure_threshold: f64,
    /// Enable aggressive garbage collection
    pub aggressive_gc: bool,
    /// Pool sizes to pre-allocate
    pub pool_sizes: Vec<usize>,
    /// Enable memory tracking
    pub enable_tracking: bool,
    /// Memory warning threshold
    pub warning_threshold: usize,
    /// Enable memory compaction
    pub enable_compaction: bool,
    /// Compaction interval in seconds
    pub compaction_interval: u64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enable_pooling: true,
            max_memory_usage: 2 * 1024 * 1024 * 1024, // 2GB
            pressure_threshold: 0.8,                  // 80%
            aggressive_gc: false,
            pool_sizes: vec![64, 256, 1024, 4096, 16384, 65536], // Common allocation sizes
            enable_tracking: true,
            warning_threshold: 1024 * 1024 * 1024, // 1GB
            enable_compaction: true,
            compaction_interval: 300, // 5 minutes
        }
    }
}

/// Memory pool for specific allocation sizes
pub struct MemoryPool {
    /// Size of allocations in this pool
    allocation_size: usize,
    /// Available memory blocks
    available_blocks: Vec<Vec<u8>>,
    /// Total blocks allocated
    total_blocks: usize,
    /// Blocks currently in use
    blocks_in_use: usize,
    /// Pool statistics
    stats: PoolStats,
}

/// Statistics for a memory pool
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    /// Total allocations from this pool
    pub total_allocations: usize,
    /// Total deallocations to this pool
    pub total_deallocations: usize,
    /// Peak concurrent allocations
    pub peak_concurrent: usize,
    /// Pool hit ratio
    pub hit_ratio: f64,
    /// Average allocation time
    pub avg_allocation_time: Duration,
}

/// Global memory statistics
pub struct MemoryStats {
    /// Current memory usage
    current_usage: AtomicUsize,
    /// Peak memory usage
    peak_usage: AtomicUsize,
    /// Total allocations
    total_allocations: AtomicUsize,
    /// Total deallocations
    total_deallocations: AtomicUsize,
    /// Garbage collection runs
    gc_runs: AtomicUsize,
    /// Memory freed by GC
    gc_freed: AtomicUsize,
    /// Memory pressure events
    pressure_events: AtomicUsize,
    /// Last pressure check
    _last_pressure_check: Mutex<Instant>,
}

/// Memory pressure monitoring
pub struct MemoryPressureMonitor {
    /// Current pressure level (0.0 - 1.0)
    pressure_level: AtomicUsize, // Stored as fixed-point
    /// Pressure history for trend analysis
    pressure_history: Mutex<Vec<(Instant, f64)>>,
    /// Warning callbacks
    warning_callbacks: Mutex<Vec<Arc<dyn Fn(f64) + Send + Sync>>>,
    /// Critical callbacks
    critical_callbacks: Mutex<Vec<Arc<dyn Fn(f64) + Send + Sync>>>,
}

/// Information about an active allocation
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    /// Allocation ID
    pub id: usize,
    /// Size in bytes
    pub size: usize,
    /// Allocation timestamp
    pub allocated_at: Instant,
    /// Source location (for debugging)
    pub source: String,
    /// Reference count
    pub ref_count: usize,
}

/// Memory usage report
#[derive(Debug, Clone)]
pub struct MemoryReport {
    /// Current memory usage
    pub current_usage: usize,
    /// Peak memory usage
    pub peak_usage: usize,
    /// Memory efficiency ratio
    pub efficiency_ratio: f64,
    /// Pool statistics
    pub pool_stats: HashMap<usize, PoolStatsReport>,
    /// Pressure level
    pub pressure_level: f64,
    /// Active allocations count
    pub active_allocations: usize,
    /// Fragmentation ratio
    pub fragmentation_ratio: f64,
    /// Garbage collection stats
    pub gc_stats: GcStats,
}

/// Pool statistics for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStatsReport {
    pub allocation_size: usize,
    pub total_blocks: usize,
    pub blocks_in_use: usize,
    pub hit_ratio: f64,
    pub efficiency: f64,
}

/// Garbage collection statistics
#[derive(Debug, Clone)]
pub struct GcStats {
    pub total_runs: usize,
    pub total_freed: usize,
    pub average_duration: Duration,
    pub last_run: Option<Instant>,
}

impl MemoryManager {
    pub fn new(config: MemoryConfig) -> Self {
        let mut memory_pools = HashMap::new();

        // Initialize memory pools for common sizes
        for &size in &config.pool_sizes {
            memory_pools.insert(size, MemoryPool::new(size));
        }

        let manager = Self {
            memory_pools: Arc::new(RwLock::new(memory_pools)),
            stats: Arc::new(MemoryStats::new()),
            pressure_monitor: Arc::new(MemoryPressureMonitor::new()),
            config,
            allocations: Arc::new(RwLock::new(BTreeMap::new())),
            next_alloc_id: AtomicUsize::new(1),
        };

        // Start background monitoring if enabled
        if manager.config.enable_tracking {
            manager.start_background_monitoring();
        }

        manager
    }

    /// Allocate memory with tracking
    pub fn allocate(&self, size: usize, source: &str) -> Result<Vec<u8>> {
        let _start_time = Instant::now();

        // Check memory pressure
        self.check_memory_pressure()?;

        // Try to allocate from pool first
        let memory = if self.config.enable_pooling {
            self.allocate_from_pool(size)
                .unwrap_or_else(|| vec![0; size])
        } else {
            vec![0; size]
        };

        // Track allocation
        if self.config.enable_tracking {
            let alloc_id = self.next_alloc_id.fetch_add(1, Ordering::Relaxed);
            let alloc_info = AllocationInfo {
                id: alloc_id,
                size,
                allocated_at: Instant::now(),
                source: source.to_string(),
                ref_count: 1,
            };
            self.allocations.write().insert(alloc_id, alloc_info);
        }

        // Update statistics
        self.stats.current_usage.fetch_add(size, Ordering::Relaxed);
        self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);

        let current = self.stats.current_usage.load(Ordering::Relaxed);
        let peak = self.stats.peak_usage.load(Ordering::Relaxed);
        if current > peak {
            self.stats.peak_usage.store(current, Ordering::Relaxed);
        }

        Ok(memory)
    }

    /// Deallocate memory
    pub fn deallocate(&self, alloc_id: usize, memory: Vec<u8>) {
        let size = memory.len();

        // Return to pool if possible
        if self.config.enable_pooling {
            self.return_to_pool(memory);
        }

        // Remove from tracking
        if self.config.enable_tracking {
            self.allocations.write().remove(&alloc_id);
        }

        // Update statistics
        self.stats.current_usage.fetch_sub(size, Ordering::Relaxed);
        self.stats
            .total_deallocations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Allocate from memory pool
    fn allocate_from_pool(&self, size: usize) -> Option<Vec<u8>> {
        // Find the smallest pool that can accommodate the size
        let pool_size = self
            .config
            .pool_sizes
            .iter()
            .find(|&&pool_size| pool_size >= size)
            .copied()?;

        let mut pools = self.memory_pools.write();
        if let Some(pool) = pools.get_mut(&pool_size) {
            pool.allocate()
        } else {
            None
        }
    }

    /// Return memory to pool
    fn return_to_pool(&self, mut memory: Vec<u8>) {
        let size = memory.len();

        // Find matching pool
        if let Some(&pool_size) = self.config.pool_sizes.iter().find(|&&ps| ps == size) {
            let mut pools = self.memory_pools.write();
            if let Some(pool) = pools.get_mut(&pool_size) {
                // Clear memory before returning to pool
                memory.fill(0);
                pool.deallocate(memory);
            }
        }
    }

    /// Check memory pressure and take action if needed
    fn check_memory_pressure(&self) -> Result<()> {
        let current_usage = self.stats.current_usage.load(Ordering::Relaxed);
        let pressure = current_usage as f64 / self.config.max_memory_usage as f64;

        self.pressure_monitor.update_pressure(pressure);

        if pressure > self.config.pressure_threshold {
            self.stats.pressure_events.fetch_add(1, Ordering::Relaxed);

            // Trigger garbage collection
            if self.config.aggressive_gc || pressure > 0.9 {
                self.run_garbage_collection()?;
            }

            // If still over threshold, return error
            let new_usage = self.stats.current_usage.load(Ordering::Relaxed);
            let new_pressure = new_usage as f64 / self.config.max_memory_usage as f64;
            if new_pressure > self.config.pressure_threshold {
                return Err(anyhow::anyhow!(
                    "Memory pressure too high: {:.2}%",
                    new_pressure * 100.0
                ));
            }
        }

        Ok(())
    }

    /// Run garbage collection
    fn run_garbage_collection(&self) -> Result<usize> {
        let start_time = Instant::now();
        let mut freed = 0;

        // Compact memory pools
        if self.config.enable_compaction {
            freed += self.compact_memory_pools();
        }

        // Clear unused allocations (this would be more sophisticated in a real implementation)
        let mut allocations = self.allocations.write();
        let before_count = allocations.len();

        // Remove allocations older than a threshold (simplified GC)
        let cutoff = Instant::now() - Duration::from_secs(60); // 1 minute
        allocations.retain(|_, alloc| alloc.allocated_at > cutoff || alloc.ref_count > 0);

        let after_count = allocations.len();
        let _removed = before_count - after_count;

        drop(allocations);

        // Update statistics
        self.stats.gc_runs.fetch_add(1, Ordering::Relaxed);
        self.stats.gc_freed.fetch_add(freed, Ordering::Relaxed);

        // Notify about GC completion
        if freed > 0 {
            log::info!(
                "Garbage collection freed {} bytes in {:?}",
                freed,
                start_time.elapsed()
            );
        }

        Ok(freed)
    }

    /// Compact memory pools to reduce fragmentation
    fn compact_memory_pools(&self) -> usize {
        let mut freed = 0;
        let mut pools = self.memory_pools.write();

        for pool in pools.values_mut() {
            freed += pool.compact();
        }

        freed
    }

    /// Start background monitoring
    fn start_background_monitoring(&self) {
        let stats = Arc::clone(&self.stats);
        let pressure_monitor = Arc::clone(&self.pressure_monitor);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Update pressure monitoring
                let current_usage = stats.current_usage.load(Ordering::Relaxed);
                let pressure = current_usage as f64 / config.max_memory_usage as f64;
                pressure_monitor.update_pressure(pressure);

                // Log warnings if memory usage is high
                if current_usage > config.warning_threshold {
                    log::warn!("High memory usage: {} MB", current_usage / (1024 * 1024));
                }
            }
        });
    }

    /// Get current memory report
    pub fn get_memory_report(&self) -> MemoryReport {
        let current_usage = self.stats.current_usage.load(Ordering::Relaxed);
        let peak_usage = self.stats.peak_usage.load(Ordering::Relaxed);
        let total_allocs = self.stats.total_allocations.load(Ordering::Relaxed);
        let total_deallocs = self.stats.total_deallocations.load(Ordering::Relaxed);

        let efficiency_ratio = if total_allocs > 0 {
            total_deallocs as f64 / total_allocs as f64
        } else {
            0.0
        };

        let pools = self.memory_pools.read();
        let mut pool_stats = HashMap::new();

        for (&size, pool) in pools.iter() {
            pool_stats.insert(
                size,
                PoolStatsReport {
                    allocation_size: size,
                    total_blocks: pool.total_blocks,
                    blocks_in_use: pool.blocks_in_use,
                    hit_ratio: pool.stats.hit_ratio,
                    efficiency: if pool.total_blocks > 0 {
                        (pool.total_blocks - pool.blocks_in_use) as f64 / pool.total_blocks as f64
                    } else {
                        0.0
                    },
                },
            );
        }

        let pressure_level = self.pressure_monitor.get_current_pressure();
        let active_allocations = self.allocations.read().len();

        // Calculate fragmentation (simplified)
        let fragmentation_ratio = if peak_usage > 0 {
            1.0 - (current_usage as f64 / peak_usage as f64)
        } else {
            0.0
        };

        let gc_runs = self.stats.gc_runs.load(Ordering::Relaxed);
        let gc_freed = self.stats.gc_freed.load(Ordering::Relaxed);

        MemoryReport {
            current_usage,
            peak_usage,
            efficiency_ratio,
            pool_stats,
            pressure_level,
            active_allocations,
            fragmentation_ratio,
            gc_stats: GcStats {
                total_runs: gc_runs,
                total_freed: gc_freed,
                average_duration: Duration::from_millis(50), // Placeholder
                last_run: None,                              // Would track in real implementation
            },
        }
    }

    /// Register memory pressure callback
    pub fn register_pressure_callback<F>(&self, threshold: f64, callback: F)
    where
        F: Fn(f64) + Send + Sync + 'static,
    {
        if threshold >= 0.9 {
            self.pressure_monitor
                .critical_callbacks
                .lock()
                .push(Arc::new(callback));
        } else {
            self.pressure_monitor
                .warning_callbacks
                .lock()
                .push(Arc::new(callback));
        }
    }

    /// Force garbage collection
    pub fn force_gc(&self) -> Result<usize> {
        self.run_garbage_collection()
    }

    /// Get memory statistics
    pub fn get_stats(&self) -> MemoryStatistics {
        MemoryStatistics {
            current_usage: self.stats.current_usage.load(Ordering::Relaxed),
            peak_usage: self.stats.peak_usage.load(Ordering::Relaxed),
            total_allocations: self.stats.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.stats.total_deallocations.load(Ordering::Relaxed),
            gc_runs: self.stats.gc_runs.load(Ordering::Relaxed),
            gc_freed: self.stats.gc_freed.load(Ordering::Relaxed),
            pressure_events: self.stats.pressure_events.load(Ordering::Relaxed),
            active_allocations: self.allocations.read().len(),
        }
    }
}

impl MemoryPool {
    fn new(allocation_size: usize) -> Self {
        Self {
            allocation_size,
            available_blocks: Vec::new(),
            total_blocks: 0,
            blocks_in_use: 0,
            stats: PoolStats::default(),
        }
    }

    fn allocate(&mut self) -> Option<Vec<u8>> {
        self.stats.total_allocations += 1;

        if let Some(block) = self.available_blocks.pop() {
            self.blocks_in_use += 1;
            self.stats.hit_ratio =
                self.stats.total_deallocations as f64 / self.stats.total_allocations as f64;
            Some(block)
        } else {
            // Create new block
            self.total_blocks += 1;
            self.blocks_in_use += 1;
            Some(vec![0; self.allocation_size])
        }
    }

    fn deallocate(&mut self, block: Vec<u8>) {
        if block.len() == self.allocation_size {
            self.available_blocks.push(block);
            self.blocks_in_use = self.blocks_in_use.saturating_sub(1);
            self.stats.total_deallocations += 1;
            self.stats.hit_ratio =
                self.stats.total_deallocations as f64 / self.stats.total_allocations as f64;
        }
    }

    fn compact(&mut self) -> usize {
        // Remove excess blocks to reduce memory usage
        let target_size = self.blocks_in_use + (self.blocks_in_use / 4); // Keep 25% extra
        let excess = self.available_blocks.len().saturating_sub(target_size);

        if excess > 0 {
            let freed = excess * self.allocation_size;
            self.available_blocks.truncate(target_size);
            self.total_blocks = self.blocks_in_use + self.available_blocks.len();
            freed
        } else {
            0
        }
    }
}

impl MemoryStats {
    fn new() -> Self {
        Self {
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            total_allocations: AtomicUsize::new(0),
            total_deallocations: AtomicUsize::new(0),
            gc_runs: AtomicUsize::new(0),
            gc_freed: AtomicUsize::new(0),
            pressure_events: AtomicUsize::new(0),
            _last_pressure_check: Mutex::new(Instant::now()),
        }
    }
}

impl MemoryPressureMonitor {
    fn new() -> Self {
        Self {
            pressure_level: AtomicUsize::new(0),
            pressure_history: Mutex::new(Vec::new()),
            warning_callbacks: Mutex::new(Vec::new()),
            critical_callbacks: Mutex::new(Vec::new()),
        }
    }

    fn update_pressure(&self, pressure: f64) {
        let pressure_fixed = (pressure * 1000.0) as usize; // Fixed point with 3 decimal places
        self.pressure_level.store(pressure_fixed, Ordering::Relaxed);

        // Store in history
        let mut history = self.pressure_history.lock();
        history.push((Instant::now(), pressure));

        // Keep only last hour of history
        let cutoff = Instant::now() - Duration::from_secs(3600);
        history.retain(|(time, _)| *time > cutoff);

        // Trigger callbacks
        if pressure >= 0.9 {
            let callbacks = self.critical_callbacks.lock();
            for callback in callbacks.iter() {
                callback(pressure);
            }
        } else if pressure >= 0.7 {
            let callbacks = self.warning_callbacks.lock();
            for callback in callbacks.iter() {
                callback(pressure);
            }
        }
    }

    fn get_current_pressure(&self) -> f64 {
        let pressure_fixed = self.pressure_level.load(Ordering::Relaxed);
        pressure_fixed as f64 / 1000.0
    }
}

/// Memory statistics snapshot
#[derive(Debug, Clone)]
pub struct MemoryStatistics {
    pub current_usage: usize,
    pub peak_usage: usize,
    pub total_allocations: usize,
    pub total_deallocations: usize,
    pub gc_runs: usize,
    pub gc_freed: usize,
    pub pressure_events: usize,
    pub active_allocations: usize,
}
