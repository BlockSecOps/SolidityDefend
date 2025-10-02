use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
// use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
use std::time::{Duration, Instant};
use std::thread;

use detectors::types::{Finding, AnalysisResult};

/// Parallel execution framework for detector analysis
pub struct ParallelExecutor {
    /// Worker pool configuration
    config: ParallelConfig,
    /// Task queue for work distribution
    task_queue: (Sender<AnalysisTask>, Receiver<AnalysisTask>),
    /// Result collector
    result_collector: (Sender<TaskResult>, Receiver<TaskResult>),
    /// Worker threads
    workers: Vec<WorkerHandle>,
    /// Execution statistics
    stats: Arc<ParallelStats>,
    /// Active tasks tracking
    active_tasks: Arc<AtomicUsize>,
}

/// Configuration for parallel execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelConfig {
    /// Number of worker threads
    pub worker_threads: usize,
    /// Enable work stealing
    pub enable_work_stealing: bool,
    /// Task queue capacity
    pub queue_capacity: usize,
    /// Enable load balancing
    pub enable_load_balancing: bool,
    /// Maximum task execution time
    pub max_task_duration: Duration,
    /// Enable parallel execution (when AST is thread-safe)
    pub enable_parallel: bool,
    /// Batch size for bulk operations
    pub batch_size: usize,
    /// Enable adaptive scheduling
    pub adaptive_scheduling: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get().min(8),
            enable_work_stealing: true,
            queue_capacity: 1000,
            enable_load_balancing: true,
            max_task_duration: Duration::from_secs(30),
            enable_parallel: false, // Disabled until AST is thread-safe
            batch_size: 10,
            adaptive_scheduling: true,
        }
    }
}

/// Task for parallel execution
#[derive(Debug, Clone)]
pub struct AnalysisTask {
    /// Unique task identifier
    pub id: usize,
    /// Task type
    pub task_type: TaskType,
    /// Task data
    pub data: TaskData,
    /// Priority (higher = more urgent)
    pub priority: i32,
    /// Creation timestamp
    pub created_at: Instant,
    /// Expected execution time
    pub estimated_duration: Option<Duration>,
}

/// Type of analysis task
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskType {
    /// Single file analysis
    FileAnalysis,
    /// Detector execution
    DetectorExecution,
    /// Dependency resolution
    DependencyResolution,
    /// Cache operation
    CacheOperation,
    /// Batch processing
    BatchProcessing,
}

/// Task data payload
#[derive(Debug, Clone)]
pub enum TaskData {
    /// File analysis data
    File {
        file_path: String,
        content: String,
        detectors: Vec<String>,
    },
    /// Detector execution data
    Detector {
        detector_id: String,
        context_data: String, // Serialized context
    },
    /// Dependency data
    Dependency {
        file_path: String,
        dependencies: Vec<String>,
    },
    /// Cache operation data
    Cache {
        operation: String,
        key: String,
        data: Option<String>,
    },
    /// Batch operation data
    Batch {
        sub_tasks: Vec<AnalysisTask>,
    },
}

/// Result of task execution
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// Task ID
    pub task_id: usize,
    /// Execution status
    pub status: TaskStatus,
    /// Result data
    pub result: TaskResultData,
    /// Execution metrics
    pub metrics: TaskMetrics,
}

/// Task execution status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Task completed successfully
    Completed,
    /// Task failed with error
    Failed(String),
    /// Task was cancelled
    Cancelled,
    /// Task timed out
    TimedOut,
}

/// Task result data
#[derive(Debug, Clone)]
pub enum TaskResultData {
    /// Analysis findings
    Findings(Vec<Finding>),
    /// Analysis result
    AnalysisResult(AnalysisResult),
    /// Dependency information
    Dependencies(Vec<String>),
    /// Cache result
    CacheResult(Option<String>),
    /// Batch results
    BatchResults(Vec<TaskResult>),
    /// Empty result
    Empty,
}

/// Task execution metrics
#[derive(Debug, Clone)]
pub struct TaskMetrics {
    /// Execution duration
    pub duration: Duration,
    /// Queue wait time
    pub wait_time: Duration,
    /// Worker ID that executed the task
    pub worker_id: usize,
    /// Memory usage during execution
    pub memory_usage: usize,
    /// CPU time used
    pub cpu_time: Duration,
}

/// Worker thread handle
pub struct WorkerHandle {
    /// Worker ID
    pub id: usize,
    /// Thread handle
    pub handle: thread::JoinHandle<()>,
    /// Worker statistics
    pub stats: Arc<WorkerStats>,
}

/// Statistics for a worker thread
#[derive(Debug, Default)]
pub struct WorkerStats {
    /// Tasks completed
    pub tasks_completed: AtomicUsize,
    /// Tasks failed
    pub tasks_failed: AtomicUsize,
    /// Total execution time
    pub total_execution_time: parking_lot::Mutex<Duration>,
    /// Average task duration
    pub average_task_duration: parking_lot::Mutex<Duration>,
    /// Worker utilization
    pub utilization: parking_lot::Mutex<f64>,
}

/// Global parallel execution statistics
#[derive(Debug, Default)]
pub struct ParallelStats {
    /// Total tasks submitted
    pub tasks_submitted: AtomicUsize,
    /// Total tasks completed
    pub tasks_completed: AtomicUsize,
    /// Total tasks failed
    pub tasks_failed: AtomicUsize,
    /// Total execution time
    pub total_execution_time: parking_lot::Mutex<Duration>,
    /// Parallel efficiency
    pub parallel_efficiency: parking_lot::Mutex<f64>,
    /// Queue depth over time
    pub queue_depth_history: parking_lot::Mutex<Vec<(Instant, usize)>>,
    /// Throughput history
    pub throughput_history: parking_lot::Mutex<Vec<(Instant, f64)>>,
}

/// Parallel execution result
#[derive(Debug, Clone)]
pub struct ParallelExecutionResult {
    /// All task results
    pub results: Vec<TaskResult>,
    /// Execution summary
    pub summary: ExecutionSummary,
    /// Performance metrics
    pub performance: ParallelPerformanceMetrics,
}

/// Execution summary
#[derive(Debug, Clone)]
pub struct ExecutionSummary {
    /// Total tasks
    pub total_tasks: usize,
    /// Successful tasks
    pub successful_tasks: usize,
    /// Failed tasks
    pub failed_tasks: usize,
    /// Total execution time
    pub total_duration: Duration,
    /// Average task duration
    pub average_task_duration: Duration,
    /// Throughput (tasks per second)
    pub throughput: f64,
}

/// Performance metrics for parallel execution
#[derive(Debug, Clone)]
pub struct ParallelPerformanceMetrics {
    /// Speedup over sequential execution
    pub speedup: f64,
    /// Parallel efficiency
    pub efficiency: f64,
    /// Load balancing factor
    pub load_balance: f64,
    /// Queue utilization
    pub queue_utilization: f64,
    /// Worker utilization per thread
    pub worker_utilization: Vec<f64>,
}

impl ParallelExecutor {
    pub fn new(config: ParallelConfig) -> Result<Self> {
        let (task_sender, task_receiver) = if config.queue_capacity > 0 {
            bounded(config.queue_capacity)
        } else {
            unbounded()
        };

        let (result_sender, result_receiver) = unbounded();

        let stats = Arc::new(ParallelStats::default());
        let active_tasks = Arc::new(AtomicUsize::new(0));

        let mut workers = Vec::new();

        // Create worker threads
        for worker_id in 0..config.worker_threads {
            let worker_receiver = task_receiver.clone();
            let worker_result_sender = result_sender.clone();
            let worker_stats = Arc::new(WorkerStats::default());
            let worker_config = config.clone();
            let worker_active_tasks = Arc::clone(&active_tasks);

            let worker_stats_clone = Arc::clone(&worker_stats);

            let handle = thread::spawn(move || {
                Self::worker_thread_main(
                    worker_id,
                    worker_receiver,
                    worker_result_sender,
                    worker_stats_clone,
                    worker_config,
                    worker_active_tasks,
                );
            });

            workers.push(WorkerHandle {
                id: worker_id,
                handle,
                stats: worker_stats,
            });
        }

        Ok(Self {
            config,
            task_queue: (task_sender, task_receiver),
            result_collector: (result_sender, result_receiver),
            workers,
            stats,
            active_tasks,
        })
    }

    /// Submit a task for parallel execution
    pub fn submit_task(&self, task: AnalysisTask) -> Result<()> {
        if !self.config.enable_parallel {
            return Err(anyhow::anyhow!("Parallel execution is disabled"));
        }

        self.stats.tasks_submitted.fetch_add(1, Ordering::Relaxed);
        self.task_queue.0.send(task)?;
        Ok(())
    }

    /// Submit multiple tasks in batch
    pub fn submit_batch(&self, tasks: Vec<AnalysisTask>) -> Result<()> {
        for task in tasks {
            self.submit_task(task)?;
        }
        Ok(())
    }

    /// Execute tasks in parallel and collect results
    pub fn execute_parallel(&self, tasks: Vec<AnalysisTask>) -> Result<ParallelExecutionResult> {
        if !self.config.enable_parallel {
            // Fall back to sequential execution
            return self.execute_sequential(tasks);
        }

        let start_time = Instant::now();
        let total_tasks = tasks.len();

        // Submit all tasks
        for task in tasks {
            self.submit_task(task)?;
        }

        // Collect results
        let mut results = Vec::new();
        let mut collected = 0;

        while collected < total_tasks {
            if let Ok(result) = self.result_collector.1.recv_timeout(Duration::from_secs(1)) {
                results.push(result);
                collected += 1;
            }
        }

        let total_duration = start_time.elapsed();
        let successful_tasks = results.iter().filter(|r| matches!(r.status, TaskStatus::Completed)).count();
        let failed_tasks = total_tasks - successful_tasks;

        let average_task_duration = if total_tasks > 0 {
            total_duration / total_tasks as u32
        } else {
            Duration::ZERO
        };

        let throughput = if total_duration.as_secs_f64() > 0.0 {
            total_tasks as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let summary = ExecutionSummary {
            total_tasks,
            successful_tasks,
            failed_tasks,
            total_duration,
            average_task_duration,
            throughput,
        };

        let performance = self.calculate_performance_metrics(&results, total_duration);

        Ok(ParallelExecutionResult {
            results,
            summary,
            performance,
        })
    }

    /// Execute tasks sequentially (fallback)
    fn execute_sequential(&self, tasks: Vec<AnalysisTask>) -> Result<ParallelExecutionResult> {
        let start_time = Instant::now();
        let mut results = Vec::new();

        for task in tasks {
            let _task_start = Instant::now();
            let result = self.execute_task_sequentially(task);
            results.push(result);
        }

        let total_duration = start_time.elapsed();
        let total_tasks = results.len();
        let successful_tasks = results.iter().filter(|r| matches!(r.status, TaskStatus::Completed)).count();
        let failed_tasks = total_tasks - successful_tasks;

        let summary = ExecutionSummary {
            total_tasks,
            successful_tasks,
            failed_tasks,
            total_duration,
            average_task_duration: if total_tasks > 0 { total_duration / total_tasks as u32 } else { Duration::ZERO },
            throughput: if total_duration.as_secs_f64() > 0.0 { total_tasks as f64 / total_duration.as_secs_f64() } else { 0.0 },
        };

        let performance = ParallelPerformanceMetrics {
            speedup: 1.0, // Sequential execution
            efficiency: 1.0,
            load_balance: 1.0,
            queue_utilization: 0.0,
            worker_utilization: vec![1.0], // Single thread
        };

        Ok(ParallelExecutionResult {
            results,
            summary,
            performance,
        })
    }

    /// Execute a single task sequentially
    fn execute_task_sequentially(&self, task: AnalysisTask) -> TaskResult {
        let start_time = Instant::now();

        // Simulate task execution (in a real implementation, this would call actual detectors)
        let result = match task.task_type {
            TaskType::FileAnalysis => {
                // Simulate file analysis
                std::thread::sleep(Duration::from_millis(10));
                TaskResultData::Findings(vec![])
            }
            TaskType::DetectorExecution => {
                // Simulate detector execution
                std::thread::sleep(Duration::from_millis(5));
                TaskResultData::Findings(vec![])
            }
            _ => TaskResultData::Empty,
        };

        let duration = start_time.elapsed();

        TaskResult {
            task_id: task.id,
            status: TaskStatus::Completed,
            result,
            metrics: TaskMetrics {
                duration,
                wait_time: Duration::ZERO,
                worker_id: 0,
                memory_usage: 0,
                cpu_time: duration,
            },
        }
    }

    /// Worker thread main function
    fn worker_thread_main(
        worker_id: usize,
        task_receiver: Receiver<AnalysisTask>,
        result_sender: Sender<TaskResult>,
        stats: Arc<WorkerStats>,
        config: ParallelConfig,
        active_tasks: Arc<AtomicUsize>,
    ) {
        while let Ok(task) = task_receiver.recv() {
            let start_time = Instant::now();
            active_tasks.fetch_add(1, Ordering::Relaxed);

            // Execute the task
            let result = Self::execute_task(task, worker_id, &config);

            // Update statistics
            match result.status {
                TaskStatus::Completed => {
                    stats.tasks_completed.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    stats.tasks_failed.fetch_add(1, Ordering::Relaxed);
                }
            }

            let duration = start_time.elapsed();
            {
                let mut total_time = stats.total_execution_time.lock();
                *total_time += duration;
            }

            // Send result
            if result_sender.send(result).is_err() {
                break; // Receiver dropped, shutdown
            }

            active_tasks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Execute a single task
    fn execute_task(task: AnalysisTask, worker_id: usize, config: &ParallelConfig) -> TaskResult {
        let start_time = Instant::now();

        // Check for timeout
        let timeout = config.max_task_duration;
        let task_id = task.id;

        // Simulate task execution based on type
        let (status, result) = match task.task_type {
            TaskType::FileAnalysis => {
                // In a real implementation, this would parse and analyze the file
                std::thread::sleep(Duration::from_millis(20));
                (TaskStatus::Completed, TaskResultData::Findings(vec![]))
            }
            TaskType::DetectorExecution => {
                // In a real implementation, this would run specific detectors
                std::thread::sleep(Duration::from_millis(10));
                (TaskStatus::Completed, TaskResultData::Findings(vec![]))
            }
            TaskType::DependencyResolution => {
                // In a real implementation, this would resolve dependencies
                std::thread::sleep(Duration::from_millis(5));
                (TaskStatus::Completed, TaskResultData::Dependencies(vec![]))
            }
            TaskType::CacheOperation => {
                // In a real implementation, this would perform cache operations
                std::thread::sleep(Duration::from_millis(1));
                (TaskStatus::Completed, TaskResultData::CacheResult(None))
            }
            TaskType::BatchProcessing => {
                // In a real implementation, this would process sub-tasks
                (TaskStatus::Completed, TaskResultData::BatchResults(vec![]))
            }
        };

        let duration = start_time.elapsed();

        // Check for timeout
        let final_status = if duration > timeout {
            TaskStatus::TimedOut
        } else {
            status
        };

        TaskResult {
            task_id,
            status: final_status,
            result,
            metrics: TaskMetrics {
                duration,
                wait_time: Duration::ZERO, // Would be calculated from queue time
                worker_id,
                memory_usage: 0, // Would be measured in real implementation
                cpu_time: duration,
            },
        }
    }

    /// Calculate performance metrics
    fn calculate_performance_metrics(
        &self,
        results: &[TaskResult],
        total_duration: Duration,
    ) -> ParallelPerformanceMetrics {
        let worker_count = self.config.worker_threads;

        // Calculate theoretical sequential time
        let sequential_time: Duration = results.iter().map(|r| r.metrics.duration).sum();

        // Calculate speedup
        let speedup = if total_duration.as_secs_f64() > 0.0 {
            sequential_time.as_secs_f64() / total_duration.as_secs_f64()
        } else {
            1.0
        };

        // Calculate efficiency
        let efficiency = speedup / worker_count as f64;

        // Calculate load balance (simplified)
        let load_balance = if worker_count > 0 {
            let tasks_per_worker: Vec<_> = (0..worker_count)
                .map(|id| results.iter().filter(|r| r.metrics.worker_id == id).count())
                .collect();

            let max_tasks = tasks_per_worker.iter().max().unwrap_or(&0);
            let min_tasks = tasks_per_worker.iter().min().unwrap_or(&0);

            if *max_tasks > 0 {
                *min_tasks as f64 / *max_tasks as f64
            } else {
                1.0
            }
        } else {
            1.0
        };

        // Calculate worker utilization
        let worker_utilization: Vec<f64> = (0..worker_count)
            .map(|id| {
                let worker_time: Duration = results
                    .iter()
                    .filter(|r| r.metrics.worker_id == id)
                    .map(|r| r.metrics.duration)
                    .sum();

                if total_duration.as_secs_f64() > 0.0 {
                    worker_time.as_secs_f64() / total_duration.as_secs_f64()
                } else {
                    0.0
                }
            })
            .collect();

        ParallelPerformanceMetrics {
            speedup,
            efficiency,
            load_balance,
            queue_utilization: 0.0, // Would be calculated from queue depth history
            worker_utilization,
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> ParallelExecutionStats {
        let tasks_submitted = self.stats.tasks_submitted.load(Ordering::Relaxed);
        let tasks_completed = self.stats.tasks_completed.load(Ordering::Relaxed);
        let tasks_failed = self.stats.tasks_failed.load(Ordering::Relaxed);
        let active_tasks = self.active_tasks.load(Ordering::Relaxed);

        let worker_stats: Vec<_> = self.workers
            .iter()
            .map(|w| WorkerStatsSnapshot {
                worker_id: w.id,
                tasks_completed: w.stats.tasks_completed.load(Ordering::Relaxed),
                tasks_failed: w.stats.tasks_failed.load(Ordering::Relaxed),
                utilization: *w.stats.utilization.lock(),
            })
            .collect();

        ParallelExecutionStats {
            tasks_submitted,
            tasks_completed,
            tasks_failed,
            active_tasks,
            worker_count: self.workers.len(),
            worker_stats,
            queue_depth: self.task_queue.1.len(),
        }
    }

    /// Shutdown the executor
    pub fn shutdown(self) -> Result<()> {
        // Drop senders to signal workers to stop
        drop(self.task_queue.0);
        drop(self.result_collector.0);

        // Wait for workers to finish
        for worker in self.workers {
            worker.handle.join().map_err(|_| anyhow::anyhow!("Worker thread panicked"))?;
        }

        Ok(())
    }
}

/// Statistics snapshot for parallel execution
#[derive(Debug, Clone)]
pub struct ParallelExecutionStats {
    pub tasks_submitted: usize,
    pub tasks_completed: usize,
    pub tasks_failed: usize,
    pub active_tasks: usize,
    pub worker_count: usize,
    pub worker_stats: Vec<WorkerStatsSnapshot>,
    pub queue_depth: usize,
}

/// Worker statistics snapshot
#[derive(Debug, Clone)]
pub struct WorkerStatsSnapshot {
    pub worker_id: usize,
    pub tasks_completed: usize,
    pub tasks_failed: usize,
    pub utilization: f64,
}