#pragma once

#include "batch_types.hpp"
#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "ml_classifier.hpp"
#include "resource_monitor.hpp"
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>

namespace samulibre::gpu {

class BatchScheduler {
public:
    explicit BatchScheduler(GPUComputeEngine& engine,
                            SignatureScanner& scanner,
                            MLClassifier& classifier);
    ~BatchScheduler();

    // Configuration & Profile adjustment
    void set_profile(ResourceProfile profile);
    ResourceProfile get_profile() const { return profile_; }

    // Queue management
    void enqueue_task(const ScanTask& task);
    void enqueue_file(const std::string& file_path, TaskPriority priority = TaskPriority::NORMAL);
    void enqueue_buffer(const uint8_t* data, size_t size,
                        const std::string& virtual_path = "memory_buffer",
                        TaskPriority priority = TaskPriority::NORMAL);
    
    size_t pending_tasks_count();
    void clear_queue();

    // Pipeline Execution: runs streaming double/triple buffering
    BatchMetrics process_all(TaskCallback callback = nullptr);

    // Single task execution directly through pipeline
    TaskScanReport process_single_task(const ScanTask& task);

    // Inspect active pipeline buffer capacities
    size_t get_slot_count() const { return slots_.size(); }
    size_t get_slot_capacity_bytes() const { return slot_capacity_bytes_; }

    // Resource Controller and Telemetry Monitor
    ResourceMonitor& get_resource_monitor() { return monitor_; }
    const ResourceMonitor& get_resource_monitor() const { return monitor_; }

private:
    struct PipelineSlot {
        uint32_t slot_id = 0;
        void* stream = nullptr;
        void* pinned_host_buffer = nullptr;
        void* device_buffer = nullptr;
        size_t capacity_bytes = 0;
        bool is_allocated = false;
    };

    void init_pipeline_slots();
    void release_pipeline_slots();
    
    TaskScanReport execute_task_on_slot(const ScanTask& task, PipelineSlot& slot);
    TaskScanReport execute_task_cpu_fallback(const ScanTask& task);

    GPUComputeEngine& engine_;
    SignatureScanner& scanner_;
    MLClassifier& classifier_;
    ResourceMonitor monitor_;
    ResourceProfile profile_;

    std::vector<PipelineSlot> slots_;
    size_t slot_capacity_bytes_ = 8 * 1024 * 1024; // Default 8 MB per slot

    std::queue<ScanTask> task_queue_;
    std::mutex queue_mutex_;
    std::atomic<uint64_t> next_task_id_{1};
    std::atomic<bool> is_running_{false};
};

} // namespace samulibre::gpu
