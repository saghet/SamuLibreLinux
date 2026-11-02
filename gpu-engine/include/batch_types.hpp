#pragma once

#include "pattern_types.hpp"
#include "ml_types.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace samulibre::gpu {

// Security Bound: 128 MB maximum file scan limit to prevent Out-Of-Memory DoS
constexpr size_t MAX_SCAN_FILE_SIZE = 128 * 1024 * 1024;

enum class TaskPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

struct ScanTask {
    uint64_t task_id = 0;
    std::string file_path;
    std::vector<uint8_t> inline_data; // Non-empty if scanning memory directly
    size_t file_size = 0;
    TaskPriority priority = TaskPriority::NORMAL;
};

struct TaskScanReport {
    uint64_t task_id = 0;
    std::string file_path;
    size_t file_size = 0;
    
    // Entropy & Packing
    double shannon_entropy = 0.0;
    bool is_suspicious_packed = false;
    
    // Pattern & Signature Matches (Phase 4)
    std::vector<PatternMatch> pattern_matches;
    
    // Machine Learning Ingestion (Phase 5)
    float ml_risk_probability = 0.0f;
    std::string ml_classification;
    std::vector<std::string> ml_contributing_features;
    
    // Final EDR Correlation Verdict (Secure by Design)
    std::string final_verdict; // "CLEAN", "SUSPICIOUS", "MALICIOUS"
    bool quarantine_recommended = false;
    
    // Performance & Pipeline Telemetry
    double total_duration_ms = 0.0;
    double pcie_dma_time_ms = 0.0;
    double gpu_compute_time_ms = 0.0;
    std::string backend_used;
    uint32_t stream_id = 0;
};

struct BatchMetrics {
    size_t total_tasks = 0;
    uint64_t total_bytes_scanned = 0;
    uint32_t total_threats_found = 0;
    double total_wall_time_ms = 0.0;
    double throughput_mb_s = 0.0;
    
    // PCIe Overlapping Telemetry
    double cumulative_dma_transfer_ms = 0.0;
    double cumulative_kernel_compute_ms = 0.0;
    double overlap_efficiency_ratio = 1.0; // Ratio of compute/DMA overlap (> 1.0 indicates parallel speedup)
    uint32_t active_streams = 1;
    size_t pinned_buffer_size_bytes = 0;
};

using TaskCallback = std::function<void(const TaskScanReport&)>;

} // namespace samulibre::gpu
